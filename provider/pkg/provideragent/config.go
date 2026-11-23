package provideragent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// ConfigSchema names the agent's configuration file.
const ConfigSchema = "tos.service.mcp-provider.agent-config.v1"

// maxConfigBytes bounds the configuration file.
const maxConfigBytes = 64 << 10

// Defaults of the autonomous bounds (section 2.5, decisions P1 and P3) and
// of the withdrawal preview bound.
const (
	DefaultMaxAdmissionsPerDay       = 50
	DefaultMinWalletNanoTOS          = 2_000_000_000
	DefaultMaxWithdrawPreviewsPerDay = 8
	// Retention bounds every offer bound must lie in.
	MinRetentionSeconds = 3_600
	MaxRetentionSeconds = 2_592_000
)

// OfferInputs are the operator's offer inputs, which the model can never
// supply (section 4.9).
type OfferInputs struct {
	ExecutorSocket       string `json:"executor_socket,omitempty"`
	ExecutorBinary       string `json:"executor_binary,omitempty"`
	ExecutorSHA256       string `json:"executor_sha256,omitempty"`
	ContainerdSocket     string `json:"containerd_socket,omitempty"`
	FIFODir              string `json:"fifo_dir,omitempty"`
	DeployFundingNanoTOS string `json:"deploy_funding_nanotos,omitempty"`
	RespondBudgetSeconds int    `json:"respond_budget_seconds,omitempty"`
	OfferPath            string `json:"offer_path,omitempty"`
	GatewayCardPath      string `json:"gateway_card_path,omitempty"`
	AttestorController   string `json:"attestor_controller,omitempty"`
	TestProfileActor     bool   `json:"test_profile_actor,omitempty"`
}

// OfferBounds are what a previewed offer must lie in (section 2.4).
type OfferBounds struct {
	MinPriceNanoTOS                string `json:"min_price_nanotos"`
	MaxPriceNanoTOS                string `json:"max_price_nanotos"`
	MaxStorageFeeNanoTOS           string `json:"max_storage_fee_nanotos"`
	MaxCleanupBountyNanoTOS        string `json:"max_cleanup_bounty_nanotos"`
	MinResponseSLASeconds          uint32 `json:"min_response_sla_seconds"`
	MaxResponseSLASeconds          uint32 `json:"max_response_sla_seconds"`
	MinRefundClaimWindowSeconds    uint32 `json:"min_refund_claim_window_seconds"`
	MaxRefundClaimWindowSeconds    uint32 `json:"max_refund_claim_window_seconds"`
	MinRetentionSeconds            uint64 `json:"min_retention_seconds"`
	MaxRetentionSeconds            uint64 `json:"max_retention_seconds"`
	minPrice, maxPrice, maxStorage uint64
	maxBounty                      uint64
}

// Config is the agent's configuration (section 2.4). It is decoded
// strictly: an unknown field, a duplicate key or trailing data refuses the
// file.
type Config struct {
	Schema     string      `json:"schema"`
	RailConfig string      `json:"rail_config"`
	StateDir   string      `json:"state_dir"`
	SocketDir  string      `json:"socket_dir"`
	ClientUID  uint32      `json:"client_uid"`
	Offer      OfferInputs `json:"offer"`
	Bounds     OfferBounds `json:"offer_bounds"`
	// The autonomous bounds; zero takes the default.
	MaxAdmissionsPerDay       uint64 `json:"max_admissions_per_day,omitempty"`
	MinWalletNanoTOS          string `json:"min_wallet_nanotos,omitempty"`
	MaxWithdrawPreviewsPerDay int    `json:"max_withdraw_previews_per_day,omitempty"`

	minWallet     uint64
	deployFunding uint64
}

var amountPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})$`)

// parseAmount reads a decimal nanoTOS amount of at most 2^64-1.
func parseAmount(text string) (uint64, bool) {
	if !amountPattern.MatchString(text) {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 64)
	return value, err == nil
}

// ReadConfig reads the configuration: an owner-private regular file of the
// agent's account, decoded strictly, with every bound checked and the
// defaults filled in.
func ReadConfig(path string) (Config, error) {
	var config Config
	if !cleanAbsolute(path) {
		return config, errors.New("--config must be an absolute, clean path")
	}
	if err := checkPrivateFile(path, "agent configuration"); err != nil {
		return config, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return config, err
	}
	if info.Size() > maxConfigBytes {
		return config, errors.New("the agent configuration exceeds 64 KiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	if err := decodeStrictNoDuplicates(raw, &config); err != nil {
		return config, fmt.Errorf("the agent configuration does not decode strictly: %w", err)
	}
	return config, config.check()
}

func (c *Config) check() error {
	switch {
	case c.Schema != ConfigSchema:
		return errors.New("the agent configuration names another schema")
	case !cleanAbsolute(c.RailConfig) || !cleanAbsolute(c.StateDir) || !cleanAbsolute(c.SocketDir):
		return errors.New("rail_config, state_dir and socket_dir must be absolute clean paths")
	case c.ClientUID == 0:
		return errors.New("the agent configuration must name client_uid, and it must not be root")
	case c.ClientUID == uint32(os.Geteuid()):
		return errors.New("client_uid must differ from the agent's own uid")
	}
	if c.MaxAdmissionsPerDay == 0 {
		c.MaxAdmissionsPerDay = DefaultMaxAdmissionsPerDay
	}
	if c.MaxAdmissionsPerDay > 100_000 {
		return errors.New("max_admissions_per_day must be 1 to 100000")
	}
	if c.MaxWithdrawPreviewsPerDay == 0 {
		c.MaxWithdrawPreviewsPerDay = DefaultMaxWithdrawPreviewsPerDay
	}
	if c.MaxWithdrawPreviewsPerDay < 0 || c.MaxWithdrawPreviewsPerDay > 1000 {
		return errors.New("max_withdraw_previews_per_day must be 1 to 1000")
	}
	c.minWallet = DefaultMinWalletNanoTOS
	if c.MinWalletNanoTOS != "" {
		value, ok := parseAmount(c.MinWalletNanoTOS)
		if !ok || value == 0 {
			return errors.New("min_wallet_nanotos must be a decimal nanoTOS amount greater than zero")
		}
		c.minWallet = value
	}
	if err := c.Offer.check(); err != nil {
		return err
	}
	if c.Offer.DeployFundingNanoTOS != "" {
		value, ok := parseAmount(c.Offer.DeployFundingNanoTOS)
		if !ok || value < servicebridge.MinimumDeployFundingNano {
			return fmt.Errorf("offer.deploy_funding_nanotos must be at least %d", servicebridge.MinimumDeployFundingNano)
		}
		c.deployFunding = value
	}
	return c.Bounds.check(c.Offer.TestProfileActor)
}

func (o OfferInputs) check() error {
	for name, path := range map[string]string{
		"executor_socket": o.ExecutorSocket, "executor_binary": o.ExecutorBinary,
		"containerd_socket": o.ContainerdSocket, "fifo_dir": o.FIFODir, "offer_path": o.OfferPath,
		"gateway_card_path": o.GatewayCardPath,
	} {
		if path != "" && !cleanAbsolute(path) {
			return fmt.Errorf("offer.%s must be an absolute clean path", name)
		}
	}
	if o.RespondBudgetSeconds < 0 || o.RespondBudgetSeconds > 3600 {
		return errors.New("offer.respond_budget_seconds must be 0 (the default) to 3600")
	}
	return nil
}

func (b *OfferBounds) check(testProfile bool) error {
	var ok bool
	parsed := []struct {
		name  string
		text  string
		value *uint64
	}{
		{"min_price_nanotos", b.MinPriceNanoTOS, &b.minPrice}, {"max_price_nanotos", b.MaxPriceNanoTOS, &b.maxPrice},
		{"max_storage_fee_nanotos", b.MaxStorageFeeNanoTOS, &b.maxStorage},
		{"max_cleanup_bounty_nanotos", b.MaxCleanupBountyNanoTOS, &b.maxBounty},
	}
	for _, field := range parsed {
		if *field.value, ok = parseAmount(field.text); !ok {
			return fmt.Errorf("offer_bounds.%s must be a decimal nanoTOS amount", field.name)
		}
	}
	minWindow := servicebridge.MinPolicyWindowSecs
	if testProfile {
		minWindow = servicebridge.MinTestProfileWindowSecs
	}
	floor, err := checkedAdd(servicebridge.MinStorageFeeBaseNano, servicebridge.MinCleanupBountyNano)
	if err != nil {
		return err
	}
	switch {
	case b.minPrice == 0 || b.minPrice > b.maxPrice:
		return errors.New("offer_bounds: the price range must be non-empty and start above zero")
	case b.maxBounty < servicebridge.MinCleanupBountyNano || b.maxBounty > servicebridge.MaxCleanupBountyNano:
		return errors.New("offer_bounds.max_cleanup_bounty_nanotos must lie within the contract's cleanup bounty bounds")
	case b.maxStorage < floor:
		return errors.New("offer_bounds.max_storage_fee_nanotos is below the contract's lowest storage fee")
	case !windowRange(b.MinResponseSLASeconds, b.MaxResponseSLASeconds, minWindow):
		return errors.New("offer_bounds: the response SLA range must lie within the contract's window bounds")
	case !windowRange(b.MinRefundClaimWindowSeconds, b.MaxRefundClaimWindowSeconds, minWindow):
		return errors.New("offer_bounds: the refund claim window range must lie within the contract's window bounds")
	case b.MinRetentionSeconds < MinRetentionSeconds || b.MaxRetentionSeconds > MaxRetentionSeconds ||
		b.MinRetentionSeconds > b.MaxRetentionSeconds:
		return errors.New("offer_bounds: the retention range must lie within 3600 to 2592000 seconds")
	}
	return nil
}

func windowRange(low, high, minWindow uint32) bool {
	return low >= minWindow && high <= servicebridge.MaxPolicyWindowSecs && low <= high
}

func checkedAdd(a, b uint64) (uint64, error) {
	sum := a + b
	if sum < a {
		return 0, servicebridge.ErrAmountOverflow
	}
	return sum, nil
}

// checkRailConfig refuses a rail configuration the agent does not serve: a
// buyer, chat or messenger carrier, or a state directory that is not owner
// private. A configuration without a provider section is accepted: that is
// a node `init` set up and whose offer is not yet published, which the
// agent publishes (section 3.1).
func checkRailConfig(path string, rail servicebridge.NodeConfig, agentState, socketDir string) error {
	switch {
	case rail.Buyer != nil || rail.Chat != nil || rail.MessengerSocket != "":
		return errors.New("the rail configuration names a buyer, chat or messenger carrier; the provider agent " +
			"serves provider nodes only")
	case !cleanAbsolute(rail.StateDir):
		return errors.New("the rail configuration's state_dir must be absolute and clean")
	}
	if err := checkPrivateFile(path, "rail configuration"); err != nil {
		return err
	}
	if err := checkPrivateDir(rail.StateDir); err != nil {
		return fmt.Errorf("the rail state_dir: %w", err)
	}
	if rail.TOSCTL.ConfigPath != "" {
		if err := checkPrivateFile(rail.TOSCTL.ConfigPath, "tosctl configuration"); err != nil {
			return err
		}
	}
	for _, pair := range [][2]string{{agentState, rail.StateDir}, {socketDir, rail.StateDir}, {socketDir, agentState}} {
		if within(pair[0], pair[1]) || within(pair[1], pair[0]) {
			return errors.New("the agent state_dir, the socket_dir and the rail state_dir must be separate " +
				"directories, none inside another")
		}
	}
	return nil
}

// within reports whether path is base or inside it.
func within(path, base string) bool {
	relative, err := filepath.Rel(base, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, "../")
}
