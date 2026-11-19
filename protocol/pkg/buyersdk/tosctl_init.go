package buyersdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// The tosctl commands `tos-service-buyer init` drives (MCP_BUYER_ADAPTER_V1
// section 3.2). None of them prints key material: tosctl keeps the wallet
// and controller keys in its vault and returns only public values. tosctl's
// own diagnostics are never returned, since they can quote the configuration
// or the vault; every failure is a fixed error.

// TOSCTLNamePattern is the wallet and controller names init accepts.
var TOSCTLNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// BuyerWalletVersion is the version init creates a buyer wallet with. Its
// signed messages expire, so a send that is absent past its window can no
// longer land.
const BuyerWalletVersion = "V4R2"

// ExpiringWalletTypes are the wallet versions whose messages tosctl signs
// with an expiry. A V1R3 message stays valid until its sequence number is
// used, so it could land long after it seemed lost.
var ExpiringWalletTypes = map[string]bool{"V3R2": true, "V4R2": true, "V5R1": true}

var (
	// ErrTOSCTLAbsent is tosctl reporting that its vault or configuration
	// holds no entry of that name.
	ErrTOSCTLAbsent = errors.New("tosctl holds no entry of that name")
	// ErrTOSCTLFailed is any other failed tosctl run.
	ErrTOSCTLFailed = errors.New("tosctl failed")
	// ErrTOSCTLAnswer is a tosctl answer of an unexpected shape.
	ErrTOSCTLAnswer = errors.New("tosctl returned an unexpected answer")
)

// RegistryDomain is the identity domain tosctl derives from a chain global
// configuration and a network label.
type RegistryDomain struct {
	NetworkLabel    string
	GenesisRootHash string
	GenesisFileHash string
	CodeHash        string
}

// ControllerKey is the public half of a vault controller.
type ControllerKey struct {
	Name      string
	KeyID     [mldsa44.KeyIDSize]byte
	PublicKey []byte
}

// Text is the controller's key ID as mldsa44:<hex>.
func (k ControllerKey) Text() string { return mldsa44.KeyIDText(k.KeyID) }

// CustodyWallet is a wallet of the tosctl configuration.
type CustodyWallet struct {
	Name string
	// Address is the raw workchain 0 address tosctl derives.
	Address string
	// Type is the wallet version tosctl read from the deployed account;
	// empty when it could not read one.
	Type string
}

// SignedAgentRegistration is an Agent registration tosctl built and signed
// with a controller. It is public data: a wallet still has to send it.
type SignedAgentRegistration struct {
	AgentID      string `json:"agent_id"`
	Destination  string `json:"destination"`
	ActionHash   string `json:"action_hash"`
	StateInitBOC string `json:"state_init_boc"`
	BodyBOC      string `json:"body_boc"`
}

// Validate checks the registration's shape.
func (r SignedAgentRegistration) Validate() error {
	if !agentIDPattern.MatchString(r.AgentID) || !isRawAddress(r.Destination) || len(r.ActionHash) != 64 ||
		!isLowerHex(r.ActionHash) || !canonicalBOC(r.StateInitBOC) || !canonicalBOC(r.BodyBOC) {
		return errors.New("invalid Agent registration")
	}
	return nil
}

func isLowerHex(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}

func canonicalBOC(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) > 0 && base64.StdEncoding.EncodeToString(raw) == value
}

// TOSCTLInitCustodyConfig pins the custody binary by SHA-256.
type TOSCTLInitCustodyConfig struct {
	BinaryPath   string
	BinarySHA256 string
	// ConfigPath is the tosctl configuration. Creating a wallet writes it;
	// every other command runs from a pinned copy of its bytes.
	ConfigPath   string
	VaultURL     string
	GlobalConfig string
	NetworkLabel string
	Endpoints    EndpointVetter
	Timeout      time.Duration
}

// TOSCTLInitCustody runs the tosctl commands of init.
type TOSCTLInitCustody struct {
	configPath, globalConfig, label string
	runner                          *execRunner
	endpoints                       EndpointVetter
	// run passes the pinned configuration on a descriptor; runPath writes
	// it to a private copy for commands that read only a path; runLive
	// runs against the configuration file itself.
	run, runPath, runLive func(ctx context.Context, args ...string) ([]byte, error)
}

// NewTOSCTLInitCustody pins the binary and the configuration.
func NewTOSCTLInitCustody(config TOSCTLInitCustodyConfig) (*TOSCTLInitCustody, error) {
	if !secureExecutable(config.BinaryPath) || !secureConfigFile(config.ConfigPath) || config.Endpoints == nil ||
		!cleanAbsolutePath(config.GlobalConfig) || !validNetworkLabel(config.NetworkLabel) {
		return nil, errors.New("invalid tosctl init configuration")
	}
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Minute
	}
	if config.Timeout < time.Second || config.Timeout > 10*time.Minute {
		return nil, errors.New("invalid tosctl timeout")
	}
	runner, err := newPinnedExecRunnerWithVault(config.BinaryPath, config.ConfigPath, config.VaultURL)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(runner.identity.digest[:]) != config.BinarySHA256 {
		return nil, errors.New("the tosctl binary does not have the pinned SHA-256")
	}
	bounded := func(run func(context.Context, string, ...string) ([]byte, error)) func(context.Context, ...string) ([]byte, error) {
		return func(ctx context.Context, args ...string) ([]byte, error) {
			call, cancel := context.WithTimeout(ctx, config.Timeout)
			defer cancel()
			return run(call, config.BinaryPath, args...)
		}
	}
	custody := &TOSCTLInitCustody{configPath: config.ConfigPath, globalConfig: config.GlobalConfig,
		label: config.NetworkLabel, runner: runner, endpoints: config.Endpoints}
	custody.run = bounded(runner.run)
	custody.runPath = bounded(runner.runWithConfigPath)
	custody.runLive = bounded(func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		return runner.runAtConfigPath(ctx, binary, config.ConfigPath, args...)
	})
	return custody, nil
}

// reload re-reads the configuration after runLive changed it, under the
// same checks as when it was pinned.
func (c *TOSCTLInitCustody) reload() error {
	if !secureConfigFile(c.configPath) {
		return errors.New("the tosctl configuration is no longer an owner-private file")
	}
	raw, err := os.ReadFile(c.configPath)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return errors.New("read bounded tosctl custody configuration")
	}
	c.runner.config = raw
	return nil
}

func cleanAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validNetworkLabel(label string) bool {
	return label != "" && len(label) <= 64 && !strings.HasPrefix(label, "-") &&
		!strings.ContainsAny(label, " \t\r\n\x00")
}

// runAtConfigPath runs the pinned executable against the configuration file
// itself, for a command that changes it.
func (r *execRunner) runAtConfigPath(ctx context.Context, binary, configPath string, args ...string) ([]byte, error) {
	executable, identity, err := openAndIdentifyExecutable(binary)
	if err != nil || identity != r.identity {
		if executable != nil {
			_ = executable.Close()
		}
		return nil, fmt.Errorf("%w: enrolled tosctl executable identity changed", ErrCallNotStarted)
	}
	defer executable.Close()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", append(append([]string(nil), args...), "-c", configPath)...)
	command.ExtraFiles = []*os.File{executable}
	command.Env = r.childEnvironment()
	output := cappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = &output, &output
	err = command.Run()
	return output.Bytes(), err
}

// finalFailure reports whether a failed run's last line is tosctl's
// "command failed:" line naming phrase. A phrase in an earlier progress line
// says nothing about why the run ended.
func finalFailure(output []byte, phrase string) bool {
	lines := bytes.Split(bytes.TrimRight(output, "\r\n \t"), []byte("\n"))
	final := bytes.TrimRight(lines[len(lines)-1], "\r")
	return bytes.HasPrefix(final, []byte("command failed: ")) && bytes.Contains(final, []byte(phrase))
}

// failure turns a failed run into a fixed error.
func failure(label string, output []byte, err error) error {
	if errors.Is(err, ErrCallNotStarted) {
		return fmt.Errorf("tosctl %s: %w", label, ErrCallNotStarted)
	}
	if finalFailure(output, "[E100: Not found]") {
		return fmt.Errorf("tosctl %s: %w", label, ErrTOSCTLAbsent)
	}
	return fmt.Errorf("tosctl %s: %w", label, ErrTOSCTLFailed)
}

// decodeAnswer decodes tosctl's JSON answer strictly: an unknown or missing
// field means another tosctl than the one this code was written against.
func decodeAnswer(label string, output []byte, value any) error {
	if err := jsonstrict.Decode(bytes.TrimSpace(output), value); err != nil {
		return fmt.Errorf("tosctl %s: %w", label, ErrTOSCTLAnswer)
	}
	return nil
}

// CheckEndpoints requires every endpoint the tosctl configuration submits
// through to be a verified endpoint of the verified network.
func (c *TOSCTLInitCustody) CheckEndpoints(ctx context.Context) error {
	return checkTOSCTLEndpoints(ctx, c.runner.config, c.endpoints)
}

// Domain runs `agent native-registry domain`, which reads only the global
// configuration, and checks that it answers for the label given.
func (c *TOSCTLInitCustody) Domain(ctx context.Context) (RegistryDomain, error) {
	const label = "agent native-registry domain"
	output, err := c.runPath(ctx, "agent", "native-registry", "domain", "--global-config", c.globalConfig,
		"--network-label", c.label, "--format", "json")
	if err != nil {
		return RegistryDomain{}, failure(label, output, err)
	}
	var answer struct {
		NetworkLabel string `json:"network_label"`
		GenesisRoot  string `json:"genesis_root"`
		GenesisFile  string `json:"genesis_file"`
		NetworkHash  string `json:"network_hash"`
		CodeHash     string `json:"code_hash"`
	}
	if err := decodeAnswer(label, output, &answer); err != nil {
		return RegistryDomain{}, err
	}
	labelHash := sha256.Sum256([]byte(c.label))
	if answer.NetworkLabel != c.label || answer.NetworkHash != hex.EncodeToString(labelHash[:]) ||
		!hex64(answer.GenesisRoot) || !hex64(answer.GenesisFile) || !hex64(answer.CodeHash) {
		return RegistryDomain{}, fmt.Errorf("tosctl %s: the domain does not answer for the network label: %w", label,
			ErrTOSCTLAnswer)
	}
	return RegistryDomain{NetworkLabel: c.label, GenesisRootHash: "sha256:" + answer.GenesisRoot,
		GenesisFileHash: "sha256:" + answer.GenesisFile, CodeHash: "tvm-cell-sha256:" + answer.CodeHash}, nil
}

func hex64(value string) bool { return len(value) == 64 && isLowerHex(value) }

// Wallet resolves one configured wallet with `wallet ls`: the address tosctl
// derives from the vault key and, online, the wallet type tosctl reads from
// the deployed account. Offline it reads no chain. Balances are read from
// finalized state, never from tosctl.
func (c *TOSCTLInitCustody) Wallet(ctx context.Context, name string, online bool) (CustodyWallet, error) {
	const label = "wallet ls"
	if !TOSCTLNamePattern.MatchString(name) {
		return CustodyWallet{}, errors.New("invalid tosctl wallet name")
	}
	args := []string{"wallet", "ls", "--format", "json"}
	if !online {
		args = append(args, "--offline")
	}
	output, err := c.run(ctx, args...)
	if err != nil {
		return CustodyWallet{}, failure(label, output, err)
	}
	var answers []struct {
		Name       string  `json:"name"`
		Address    *string `json:"address"`
		Balance    *string `json:"balance"`
		State      *string `json:"state"`
		WalletType *string `json:"wallet_type"`
		Seqno      *uint32 `json:"seqno"`
	}
	if err := decodeAnswer(label, output, &answers); err != nil {
		return CustodyWallet{}, err
	}
	for _, answer := range answers {
		if answer.Name != name {
			continue
		}
		if answer.Address == nil {
			return CustodyWallet{}, fmt.Errorf("tosctl %s: the key of wallet %q is not in the vault: %w", label, name,
				ErrTOSCTLAnswer)
		}
		parsed, err := parseAnyAddress(*answer.Address)
		if err != nil || parsed == nil || parsed.Workchain() != 0 {
			return CustodyWallet{}, fmt.Errorf("tosctl %s: wallet %q is not a workchain 0 address: %w", label, name,
				ErrTOSCTLAnswer)
		}
		wallet := CustodyWallet{Name: name, Address: parsed.StringRaw()}
		if answer.WalletType != nil {
			wallet.Type = *answer.WalletType
		}
		return wallet, nil
	}
	return CustodyWallet{}, fmt.Errorf("tosctl %s: wallet %q: %w", label, name, ErrTOSCTLAbsent)
}

// CreateWallet creates a buyer wallet in the vault and the configuration.
// tosctl refuses a name the configuration already has, so an existing
// wallet is never replaced.
func (c *TOSCTLInitCustody) CreateWallet(ctx context.Context, name string) error {
	const label = "wallet create"
	if !TOSCTLNamePattern.MatchString(name) {
		return errors.New("invalid tosctl wallet name")
	}
	output, err := c.runLive(ctx, "wallet", "create", "-n", name, "-v", BuyerWalletVersion, "-w", "0")
	if err != nil {
		return failure(label, output, err)
	}
	return c.reload()
}

// ActivateWallet deploys a funded wallet. tosctl skips a wallet that is
// already active or underfunded and still succeeds, so only finalized state
// tells whether it is active.
func (c *TOSCTLInitCustody) ActivateWallet(ctx context.Context, name string) error {
	const label = "wallet activate"
	if !TOSCTLNamePattern.MatchString(name) {
		return fmt.Errorf("invalid tosctl wallet name: %w", ErrCallNotStarted)
	}
	if err := c.CheckEndpoints(ctx); err != nil {
		return errors.Join(ErrCallNotStarted, err)
	}
	output, err := c.runPath(ctx, "wallet", "activate", "-n", name)
	if err != nil {
		return failure(label, output, err)
	}
	return nil
}

type controllerAnswer struct {
	Name      string `json:"name"`
	Suite     string `json:"suite"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func (c *TOSCTLInitCustody) controllerCommand(ctx context.Context, verb, name string) (ControllerKey, error) {
	label := "agent native-registry " + verb
	if !TOSCTLNamePattern.MatchString(name) {
		return ControllerKey{}, errors.New("invalid tosctl controller name")
	}
	output, err := c.runPath(ctx, "agent", "native-registry", verb, "--name", name, "--format", "json")
	if err != nil {
		return ControllerKey{}, failure(label, output, err)
	}
	var answer controllerAnswer
	if err := decodeAnswer(label, output, &answer); err != nil {
		return ControllerKey{}, err
	}
	publicKey, err := hex.DecodeString(answer.PublicKey)
	if err != nil || answer.Name != name || answer.Suite != "ML-DSA-44" || len(publicKey) != mldsa44.PublicKeySize {
		return ControllerKey{}, fmt.Errorf("tosctl %s: %w", label, ErrTOSCTLAnswer)
	}
	derived, err := mldsa44.KeyID(publicKey)
	if err != nil || hex.EncodeToString(derived[:]) != answer.KeyID {
		return ControllerKey{}, fmt.Errorf("tosctl %s: the public key does not derive the stated key ID: %w", label,
			ErrTOSCTLAnswer)
	}
	return ControllerKey{Name: name, KeyID: derived, PublicKey: publicKey}, nil
}

// Controller reads a controller's public key; ErrTOSCTLAbsent when the vault
// holds none of that name.
func (c *TOSCTLInitCustody) Controller(ctx context.Context, name string) (ControllerKey, error) {
	return c.controllerCommand(ctx, "controller", name)
}

// NewController creates a controller. tosctl stores it only if the name is
// free, so an existing key is never replaced.
func (c *TOSCTLInitCustody) NewController(ctx context.Context, name string) (ControllerKey, error) {
	return c.controllerCommand(ctx, "new-controller", name)
}

// BuyerAgentPolicy is the policy a buyer Agent is registered with: one
// controller that alone meets both thresholds and carries every purpose,
// until the registry has a packet-only purpose (MCP_BUYER_ADAPTER_V1 3.1).
func BuyerAgentPolicy(controller ControllerKey) ([]byte, error) {
	if len(controller.PublicKey) != mldsa44.PublicKeySize {
		return nil, errors.New("invalid controller public key")
	}
	return json.Marshal(map[string]any{"threshold": 1, "recovery_threshold": 1, "recovery_timelock": 3600,
		"controllers": []map[string]any{{"public_key": hex.EncodeToString(controller.PublicKey), "weight": 1,
			"purposes": 15}}})
}

// RegisterAgent builds and signs an Agent registration with the policy file
// and the 32-byte hex nonce. Nothing is sent.
func (c *TOSCTLInitCustody) RegisterAgent(ctx context.Context, policyPath, nonce, signer string) (SignedAgentRegistration, error) {
	const label = "agent native-registry register-agent"
	if !cleanAbsolutePath(policyPath) || !hex64(nonce) || !TOSCTLNamePattern.MatchString(signer) {
		return SignedAgentRegistration{}, errors.New("invalid Agent registration request")
	}
	output, err := c.runPath(ctx, "agent", "native-registry", "register-agent", "--global-config", c.globalConfig,
		"--network-label", c.label, "--policy", policyPath, "--nonce", nonce, "--signer", signer, "--format", "json")
	if err != nil {
		return SignedAgentRegistration{}, failure(label, output, err)
	}
	var answer struct {
		Kind         string `json:"kind"`
		ObjectID     string `json:"object_id"`
		Destination  string `json:"destination"`
		FinalTarget  string `json:"final_target"`
		ActionHash   string `json:"action_hash"`
		Generation   uint64 `json:"generation"`
		Sequence     uint64 `json:"sequence"`
		StateInitBOC string `json:"state_init_boc"`
		BodyBOC      string `json:"body_boc"`
	}
	if err := decodeAnswer(label, output, &answer); err != nil {
		return SignedAgentRegistration{}, err
	}
	registration := SignedAgentRegistration{AgentID: "agent_" + answer.ObjectID, Destination: answer.Destination,
		ActionHash: answer.ActionHash, StateInitBOC: answer.StateInitBOC, BodyBOC: answer.BodyBOC}
	if answer.Kind != "register-agent" || answer.Destination != answer.FinalTarget || registration.Validate() != nil {
		return SignedAgentRegistration{}, fmt.Errorf("tosctl %s: %w", label, ErrTOSCTLAnswer)
	}
	return registration, nil
}

// SendRegistration sends the registration from the wallet with exactly
// valueNano attached. tosctl returns success only after the wallet's
// sequence number moved. ErrCallNotStarted means nothing was broadcast; any
// other error leaves the outcome to finalized state.
func (c *TOSCTLInitCustody) SendRegistration(ctx context.Context, wallet string, valueNano uint64,
	registration SignedAgentRegistration) error {
	const label = "wallet send"
	if !TOSCTLNamePattern.MatchString(wallet) || valueNano == 0 || registration.Validate() != nil {
		return fmt.Errorf("invalid registration send: %w", ErrCallNotStarted)
	}
	if err := c.CheckEndpoints(ctx); err != nil {
		return errors.Join(ErrCallNotStarted, err)
	}
	output, err := c.run(ctx, "wallet", "send", "--from", wallet, "--to", registration.Destination,
		"--amount-nanotos", strconv.FormatUint(valueNano, 10), "--body-boc", registration.BodyBOC,
		"--state-init-boc", registration.StateInitBOC, "--yes")
	if err != nil {
		// These are wallet checks tosctl makes before it builds the message.
		// A generic error such as a vault or RPC "not found" is not one of
		// them: it can come after the broadcast. tosctl's wallet send prints
		// no signed-message line, so there is no positive marker either.
		for _, phrase := range []string{"Wrong amount value", "is uninitialized", "is frozen"} {
			if finalFailure(output, phrase) {
				return fmt.Errorf("tosctl %s refused before broadcasting: %w", label, ErrCallNotStarted)
			}
		}
		return failure(label, output, err)
	}
	if !bytes.Contains(output, []byte("Transfer sent")) {
		return fmt.Errorf("tosctl %s: no transfer report: %w", label, ErrTOSCTLAnswer)
	}
	return nil
}
