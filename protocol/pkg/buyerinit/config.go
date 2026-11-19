package buyerinit

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
)

// AgentConfigSchema names the buyer agent's configuration file, which init
// writes and `tos-service-buyer agent` reads (MCP_BUYER_ADAPTER_V1 3.2 and
// 6).
const AgentConfigSchema = "tos.service.mcp-buyer.agent-config.v1"

// MaxAgentConfigBytes bounds the configuration file.
const MaxAgentConfigBytes = 64 << 10

// AgentConfig is the buyer agent's configuration. It names keys only by
// their tosctl names; it holds no key material and no vault credential.
type AgentConfig struct {
	Schema            string        `json:"schema"`
	StateDir          string        `json:"state_dir"`
	SocketDir         string        `json:"socket_dir"`
	ClientUID         uint32        `json:"client_uid"`
	Network           NetworkConfig `json:"network"`
	Endpoints         []string      `json:"rpc_endpoints"`
	Quorum            int           `json:"quorum"`
	RegistryCodeFile  string        `json:"registry_code_boc_file"`
	RegistryCodeHash  string        `json:"registry_code_hash"`
	RegistryWorkchain int32         `json:"registry_workchain"`
	ActorCodeHash     string        `json:"actor_code_hash"`
	ManifestDir       string        `json:"manifest_dir"`
	BuyerWallet       string        `json:"buyer_wallet"`
	BuyerAgentID      string        `json:"buyer_agent_id"`
	Tosctl            TosctlConfig  `json:"tosctl"`
	// PacketControllerKeyID is mldsa44:<hex>.
	PacketControllerKeyID string   `json:"packet_controller_key_id"`
	Relays                []string `json:"relays"`
	RelayCAFile           string   `json:"relay_ca_file"`
	// GatewayURL, when set, names a gateway the agent uses as a search
	// hint source and for gateway Quotes; an https gateway is verified
	// against GatewayCAFile only, and the bearer token is read from the
	// owner-private GatewayTokenFile.
	GatewayURL       string `json:"gateway_url,omitempty"`
	GatewayCAFile    string `json:"gateway_ca_file,omitempty"`
	GatewayTokenFile string `json:"gateway_token_file,omitempty"`
	// CatalogDir, when set, is an owner-private capability catalog the
	// agent uses as a search hint source.
	CatalogDir string       `json:"catalog_dir,omitempty"`
	Budget     BudgetConfig `json:"budget"`
}

// NetworkConfig is the network tuple.
type NetworkConfig struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

// TosctlConfig pins tosctl and names the custody wallet and controller.
type TosctlConfig struct {
	Binary     string `json:"binary"`
	SHA256     string `json:"sha256"`
	ConfigPath string `json:"config_path"`
	Wallet     string `json:"wallet"`
	Controller string `json:"packet_controller"`
}

// BudgetConfig is the budget policy of section 6.
type BudgetConfig struct {
	WindowSeconds      int64  `json:"window_seconds"`
	MaxCalls           int    `json:"max_calls"`
	MaxPerCallNanoTOS  string `json:"max_per_call_nanotos"`
	MaxWindowNanoTOS   string `json:"max_window_nanotos"`
	MaxUnconfirmed     int    `json:"max_unconfirmed"`
	MaxLifecycleSends  int    `json:"max_lifecycle_sends_per_window"`
	DutyIntervalSecond int    `json:"duty_interval_seconds"`
}

// DecodeAgentConfig decodes a configuration strictly: unknown fields,
// duplicate keys, trailing data and another schema are refused.
func DecodeAgentConfig(raw []byte) (AgentConfig, error) {
	var config AgentConfig
	if len(raw) > MaxAgentConfigBytes {
		return config, errors.New("the agent configuration exceeds its bound")
	}
	if err := jsonstrict.Decode(raw, &config); err != nil {
		return config, fmt.Errorf("the agent configuration does not decode strictly: %w", err)
	}
	if config.Schema != AgentConfigSchema {
		return config, errors.New("the agent configuration names another schema")
	}
	return config, nil
}

// writeAgentConfig writes the configuration custody-only and requires it to
// read back, strictly, as exactly what was written.
func writeAgentConfig(path string, config AgentConfig) error {
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.New("encode the agent configuration")
	}
	if err := writePrivateFile(path, append(encoded, '\n')); err != nil {
		return err
	}
	raw, err := readPrivateFile(path, MaxAgentConfigBytes)
	if err != nil {
		return err
	}
	loaded, err := DecodeAgentConfig(raw)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(loaded, config) {
		return errors.New("the agent configuration does not read back as written")
	}
	return nil
}
