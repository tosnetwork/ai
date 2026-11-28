package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/capabilitycatalog"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactorindex"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// AgentConfigSchema names the agent's configuration file.
const AgentConfigSchema = "tos.service.mcp-buyer.agent-config.v1"

// maxAgentConfigBytes bounds the configuration file.
const maxAgentConfigBytes = 64 << 10

// agentConfig is the buyer agent's configuration (MCP_BUYER_ADAPTER_V1
// sections 3.2 and 6). It is decoded strictly: an unknown field, a
// missing required field or trailing data refuses the file.
type agentConfig struct {
	TokenAssets []tokenAssetConfig `json:"token_assets,omitempty"`
	Schema      string             `json:"schema"`
	StateDir    string             `json:"state_dir"`
	SocketDir   string             `json:"socket_dir"`
	ClientUID   uint32             `json:"client_uid"`
	Network     struct {
		NetworkID       string `json:"network_id"`
		GenesisRootHash string `json:"genesis_root_hash"`
		GenesisFileHash string `json:"genesis_file_hash"`
	} `json:"network"`
	Endpoints         []string `json:"rpc_endpoints"`
	Quorum            int      `json:"quorum"`
	RegistryCodeFile  string   `json:"registry_code_boc_file"`
	RegistryCodeHash  string   `json:"registry_code_hash"`
	RegistryWorkchain int32    `json:"registry_workchain"`
	ActorCodeHash     string   `json:"actor_code_hash"`
	ManifestDir       string   `json:"manifest_dir"`
	BuyerWallet       string   `json:"buyer_wallet"`
	BuyerAgentID      string   `json:"buyer_agent_id"`
	Tosctl            struct {
		Binary     string `json:"binary"`
		SHA256     string `json:"sha256"`
		ConfigPath string `json:"config_path"`
		Wallet     string `json:"wallet"`
		Controller string `json:"packet_controller"`
	} `json:"tosctl"`
	PacketControllerKeyID   string   `json:"packet_controller_key_id"`
	Relays                  []string `json:"relays"`
	RelayCAFile             string   `json:"relay_ca_file"`
	RelayDirectories        []string `json:"relay_directories,omitempty"`
	TransportDelegationFile string   `json:"transport_delegation_file,omitempty"`
	TransportSeedFile       string   `json:"transport_seed_file,omitempty"`
	// GatewayURL, when set, names a gateway used as a search hint source
	// and for gateway Quotes (sections 4.3 and 4.4). An https gateway is
	// verified against GatewayCAFile only; the bearer token is read from
	// GatewayTokenFile, owner-private, for every call.
	GatewayURL       string `json:"gateway_url,omitempty"`
	GatewayCAFile    string `json:"gateway_ca_file,omitempty"`
	GatewayTokenFile string `json:"gateway_token_file,omitempty"`
	// CatalogDir, when set, is an owner-private capability catalog used as
	// a search hint source.
	CatalogDir string `json:"catalog_dir,omitempty"`
	Budget     struct {
		WindowSeconds      int64  `json:"window_seconds"`
		MaxCalls           int    `json:"max_calls"`
		MaxPerCallNanoTOS  string `json:"max_per_call_nanotos"`
		MaxWindowNanoTOS   string `json:"max_window_nanotos"`
		MaxUnconfirmed     int    `json:"max_unconfirmed"`
		MaxLifecycleSends  int    `json:"max_lifecycle_sends_per_window"`
		DutyIntervalSecond int    `json:"duty_interval_seconds"`
	} `json:"budget"`
}

var tosctlNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// readAgentConfig reads the configuration: an owner-private regular file
// of the agent's account, decoded strictly and checked for every required
// field.
func readAgentConfig(path string) (agentConfig, error) {
	var config agentConfig
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config, errors.New("--config must be an absolute, clean path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return config, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return config, errors.New("the agent configuration must be a regular file private to the agent's account")
	}
	raw, err := readBounded(path, maxAgentConfigBytes)
	if err != nil {
		return config, err
	}
	if err := decodeStrict(raw, &config); err != nil {
		return config, fmt.Errorf("the agent configuration does not decode strictly: %w", err)
	}
	if config.Schema != AgentConfigSchema {
		return config, errors.New("the agent configuration names another schema")
	}
	switch {
	case config.StateDir == "" || config.SocketDir == "" || config.ClientUID == 0:
		return config, errors.New("the agent configuration needs state_dir, socket_dir and client_uid")
	case config.Network.NetworkID == "" || config.Network.GenesisRootHash == "" || config.Network.GenesisFileHash == "":
		return config, errors.New("the agent configuration needs the network tuple")
	case len(config.Endpoints) < 3 || len(config.Endpoints) > 8:
		return config, errors.New("the agent configuration needs 3 to 8 rpc_endpoints")
	case config.Quorum != 0 && (config.Quorum <= len(config.Endpoints)/2 || config.Quorum > len(config.Endpoints)):
		return config, errors.New("the quorum must be a strict majority of the endpoints")
	case config.RegistryCodeFile == "" || config.RegistryCodeHash == "" || config.ActorCodeHash == "" ||
		config.ManifestDir == "" || config.BuyerWallet == "" || config.BuyerAgentID == "":
		return config, errors.New("the agent configuration needs the registry code, actor code hash, manifest_dir, " +
			"buyer_wallet and buyer_agent_id")
	case config.Tosctl.Binary == "" || config.Tosctl.SHA256 == "" || config.Tosctl.ConfigPath == "" ||
		!tosctlNamePattern.MatchString(config.Tosctl.Wallet) || !tosctlNamePattern.MatchString(config.Tosctl.Controller):
		return config, errors.New("the agent configuration needs the pinned tosctl, its configuration, the wallet and the packet controller")
	case config.PacketControllerKeyID == "" || len(config.Relays) == 0:
		return config, errors.New("the agent configuration needs packet_controller_key_id and relays")
	case config.Budget.WindowSeconds <= 0 || config.Budget.MaxCalls <= 0 || config.Budget.MaxPerCallNanoTOS == "" ||
		config.Budget.MaxWindowNanoTOS == "":
		return config, errors.New("the agent configuration needs the budget window, max_calls and the nanoTOS limits")
	}
	if config.Budget.DutyIntervalSecond < 0 || config.Budget.DutyIntervalSecond > int(buyeragent.MaxDutyInterval/time.Second) {
		return config, errors.New("duty_interval_seconds must be 0 to 60")
	}
	// An HTTPS relay is verified against the pinned CA only; without one
	// pinned, no HTTPS relay could ever be reached, so the agent refuses to
	// start rather than poll nothing.
	for _, relay := range append(append([]string(nil), config.Relays...), config.RelayDirectories...) {
		if strings.HasPrefix(relay, "https://") && config.RelayCAFile == "" {
			return config, errors.New("an https relay is configured but relay_ca_file pins no CA")
		}
	}
	if _, _, err := tokenPolicy(config.TokenAssets); err != nil {
		return config, err
	}
	if _, err := tokenIssuerPolicies(config.TokenAssets); err != nil {
		return config, err
	}
	if err := checkGatewayConfig(config); err != nil {
		return config, err
	}
	return config, nil
}

// checkPrivateFile requires an owner-private regular file of the agent's
// account: the vault configuration must not be readable by others.
func checkPrivateFile(path, name string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return fmt.Errorf("the %s must be a regular file private to the agent's account", name)
	}
	return nil
}

// relayTransport is the HTTPS transport of every relay client: TLS 1.2 at
// least, verified against the pinned CA certificates only, never the
// system pool.
func relayTransport(caFile string) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if caFile != "" {
		raw, err := readBounded(caFile, 1<<20)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("the relay CA file holds no PEM certificate")
		}
	}
	return &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  buyeragent.RelayCallTimeout,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		ForceAttemptHTTP2:      true,
	}, nil
}

// relayClients builds one client per relay base URL over the pinned
// transport, and keeps it.
type relayClients struct {
	mu        sync.Mutex
	transport http.RoundTripper
	clients   map[string]*agentpacketrelay.V2Client
}

func (r *relayClients) client(base string) (*agentpacketrelay.V2Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client, ok := r.clients[base]; ok {
		return client, nil
	}
	client, err := agentpacketrelay.NewV2Client(base, r.transport, nil)
	if err != nil {
		return nil, err
	}
	r.clients[base] = client
	return client, nil
}

// manifestSources asks each source in order for a manifest; the buyer
// checks whatever bytes come back against the finalized digest.
type manifestSources []serviceactor.ManifestSource

func (m manifestSources) Manifest(ctx context.Context, digest string) ([]byte, error) {
	err := errors.New("no manifest source holds the manifest")
	for _, source := range m {
		raw, sourceErr := source.Manifest(ctx, digest)
		if sourceErr == nil {
			return raw, nil
		}
		err = sourceErr
	}
	return nil, err
}

// agentRuntime is everything the agent subcommand opened: the agent with
// its duty round, the carrier's relay poller and the socket server.
type agentRuntime struct {
	agent        dutyAgent
	carrier      relayPoller
	server       socketServer
	config       agentConfig
	closeCarrier func() error
}

// dutyAgent is the part of buyeragent.Agent the runtime drives.
type dutyAgent interface {
	RunDuties(ctx context.Context, interval time.Duration, report func([]error))
	LookupPurchase(requestHash string) (buyeragent.InboundPurchase, bool, error)
	Close()
}

// relayPoller is the part of buyeragent.Carrier the runtime drives.
type relayPoller interface {
	RunPoll(ctx context.Context, lookup buyeragent.PurchaseLookup, report func([]error))
}

// socketServer is the part of buyeragent.Server the runtime drives.
type socketServer interface {
	Serve(ctx context.Context) error
}

// privateSubdir creates an owner-private directory under the state
// directory, or checks an existing one.
func privateSubdir(stateDir, name string) (string, error) {
	path := filepath.Join(stateDir, name)
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return "", fmt.Errorf("the %s directory must be private to the agent's account", name)
	}
	return path, nil
}

// openAgent opens the buyer, the carrier, the agent and its socket from a
// configuration. Nothing runs yet.
func openAgent(ctx context.Context, config agentConfig, vaultURL string) (_ *agentRuntime, err error) {
	if vaultURL == "" {
		return nil, errors.New("VAULT_URL must name the tosctl vault")
	}
	if err := checkPrivateFile(config.Tosctl.ConfigPath, "tosctl configuration"); err != nil {
		return nil, err
	}
	network := &nativev1.NetworkDomain{NetworkId: config.Network.NetworkID, GenesisRootHash: config.Network.GenesisRootHash,
		GenesisFileHash: config.Network.GenesisFileHash}
	chainDir, err := privateSubdir(config.StateDir, "chain")
	if err != nil {
		return nil, err
	}
	chain, locator, registry, err := openRegistry(network, config.Endpoints, config.Quorum, config.RegistryCodeFile,
		config.RegistryCodeHash, config.RegistryWorkchain, chainDir)
	if err != nil {
		return nil, err
	}
	reader, err := toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: chain, Network: network,
		ActorCodeHash: config.ActorCodeHash, Registry: registry, CheckpointPath: filepath.Join(chainDir, "service-actor.checkpoint")})
	if err != nil {
		return nil, err
	}
	sender, err := buyersdk.NewTOSCTLServiceActorSender(buyersdk.TOSCTLServiceActorSenderConfig{BinaryPath: config.Tosctl.Binary,
		BinarySHA256: config.Tosctl.SHA256, ConfigPath: config.Tosctl.ConfigPath, WalletName: config.Tosctl.Wallet,
		VaultURL: vaultURL, Endpoints: reader})
	if err != nil {
		return nil, err
	}
	journalDir, err := privateSubdir(config.StateDir, "journal")
	if err != nil {
		return nil, err
	}
	journal, err := buyersdk.OpenServiceActorJournal(journalDir, time.Now())
	if err != nil {
		return nil, err
	}
	perCall, ok := new(big.Int).SetString(config.Budget.MaxPerCallNanoTOS, 10)
	if !ok {
		return nil, errors.New("max_per_call_nanotos is not a decimal")
	}
	window, ok := new(big.Int).SetString(config.Budget.MaxWindowNanoTOS, 10)
	if !ok {
		return nil, errors.New("max_window_nanotos is not a decimal")
	}
	unconfirmed := config.Budget.MaxUnconfirmed
	if unconfirmed == 0 {
		unconfirmed = 4
	}
	// The agent keeps the manifest of every Quote it accepts in its own
	// store; admission at prepare reads the configured directory, then that
	// store.
	manifestsDir, err := privateSubdir(config.StateDir, "manifests")
	if err != nil {
		return nil, err
	}
	quoted, err := buyeragent.NewManifestStore(manifestsDir)
	if err != nil {
		return nil, err
	}
	issuerPolicies, err := tokenIssuerPolicies(config.TokenAssets)
	if err != nil {
		return nil, err
	}
	tokenPins, tokenLimits, err := tokenPolicy(config.TokenAssets)
	if err != nil {
		return nil, err
	}
	buyer, err := buyersdk.NewServiceActorBuyer(buyersdk.ServiceActorBuyerConfig{Reader: buyersdk.BuyerReaderFromChain(reader),
		Manifests: manifestSources{manifestDirectory(config.ManifestDir), quoted}, Network: network, ActorCodeHash: config.ActorCodeHash,
		BuyerWallet: config.BuyerWallet, Sender: sender, TokenSender: sender, TokenPins: tokenPins, Lifecycle: sender, Journal: journal,
		Limits: buyersdk.ServiceActorLimits{Window: time.Duration(config.Budget.WindowSeconds) * time.Second,
			TokenAssets: tokenLimits, MaxCalls: config.Budget.MaxCalls, MaxPerCallNanoTOS: perCall, MaxWindowNanoTOS: window, MaxPrepared: unconfirmed}})
	if err != nil {
		return nil, err
	}
	custody, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: config.Tosctl.Binary, SHA256: config.Tosctl.SHA256,
		ConfigPath: config.Tosctl.ConfigPath, VaultURL: vaultURL})
	if err != nil {
		return nil, err
	}
	controllerKeyID, err := mldsa44.ParseKeyIDText(config.PacketControllerKeyID)
	if err != nil {
		return nil, errors.New("packet_controller_key_id is not an ML-DSA-44 key ID")
	}
	transport, err := relayTransport(config.RelayCAFile)
	if err != nil {
		return nil, err
	}
	relays := &relayClients{transport: transport, clients: map[string]*agentpacketrelay.V2Client{}}
	carrierDir, err := privateSubdir(config.StateDir, "carrier")
	if err != nil {
		return nil, err
	}
	transportConfig, err := buyerTransport(config, network, locator, registry, relays)
	if err != nil {
		return nil, err
	}
	defer clear(transportConfig.Key)
	carrier, err := buyeragent.NewCarrier(ctx, buyeragent.CarrierConfig{StateDir: carrierDir, BuyerAgentID: config.BuyerAgentID,
		Network: network, Controller: config.Tosctl.Controller, ControllerKeyID: controllerKeyID, Signer: custody,
		Verifier: custody, Cards: buyer, Relays: config.Relays, Transport: transportConfig})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = carrier.Close()
		}
	}()
	// Search by capability_id and local Quotes need no hint source: every
	// fact is read from finalized state. A configured gateway and catalog
	// add search hints, and the gateway serves gateway Quotes.
	sessions := serviceactorindex.FromChain(reader)
	offersConfig := buyeragent.OffersConfig{Network: network, RegistryCodeHash: config.RegistryCodeHash,
		ActorCodeHash: config.ActorCodeHash, BuyerWallet: config.BuyerWallet, Sessions: sessions, TokenPins: tokenPins, TokenAssets: tokenLimits,
		Manifests: quoted, Cards: carrier}
	if config.GatewayURL != "" {
		gateway, err := newGatewayClient(config.GatewayURL, config.GatewayCAFile, config.GatewayTokenFile)
		if err != nil {
			return nil, err
		}
		offersConfig.Gateway = gateway
		offersConfig.Hints = append(offersConfig.Hints, buyeragent.GatewayHints{Gateway: gateway})
	}
	if config.CatalogDir != "" {
		catalog, err := capabilitycatalog.New(capabilitycatalog.Config{Directory: config.CatalogDir,
			Resolver: finalizedResolver{reader: sessions}, Network: network, RegistryCodeHash: config.RegistryCodeHash,
			CallerID: "tos-service-buyer"})
		if err != nil {
			return nil, err
		}
		offersConfig.Hints = append(offersConfig.Hints, buyeragent.CatalogHints{Catalog: catalog})
	}
	offers, err := buyeragent.NewOffers(offersConfig)
	if err != nil {
		return nil, err
	}
	agentDir, err := privateSubdir(config.StateDir, "agent")
	if err != nil {
		return nil, err
	}
	agent, err := buyeragent.Open(buyeragent.Config{StateDir: agentDir, BuyerAgentID: config.BuyerAgentID, Network: network,
		Buyer: buyer, Carriage: carrier, Delivery: carrier, Results: carrier, Accepted: carrier, Offers: offers, TokenIssuers: issuerPolicies,
		MaxLifecycleSends: config.Budget.MaxLifecycleSends})
	if err != nil {
		return nil, err
	}
	server, err := buyeragent.Listen(buyeragent.ServerConfig{Agent: agent, SocketDir: config.SocketDir, ClientUID: config.ClientUID})
	if err != nil {
		agent.Close()
		return nil, err
	}
	return &agentRuntime{agent: agent, carrier: carrier, server: server, config: config, closeCarrier: carrier.Close}, nil
}

// run serves the socket and runs the duty round and the relay poller until
// ctx ends. None of them needs an MCP session.
func (r *agentRuntime) run(parent context.Context, report func(string, []error)) error {
	// The loops stop with the socket: a server that fails stops them too.
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	interval := time.Duration(r.config.Budget.DutyIntervalSecond) * time.Second
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		r.agent.RunDuties(ctx, interval, func(failures []error) { report("duty", failures) })
	}()
	go func() {
		defer wait.Done()
		r.carrier.RunPoll(ctx, r.agent.LookupPurchase, func(failures []error) { report("poll", failures) })
	}()
	err := r.server.Serve(ctx)
	cancel()
	wait.Wait()
	r.agent.Close()
	if r.closeCarrier != nil {
		err = errors.Join(err, r.closeCarrier())
	}
	if parent.Err() != nil {
		return nil
	}
	return err
}

// runAgent is `tos-service-buyer agent`: the long-running buyer agent in
// the custody account.
func runAgent(arguments []string) error {
	set := flag.NewFlagSet("agent", flag.ContinueOnError)
	set.SetOutput(usageOutput)
	configPath := set.String("config", "", "absolute path of the agent configuration (owner-private JSON)")
	if err := set.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("agent takes no positional arguments")
	}
	config, err := readAgentConfig(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runtime, err := openAgent(ctx, config, os.Getenv("VAULT_URL"))
	if err != nil {
		return err
	}
	return runtime.run(ctx, func(round string, failures []error) {
		for _, failure := range failures {
			fmt.Fprintf(os.Stderr, "tos-service-buyer agent: %s: %v\n", round, failure)
		}
	})
}
