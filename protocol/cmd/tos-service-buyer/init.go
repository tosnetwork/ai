package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/buyerinit"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

const initUsage = "usage: tos-service-buyer init <plan|apply> [flags]"

// runInit is `tos-service-buyer init plan|apply` (MCP_BUYER_ADAPTER_V1
// 3.2). plan prints every change and sends nothing; apply makes them. It
// runs as the custody account; the vault URL is read from VAULT_URL, as
// tosctl itself reads it, and handed to tosctl only in its environment.
func runInit(arguments []string, out io.Writer) error {
	if len(arguments) == 0 || (arguments[0] != "plan" && arguments[0] != "apply") {
		return errors.New(initUsage)
	}
	apply := arguments[0] == "apply"
	set := flag.NewFlagSet("init "+arguments[0], flag.ContinueOnError)
	set.SetOutput(usageOutput)
	var in buyerinit.Input
	var endpoints string
	var clientUID uint
	var relays patternsFlag
	var window time.Duration
	var timeout time.Duration
	yes := set.Bool("yes", false, "send every chain message without asking (apply only)")
	set.StringVar(&in.ConfigPath, "config", "", "the agent configuration file to write (custody-owned)")
	set.StringVar(&in.StateDir, "state-dir", "", "the agent's custody-owned state directory")
	set.StringVar(&in.SocketDir, "socket-dir", "", "the directory the agent creates its socket in")
	set.UintVar(&clientUID, "client-uid", 0, "uid of the developer account the MCP server runs as")
	set.StringVar(&in.NetworkLabel, "network-label", "", "network label of the identity domain, e.g. tos:global-id:2")
	set.StringVar(&in.GlobalConfig, "global-config", "", "the chain's global configuration (genesis anchors)")
	set.StringVar(&endpoints, "rpc", "", "comma-separated TOS JSON-RPC endpoints (3 to 8)")
	set.IntVar(&in.Quorum, "quorum", 0, "strict-majority quorum; defaults to a majority of --rpc")
	set.StringVar(&in.RegistryCodeFile, "registry-code-boc", "", "file holding the Native Registry code BOC (base64)")
	set.StringVar(&in.ActorCodeHash, "actor-code-hash", "", "tvm-cell-sha256:<hex> pinned Service Actor release code hash")
	set.StringVar(&in.ManifestDir, "manifest-dir", "", "directory of canonical manifests named <sha256 hex>.cbor")
	set.StringVar(&in.TOSCTLBinary, "tosctl", "", "absolute path of the tosctl custody binary")
	set.StringVar(&in.TOSCTLSHA256, "tosctl-sha256", "", "lowercase hex SHA-256 of that binary")
	set.StringVar(&in.TOSCTLConfig, "tosctl-config", "", "absolute path of the tosctl configuration (JSON)")
	set.StringVar(&in.Wallet, "wallet", "", "tosctl name of the buyer wallet (created when absent)")
	set.StringVar(&in.Controller, "packet-controller", "", "tosctl name of the packet controller (created when absent)")
	set.Var(&relays, "relay", "an Agent Packet Relay base URL the agent polls; repeat for 1 to 4")
	set.StringVar(&in.RelayCAFile, "relay-ca-file", "", "PEM certificate authorities the relays are verified against")
	set.StringVar(&in.GatewayURL, "gateway-url", "", "optional gateway base URL: https, or http on a loopback address")
	set.StringVar(&in.GatewayCAFile, "gateway-ca-file", "", "PEM certificate authorities an https gateway is verified against")
	set.StringVar(&in.GatewayTokenFile, "gateway-token-file", "", "custody-owned 0600 file holding the gateway bearer token")
	set.StringVar(&in.CatalogDir, "catalog-dir", "", "optional custody-owned capability catalog directory")
	set.DurationVar(&window, "budget-window", 24*time.Hour, "budget window, at most 31 days")
	set.IntVar(&in.Budget.MaxCalls, "max-calls", 100, "most calls reserved in the window")
	set.StringVar(&in.Budget.MaxPerCallNanoTOS, "max-per-call-nanotos", "1000000000", "largest payment of one call")
	set.StringVar(&in.Budget.MaxWindowNanoTOS, "max-window-nanotos", "10000000000", "largest total reserved in the window")
	set.IntVar(&in.Budget.MaxUnconfirmed, "max-unconfirmed", 4, "prepared purchases awaiting a decision")
	set.IntVar(&in.Budget.MaxLifecycleSends, "max-lifecycle-sends", 0, "expire, claim_refund and sweep sends per window; 0 is 2 * max-calls + 8")
	set.IntVar(&in.Budget.DutyIntervalSecond, "duty-interval-seconds", 0, "refund duty interval, 0 to 60; 0 is the agent's default")
	set.DurationVar(&timeout, "timeout", 15*time.Minute, "overall command timeout")
	if err := set.Parse(arguments[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if set.NArg() != 0 {
		return errors.New("init takes no positional arguments")
	}
	if *yes && !apply {
		return errors.New("--yes applies to init apply only")
	}
	if clientUID > 1<<31-1 {
		return errors.New("--client-uid is out of range")
	}
	in.ClientUID = uint32(clientUID)
	in.Relays = relays
	in.Budget.WindowSeconds = int64(window / time.Second)
	if endpoints != "" {
		in.Endpoints = strings.Split(endpoints, ",")
	}
	if in.Quorum == 0 {
		in.Quorum = len(in.Endpoints)/2 + 1
	}
	// Nothing runs, not even tosctl, as root, as the developer account or
	// on an invalid input.
	if err := buyerinit.Check(in, os.Geteuid()); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	env, closeEnv, err := initEnvironment(ctx, in, os.Getenv("VAULT_URL"))
	if err != nil {
		return err
	}
	defer closeEnv()
	env.Yes = *yes
	env.Confirm = confirmOn(bufio.NewReader(os.Stdin), os.Stderr)
	env.Report = func(line string) { fmt.Fprintln(os.Stderr, line) }
	run := buyerinit.Plan
	if apply {
		run = buyerinit.Apply
	}
	report, runErr := run(ctx, in, env)
	if err := printJSON(out, report); err != nil {
		return err
	}
	return runErr
}

// confirmOn asks on the custody account's terminal; only "yes" confirms.
func confirmOn(in *bufio.Reader, prompt io.Writer) func(string) (bool, error) {
	return func(question string) (bool, error) {
		fmt.Fprintf(prompt, "%s Type yes to send: ", question)
		line, err := in.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		return strings.TrimRight(line, "\r\n") == "yes", nil
	}
}

// vetter forwards to the finalized reader once the network is known: tosctl
// derives the network from the global configuration before the reader that
// vets its endpoints can be built.
type vetter struct{ reader *toschain.ServiceActorReader }

func (v *vetter) Endpoints() []string {
	if v.reader == nil {
		return nil
	}
	return v.reader.Endpoints()
}

func (v *vetter) CheckEndpointGenesis(ctx context.Context, endpoint string) error {
	if v.reader == nil {
		return errors.New("the finalized reader is not open")
	}
	return v.reader.CheckEndpointGenesis(ctx, endpoint)
}

// chain adapts the reader to buyerinit.Chain.
type chain struct{ *toschain.ServiceActorReader }

func (c chain) Begin(ctx context.Context) (buyerinit.Session, error) {
	session, err := c.ServiceActorReader.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// initEnvironment pins tosctl, derives the network through it and opens the
// finalized reader. The reader's checkpoint fences live in a private
// temporary directory, so a plan writes nothing to the state directory.
func initEnvironment(ctx context.Context, in buyerinit.Input, vaultURL string) (buyerinit.Env, func(), error) {
	forward := &vetter{}
	custody, err := buyersdk.NewTOSCTLInitCustody(buyersdk.TOSCTLInitCustodyConfig{BinaryPath: in.TOSCTLBinary,
		BinarySHA256: in.TOSCTLSHA256, ConfigPath: in.TOSCTLConfig, VaultURL: vaultURL, GlobalConfig: in.GlobalConfig,
		NetworkLabel: in.NetworkLabel, Endpoints: forward})
	if err != nil {
		return buyerinit.Env{}, nil, err
	}
	domain, err := custody.Domain(ctx)
	if err != nil {
		return buyerinit.Env{}, nil, err
	}
	network := &nativev1.NetworkDomain{NetworkId: in.NetworkLabel, GenesisRootHash: domain.GenesisRootHash,
		GenesisFileHash: domain.GenesisFileHash}
	adapter, err := toschain.New(toschain.Config{Network: in.NetworkLabel, Endpoints: in.Endpoints, Quorum: in.Quorum})
	if err != nil {
		return buyerinit.Env{}, nil, err
	}
	code, err := readBounded(in.RegistryCodeFile, 1<<20)
	if err != nil {
		return buyerinit.Env{}, nil, err
	}
	locator, err := nativecore.NewLocator(network, 0, strings.Join(strings.Fields(string(code)), ""), domain.CodeHash)
	if err != nil {
		return buyerinit.Env{}, nil, fmt.Errorf("the registry code file does not hold the code this tosctl signs for: %w", err)
	}
	fences, err := os.MkdirTemp("", "tos-service-buyer-init-")
	if err != nil {
		return buyerinit.Env{}, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(fences) }
	if err := os.Chmod(fences, 0o700); err != nil {
		cleanup()
		return buyerinit.Env{}, nil, err
	}
	registry, err := toschain.NewSimplifiedNativeResolver(adapter, locator, filepath.Join(fences, "registry.checkpoint"))
	if err != nil {
		cleanup()
		return buyerinit.Env{}, nil, err
	}
	reader, err := toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: adapter, Network: network,
		ActorCodeHash: in.ActorCodeHash, Registry: registry, CheckpointPath: filepath.Join(fences, "service-actor.checkpoint")})
	if err != nil {
		cleanup()
		return buyerinit.Env{}, nil, err
	}
	forward.reader = reader
	return buyerinit.Env{Custody: custody, Chain: chain{reader}}, cleanup, nil
}
