package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// defaultPacketController names the vault controller `init` creates when
// neither the flag nor an existing rail configuration names one.
const defaultPacketController = "service-packet"

// setupEnv reports previews and progress on standard error; standard output
// carries only the JSON result.
func setupEnv(std streams) servicebridge.SetupEnv {
	return servicebridge.SetupEnv{Report: func(line string) { fmt.Fprintln(std.err, line) }}
}

// finishSetup prints the report and keeps the command's error, so a run
// that stopped still shows what it did and what it planned.
func finishSetup(std streams, report any, err error) error {
	if printErr := printJSON(std.out, report); printErr != nil {
		return errors.Join(err, printErr)
	}
	return err
}

func parseDirectPeers(values []string) (map[string]string, error) {
	peers := map[string]string{}
	for _, value := range values {
		agent, socket, found := strings.Cut(value, "=")
		if !found || agent == "" || socket == "" {
			return nil, usagef("--direct-peer takes agent_<hex>=<absolute socket path>")
		}
		if _, duplicate := peers[agent]; duplicate {
			return nil, usagef("--direct-peer names an Agent twice")
		}
		peers[agent] = socket
	}
	return peers, nil
}

// tosFlag reads a decimal TOS amount into nanoTOS.
func tosFlag(name, value string, allowEmpty bool) (uint64, error) {
	if value == "" && allowEmpty {
		return 0, nil
	}
	amount, err := servicebridge.ParseTOSAmount(value)
	if err != nil {
		return 0, usagef("--%s: %w", name, err)
	}
	return amount, nil
}

// uint32Flag registers a flag that takes an unsigned 32-bit decimal.
func uint32Flag(set *flag.FlagSet, target *uint32, name, usage string) {
	set.Func(name, usage, func(value string) error {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return errors.New("not an unsigned 32-bit decimal")
		}
		*target = uint32(parsed)
		return nil
	})
}

// packetController is the packet controller `init` uses when the flag was
// not given, so that a re-run continues the node it finds: the one the setup
// journal under stateDir records (an earlier init that stopped after its
// journal and before its rail configuration is found only there), else the
// one an existing rail configuration records, else the default. A journal
// that exists but cannot be read is an error rather than a reason to pick
// another controller. A state directory that is not clean and absolute is
// left to init, which refuses it with its own message.
func packetController(railConfigPath, stateDir string) (string, error) {
	if filepath.IsAbs(stateDir) && filepath.Clean(stateDir) == stateDir {
		recorded, err := servicebridge.RecordedPacketController(stateDir)
		if err != nil {
			return "", err
		}
		if recorded != "" {
			return recorded, nil
		}
	}
	if existing, err := servicebridge.LoadNodeConfig(railConfigPath); err == nil && existing.PacketController != "" {
		return existing.PacketController, nil
	}
	return defaultPacketController, nil
}

func runInit(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var in servicebridge.InitInput
	var directPeers []string
	set.StringVar(&in.RailConfigPath, "rail-config", "", "where to write the owner-private rail configuration")
	set.StringVar(&in.StateDir, "state-dir", "", "the node's owner-private state directory")
	listFlag(set, &in.RPCEndpoints, "rpc", "chain RPC endpoint (repeat: 3 to 8 distinct endpoints)")
	set.IntVar(&in.Quorum, "quorum", 0, "endpoint quorum (default: a strict majority)")
	set.StringVar(&in.GlobalConfigFile, "global-config", "", "chain global configuration file (JSON)")
	set.StringVar(&in.NetworkLabel, "network-label", "", "network label of the identity domain (tos:global-id:<n>)")
	set.StringVar(&in.TOSCTLBinary, "tosctl", "", "tosctl binary")
	set.StringVar(&in.TOSCTLSHA256, "tosctl-sha256", "", "SHA-256 the tosctl binary must have (default: pin the "+
		"binary found, trust on first use)")
	set.StringVar(&in.TOSCTLConfigPath, "tosctl-config", "", "tosctl configuration file")
	set.StringVar(&in.VaultURLEnv, "vault-url-env", "VAULT_URL", "environment variable that carries the vault "+
		"URL (its value is never printed or stored)")
	set.StringVar(&in.WalletName, "wallet", "", "tosctl wallet that owns and funds this node")
	set.StringVar(&in.PacketController, "packet-controller", "", "vault controller that signs Agent Packets and "+
		"controls the Agent, created if absent (default: the one the rail configuration records, else "+
		defaultPacketController+")")
	set.StringVar(&in.RegistryCodeBOC, "registry-code-boc", "", "Native Registry code BOC file (base64)")
	set.StringVar(&in.ActorCodeHash, "actor-code-hash", "", "pinned Service Actor release code hash "+
		"(tvm-cell-sha256:<hex>)")
	set.StringVar(&in.ReceiverSocket, "receiver-socket", "", "this node's Agent Packet receiver socket (default: "+
		"<state-dir>/rail-receiver.sock)")
	listFlag(set, &directPeers, "direct-peer", "agent_<hex>=<socket>: deliver that Agent's packets to its receiver "+
		"socket on this host (repeatable; same host and user only)")
	listFlag(set, &in.RelayURLs, "relay-url", "Agent Packet Relay base URL this node publishes in its encryption "+
		"key card and polls (repeatable, at most 4; https, or http only to a loopback host): packets to peers "+
		"whose verified card is known are sealed end to end and deposited at the peer's relays")
	set.StringVar(&in.RelayCAFile, "relay-ca-file", "", "PEM file of one or more certificate authorities this "+
		"node's own https relays are verified against instead of the system trust store (copied into the "+
		"owner-only state; kept by a re-run that names neither this nor --relay-system-roots)")
	set.BoolVar(&in.RelaySystemRoots, "relay-system-roots", false, "drop a pinned --relay-ca-file: verify this "+
		"node's relays against the system trust store again")
	set.BoolVar(&in.Yes, "yes", false, "create the controller, sign and send as previewed")
	if done, err := parse(set, arguments, "rail-config", "state-dir", "rpc", "global-config", "network-label",
		"tosctl", "tosctl-config", "wallet", "registry-code-boc", "actor-code-hash"); done || err != nil {
		return err
	}
	peers, err := parseDirectPeers(directPeers)
	if err != nil {
		return err
	}
	in.DirectPeers = peers
	if err = checkExistingCarriers(in.RailConfigPath); err != nil {
		return err
	}
	if in.PacketController == "" {
		if in.PacketController, err = packetController(in.RailConfigPath, in.StateDir); err != nil {
			return err
		}
	}
	result, err := servicebridge.RunInit(ctx, in, setupEnv(std))
	if result == nil {
		return err
	}
	return finishSetup(std, result, err)
}

func runOffer(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var in servicebridge.OfferInput
	var price, storageFee, cleanupBounty, deployFunding string
	railConfigFlag(set, &in.RailConfigPath)
	set.StringVar(&price, "price", "", "price per call, in TOS")
	set.StringVar(&storageFee, "storage-fee", "", "non-refundable storage fee per call, in TOS (at least 0.1 "+
		"plus the cleanup bounty)")
	set.StringVar(&cleanupBounty, "cleanup-bounty", "", "bounty for sweeping an expired request, in TOS (0.1 to 1)")
	uint32Flag(set, &in.Terms.ResponseSLA, "response-sla", "seconds a call has to be responded to (3600 to "+
		"2592000; 600 to 2592000 with --test-profile-actor)")
	uint32Flag(set, &in.Terms.RefundClaimWindow, "refund-claim-window", "seconds a refund stays claimable (3600 "+
		"to 2592000; 600 to 2592000 with --test-profile-actor)")
	set.StringVar(&in.Version, "version", servicebridge.DefaultOfferVersion, "Capability version")
	set.StringVar(&in.AttestorController, "attestor-controller", servicebridge.DefaultAttestorController,
		"vault controller that attests responses (created if absent)")
	set.StringVar(&in.ExecutorSocket, "executor-socket", "", "socket of the root-run executor service (default "+
		servicebridge.DefaultExecutorSocket+" unless --executor is given)")
	set.StringVar(&in.ExecutorBinary, "executor", "", "software-work executor binary to run as this user instead "+
		"of the executor service (needs --containerd-socket)")
	set.StringVar(&in.ExecutorSHA256, "executor-sha256", "", "SHA-256 the executor must have (default: pin the "+
		"binary found, trust on first use)")
	set.StringVar(&in.ContainerdSocket, "containerd-socket", "", "private container runtime socket")
	set.StringVar(&in.FIFODir, "fifo-dir", "", "executor FIFO directory (default: <state_dir>/fifo)")
	set.IntVar(&in.RespondBudgetSeconds, "respond-budget-seconds", servicebridge.DefaultRespondBudget,
		"time kept for responding after execution")
	set.Uint64Var(&in.RetentionSeconds, "retention-seconds", servicebridge.DefaultRetentionSeconds,
		"how long results are redelivered")
	set.StringVar(&deployFunding, "deploy-funding", "", "TOS sent with the deployment (default and minimum 1.2: "+
		"the actor's 1 TOS reserve plus a fee margin)")
	set.StringVar(&in.OfferPath, "offer-out", "", "where to write the offer file (default: "+
		"<state_dir>/setup/offer.json)")
	set.StringVar(&in.GatewayCardPath, "gateway-card-out", "", "the gateway quote profile's "+
		"provider_key_card_file: write the current key card there and keep it current while serving (needs "+
		"relays; default: the path the provider section already names, if any)")
	set.BoolVar(&in.TestProfileActor, "test-profile-actor", false, "TEST NETWORKS ONLY: deploy the "+
		"test-network-only Service Actor build, whose response SLA and refund-claim window may be as short as "+
		"600 seconds; required when, and refused unless, the rail configuration pins its code hash "+
		servicebridge.TestProfileActorCodeHash)
	set.BoolVar(&in.Yes, "yes", false, "create the controller, sign and send as previewed")
	if done, err := parse(set, arguments, "rail-config", "price", "storage-fee", "cleanup-bounty", "response-sla",
		"refund-claim-window"); done || err != nil {
		return err
	}
	var err error
	if in.Terms.PriceNano, err = tosFlag("price", price, false); err != nil {
		return err
	}
	if in.Terms.StorageFeeNano, err = tosFlag("storage-fee", storageFee, false); err != nil {
		return err
	}
	if in.Terms.CleanupBountyNano, err = tosFlag("cleanup-bounty", cleanupBounty, false); err != nil {
		return err
	}
	if in.DeployFundingNano, err = tosFlag("deploy-funding", deployFunding, true); err != nil {
		return err
	}
	if err = checkExistingCarriers(in.RailConfigPath); err != nil {
		return err
	}
	result, err := servicebridge.RunOffer(ctx, in, setupEnv(std))
	if result == nil {
		return err
	}
	return finishSetup(std, result, err)
}

func runWithdraw(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var in servicebridge.WithdrawInput
	var amount, note string
	var acknowledge uint64
	railConfigFlag(set, &in.RailConfigPath)
	set.StringVar(&amount, "amount", "", "amount to withdraw, in TOS")
	set.BoolVar(&in.All, "all", false, "withdraw all credited revenue")
	set.Uint64Var(&acknowledge, "acknowledge", 0, "query id of an earlier withdrawal that finalized state cannot "+
		"decide and whose inclusion window has passed: close its record so it no longer blocks withdrawals "+
		"(moves no funds, sends nothing, never automatic)")
	set.StringVar(&note, "note", "", "with --acknowledge: what you checked, stored with the record")
	set.BoolVar(&in.Yes, "yes", false, "send the withdrawal, or record the acknowledgement, as previewed")
	if done, err := parse(set, arguments, "rail-config"); done || err != nil {
		return err
	}
	given := givenFlags(set)
	if given["acknowledge"] {
		if in.All || given["amount"] {
			return usagef("--acknowledge closes an earlier withdrawal; it takes neither --amount nor --all")
		}
		if err := checkExistingCarriers(in.RailConfigPath); err != nil {
			return err
		}
		result, err := servicebridge.RunWithdrawAcknowledge(ctx, servicebridge.AcknowledgeInput{
			RailConfigPath: in.RailConfigPath, QueryID: acknowledge, Note: note, Yes: in.Yes,
		}, setupEnv(std))
		return finishSetup(std, result, err)
	}
	if given["note"] {
		return usagef("--note belongs to --acknowledge")
	}
	if in.All == given["amount"] {
		return usagef("give exactly one of --amount and --all")
	}
	if !in.All {
		nano, err := tosFlag("amount", amount, false)
		if err != nil {
			return err
		}
		if nano == 0 {
			return &usageError{err: servicebridge.ErrWithdrawZero}
		}
		in.AmountNano = nano
	}
	if err := checkExistingCarriers(in.RailConfigPath); err != nil {
		return err
	}
	result, err := servicebridge.RunWithdraw(ctx, in, setupEnv(std))
	return finishSetup(std, result, err)
}
