// Command tos-service-verify is the third-party verifier of one Service Actor
// purchase. It uses only public inputs: the network's global config (or its
// network tuple), JSON-RPC endpoints read at an N-of-M quorum, the Native
// Registry and Service Actor release code hashes, the actor address and the
// request IDs or request_hash, and optionally the buyer's evidence bundle,
// Receipt and artifact files, which it checks rather than trusts.
//
// It reads one quorum-finalized checkpoint and reports, from it alone, the
// actor's code hash against the pinned release, each request's call and its
// respond, expire, claim_refund or sweep, and whether the files given are the
// finalized response. It prints a strict JSON verdict on standard output and
// a human summary on standard error. It signs nothing, holds no key, needs no
// custody tool and writes nothing but a private scratch directory for its
// finality fences, removed on exit.
//
// Exit status: 0 the verdict passed, 1 it failed, 2 the inputs were unusable.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

const usage = "usage: tos-service-verify (--global-config FILE --network-id ID | --network-domain FILE) " +
	"--rpc URL,URL,URL [--quorum N] --registry-code-boc FILE --registry-code-hash H --actor-code-hash H " +
	"[--actor ADDR] (--request-id N | --request-hash H)... [--evidence FILE] [--receipt FILE] [--artifact FILE]"

// Exit statuses.
const (
	exitPass  = 0
	exitFail  = 1
	exitUsage = 2
)

// File bounds.
const (
	maxNetworkFile  = 1 << 20
	maxRegistryCode = 1 << 20
	maxReceiptFile  = railwork.MaxReceiptBytes
	maxArtifactFile = railwork.MaxResultBytes
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// options are the parsed flags.
type options struct {
	globalConfig, networkID, networkDomain  string
	endpoints                               []string
	quorum, registryWorkchain               int
	registryCodePath, registryCodeHash      string
	actorCodeHash, actor                    string
	requestIDs, requestHashes               listFlag
	evidencePath, receiptPath, artifactPath string
	timeout                                 time.Duration
}

// readConfig is what a chain session is opened from.
type readConfig struct {
	network          *nativev1.NetworkDomain
	endpoints        []string
	quorum           int
	registryCode     string
	registryCodeHash string
	registryWork     int32
	actorCodeHash    string
}

// opened is a finalized session and what was learned opening it.
type opened struct {
	session   purchaseevidence.Session
	endpoints []purchaseevidence.EndpointReport
	close     func()
}

// openSession opens the finalized session; tests replace it.
var openSession = openChainSession

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 1 && (arguments[0] == "help" || arguments[0] == "-h" || arguments[0] == "--help") {
		fmt.Fprintln(stdout, usage)
		return exitPass
	}
	opts, err := parse(arguments, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	inputs := []purchaseevidence.FileDigest{}
	network, err := readNetwork(opts, &inputs)
	if err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	input, config, err := buildInput(opts, network, &inputs)
	if err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	verdict := purchaseevidence.NewVerdict(network)
	session, err := openSession(ctx, config)
	if err != nil {
		verdict.Fail("finalized-read", err.Error())
	} else {
		defer session.close()
		verdict = purchaseevidence.Verify(ctx, session.session, input)
		verdict.Reads = &purchaseevidence.Reads{Endpoints: session.endpoints, Quorum: config.quorum}
	}
	tool := buildTool("tos-service-verify")
	verdict.Tool, verdict.Inputs = &tool, inputs
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	fmt.Fprint(stderr, purchaseevidence.Summary(verdict))
	if verdict.Result != purchaseevidence.ResultPass {
		return exitFail
	}
	return exitPass
}

func parse(arguments []string, stderr io.Writer) (*options, error) {
	opts := &options{}
	set := flag.NewFlagSet("tos-service-verify", flag.ContinueOnError)
	set.SetOutput(stderr)
	var endpoints string
	set.StringVar(&opts.globalConfig, "global-config", "", "the network's global config JSON (genesis from zero_state)")
	set.StringVar(&opts.networkID, "network-id", "", "the network ID, with --global-config (for example tos:global-id:2)")
	set.StringVar(&opts.networkDomain, "network-domain", "", "JSON file {network_id, genesis_root_hash, genesis_file_hash}")
	set.StringVar(&endpoints, "rpc", "", "comma-separated TOS JSON-RPC endpoints (3 to 8)")
	set.IntVar(&opts.quorum, "quorum", 0, "agreeing endpoints required; defaults to every endpoint given")
	set.StringVar(&opts.registryCodePath, "registry-code-boc", "", "file holding the Native Registry code BOC (base64)")
	set.StringVar(&opts.registryCodeHash, "registry-code-hash", "", "tvm-cell-sha256:<hex> Native Registry release code hash")
	set.IntVar(&opts.registryWorkchain, "registry-workchain", 0, "Native Registry workchain")
	set.StringVar(&opts.actorCodeHash, "actor-code-hash", "", "tvm-cell-sha256:<hex> pinned Service Actor release code hash")
	set.StringVar(&opts.actor, "actor", "", "raw Service Actor address; defaults to the evidence bundle's")
	set.Var(&opts.requestIDs, "request-id", "request ID to verify (repeatable)")
	set.Var(&opts.requestHashes, "request-hash", "request_hash to verify (repeatable)")
	set.StringVar(&opts.evidencePath, "evidence", "", "the buyer's evidence bundle (evidence.json), checked, not trusted")
	set.StringVar(&opts.receiptPath, "receipt", "", "the Receipt BOC file (receipt.boc) of the one selected request")
	set.StringVar(&opts.artifactPath, "artifact", "", "the artifact tar (artifact.tar), checked against the Receipt")
	set.DurationVar(&opts.timeout, "timeout", 2*time.Minute, "overall timeout")
	if err := set.Parse(arguments); err != nil {
		return nil, err
	}
	if set.NArg() != 0 {
		return nil, errors.New("unexpected positional arguments; " + usage)
	}
	if endpoints == "" || opts.registryCodePath == "" || opts.registryCodeHash == "" || opts.actorCodeHash == "" {
		return nil, errors.New("--rpc, --registry-code-boc, --registry-code-hash and --actor-code-hash are required")
	}
	opts.endpoints = strings.Split(endpoints, ",")
	if opts.quorum == 0 {
		opts.quorum = len(opts.endpoints)
	}
	if opts.quorum <= len(opts.endpoints)/2 || opts.quorum > len(opts.endpoints) {
		return nil, errors.New("--quorum must be a strict majority of the endpoints, at most all of them")
	}
	if opts.timeout <= 0 || opts.timeout > 30*time.Minute {
		return nil, errors.New("--timeout must be positive and at most 30m")
	}
	return opts, nil
}

// readNetwork reads the network tuple from exactly one of the global config
// (with the network ID) and a network-domain file.
func readNetwork(opts *options, inputs *[]purchaseevidence.FileDigest) (*nativev1.NetworkDomain, error) {
	switch {
	case opts.globalConfig != "" && opts.networkDomain == "":
		if opts.networkID == "" {
			return nil, errors.New("--global-config needs --network-id")
		}
		raw, err := readFile(opts.globalConfig, maxNetworkFile, "global-config", inputs)
		if err != nil {
			return nil, err
		}
		return networkFromGlobalConfig(raw, opts.networkID)
	case opts.networkDomain != "" && opts.globalConfig == "" && opts.networkID == "":
		raw, err := readFile(opts.networkDomain, maxNetworkFile, "network-domain", inputs)
		if err != nil {
			return nil, err
		}
		var domain purchaseevidence.NetworkTuple
		if err := jsonstrict.Decode(raw, &domain); err != nil {
			return nil, fmt.Errorf("--network-domain: %w", err)
		}
		return checkNetwork(&nativev1.NetworkDomain{NetworkId: domain.NetworkID, GenesisRootHash: domain.GenesisRootHash,
			GenesisFileHash: domain.GenesisFileHash})
	}
	return nil, errors.New("give either --global-config with --network-id, or --network-domain")
}

// networkFromGlobalConfig derives the genesis identity from the zero state
// a global config names.
func networkFromGlobalConfig(raw []byte, networkID string) (*nativev1.NetworkDomain, error) {
	var config struct {
		Type      string `json:"@type"`
		Validator struct {
			Type      string `json:"@type"`
			ZeroState struct {
				Workchain int    `json:"workchain"`
				Seqno     uint64 `json:"seqno"`
				RootHash  string `json:"root_hash"`
				FileHash  string `json:"file_hash"`
			} `json:"zero_state"`
		} `json:"validator"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("--global-config does not decode: %w", err)
	}
	zero := config.Validator.ZeroState
	if config.Type != "config.global" || config.Validator.Type != "validator.config.global" || zero.Workchain != -1 || zero.Seqno != 0 {
		return nil, errors.New("--global-config is not a global config naming a masterchain zero state")
	}
	root, err := base64.StdEncoding.Strict().DecodeString(zero.RootHash)
	if err != nil || len(root) != 32 {
		return nil, errors.New("--global-config zero_state root_hash is not a base64 32-byte hash")
	}
	file, err := base64.StdEncoding.Strict().DecodeString(zero.FileHash)
	if err != nil || len(file) != 32 {
		return nil, errors.New("--global-config zero_state file_hash is not a base64 32-byte hash")
	}
	return checkNetwork(&nativev1.NetworkDomain{NetworkId: networkID, GenesisRootHash: "sha256:" + hex.EncodeToString(root),
		GenesisFileHash: "sha256:" + hex.EncodeToString(file)})
}

func checkNetwork(network *nativev1.NetworkDomain) (*nativev1.NetworkDomain, error) {
	for _, digest := range []string{network.GenesisRootHash, network.GenesisFileHash} {
		raw, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
		if !strings.HasPrefix(digest, "sha256:") || err != nil || len(raw) != 32 || "sha256:"+hex.EncodeToString(raw) != digest {
			return nil, errors.New("the genesis hashes must be sha256:<64 lowercase hex>")
		}
	}
	if network.NetworkId == "" || len(network.NetworkId) > 128 {
		return nil, errors.New("the network ID is required")
	}
	return network, nil
}

// buildInput reads the files and selectors into a verification input and a
// session configuration.
func buildInput(opts *options, network *nativev1.NetworkDomain, inputs *[]purchaseevidence.FileDigest) (purchaseevidence.Input,
	readConfig, error) {
	input := purchaseevidence.Input{Network: network, ActorCodeHash: opts.actorCodeHash, Actor: opts.actor}
	code, err := readFile(opts.registryCodePath, maxRegistryCode, "registry-code-boc", inputs)
	if err != nil {
		return input, readConfig{}, err
	}
	config := readConfig{network: network, endpoints: opts.endpoints, quorum: opts.quorum,
		registryCode: strings.Join(strings.Fields(string(code)), ""), registryCodeHash: opts.registryCodeHash,
		registryWork: int32(opts.registryWorkchain), actorCodeHash: opts.actorCodeHash}
	for _, text := range opts.requestIDs {
		id, err := strconv.ParseUint(text, 10, 64)
		if err != nil || strconv.FormatUint(id, 10) != text {
			return input, config, fmt.Errorf("--request-id %q is not a canonical unsigned decimal", text)
		}
		input.RequestIDs = append(input.RequestIDs, id)
	}
	input.RequestHashes = append(input.RequestHashes, opts.requestHashes...)
	if opts.evidencePath != "" {
		raw, err := readFile(opts.evidencePath, purchaseevidence.MaxBundleBytes, "evidence", inputs)
		if err != nil {
			return input, config, err
		}
		bundle, err := purchaseevidence.DecodeBundle(raw)
		if err != nil {
			return input, config, err
		}
		input.Bundle = bundle
		if input.Actor == "" {
			input.Actor = bundle.Actor
		}
		// The bundle selects its own request; naming it again is allowed.
		if len(input.RequestIDs) == 0 && (len(input.RequestHashes) == 0 ||
			len(input.RequestHashes) == 1 && input.RequestHashes[0] == bundle.Request.RequestHash) {
			input.RequestHashes = []string{bundle.Request.RequestHash}
		}
	}
	if opts.receiptPath != "" {
		if input.Receipt, err = readFile(opts.receiptPath, maxReceiptFile, "receipt", inputs); err != nil {
			return input, config, err
		}
	}
	if opts.artifactPath != "" {
		if input.Artifact, err = readFile(opts.artifactPath, maxArtifactFile, "artifact", inputs); err != nil {
			return input, config, err
		}
	}
	if input.Actor == "" {
		return input, config, errors.New("--actor is required without an evidence bundle")
	}
	return input, config, nil
}

// readFile reads a bounded regular file and records its digest.
func readFile(path string, maximum int64, role string, inputs *[]purchaseevidence.FileDigest) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", role, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, fmt.Errorf("--%s is not a regular file within %d bytes", role, maximum)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("--%s does not read within %d bytes", role, maximum)
	}
	sum := sha256.Sum256(raw)
	*inputs = append(*inputs, purchaseevidence.FileDigest{Name: role, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Bytes: len(raw)})
	return raw, nil
}

// openChainSession opens a quorum-finalized session over the endpoints. Its
// finality fences live in a private scratch directory removed by close; a
// verifier keeps no state between runs.
func openChainSession(ctx context.Context, config readConfig) (*opened, error) {
	chain, err := toschain.New(toschain.Config{Network: config.network.NetworkId, Endpoints: config.endpoints, Quorum: config.quorum})
	if err != nil {
		return nil, err
	}
	locator, err := nativecore.NewLocator(config.network, config.registryWork, config.registryCode, config.registryCodeHash)
	if err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp("", "tos-service-verify-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	if err := os.Chmod(scratch, 0o700); err != nil {
		cleanup()
		return nil, err
	}
	registry, err := toschain.NewSimplifiedNativeResolver(chain, locator, filepath.Join(scratch, "registry.checkpoint"))
	if err != nil {
		cleanup()
		return nil, err
	}
	reader, err := toschain.NewServiceActorReader(toschain.ServiceActorReaderConfig{Chain: chain, Network: config.network,
		ActorCodeHash: config.actorCodeHash, Registry: registry, CheckpointPath: filepath.Join(scratch, "service-actor.checkpoint")})
	if err != nil {
		cleanup()
		return nil, err
	}
	reports := make([]purchaseevidence.EndpointReport, 0, len(config.endpoints))
	for _, endpoint := range config.endpoints {
		report := purchaseevidence.EndpointReport{URL: endpoint, GenesisOK: true}
		if err := reader.CheckEndpointGenesis(ctx, endpoint); err != nil {
			report.GenesisOK, report.Error = false, err.Error()
		}
		reports = append(reports, report)
	}
	session, err := reader.Begin(ctx)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &opened{session: session, endpoints: reports, close: cleanup}, nil
}

// buildTool names this build from its embedded build information.
func buildTool(name string) purchaseevidence.Tool {
	tool := purchaseevidence.Tool{Name: name}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return tool
	}
	tool.Module, tool.GoVersion = info.Main.Path, info.GoVersion
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			tool.VCSRevision = setting.Value
		case "vcs.modified":
			tool.VCSModified = setting.Value == "true"
		}
	}
	return tool
}
