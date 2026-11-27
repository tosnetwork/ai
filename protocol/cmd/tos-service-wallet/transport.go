package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativeclient"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/nativewallet"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type transportConfig struct {
	Network                *nativev1.NetworkDomain    `json:"network"`
	Mode                   agenttransport.NetworkMode `json:"mode"`
	RPC                    []string                   `json:"rpc"`
	Quorum                 int                        `json:"quorum"`
	RegistryCodeBOC        string                     `json:"registry_code_boc_base64"`
	RegistryCodeHash       string                     `json:"registry_code_hash"`
	MinFinalizedCheckpoint uint64                     `json:"min_finalized_checkpoint"`
	RelayURL               string                     `json:"relay_url"`
	InsecureRelay          bool                       `json:"insecure_relay"`
}
type transportLocator struct{ locator *nativecore.Locator }

func (l transportLocator) Locate(code, id string) (string, error) {
	if code != l.locator.CodeHash {
		return "", errors.New("unrecognized registry code")
	}
	found, err := l.locator.Locate(id)
	return found.Address, err
}

func transportCommand(ctx context.Context, args []string, input io.Reader, output, reviewOutput io.Writer) error {
	set := flag.NewFlagSet("transport-delegate", flag.ContinueOnError)
	set.SetOutput(reviewOutput)
	configPath := set.String("transport-config", "", "owner-private network/registry/read/relay JSON configuration")
	directory := set.String("journal", "", "absolute owner-private operation directory; reuse it after a crash")
	agent := set.String("agent", "", "Agent identifier")
	key := set.String("key-name", "", "new non-extractable vault record name (up to 30 characters)")
	epoch := set.Uint64("authorization-epoch", 0, "current finalized epoch; legacy approved test networks require zero")
	purposes := set.Uint("purposes", 7, "nonzero transport purpose mask, 1..7")
	lifetime := set.Uint64("lifetime-seconds", 86400, "delegation lifetime, at most 31536000 seconds")
	credential := set.Uint64("max-credential-seconds", 21600, "credential lifetime, at most 604800 seconds")
	binary := set.String("tosctl", "", "pinned tosctl custody helper")
	pin := set.String("tosctl-sha256", "", "tosctl SHA-256")
	walletConfig := set.String("tosctl-config", "", "tosctl configuration path")
	vaultBinary := set.String("vault-helper", "", "pinned secrets-vault-cli executable sharing VAULT_URL")
	vaultPin := set.String("vault-helper-sha256", "", "vault helper SHA-256")
	timeout := set.Duration("timeout", 10*time.Minute, "overall operation timeout, at most 30m")
	var controllers namesFlag
	set.Var(&controllers, "authority-controller", "delegation-purpose controller; repeat for multisig")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 || *purposes == 0 || *purposes > 7 || *credential == 0 || *credential > agenttransport.MaxCredentialSeconds || *timeout <= 0 || *timeout > 30*time.Minute {
		return errors.New("invalid transport command limits")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var config transportConfig
	if err := loadTransportConfig(*configPath, &config); err != nil {
		return err
	}
	// Enforce the same compiled network gate before opening a checkpoint, vault,
	// signer, or relay connection. No production/epoch-aware registry exists yet.

	if _, err := agenttransport.NewLegacyTestNetworkResolver(config.Mode, config.Network, unopenedReader{}); err != nil {
		return err
	}
	if *epoch != 0 {
		return errors.New("transport wallet requires current epoch zero in test-network-legacy-epoch-zero mode")
	}
	if err := makeTransportDirectory(*directory); err != nil {
		return err
	}
	locator, err := nativecore.NewLocator(nativewallet.NativeTransportNetwork(config.Network), 0, config.RegistryCodeBOC, config.RegistryCodeHash)
	if err != nil {
		return err
	}
	idText := strings.TrimPrefix(config.Network.NetworkId, "tos:global-id:")
	if idText != "2" && idText != "3" {
		return agenttransport.ErrUnapprovedNetwork
	}
	var globalID int32 = 2
	if idText == "3" {
		globalID = 3
	}
	adapter, err := toschain.New(toschain.Config{Network: config.Network.NetworkId, Endpoints: config.RPC, Quorum: config.Quorum, PinnedNetworkDomain: &toschain.PinnedNetworkDomain{NetworkID: config.Network.NetworkId, GlobalID: globalID, ZeroStateRootHash: "sha256:" + config.Network.GenesisRootHash, ZeroStateFileHash: "sha256:" + config.Network.GenesisFileHash, WorkchainID: 0}})
	if err != nil {
		return err
	}
	resolver, err := toschain.NewSimplifiedNativeResolver(adapter, locator, filepath.Join(*directory, "registry.checkpoint"))
	if err != nil {
		return err
	}
	legacy, err := agenttransport.NewLegacyTestNetworkResolver(config.Mode, config.Network, resolver)
	if err != nil {
		return err
	}
	signer, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: *binary, SHA256: *pin, ConfigPath: *walletConfig, VaultURL: os.Getenv("VAULT_URL")})
	if err != nil {
		return err
	}
	vault, err := signer.TransportKeys(*vaultBinary, *vaultPin)
	if err != nil {
		return err
	}
	relay, err := nativeclient.New(nativeclient.Config{BaseURL: config.RelayURL, BearerToken: os.Getenv("TOS_SERVICE_RELAY_TOKEN"), Insecure: config.InsecureRelay})
	if err != nil {
		return err
	}
	defer relay.Close()
	issuer := nativewallet.TransportIssuer{Config: agenttransport.Config{Mode: config.Mode, Network: config.Network, ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{config.RegistryCodeHash}, MinFinalizedCheckpoint: config.MinFinalizedCheckpoint, Locator: transportLocator{locator}}}, Resolver: legacy, Keys: vault, Signer: signer, Submitter: relay, Confirm: func(ctx context.Context, review nativewallet.Review) error {
		raw, err := json.MarshalIndent(review, "", "  ")
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(reviewOutput, "%s\nType the complete action hash to sign: ", raw); err != nil {
			return err
		}
		return confirmTransportHash(ctx, input, review.ActionHash)
	}}
	wire, err := issuer.IssueTransport(ctx, *directory, nativewallet.TransportRequest{AgentID: *agent, KeyName: *key, Epoch: *epoch, Purposes: agenttransport.Purpose(*purposes), Lifetime: *lifetime, CredentialLifetime: uint32(*credential), Controllers: controllers})
	if err != nil {
		return err
	}
	digest, err := agenttransport.DelegationDigest(wire)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Version    string `json:"version"`
		Delegation string `json:"delegation_base64"`
		Digest     string `json:"delegation_digest"`
		KeyName    string `json:"key_name"`
	}{"tos-service-transport-delegation.v1", base64.StdEncoding.EncodeToString(wire), "sha256:" + hex.EncodeToString(digest[:]), *key})
}

type unopenedReader struct{}

func (unopenedReader) ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error) {
	return nil, false, errors.New("reader not opened")
}
func loadTransportConfig(path string, config *transportConfig) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("transport config must be an absolute clean path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) || info.Size() > 1<<20 {
		return errors.New("transport config must be a bounded owner-private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return jsonstrict.Decode(raw, config)
}
func makeTransportDirectory(path string) error {
	// The issuer validates permissions again while acquiring the operation lock.
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("journal must be an absolute clean path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return errors.New("journal must be an owner-private directory")
	}
	return nil
}

// The command makes one prompt, then exits on cancellation. The buffered
// result lets a reader finish without blocking after the command times out.
func confirmTransportHash(ctx context.Context, input io.Reader, expected string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 257)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			result <- err
			return
		}
		if len(line) > 256 {
			result <- errors.New("transport confirmation line exceeds 256 bytes")
			return
		}
		result <- nativewallet.ConfirmHash(bufio.NewReader(strings.NewReader(line)), expected)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
