package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// serviceInterval is how often the serving node runs its duties when no
// packet prompts it sooner.
const serviceInterval = 5 * time.Second

// serveStarted is the one line `serve` prints once the node is assembled and
// its receiver socket is open.
type serveStarted struct {
	Serving        bool     `json:"serving"`
	AgentID        string   `json:"agent_id"`
	CapabilityID   string   `json:"capability_id"`
	ReceiverSocket string   `json:"receiver_socket"`
	RelayURLs      []string `json:"relay_urls"`
}

func runServe(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var path string
	railConfigFlag(set, &path)
	if done, err := parse(set, arguments, "rail-config"); done || err != nil {
		return err
	}
	config, err := loadProviderConfig(path)
	if err != nil {
		return err
	}
	node, err := servicebridge.OpenNode(ctx, config, servicebridge.NodeOptions{Report: func(stage string, err error) {
		fmt.Fprintf(std.err, "%s: %s: %v\n", time.Now().UTC().Format(time.RFC3339), stage, err)
	}})
	if err != nil {
		return err
	}
	relays := node.Config.RelayURLs
	if relays == nil {
		relays = []string{}
	}
	err = node.Serve(ctx, serviceInterval, func() error {
		started, encodeErr := json.Marshal(serveStarted{
			Serving: true, AgentID: node.Config.AgentID, CapabilityID: node.Config.Provider.CapabilityID,
			ReceiverSocket: node.Config.ReceiverSocket, RelayURLs: relays,
		})
		if encodeErr == nil {
			_, encodeErr = fmt.Fprintf(std.out, "%s\n", started)
		}
		if encodeErr != nil {
			return fmt.Errorf("report that the node is serving: %w", encodeErr)
		}
		return nil
	})
	return errors.Join(err, node.Close())
}

func runStatus(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var path string
	var offline, recordsOnly bool
	railConfigFlag(set, &path)
	set.BoolVar(&offline, "offline", false, "do not read finalized chain facts")
	set.BoolVar(&recordsOnly, "records", false, "print only the request list")
	if done, err := parse(set, arguments, "rail-config"); done || err != nil {
		return err
	}
	config, err := loadProviderConfig(path)
	if err != nil {
		return err
	}
	var chain servicebridge.StatusChain
	if !offline {
		chain, err = servicebridge.OpenStatusChain(config)
		if err != nil {
			// The local view is still worth printing; the failure is
			// reported in actor.error and chain-decided states stay unknown.
			chain = servicebridge.UnavailableStatusChain(fmt.Errorf("open the finalized reader: %w", err))
		}
	}
	status, err := servicebridge.ReadProviderStatus(ctx, config, chain, time.Now())
	if err != nil {
		return err
	}
	if recordsOnly {
		return printJSON(std.out, status.Requests)
	}
	return printJSON(std.out, status)
}

func runPreflight(ctx context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var path, alias string
	railConfigFlag(set, &path)
	set.StringVar(&alias, "config", "", "alias of --rail-config")
	if done, err := parse(set, arguments); done || err != nil {
		return err
	}
	if path != "" && alias != "" && path != alias {
		return usagef("--rail-config and --config name different files")
	}
	if path == "" {
		path = alias
	}
	if path == "" {
		return usagef("required flag(s) --rail-config not set")
	}
	report := servicebridge.RunPreflight(ctx, path, servicebridge.PreflightEnv{})
	if err := printJSON(std.out, report); err != nil {
		return err
	}
	if !report.OK {
		return errNotReady
	}
	return nil
}

func runPause(_ context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var path, reason string
	railConfigFlag(set, &path)
	set.StringVar(&reason, "reason", "", "one-line note shown in status (at most 256 bytes)")
	if done, err := parse(set, arguments, "rail-config"); done || err != nil {
		return err
	}
	config, err := loadProviderConfig(path)
	if err != nil {
		return err
	}
	// The operator's pause: over the provider agent's own pause it re-stamps
	// the marker as the operator's, so the agent can no longer lift it.
	result, err := servicebridge.PauseAdmissionAs(config.StateDir, servicebridge.PauseOriginOperator, reason, time.Now())
	if err != nil {
		return err
	}
	answer := map[string]any{
		"paused": true, "already_paused": result.Already, "paused_unix": result.Pause.PausedUnix,
		"reason": result.Pause.Reason, "origin": result.Pause.Origin, "restamped": result.Restamped,
	}
	if result.Already {
		answer["previous_origin"] = result.PreviousOrigin
	}
	return printJSON(std.out, answer)
}

func runResume(_ context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var path string
	railConfigFlag(set, &path)
	if done, err := parse(set, arguments, "rail-config"); done || err != nil {
		return err
	}
	config, err := loadProviderConfig(path)
	if err != nil {
		return err
	}
	wasPaused, err := servicebridge.ResumeAdmission(config.StateDir)
	if err != nil {
		return err
	}
	return printJSON(std.out, map[string]any{"paused": false, "was_paused": wasPaused})
}

func runManifest(_ context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var input servicebridge.ManifestInput
	var out, tokenConfig string
	set.StringVar(&tokenConfig, "token-config", "", "token provider configuration supplying independent asset pins (optional)")
	set.StringVar(&input.ProviderAgentID, "provider-agent", "", "provider Agent id (agent_<hex>)")
	set.StringVar(&input.Actor, "actor", "", "Service Actor address (0:<hex>)")
	set.StringVar(&input.ActorCodeHash, "code-hash", "", "pinned Service Actor release code hash "+
		"(tvm-cell-sha256:<hex>)")
	set.StringVar(&input.Attestor, "attestor", "", "attestor controller key id (mldsa44:<hex>)")
	set.StringVar(&input.Version, "version", servicebridge.DefaultOfferVersion, "Capability version")
	set.Uint64Var(&input.RetentionSeconds, "retention-seconds", servicebridge.DefaultRetentionSeconds,
		"how long results are redelivered")
	set.StringVar(&out, "out-dir", "", "existing directory for the manifest file")
	if done, err := parse(set, arguments, "out-dir"); done || err != nil {
		return err
	}
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return usagef("--out-dir must be an absolute clean path")
	}
	var encoded []byte
	var digest string
	var err error
	if tokenConfig == "" {
		encoded, digest, _, err = servicebridge.BuildManifest(input)
	} else {
		var c servicebridge.NodeConfig
		c, err = servicebridge.LoadNodeConfig(tokenConfig)
		if err == nil && c.Token == nil {
			return usagef("--token-config has no asset pins")
		}
		if err == nil {
			var a servicebridge.TokenActorConfig
			a, err = c.Token.Actor(input.Actor)
			if err == nil && (a.CodeHash != input.ActorCodeHash || c.AgentID != input.ProviderAgentID) {
				return usagef("token manifest differs from configured actor or Agent")
			}
			if err == nil {
				found := false
				for _, pin := range c.Token.Pins {
					if pin.Master == a.Master {
						found = true
						encoded, digest, _, err = servicebridge.BuildTokenManifest(input, pin)
						break
					}
				}
				if !found {
					return usagef("token actor has no independent asset pin")
				}
			}
		}
	}
	if err != nil {
		return err
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	path := filepath.Join(out, hexDigest+".cbor")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return fmt.Errorf("write the manifest: %w", err)
	}
	next := []string{
		"tosctl agent service deploy ... --attestor-controller <attestor> (if the actor is not deployed yet)",
		"tosctl agent native-registry action --kind register-capability --manifest " + hexDigest + " ...",
		programName + " metadata --capability-id <cap_...> --manifest-digest " + digest + " ...",
		"tosctl agent service send --operation update-policy --metadata-hash <NSM1> ...",
	}
	if tokenConfig != "" {
		next = []string{
			"tosctl agent native-registry action --kind register-capability --manifest " + hexDigest + " ...",
			programName + " metadata --capability-id <cap_...> --manifest-digest " + digest + " ...",
			"tosctl agent service-token send --operation update-policy --metadata-hash <NSM1> ...",
		}
	}
	return printJSON(std.out, map[string]any{"manifest_digest": digest, "path": path, "next_steps": next})
}

func runMetadata(_ context.Context, set *flag.FlagSet, arguments []string, std streams) error {
	var networkID, root, file, capability, provider, version, digest string
	set.StringVar(&networkID, "network-id", "", "network id")
	set.StringVar(&root, "genesis-root-hash", "", "genesis root hash")
	set.StringVar(&file, "genesis-file-hash", "", "genesis file hash")
	set.StringVar(&capability, "capability-id", "", "registered Capability id")
	set.StringVar(&provider, "provider-agent", "", "provider Agent id")
	set.StringVar(&version, "version", servicebridge.DefaultOfferVersion, "Capability version")
	set.StringVar(&digest, "manifest-digest", "", "manifest digest")
	if done, err := parse(set, arguments); done || err != nil {
		return err
	}
	hash, err := servicebridge.MetadataHash(&nativev1.NetworkDomain{
		NetworkId: networkID, GenesisRootHash: root, GenesisFileHash: file,
	}, capability, provider, version, digest)
	if err != nil {
		return err
	}
	return printJSON(std.out, map[string]string{"metadata_hash": hash})
}
