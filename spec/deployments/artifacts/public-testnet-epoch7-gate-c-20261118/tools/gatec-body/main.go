// Command gatec-body turns a SignedNativeActionV1 (the output of
// tos-service-wallet) into the exact Native Registry submission body that a
// fee-payer wallet carries to the owner Agent, using the production nativecore
// encoders. It is used only for refusal controls whose action the tosctl
// builder declines to sign because finalized state already shows the refusal.
//
// It reads no chain state and holds no key. Its output names the action hash,
// the body BOC (standard base64) and the address of the Agent the body must be
// sent to, derived by the production locator from the pinned release code.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gatec-body:", err)
		os.Exit(1)
	}
}

func run() error {
	signedPath := flag.String("signed", "", "absolute path of the SignedNativeActionV1 JSON")
	agentID := flag.String("agent", "", "agent_<hex> ID of the Agent that receives the body")
	codePath := flag.String("code-base64", "", "path to the frozen registry code BOC Base64")
	codeHash := flag.String("code-hash", "", "tvm-cell-sha256:<hex> registry code hash")
	queryID := flag.Uint64("query-id", 0, "transport-only query ID")
	workchain := flag.Int("workchain", 0, "Registry workchain")
	flag.Parse()
	if *signedPath == "" || *agentID == "" || *codePath == "" || *codeHash == "" {
		return errors.New("--signed, --agent, --code-base64 and --code-hash are required")
	}
	if !filepath.IsAbs(*signedPath) || filepath.Clean(*signedPath) != *signedPath {
		return errors.New("--signed must be an absolute clean path")
	}
	info, err := os.Lstat(*signedPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return errors.New("--signed must be a bounded regular file")
	}
	raw, err := os.ReadFile(*signedPath)
	if err != nil {
		return err
	}
	var signed nativev1.SignedNativeActionV1
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("decode signed action: %w", err)
	}
	if signed.Action == nil {
		return errors.New("signed action has no action")
	}
	built, err := nativecore.BuildAction(signed.Action)
	if err != nil {
		return fmt.Errorf("build action: %w", err)
	}
	// An Agent action is submitted to the Agent itself; a Capability action is
	// carried to its owner Agent for authorization, which forwards it on.
	encode := nativecore.MessageBody
	if strings.HasPrefix(signed.Action.TargetObjectId, "cap_") {
		encode = nativecore.AgentAuthorizationBody
	}
	body, err := encode(built, signed.AuthoritySignatures, signed.CounterpartySignatures, *queryID)
	if err != nil {
		return fmt.Errorf("build body: %w", err)
	}
	code, err := os.ReadFile(*codePath)
	if err != nil {
		return err
	}
	if *workchain < -128 || *workchain > 127 {
		return errors.New("--workchain out of range")
	}
	locator, err := nativecore.NewLocator(signed.Action.Network, int32(*workchain),
		strings.Join(strings.Fields(string(code)), ""), *codeHash)
	if err != nil {
		return fmt.Errorf("locator: %w", err)
	}
	agent, err := locator.Locate(*agentID)
	if err != nil {
		return fmt.Errorf("locate agent: %w", err)
	}
	target, err := locator.Locate(signed.Action.TargetObjectId)
	if err != nil {
		return fmt.Errorf("locate target: %w", err)
	}
	out := map[string]any{
		"action_hash":  hex.EncodeToString(built.Hash),
		"kind_code":    int(built.Kind),
		"target_id":    signed.Action.TargetObjectId,
		"generation":   signed.Action.Generation,
		"sequence":     signed.Action.Sequence,
		"predecessor":  signed.Action.PredecessorTvmStateHash,
		"destination":  agent.Address,
		"final_target": target.Address,
		"body_boc":     base64.StdEncoding.EncodeToString(body.ToBOC()),
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(encoded))
	return err
}
