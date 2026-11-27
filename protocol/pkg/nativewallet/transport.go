package nativewallet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// TransportKeys holds non-extractable Ed25519 keys in the same vault as the
// controller keys. The wallet only receives the public half.
type TransportKeys interface {
	EnsureKey(context.Context, string) ([32]byte, error)
}
type ActionSubmitter interface {
	SubmitNativeAction(context.Context, *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error)
}

type TransportRequest struct {
	AgentID            string                 `json:"agent_id"`
	KeyName            string                 `json:"key_name"`
	Epoch              uint64                 `json:"authorization_epoch"`
	Purposes           agenttransport.Purpose `json:"purposes"`
	Lifetime           uint64                 `json:"lifetime_seconds"`
	CredentialLifetime uint32                 `json:"credential_lifetime_seconds"`
	Controllers        []string               `json:"controllers"`
}

type TransportIssuer struct {
	Config    agenttransport.Config
	Resolver  agenttransport.FinalizedResolver
	Keys      TransportKeys
	Signer    mldsa44.Signer
	Submitter ActionSubmitter
	// Confirm retains the wallet's full-action-hash confirmation. It is called
	// before controller signing, not on an already journalled rerun. It must
	// honor the supplied context, including while waiting for operator input.
	Confirm      func(context.Context, Review) error
	PollInterval time.Duration
}

type transportRecord struct {
	Version        string                     `json:"version"`
	Request        TransportRequest           `json:"request"`
	Network        *nativev1.NetworkDomain    `json:"network"`
	Mode           agenttransport.NetworkMode `json:"mode"`
	RegistryHashes []string                   `json:"registry_hashes"`
	Delegation     []byte                     `json:"delegation,omitempty"`
	Submission     json.RawMessage            `json:"submission,omitempty"`
	Phase          string                     `json:"phase"`
}

// IssueTransport holds the operation lock throughout. Once dispatch is durable,
// subsequent invocations only reconcile; they never sign or submit a second
// action, including when the first acknowledgement was lost.
func (w *TransportIssuer) IssueTransport(ctx context.Context, directory string, request TransportRequest) ([]byte, error) {
	if ctx == nil || w.Keys == nil || w.Signer == nil || w.Submitter == nil || w.Confirm == nil {
		return nil, errors.New("transport issuer dependencies required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	interval := w.PollInterval
	if interval == 0 {
		interval = time.Second
	}
	if interval < time.Millisecond || interval > 30*time.Second {
		return nil, errors.New("invalid transport poll interval")
	}
	// Constructor enforces the code-pinned network allowlist before any key or
	// journal operation. Runtime configuration cannot authorize another genesis.
	verifier, err := agenttransport.NewVerifier(w.Config, w.Resolver)
	if err != nil {
		return nil, err
	}
	if len(request.AgentID) != 70 || !strings.HasPrefix(request.AgentID, "agent_") || request.KeyName == "" || request.Lifetime == 0 || request.Lifetime > agenttransport.MaxDelegationSeconds || request.CredentialLifetime == 0 || request.CredentialLifetime > agenttransport.MaxCredentialSeconds || len(request.Controllers) == 0 || len(request.Controllers) > nativecore.MaxSignatures {
		return nil, errors.New("invalid transport issuance request")
	}
	if _, err := hex.DecodeString(request.AgentID[6:]); err != nil {
		return nil, errors.New("invalid Agent identifier")
	}
	if err := privateDirectory(directory); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(directory, "lock")
	if err := checkPrivateFile(lockPath, true); err != nil {
		return nil, err
	}
	release, acquired, err := osguard.TryExclusiveFileLock(lockPath, 0o600)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, errors.New("transport operation is locked")
	}
	defer release()
	path := filepath.Join(directory, "transport.json")
	r := transportRecord{Version: "tos-service-transport-operation.v1", Request: request, Network: w.Config.Network, Mode: w.Config.Mode, RegistryHashes: w.Config.ChainPolicy.RegistryCodeHashes, Phase: "key"}
	if err := checkPrivateFile(path, true); err != nil {
		return nil, err
	}
	raw, err := readTransportFile(path)
	if err == nil {
		r = transportRecord{}
		if err = jsonstrict.Decode(raw, &r); err != nil {
			return nil, errors.New("invalid transport operation journal")
		}
		expected, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		actual, err := json.Marshal(r.Request)
		if err != nil {
			return nil, err
		}
		if r.Version != "tos-service-transport-operation.v1" || !bytes.Equal(expected, actual) || !proto.Equal(r.Network, w.Config.Network) || r.Mode != w.Config.Mode || !sameStrings(r.RegistryHashes, w.Config.ChainPolicy.RegistryCodeHashes) {
			return nil, errors.New("transport journal belongs to another request or network")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	} else if err = saveTransport(path, r); err != nil {
		return nil, err
	}
	if r.Phase != "key" && r.Phase != "drafted" && r.Phase != "prepared" && r.Phase != "dispatching" {
		return nil, errors.New("invalid transport journal phase")
	}
	if r.Phase == "key" && (len(r.Delegation) != 0 || len(r.Submission) != 0) {
		return nil, errors.New("unexpected key-phase journal payload")
	}

	key, err := w.Keys.EnsureKey(ctx, request.KeyName)
	if err != nil {
		return nil, err
	}
	if r.Phase == "key" {
		readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
		snapshot, err := w.Resolver.ResolveFinalizedAgent(readCtx, request.AgentID)
		readCancel()
		if err != nil {
			return nil, err
		}
		agent, err := agenttransport.CheckState(w.Config.ChainPolicy, w.Config.Network, request.AgentID, snapshot.State)
		if err != nil {
			return nil, err
		}
		policy, err := nativecore.PolicyCell(agent.Policy)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		if w.Config.Clock != nil {
			now = w.Config.Clock.Now()
		}
		if now.Unix() <= 0 || uint64(now.Unix()) > math.MaxUint64-request.Lifetime {
			return nil, errors.New("invalid transport issuance clock")
		}
		d := agenttransport.Delegation{TransportKey: key, AuthorizationEpoch: request.Epoch, Purposes: request.Purposes, NotBefore: uint64(now.Unix()), NotAfter: uint64(now.Unix()) + request.Lifetime, MaxCredentialSeconds: request.CredentialLifetime}
		id, err := hex.DecodeString(request.AgentID[6:])
		if err != nil {
			return nil, err
		}
		copy(d.AgentDigest[:], id)
		copy(d.PolicyHash[:], policy.Hash())
		wire, err := verifier.BuildDelegation(ctx, d)
		if err != nil {
			return nil, err
		}
		digest, err := agenttransport.DelegationDigest(wire)
		if err != nil {
			return nil, err
		}
		if agent.Sequence == math.MaxUint64 {
			return nil, errors.New("Agent sequence exhausted")
		}
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			return nil, err
		}
		action := &nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: NativeTransportNetwork(w.Config.Network), TargetObjectId: request.AgentID, TargetContractCodeHash: snapshot.State.Reference.ContractCodeHash, Generation: agent.Generation, Sequence: agent.Sequence + 1, PredecessorTvmStateHash: snapshot.State.TvmStateHash, Nonce: nonce, Payload: &nativev1.NativeActionV1_DelegateAgent{DelegateAgent: &nativev1.DelegateAgentV1{DelegationDigest: "sha256:" + hex.EncodeToString(digest[:])}}}
		submission, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(&nativev1.SignedNativeActionV1{Action: action})
		if err != nil {
			return nil, err
		}
		r.Delegation, r.Submission, r.Phase = wire, submission, "drafted"
		if err = saveTransport(path, r); err != nil {
			return nil, err
		}
	}
	d, err := agenttransport.DecodeDelegation(r.Delegation)
	if err != nil {
		return nil, err
	}
	if d.TransportKey != key || d.AgentID() != request.AgentID || d.AuthorizationEpoch != request.Epoch || d.Purposes != request.Purposes || d.NotAfter-d.NotBefore != request.Lifetime || d.MaxCredentialSeconds != request.CredentialLifetime {
		return nil, errors.New("transport journal key or delegation mismatch")
	}
	var signed nativev1.SignedNativeActionV1
	if err = (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(r.Submission, &signed); err != nil {
		return nil, err
	}
	if err = validateTransportSubmission(&signed, r.Delegation, w.Config.Network); err != nil {
		return nil, err
	}
	if r.Phase != "drafted" && (len(signed.AuthoritySignatures) == 0 || len(signed.AuthoritySignatures) > nativecore.MaxSignatures) {
		return nil, errors.New("prepared journal has no bounded authority signatures")
	}
	if len(signed.CounterpartySignatures) != 0 || !w.Config.ChainPolicy.AcceptsRegistry(signed.Action.TargetContractCodeHash) {
		return nil, errors.New("unexpected transport journal authority or registry")
	}
	if r.Phase == "drafted" {
		if _, err = verifier.BuildDelegation(ctx, d); err != nil {
			return nil, err
		}
		review, built, err := ReviewAction(signed.Action)
		if err != nil {
			return nil, err
		}
		if err = w.Confirm(ctx, review); err != nil {
			return nil, err
		}
		signatures, err := Sign(ctx, w.Signer, built, request.Controllers)
		if err != nil {
			return nil, err
		}
		signed.AuthoritySignatures = signatures
		encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(&signed)
		if err != nil {
			return nil, err
		}
		r.Submission, r.Phase = encoded, "prepared"
		if err = saveTransport(path, r); err != nil {
			return nil, err
		}
	}

	if r.Phase == "prepared" {
		now := time.Now()
		if w.Config.Clock != nil {
			now = w.Config.Clock.Now()
		}
		if now.Unix() < 0 || uint64(now.Unix()) >= d.NotAfter {
			return nil, errors.New("journalled delegation expired before submission")
		}

		if _, err = verifier.BuildDelegation(ctx, d); err != nil {
			return nil, err
		}
		// Persist before crossing the existing relay action boundary. A crash here
		// is intentionally ambiguous, and a retry may only reconcile.
		r.Phase = "dispatching"
		if err = saveTransport(path, r); err != nil {
			return nil, err
		}
		built, err := nativecore.BuildAction(signed.Action)
		if err != nil {
			return nil, err
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("transport submission deadline required")
		}
		requestID := "transport-" + strings.TrimPrefix(built.HashString, "tvm-cell-sha256:")
		if _, err = w.Submitter.SubmitNativeAction(ctx, &nativev1.SubmitNativeActionRequest{Submission: &signed, Context: &nativev1.RequestContext{RequestId: requestID, IdempotencyKey: requestID, CallerId: request.AgentID, DeadlineUnixMillis: deadline.UnixMilli()}}); err != nil {
			return nil, errors.New("delegation outcome unknown; keep this journal and rerun to reconcile")
		}
	}

	for {
		// A fresh verifier prevents the cached-pass path from reporting success
		// after a revocation between reruns. Never trust a relay acknowledgement.
		fresh, err := agenttransport.NewVerifier(w.Config, w.Resolver)
		if err != nil {
			return nil, err
		}
		if _, err = fresh.VerifyDelegation(ctx, r.Delegation, firstPurpose(d.Purposes)); err == nil {
			return bytes.Clone(r.Delegation), nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("delegation not confirmed; keep the journal and rerun: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func firstPurpose(p agenttransport.Purpose) agenttransport.Purpose {
	for _, v := range []agenttransport.Purpose{agenttransport.Relay, agenttransport.Hints, agenttransport.Direct} {
		if p&v != 0 {
			return v
		}
	}
	return 0
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func validateTransportSubmission(s *nativev1.SignedNativeActionV1, wire []byte, network *nativev1.NetworkDomain) error {
	d, err := agenttransport.DecodeDelegation(wire)
	if err != nil {
		return err
	}
	digest, err := agenttransport.DelegationDigest(wire)
	if err != nil {
		return err
	}
	if s.Action == nil || !proto.Equal(s.Action.Network, NativeTransportNetwork(network)) || s.Action.TargetObjectId != d.AgentID() || s.Action.GetDelegateAgent() == nil || s.Action.GetDelegateAgent().DelegationDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return errors.New("journal action differs from transport delegation")
	}
	_, err = nativecore.BuildAction(s.Action)
	return err
}
func privateDirectory(path string) error {
	if !osguard.OwnerPrivateStorageSupported() || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("transport directory must be an absolute owner-private path on a supported host")
	}
	if err := transportAncestors(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return errors.New("transport directory must be owner-private and not a symlink")
	}
	return nil
}
func checkPrivateFile(path string, absent bool) error {
	info, err := os.Lstat(path)
	if absent && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !singleTransportLink(info) || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return errors.New("transport journal must be an owner-private regular file")
	}
	return nil
}
func readTransportFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("transport journal too large")
	}
	return raw, nil
}
func saveTransport(path string, r transportRecord) error {
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("transport journal too large")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".transport-*")
	if err != nil {
		return err
	}
	// A failed write leaves a private diagnostic file, never a partial journal.
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// NativeTransportNetwork converts only the textual hash representation used by
// native actions; it cannot select a different genesis.
func NativeTransportNetwork(network *nativev1.NetworkDomain) *nativev1.NetworkDomain {
	if network == nil {
		return nil
	}
	result := proto.Clone(network).(*nativev1.NetworkDomain)
	result.GenesisRootHash = "sha256:" + result.GenesisRootHash
	result.GenesisFileHash = "sha256:" + result.GenesisFileHash
	return result
}

func transportAncestors(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
				return errors.New("transport directory has an untrusted writable or symlink ancestor")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if parent == filepath.Dir(parent) {
			return nil
		}
	}
}
