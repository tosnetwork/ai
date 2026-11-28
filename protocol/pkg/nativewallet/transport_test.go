package nativewallet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/gen/tos/service/v1/tosservicev1connect"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44/mldsa44test"
	"github.com/tosnetwork/ai/protocol/pkg/nativeclient"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type transportTestClock struct{}

func (transportTestClock) Now() time.Time { return time.Unix(1800000000, 0) }

type transportTestLocator struct{}

func (transportTestLocator) Locate(string, string) (string, error) { return "0:test", nil }

type transportTestKeys struct {
	names []string
	calls int
	key   [32]byte
}

func (k *transportTestKeys) EnsureKey(_ context.Context, name string) ([32]byte, error) {
	k.names = append(k.names, name)
	k.calls++
	return k.key, nil
}

type transportHarness struct {
	readErr      error
	mu           sync.Mutex
	t            *testing.T
	snapshot     agenttransport.Snapshot
	signer       mldsa44.Verifier
	submits      int
	finalize     bool
	lost         bool
	directory    string
	beforeSubmit func()
	onRead       func()
	reads        int
}

func (h *transportHarness) ResolveFinalizedAgent(ctx context.Context, _ string) (agenttransport.Snapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return agenttransport.Snapshot{}, err
	}
	h.reads++
	if h.onRead != nil {
		h.onRead()
	}
	if h.readErr != nil {
		return agenttransport.Snapshot{}, h.readErr
	}
	return h.snapshot, nil
}
func (h *transportHarness) SubmitNativeAction(ctx context.Context, r *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.submits++
	// The request carries the caller's own deadline. It is compared with the
	// call's context, not with the wall clock: on a loaded machine the deadline can
	// pass before the call arrives, and that is the issuer's timing, not a missing
	// context. Over HTTP the handler's deadline is the caller's, re-derived from
	// the transmitted timeout, so it may differ by the transit time.
	deadline, hasDeadline := ctx.Deadline()
	if r.Context == nil || r.Context.RequestId == "" || r.Context.IdempotencyKey != r.Context.RequestId || r.Context.CallerId != r.Submission.Action.TargetObjectId || !hasDeadline || math.Abs(float64(r.Context.DeadlineUnixMillis-deadline.UnixMilli())) > 60000 {
		h.t.Fatal("missing existing Native action request context")
	}

	raw, err := os.ReadFile(filepath.Join(h.directory, "transport.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"phase":"dispatching"`)) || !bytes.Contains(raw, []byte(`authority_signatures`)) {
		h.t.Fatal("submission was not durable before dispatch")
	}
	built, err := nativecore.BuildAction(r.Submission.Action)
	if err != nil {
		h.t.Fatal(err)
	}
	if err = nativecore.VerifySignatures(ctx, h.signer, h.snapshot.State.GetAgent().Policy, r.Submission.AuthoritySignatures, nativecore.PurposeDelegation, false, built); err != nil {
		h.t.Fatal(err)
	}
	if h.beforeSubmit != nil {
		h.beforeSubmit()
	}
	if h.finalize {
		h.commit(r.Submission)
	}
	if h.lost {
		return nil, errors.New("lost acknowledgement")
	}
	return &nativev1.SubmitNativeActionResponse{ActionHash: built.HashString, RelayAccepted: true}, nil
}
func (h *transportHarness) commit(s *nativev1.SignedNativeActionV1) {
	h.snapshot.State = proto.Clone(h.snapshot.State).(*nativev1.NativeStateV1)
	agent := h.snapshot.State.GetAgent()
	agent.DelegationDigests = append(agent.DelegationDigests, s.Action.GetDelegateAgent().DelegationDigest)
	agent.Sequence = s.Action.Sequence
	built, err := nativecore.BuildAction(s.Action)
	if err != nil {
		h.t.Fatal(err)
	}
	agent.LastActionHash = built.HashString
	h.snapshot.State.Reference.FinalizedCheckpoint++
}
func transportFixture(t *testing.T) (*TransportIssuer, *transportHarness, *transportTestKeys, TransportRequest) {
	t.Helper()
	fake := &mldsa44test.Fake{}
	network := &nativev1.NetworkDomain{NetworkId: "tos:global-id:3", GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366", GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{controller(fake.KeyID("owner"), fake.PublicKey("owner"))}}
	code := "tvm-cell-sha256:" + strings.Repeat("3", 64)
	request := TransportRequest{AgentID: "agent_" + strings.Repeat("1", 64), KeyName: "test-transport", Purposes: 7, Lifetime: 86400, CredentialLifetime: 21600, Controllers: []string{"owner"}}
	h := &transportHarness{t: t, signer: fake, finalize: true, directory: t.TempDir()}
	if err := os.Chmod(h.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	h.snapshot = agenttransport.Snapshot{State: &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("4", 64), Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: code, Account: "0:test", TransactionHash: "sha256:" + strings.Repeat("5", 64)}, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: request.AgentID, Generation: 1, Sequence: 1, Policy: policy}}}}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	keys := &transportTestKeys{}
	copy(keys.key[:], private.Public().(ed25519.PublicKey))
	issuer := &TransportIssuer{Config: agenttransport.Config{Mode: agenttransport.TestNetworkLegacyEpochZero, Network: network, Clock: transportTestClock{}, ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{code}, Locator: transportTestLocator{}}}, Resolver: h, Keys: keys, Signer: fake, Submitter: h, Confirm: func(context.Context, Review) error { return nil }, PollInterval: time.Millisecond}
	return issuer, h, keys, request
}

// issueTest runs one issuance with a budget no loaded race run reaches; a
// test that expects an outcome gets it, however slow the machine.
func issueTest(t *testing.T, w *TransportIssuer, h *transportHarness, r TransportRequest) ([]byte, error) {
	t.Helper()
	return issueWithin(t, w, h, r, 30*time.Second)
}

// issueUntilDeadline runs an issuance that is expected to wait for a
// finalization that never comes, so it ends at its short deadline.
func issueUntilDeadline(t *testing.T, w *TransportIssuer, h *transportHarness, r TransportRequest) ([]byte, error) {
	t.Helper()
	return issueWithin(t, w, h, r, time.Second)
}

func issueWithin(t *testing.T, w *TransportIssuer, h *transportHarness, r TransportRequest, budget time.Duration) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	result, err := w.IssueTransport(ctx, h.directory, r)
	return result.Delegation, err
}
func TestTransportRoundTripAndRerun(t *testing.T) {
	w, h, _, r := transportFixture(t)
	wire, err := issueTest(t, w, h, r)
	if err != nil {
		t.Fatal(err)
	}
	calls := w.Signer.(*mldsa44test.Fake).Calls()
	again, err := issueTest(t, w, h, r)
	if err != nil || !bytes.Equal(wire, again) || h.submits != 1 || w.Signer.(*mldsa44test.Fake).Calls() != calls {
		t.Fatalf("rerun: %v submits=%d", err, h.submits)
	}
	for _, name := range []string{"transport.json", "lock"} {
		info, err := os.Lstat(filepath.Join(h.directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions %s: %v %v", name, info, err)
		}
	}
	d, err := agenttransport.DecodeDelegation(wire)
	if err != nil || d.AuthorizationEpoch != 0 || d.Purposes != 7 {
		t.Fatalf("delegation %v %v", d, err)
	}
}
func TestTransportLostAcknowledgementReconcilesWithoutResubmit(t *testing.T) {
	w, h, _, r := transportFixture(t)
	h.lost = true
	if _, err := issueTest(t, w, h, r); err == nil {
		t.Fatal("lost acknowledgement reported success")
	}
	calls := w.Signer.(*mldsa44test.Fake).Calls()
	wire, err := issueTest(t, w, h, r)
	if err != nil || len(wire) != agenttransport.DelegationSize || h.submits != 1 || w.Signer.(*mldsa44test.Fake).Calls() != calls {
		t.Fatalf("reconcile %v submits %d", err, h.submits)
	}
}
func TestTransportAcknowledgementIsNotFinalization(t *testing.T) {
	w, h, _, r := transportFixture(t)
	h.finalize = false
	if _, err := issueUntilDeadline(t, w, h, r); err == nil {
		t.Fatal("unfinalized acknowledgement passed")
	}
	if _, err := issueUntilDeadline(t, w, h, r); err == nil || h.submits != 1 {
		t.Fatal("unconfirmed rerun submitted again")
	}
}
func TestTransportEpochAndNetworkRefusals(t *testing.T) {
	for _, name := range []string{"future-epoch", "production", "unknown-root", "unknown-file", "wrong-global-id", "production-mode"} {
		t.Run(name, func(t *testing.T) {
			w, h, k, r := transportFixture(t)
			switch name {
			case "future-epoch":
				r.Epoch = 1
			case "production":
				w.Config.Network.NetworkId = "tos:global-id:1"
			case "unknown-root":
				w.Config.Network.GenesisRootHash = strings.Repeat("9", 64)
			case "unknown-file":
				w.Config.Network.GenesisFileHash = strings.Repeat("9", 64)
			case "wrong-global-id":
				w.Config.Network.NetworkId = "tos:global-id:2"
			case "production-mode":
				w.Config.Mode = agenttransport.Production
			}
			if _, err := issueTest(t, w, h, r); err == nil {
				t.Fatal("invalid issuance accepted")
			}
			if h.submits != 0 || w.Signer.(*mldsa44test.Fake).Calls() != 0 {
				t.Fatal("invalid issuance signed/submitted")
			}
			if name != "future-epoch" && k.calls != 0 {
				t.Fatal("unapproved network reached custody")
			}
		})
	}
}
func TestTransportPrivateJournalAndBinding(t *testing.T) {
	for _, name := range []string{"directory", "symlink", "journal", "request", "key", "corrupt", "busy", "lock-link"} {
		t.Run(name, func(t *testing.T) {
			w, h, k, r := transportFixture(t)
			switch name {
			case "directory":
				if err := os.Chmod(h.directory, 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := t.TempDir()
				if err := os.Symlink(target, filepath.Join(h.directory, "transport.json")); err != nil {
					t.Fatal(err)
				}
			case "lock-link":
				if err := os.WriteFile(filepath.Join(h.directory, "lock"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(filepath.Join(h.directory, "lock"), filepath.Join(h.directory, "lock-alias")); err != nil {
					t.Fatal(err)
				}
			case "busy":
				release, ok, err := osguard.TryExclusiveFileLock(filepath.Join(h.directory, "lock"), 0o600)
				if err != nil || !ok {
					t.Fatal(err)
				}
				defer release()
			default:
				if _, err := issueTest(t, w, h, r); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "journal":
					if err := os.Chmod(filepath.Join(h.directory, "transport.json"), 0o644); err != nil {
						t.Fatal(err)
					}
				case "request":
					r.Controllers = []string{"another-owner"}
				case "key":
					k.key[0] ^= 1
				case "corrupt":
					path := filepath.Join(h.directory, "transport.json")
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var record map[string]json.RawMessage
					if err = json.Unmarshal(raw, &record); err != nil {
						t.Fatal(err)
					}
					delete(record, "version")
					raw, err = json.Marshal(record)
					if err != nil {
						t.Fatal(err)
					}
					if err = os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := h.submits
			if _, err := issueTest(t, w, h, r); err == nil {
				t.Fatal("invalid operation accepted")
			}
			if h.submits != before {
				t.Fatal("invalid rerun sent")
			}
		})
	}
}

type recordingTransportSigner struct {
	base   mldsa44.Signer
	before func()
}

func (s recordingTransportSigner) Sign(ctx context.Context, name string, use mldsa44.Use, payload []byte) (mldsa44.Signature, error) {
	s.before()
	return s.base.Sign(ctx, name, use, payload)
}
func TestTransportDraftIsDurableBeforeSigning(t *testing.T) {
	w, h, _, r := transportFixture(t)
	w.Signer = recordingTransportSigner{w.Signer, func() {
		raw, err := os.ReadFile(filepath.Join(h.directory, "transport.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"phase":"drafted"`)) || !bytes.Contains(raw, []byte(`delegation_digest`)) {
			t.Fatal("delegation/action not journalled before signing")
		}
	}}
	if _, err := issueTest(t, w, h, r); err != nil {
		t.Fatal(err)
	}
}
func TestTransportResumeKeepsDraftAfterDeclinedConfirmation(t *testing.T) {
	w, h, _, r := transportFixture(t)
	w.Confirm = func(context.Context, Review) error { return errors.New("declined") }
	if _, err := issueTest(t, w, h, r); err == nil {
		t.Fatal("declined confirmation proceeded")
	}
	before, err := os.ReadFile(filepath.Join(h.directory, "transport.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte(`"phase":"drafted"`)) {
		t.Fatal("draft missing")
	}
	w.Confirm = func(context.Context, Review) error { return nil }
	if _, err := issueTest(t, w, h, r); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(h.directory, "transport.json"))
	if err != nil {
		t.Fatal(err)
	}
	var first, last transportRecord
	if err = json.Unmarshal(before, &first); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(after, &last); err != nil {
		t.Fatal(err)
	}
	var a, b nativev1.SignedNativeActionV1
	if err = protojson.Unmarshal(first.Submission, &a); err != nil {
		t.Fatal(err)
	}
	if err = protojson.Unmarshal(last.Submission, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Delegation, last.Delegation) || !proto.Equal(a.Action, b.Action) {
		t.Fatal("rerun rebuilt delegation or action nonce")
	}
}
func TestTransportCrashAfterDispatchMarkNeverSendsAgain(t *testing.T) {
	w, h, _, r := transportFixture(t)
	h.finalize = false
	h.lost = true
	if _, err := issueTest(t, w, h, r); err == nil {
		t.Fatal("lost dispatch passed")
	}
	if _, err := issueUntilDeadline(t, w, h, r); err == nil || h.submits != 1 {
		t.Fatal("dispatch rerun sent twice")
	}
}
func TestTransportWriteFailurePreventsSigning(t *testing.T) {
	w, h, _, r := transportFixture(t)
	if err := os.Mkdir(filepath.Join(h.directory, "transport.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := issueTest(t, w, h, r); err == nil || h.submits != 0 || w.Signer.(*mldsa44test.Fake).Calls() != 0 {
		t.Fatal("journal refusal signed or sent")
	}
}
func TestTransportCurrentEpochOnly(t *testing.T) {
	for _, epoch := range []uint64{0, 1, 2} {
		t.Run(fmt.Sprint(epoch), func(t *testing.T) {
			w, h, _, r := transportFixture(t)
			current := uint64(1)
			h.snapshot.CurrentEpoch = &current
			h.snapshot.EpochCheckpoint = 10
			h.snapshot.AdmissionEpochs = map[[32]byte]uint64{}
			w.Config.Mode = agenttransport.TestNetworkEpochAware
			r.Epoch = epoch
			h.beforeSubmit = func() {
				raw, err := os.ReadFile(filepath.Join(h.directory, "transport.json"))
				if err != nil {
					t.Fatal(err)
				}
				var record transportRecord
				if err = json.Unmarshal(raw, &record); err != nil {
					t.Fatal(err)
				}
				digest, err := agenttransport.DelegationDigest(record.Delegation)
				if err != nil {
					t.Fatal(err)
				}
				h.snapshot.AdmissionEpochs[digest] = 1
				h.snapshot.EpochCheckpoint++
			}
			_, err := issueTest(t, w, h, r)
			if (err == nil) != (epoch == 1) {
				t.Fatalf("epoch %d: %v", epoch, err)
			}
			if epoch != 1 && h.submits != 0 {
				t.Fatal("wrong epoch submitted")
			}
		})
	}
}
func TestTransportRoundTripWithRealControllerCustody(t *testing.T) {
	w, h, _, r := transportFixture(t)
	custody := mldsa44test.NewCustody(t, "owner")
	h.snapshot.State.GetAgent().Policy = &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{controller(custody.KeyID(t, "owner"), custody.PublicKeys["owner"])}}
	w.Signer = custody.Signer
	binary := os.Getenv("TOS_SERVICE_VAULT_HELPER")
	if binary == "" {
		binary = filepath.Join(filepath.Dir(os.Getenv("TOS_SERVICE_TOSCTL")), "secrets-vault-cli")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("TOS_SERVICE_VAULT_HELPER is required:", err)
	}
	digest := sha256.Sum256(raw)
	vault, err := custody.Signer.TransportKeys(binary, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	paymentKey, err := vault.EnsureKey(t.Context(), r.KeyName)
	if err != nil {
		t.Fatal(err)
	}
	w.Keys = vault
	mux := http.NewServeMux()
	route, handler := tosservicev1connect.NewNativeServiceHandler(transportNativeHandler{h: h})
	mux.Handle(route, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client, err := nativeclient.New(nativeclient.Config{BaseURL: server.URL, BearerToken: "test-relay-token", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	w.Submitter = client
	h.signer = mldsa44test.RequireTosctl(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	result, err := w.IssueTransport(ctx, h.directory, r)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := agenttransport.DecodeDelegation(result.Delegation)
	if err != nil {
		t.Fatal(err)
	}
	if delegation.TransportKey == paymentKey || result.VaultKeyName == r.KeyName || !strings.HasPrefix(result.VaultKeyName, "mtv2-") {
		t.Fatal("transport reused an existing payment key")
	}

}

type transportMutableClock struct{ at time.Time }

func (c *transportMutableClock) Now() time.Time { return c.at }
func TestTransportExpiryBeforeDispatchRefuses(t *testing.T) {
	w, h, _, r := transportFixture(t)
	clock := &transportMutableClock{time.Unix(1800000000, 0)}
	w.Config.Clock = clock
	reads := -1
	w.Confirm = func(context.Context, Review) error {
		clock.at = clock.at.Add(time.Duration(r.Lifetime) * time.Second)
		reads = h.reads
		return nil
	}
	if _, err := issueTest(t, w, h, r); err == nil || h.submits != 0 {
		t.Fatal("expired delegation dispatched")
	}
	// An already expired journal is refused before another finalized read.
	if h.reads != reads || transportJournalPhase(t, h.directory) != "expired" {
		t.Fatalf("expired journal was read again or not recorded: reads %d/%d", h.reads, reads)
	}
}

func transportJournalPhase(t *testing.T, directory string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "transport.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Phase string `json:"phase"`
	}
	if err = json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record.Phase
}

// The final finalized read before dispatch can outlast a short delegation. The
// clock advances past not_after during that read, so the issuer must refuse
// after the read, record the refusal, and never cross the relay boundary.
func TestTransportExpiryDuringFinalReadRefuses(t *testing.T) {
	w, h, _, r := transportFixture(t)
	r.Lifetime, r.CredentialLifetime = 1, 1
	clock := &transportMutableClock{time.Unix(1800000000, 0)}
	w.Config.Clock = clock
	h.onRead = func() {
		if transportJournalPhase(t, h.directory) == "prepared" {
			clock.at = clock.at.Add(2 * time.Second)
		}
	}
	_, err := issueTest(t, w, h, r)
	if err == nil || !strings.Contains(err.Error(), "expired before submission") || h.submits != 0 {
		t.Fatalf("delegation expired during the final read was dispatched: %v submits=%d", err, h.submits)
	}
	if phase := transportJournalPhase(t, h.directory); phase != "expired" {
		t.Fatalf("refusal not recorded: phase %q", phase)
	}
	calls, reads := w.Signer.(*mldsa44test.Fake).Calls(), h.reads
	h.onRead = nil
	clock.at = time.Unix(1800000000, 0)
	_, err = issueTest(t, w, h, r)
	if err == nil || !strings.Contains(err.Error(), "expired before submission") || h.submits != 0 || h.reads != reads || w.Signer.(*mldsa44test.Fake).Calls() != calls {
		t.Fatalf("expired journal rerun was treated as in flight: %v submits=%d reads=%d/%d", err, h.submits, h.reads, reads)
	}
}
func TestTransportIssuerLimits(t *testing.T) {
	for _, name := range []string{"zero-lifetime", "long-lifetime", "zero-credential", "long-credential", "purposes", "sequence", "poll"} {
		t.Run(name, func(t *testing.T) {
			w, h, _, r := transportFixture(t)
			switch name {
			case "zero-lifetime":
				r.Lifetime = 0
			case "long-lifetime":
				r.Lifetime = agenttransport.MaxDelegationSeconds + 1
			case "zero-credential":
				r.CredentialLifetime = 0
			case "long-credential":
				r.CredentialLifetime = agenttransport.MaxCredentialSeconds + 1
			case "purposes":
				r.Purposes = 8
			case "sequence":
				h.snapshot.State.GetAgent().Sequence = math.MaxUint64
			case "poll":
				w.PollInterval = time.Hour
			}
			if _, err := issueTest(t, w, h, r); err == nil || h.submits != 0 {
				t.Fatal("invalid limit signed/submitted")
			}
		})
	}
}
func TestTransportReadAndWriteBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTransportFile(path); err == nil {
		t.Fatal("oversized journal read")
	}
	if err := saveTransport(path, transportRecord{Phase: strings.Repeat("x", (1<<20)+1)}); err == nil {
		t.Fatal("oversized journal write")
	}
	if raw, err := os.ReadFile(path); err != nil || len(raw) != (1<<20)+1 {
		t.Fatal("refused write changed prior journal")
	}
}
func TestTransportUntrustedAncestorRefuses(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(filepath.Join(parent, "child")); err == nil {
		t.Fatal("group writable ancestor accepted")
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory(filepath.Join(alias, "child")); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
}

type transportReflectedError struct{}

func (transportReflectedError) SubmitNativeAction(context.Context, *nativev1.SubmitNativeActionRequest) (*nativev1.SubmitNativeActionResponse, error) {
	return nil, errors.New("untrusted reflected relay credential")
}
func TestTransportSubmissionErrorDoesNotReflectCredentials(t *testing.T) {
	w, h, _, r := transportFixture(t)
	w.Submitter = transportReflectedError{}
	if _, err := issueTest(t, w, h, r); err == nil || strings.Contains(err.Error(), "untrusted reflected relay credential") || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("unsafe submission error: %v", err)
	}
}

type transportNativeHandler struct {
	tosservicev1connect.UnimplementedNativeServiceHandler
	h *transportHarness
}

func (s transportNativeHandler) SubmitNativeAction(ctx context.Context, r *connect.Request[nativev1.SubmitNativeActionRequest]) (*connect.Response[nativev1.SubmitNativeActionResponse], error) {
	if r.Header().Get("Authorization") != "Bearer test-relay-token" {
		s.h.t.Error("missing existing relay-token authorization")
		return nil, errors.New("relay authorization refused")
	}
	result, err := s.h.SubmitNativeAction(ctx, r.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(result), nil
}

func TestTransportVaultIDSurvivesAStopAfterKeyCreation(t *testing.T) {
	w, h, keys, r := transportFixture(t)
	h.readErr = errors.New("read unavailable")
	if _, err := issueTest(t, w, h, r); err == nil {
		t.Fatal("unavailable state accepted")
	}
	if keys.calls != 1 || len(keys.names) != 1 {
		t.Fatal("key creation cut was not exercised")
	}
	h.readErr = nil
	if _, err := issueTest(t, w, h, r); err != nil {
		t.Fatal(err)
	}
	if len(keys.names) != 2 || keys.names[0] != keys.names[1] || keys.names[0] == r.KeyName || !strings.HasPrefix(keys.names[0], "mtv2-") {
		t.Fatal("key creation was not resumed using its journalled internal ID")
	}
}
