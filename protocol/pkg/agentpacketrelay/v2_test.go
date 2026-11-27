package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const v2TestURL = "https://127.0.0.1"

func v2TestKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("relay-v2-test:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func v2Credential(t testing.TB, r recipient, extra ...agenttransport.Caveat) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	signer := v2TestKey("transport")
	holder := v2TestKey("holder")
	digest, err := agentpacketseal.AgentDigest(r.agentID)
	if err != nil {
		t.Fatal(err)
	}
	d := agenttransport.Delegation{AgentDigest: digest, Purposes: 7, NotBefore: uint64(testStart.Unix()) - 1, NotAfter: uint64(testStart.Unix()) + 86400, MaxCredentialSeconds: 604800}
	copy(d.TransportKey[:], signer.Public().(ed25519.PublicKey))
	wire, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	caveats := []agenttransport.Caveat{agenttransport.NotBeforeCaveat(uint64(testStart.Unix()) - 1), agenttransport.NotAfterCaveat(uint64(testStart.Unix()) + 3600), agenttransport.OperationsCaveat(agenttransport.OperationDeposit | agenttransport.OperationList | agenttransport.OperationFetch | agenttransport.OperationPublish), agenttransport.RelayCaveat(v2TestURL)}
	caveats = append(caveats, extra...)
	credential, err := agenttransport.IssueCredential(wire, signer, holder.Public().(ed25519.PublicKey), caveats)
	if err != nil {
		t.Fatal(err)
	}
	return credential, holder
}
func v2Checked(t testing.TB, wire []byte, holder ed25519.PrivateKey, agent string, now uint64, nonce byte) agenttransport.CheckedRequest {
	t.Helper()
	c, err := agenttransport.DecodeCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	request := agenttransport.ProofRequest{RelayURL: v2TestURL, Method: "GET", Path: "/v2/mailboxes/" + agent + "/envelopes"}
	proof, err := agenttransport.SignRequest(c, holder, request, now, [32]byte{nonce})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := agenttransport.CheckRequest(agenttransport.Request{AgentID: agent, Operation: agenttransport.OperationList, Proof: request, CredentialValue: agenttransport.EncodeCredentialHeader(wire), ProofValue: proof.Header(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return checked
}
func v2Deposit(t testing.TB, s *V2Store, r recipient, e sealed, client netip.Addr, now uint64, c *agenttransport.CheckedRequest) depositStatus {
	t.Helper()
	header, err := agentpacketseal.ParseEnvelope(e.envelope)
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.deposit(context.Background(), depositInput{header: header, envelope: e.envelope, client: client, now: now, expires: now + 3600}, c, v2Usage{s.limits.StrangerMaxEnvelopes, s.limits.StrangerMaxBytes})
	if err != nil {
		t.Fatal(err)
	}
	return status
}
func v2Loopback(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{127, byte(n >> 16), byte(n >> 8), byte(n)})
}
func v2Open(t testing.TB, path string, l V2Limits, now time.Time) *V2Store {
	t.Helper()
	s, err := OpenV2Store(path, l, now, V2OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func v2Close(t testing.TB, s *V2Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestV2SeparateFormatsAndExclusiveStore(t *testing.T) {
	l := DefaultV2Limits(1024, 64<<20)
	path := filepath.Join(v2Temp(t), "v2")
	s := v2Open(t, path, l, testStart)
	if _, err := OpenV2Store(path, l, testStart, V2OpenOptions{}); err == nil {
		t.Fatal("second writer opened")
	}
	v2Close(t, s)
	if _, err := OpenDiskStore(path, l.Base, testStart); err == nil {
		t.Fatal("V1 opened V2 data")
	}
	old := filepath.Join(v2Temp(t), "v1")
	v1, err := OpenDiskStore(old, l.Base, testStart)
	if err != nil {
		t.Fatal(err)
	}
	if err = v1.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenV2Store(old, l, testStart, V2OpenOptions{}); err == nil {
		t.Fatal("V2 opened V1 data")
	}
}
func TestV2TombstoneChargesSurviveRestart(t *testing.T) {
	l := DefaultV2Limits(256, 64<<20)
	l.StrangerMaxEnvelopes = 64
	path := filepath.Join(v2Temp(t), "v2")
	s := v2Open(t, path, l, testStart)
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	agent, _ := parseAgentText(r.agentID)
	for i := range 64 {
		e := r.seal(t, testPacket(10), now+3600)
		if status := v2Deposit(t, s, r, e, v2Loopback(1), now, nil); status != depositCreated {
			t.Fatalf("cycle %d: %v", i, status)
		}
		if status, err := s.ack(t.Context(), agent, e.id, now); err != nil || status != ackDeleted {
			t.Fatal(status, err)
		}
	}
	u := s.Usage()
	if u.StrangerEntries != 64 || u.StrangerBytes != 0 || u.Mailboxes != 0 {
		t.Fatalf("tombstone charge lost: %+v", u)
	}
	v2Close(t, s)
	s = v2Open(t, path, l, testStart)
	defer v2Close(t, s)
	if s.Usage() != u {
		t.Fatal("restart lost charge")
	}
	if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(1), now, nil); got != depositQuota {
		t.Fatal("stranger tombstones freed share")
	}
	wire, holder := v2Credential(t, r)
	checked := v2Checked(t, wire, holder, r.agentID, now, 1)
	if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(2), now, &checked); got != depositCreated {
		t.Fatal("contact reservation lost")
	}
}
func TestV2StrangerMailboxAndRelayReservation(t *testing.T) {
	l := DefaultV2Limits(1024, 64<<20)
	s := newV2Store(l)
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	for i := range 64 {
		want := depositCreated
		if i >= 32 {
			want = depositQuota
		}
		got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(i+1), now, nil)
		if got != want {
			t.Fatalf("mailbox flood %d: %v", i, got)
		}
	}
	wire, holder := v2Credential(t, r)
	checked := v2Checked(t, wire, holder, r.agentID, now, 1)
	if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(100), now, &checked); got != depositCreated {
		t.Fatal("stranger flood blocked contact")
	}
	// Opaque ciphertext is enough for an attacker: the relay never decrypts it.
	template := r.seal(t, testPacket(1), now+3600)
	accepted := 0
	for i := range 10000 {
		body := bytes.Clone(template.envelope)
		digest := sha256.Sum256([]byte(fmt.Sprint("v2-flood-", i)))
		// Locate the clear Agent field by its authenticated-header value, rather
		// than silently assuming an offset independent of the envelope codec.
		original, _ := agentpacketseal.AgentDigest(r.agentID)
		offset := bytes.Index(body, original[:])
		if offset < 0 {
			t.Fatal("missing Agent field")
		}
		copy(body[offset:offset+32], digest[:])
		header, err := agentpacketseal.ParseEnvelope(body)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.deposit(t.Context(), depositInput{header, body, v2Loopback(1000 + i), now, now + 3600}, nil, v2Usage{32, 2 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if got == depositCreated {
			accepted++
		} else if got != depositQuota {
			t.Fatal(got)
		}
	}
	if accepted != 256-32 {
		t.Fatalf("global share: added %d", accepted)
	}
	if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(100), now, &checked); got != depositCreated {
		t.Fatal("global stranger flood blocked contact")
	}
}
func TestV2TaggedLaneAndVerifiedIdentity(t *testing.T) {
	var explicit, issuer [32]byte
	explicit[0] = 1
	issuer = explicit
	if (v2LaneKey{v2ExplicitLane, explicit}) == (v2LaneKey{v2DefaultLane, issuer}) {
		t.Fatal("explicit/default namespaces collide")
	}
	r := newRecipient(t)
	wire, holder := v2Credential(t, r)
	now := uint64(testStart.Unix())
	checked := v2Checked(t, wire, holder, r.agentID, now, 1)
	lane, err := checkedV2Lane(checked)
	if err != nil || lane.Tag != v2DefaultLane {
		t.Fatal(lane, err)
	}
	c, err := agenttransport.DecodeCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.IssuerChain()
	if err != nil || lane.Value != id {
		t.Fatal("default lane is not issuer chain", err)
	}
	bad := bytes.Clone(wire)
	bad[len(bad)-1] ^= 1
	c, err = agenttransport.DecodeCredential(bad)
	if err != nil {
		t.Fatal(err)
	}
	forged := agenttransport.CheckedRequest{Credential: c, Proof: checked.Proof}
	if _, err = checkedV2Lane(forged); err == nil {
		t.Fatal("unverified chain selected a lane")
	}
	if _, err = checkedReplayIdentity(forged); err == nil {
		t.Fatal("unverified chain selected replay identity")
	}
}
func TestV2AppendedCredentialsShareDefaultLane(t *testing.T) {
	s := newV2Store(DefaultV2Limits(2048, 128<<20))
	r := newRecipient(t)
	wire, holder := v2Credential(t, r)
	now := uint64(testStart.Unix())
	ids := map[[32]byte]bool{}
	for i := range 70 {
		next := v2TestKey(fmt.Sprint("narrow-", i))
		child, err := agenttransport.AppendCredentialBlock(wire, holder, next.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.MaxEnvelopeBytesCaveat(2000 + uint32(i))})
		if err != nil {
			t.Fatal(err)
		}
		checked := v2Checked(t, child, next, r.agentID, now, byte(i))
		identity, err := checked.ReplayIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ids[identity.CredentialID] = true
		got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(i+1), now, &checked)
		want := depositCreated
		if i >= 64 {
			want = depositQuota
		}
		if got != want {
			t.Fatalf("append %d: %v", i, got)
		}
	}
	if len(ids) != 70 || s.Usage().Lanes != 1 {
		t.Fatal("appending opened default lanes")
	}
}
func TestV2ReplayRestartFloorRollbackAndBounds(t *testing.T) {
	l := DefaultV2Limits(1024, 64<<20)
	path := filepath.Join(v2Temp(t), "v2")
	s := v2Open(t, path, l, testStart)
	r := newRecipient(t)
	wire, holder := v2Credential(t, r)
	now := uint64(testStart.Unix())
	checked := v2Checked(t, wire, holder, r.agentID, now+100, 1)
	if err := s.replay.Claim(checked, now); err != nil {
		t.Fatal(err)
	}
	if err := s.replay.Claim(checked, now); !errors.Is(err, agenttransport.ErrCredentialInvalid) {
		t.Fatal("nonce reused", err)
	}
	if err := s.replay.Record(now - 100); err != nil {
		t.Fatal(err)
	}
	_, mark, _ := s.replay.State()
	if mark != now+140 {
		t.Fatal("mark decreased")
	}
	v2Close(t, s)
	s = v2Open(t, path, l, testStart.Add(-100*time.Second))
	defer v2Close(t, s)
	if err := s.replay.Claim(checked, now); !errors.Is(err, agenttransport.ErrProofFloor) {
		t.Fatal("rolled-back restart replay passed", err)
	}
	if s.replay.RetryAfter(now) != 141 || s.replay.RetryAfter(now-120) != 261 {
		t.Fatal("restart delay is not F+1")
	}
	if err := s.replay.Record(now + 141); err != nil {
		t.Fatal(err)
	}
	fresh := v2Checked(t, wire, holder, r.agentID, now+141, 2)
	if err := s.replay.Claim(fresh, now+141); err != nil {
		t.Fatal("fresh F+1 refused", err)
	}
	_, mark, _ = s.replay.State()
	atMark := v2Checked(t, wire, holder, r.agentID, mark, 3)
	if err := s.replay.Claim(atMark, mark); !errors.Is(err, agenttransport.ErrReplayTableFull) {
		t.Fatal("unrecorded horizon admitted", err)
	}
}
func TestV2MissingAndCorruptReplayRefuseUsedStore(t *testing.T) {
	for _, name := range []string{"missing", "corrupt", "truncate", "wrong-version"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(v2Temp(t), "v2")
			l := DefaultV2Limits(1024, 64<<20)
			s := v2Open(t, path, l, testStart)
			v2Close(t, s)
			record := filepath.Join(path, "REPLAY")
			switch name {
			case "missing":
				if err := os.Rename(record, record+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(record+".saved", filepath.Join(t.TempDir(), "saved")); err != nil {
					t.Fatal(err)
				}
			default:
				raw, err := os.ReadFile(record)
				if err != nil {
					t.Fatal(err)
				}
				if name == "truncate" {
					raw = raw[:len(raw)/2]
				} else if name == "wrong-version" {
					raw, err = encodeV2(v2Mark{"other", uint64(testStart.Unix()) + 140})
					if err != nil {
						t.Fatal(err)
					}
				} else {
					raw[len(raw)/2] ^= 1
				}
				if err = os.WriteFile(record, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := OpenV2Store(path, l, testStart, V2OpenOptions{}); err == nil {
				t.Fatal("used store reset missing/corrupt mark")
			}
		})
	}
}
func TestV2UncertainMarkNeverDecreasesAndStoreWritesFailClosed(t *testing.T) {
	path := filepath.Join(v2Temp(t), "v2")
	l := DefaultV2Limits(1024, 64<<20)
	s := v2Open(t, path, l, testStart)
	defer v2Close(t, s)
	now := uint64(testStart.Unix())
	s.disk.beforeSync = func(name string) error {
		if name == "REPLAY" {
			return errors.New("uncertain sync")
		}
		return nil
	}
	if err := s.replay.Record(now + 100); err == nil {
		t.Fatal("failed sync advanced admission")
	}
	_, mark, _ := s.replay.State()
	if mark != now+140 {
		t.Fatal("unconfirmed mark admitted")
	}
	s.disk.beforeSync = nil
	if err := s.replay.Record(now - 100); err != nil {
		t.Fatal(err)
	}
	_, mark, _ = s.replay.State()
	if mark != now+240 {
		t.Fatal("uncertain persisted candidate decreased")
	}
	s.disk.beforeSync = func(string) error { return errors.New("uncertain envelope sync") }
	r := newRecipient(t)
	e := r.seal(t, testPacket(1), now+3600)
	header, err := agentpacketseal.ParseEnvelope(e.envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.deposit(t.Context(), depositInput{header, e.envelope, v2Loopback(1), now, now + 3600}, nil, v2Usage{32, 2 << 20}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("uncertain write not refused", err)
	}
	if _, err = s.list(t.Context(), agentDigest{}, now); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatal("uncertain store remained active", err)
	}
}

// Keep the path identity check independent of JSON field spelling.
func TestV2RecordChecksumsAndNames(t *testing.T) {
	path := filepath.Join(v2Temp(t), "v2")
	l := DefaultV2Limits(1024, 64<<20)
	s := v2Open(t, path, l, testStart)
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	e := r.seal(t, testPacket(1), now+3600)
	if v2Deposit(t, s, r, e, v2Loopback(1), now, nil) != depositCreated {
		t.Fatal("deposit refused")
	}
	v2Close(t, s)
	agent, _ := parseAgentText(r.agentID)
	record := filepath.Join(path, "records", hex.EncodeToString(agent[:])+"-"+hex.EncodeToString(e.id[:]))
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err = os.WriteFile(record, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenV2Store(path, l, testStart, V2OpenOptions{}); err == nil {
		t.Fatal("corrupt envelope loaded")
	}
}

func v2Temp(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
