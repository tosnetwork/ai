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
	"os/exec"
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
	l := DefaultV2Limits(1024, 64<<20)
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
		t.Fatal("stranger tombstones freed the source address budget")
	}
	if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(2), now, nil); got != depositCreated {
		t.Fatal("global share masked the per-address tombstone test")
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
	raw[len(raw)-3] ^= 1
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

func TestV2AddressAndByteShares(t *testing.T) {
	now := uint64(testStart.Unix())
	r := newRecipient(t)
	t.Run("per-mailbox-address", func(t *testing.T) {
		s := newV2Store(DefaultV2Limits(1024, 64<<20))
		for i := range 9 {
			want := depositCreated
			if i == 8 {
				want = depositQuota
			}
			if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(1), now, nil); got != want {
				t.Fatal("address/mailbox cap", i, got)
			}
		}
	})
	t.Run("relay-address", func(t *testing.T) {
		s := newV2Store(DefaultV2Limits(4096, 64<<20))
		for i := range 65 {
			peer := newRecipient(t)
			want := depositCreated
			if i == 64 {
				want = depositQuota
			}
			if got := v2Deposit(t, s, peer, peer.seal(t, testPacket(1), now+3600), v2Loopback(1), now, nil); got != want {
				t.Fatal("relay address cap", i, got)
			}
		}
	})
	t.Run("ipv6-sites", func(t *testing.T) {
		s := newV2Store(DefaultV2Limits(4096, 64<<20))
		for i := range 257 {
			peer := newRecipient(t)
			var addr [16]byte
			addr[0] = 0xfd
			addr[1] = 1
			addr[6] = byte(i >> 8)
			addr[7] = byte(i)
			addr[15] = 1
			want := depositCreated
			if i == 256 {
				want = depositQuota
			}
			if got := v2Deposit(t, s, peer, peer.seal(t, testPacket(1), now+3600), netip.AddrFrom16(addr), now, nil); got != want {
				t.Fatal("IPv6 /48 cap", i, got)
			}
		}
	})
	t.Run("byte-reservation", func(t *testing.T) {
		e := r.seal(t, testPacket(100000), now+3600)
		size := int64(len(e.envelope))
		l := DefaultV2Limits(1024, size*4)
		s := newV2Store(l)
		if got := v2Deposit(t, s, r, e, v2Loopback(1), now, nil); got != depositCreated {
			t.Fatal(got)
		}
		if got := v2Deposit(t, s, r, r.seal(t, testPacket(100000), now+3600), v2Loopback(2), now, nil); got != depositQuota {
			t.Fatal("stranger byte share borrowed contact reserve")
		}
		wire, holder := v2Credential(t, r)
		checked := v2Checked(t, wire, holder, r.agentID, now, 1)
		if got := v2Deposit(t, s, r, r.seal(t, testPacket(100000), now+3600), v2Loopback(2), now, &checked); got != depositCreated {
			t.Fatal("no contact byte reserve")
		}
	})
}
func TestV2ReplayIssuerBoundAndNoLiveEviction(t *testing.T) {
	r := newRecipient(t)
	wire, holder := v2Credential(t, r)
	now := uint64(testStart.Unix())
	path := filepath.Join(v2Temp(t), "v2")
	s, err := OpenV2Store(path, DefaultV2Limits(1024, 64<<20), testStart, V2OpenOptions{Replay: agenttransport.ReplayConfig{Entries: 66}})
	if err != nil {
		t.Fatal(err)
	}
	defer v2Close(t, s)
	var first agenttransport.CheckedRequest
	for i := range 65 {
		next := v2TestKey(fmt.Sprint("replay-holder-", i))
		child, err := agenttransport.AppendCredentialBlock(wire, holder, next.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.MaxEnvelopeBytesCaveat(2000 + uint32(i))})
		if err != nil {
			t.Fatal(err)
		}
		checked := v2Checked(t, child, next, r.agentID, now, byte(i))
		if i == 0 {
			first = checked
		}
		err = s.replay.Claim(checked, now)
		if i < 64 && err != nil {
			t.Fatal(err)
		}
		if i == 64 && !errors.Is(err, agenttransport.ErrReplayCredentialFull) {
			t.Fatal("appending escaped issuer bound", err)
		}
	}
	other, otherHolder := v2Credential(t, newRecipient(t))
	for i := range 3 {
		checked := v2Checked(t, other, otherHolder, func() string {
			c, e := agenttransport.DecodeCredential(other)
			if e != nil {
				t.Fatal(e)
			}
			d, e := c.Delegation()
			if e != nil {
				t.Fatal(e)
			}
			return d.AgentID()
		}(), now, byte(i))
		err = s.replay.Claim(checked, now)
		if i < 2 && err != nil {
			t.Fatal(err)
		}
		if i == 2 && !errors.Is(err, agenttransport.ErrReplayTableFull) {
			t.Fatal("global full not refused", err)
		}
	}
	if err = s.replay.Claim(first, now); !errors.Is(err, agenttransport.ErrCredentialInvalid) {
		t.Fatal("full table evicted live nonce", err)
	}
}
func TestV2ExplicitReplayRecovery(t *testing.T) {
	l := DefaultV2Limits(1024, 64<<20)
	now := uint64(testStart.Unix())
	for _, name := range []string{"no-audit", "too-low", "valid", "valid-old-mark"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(v2Temp(t), "v2")
			s := v2Open(t, path, l, testStart)
			v2Close(t, s)
			floor := now + 140
			start := testStart
			if name == "valid-old-mark" {
				start = testStart.Add(-100 * time.Second)
				floor = now + 40
			} else if err := os.WriteFile(filepath.Join(path, "REPLAY"), []byte("damaged"), 0o600); err != nil {
				t.Fatal(err)
			}
			options := V2OpenOptions{RecoveryFloor: &floor}
			var audited uint64
			if name != "no-audit" {
				options.RecoveryAudit = func(mark uint64) error { audited = mark; return nil }
			}
			if name == "too-low" {
				floor--
			}
			recovered, err := OpenV2Store(path, l, start, options)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				defer v2Close(t, recovered)
				f, _, _ := recovered.replay.State()
				if f != floor || audited != floor {
					t.Fatal("recovery not restored/audited")
				}
			} else if err == nil {
				v2Close(t, recovered)
				t.Fatal("unsafe recovery accepted")
			}
		})
	}
}
func TestV2CrashWorker(t *testing.T) {
	root := os.Getenv("RELAY_V2_CRASH_ROOT")
	if root == "" {
		return
	}
	s := v2Open(t, root, DefaultV2Limits(1024, 64<<20), testStart)
	hook := func(name string) error {
		if name == "REPLAY" {
			os.Exit(23)
		}
		return nil
	}
	if os.Getenv("RELAY_V2_CRASH_POINT") == "before-rename" {
		s.disk.beforeRename = hook
	} else {
		s.disk.beforeSync = hook
	}
	if err := s.replay.Record(uint64(testStart.Unix()) + 100); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash cut was not reached")
}
func TestV2CrashRecordCutsKeepReplaysRefused(t *testing.T) {
	for _, point := range []string{"before-rename", "after-rename"} {
		t.Run(point, func(t *testing.T) {
			path := filepath.Join(v2Temp(t), "v2")
			l := DefaultV2Limits(1024, 64<<20)
			s := v2Open(t, path, l, testStart)
			r := newRecipient(t)
			wire, holder := v2Credential(t, r)
			checked := v2Checked(t, wire, holder, r.agentID, uint64(testStart.Unix())+100, 1)
			if err := s.replay.Claim(checked, uint64(testStart.Unix())); err != nil {
				t.Fatal(err)
			}
			v2Close(t, s)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestV2CrashWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), "RELAY_V2_CRASH_ROOT="+path, "RELAY_V2_CRASH_POINT="+point)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatal("child did not reach exact cut", err)
			}
			s = v2Open(t, path, l, testStart)
			defer v2Close(t, s)
			if err = s.replay.Claim(checked, uint64(testStart.Unix())); !errors.Is(err, agenttransport.ErrProofFloor) {
				t.Fatal("crash resurrected replay", err)
			}
		})
	}
}
func TestV2RequestLockWaitIsCancellable(t *testing.T) {
	s := newV2Store(DefaultV2Limits(1024, 64<<20))
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.list(ctx, agentDigest{}, uint64(testStart.Unix())); !errors.Is(err, context.Canceled) {
		t.Fatal("store lock ignored request cancellation", err)
	}
}

func TestV2LimitsAndLargestEnvelope(t *testing.T) {
	l := DefaultV2Limits(4096, 64<<20)
	for _, bad := range []V2Limits{
		{l.Base, 65, l.StrangerMaxBytes, 25}, {l.Base, 32, (4 << 20) + 1, 25}, {l.Base, 32, l.StrangerMaxBytes, 26}, {l.Base, -1, l.StrangerMaxBytes, 25}, {l.Base, 32, -1, 25},
	} {
		if bad.Validate() == nil {
			t.Fatal("unbounded limits accepted")
		}
	}
	if l.Validate() != nil {
		t.Fatal("valid limits refused")
	}
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	wire, holder := v2Credential(t, r)
	checked := v2Checked(t, wire, holder, r.agentID, now, 1)
	s := newV2Store(l)
	e := r.seal(t, testPacket(agentpacketseal.MaxPacketJSONBytes-len(testPacket(0))), now+3600)
	if v2Deposit(t, s, r, e, v2Loopback(1), now, &checked) != depositCreated {
		t.Fatal("large envelope refused")
	}
	agent, _ := parseAgentText(r.agentID)
	body, err := s.get(t.Context(), agent, e.id, now)
	if err != nil || !bytes.Equal(body, e.envelope) {
		t.Fatal("large roundtrip failed", err)
	}
}
func TestV2CheckedRecordShapeAndStorePermissions(t *testing.T) {
	for _, name := range []string{"format", "unknown-root", "extra-record", "public-root", "link-root"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(v2Temp(t), "v2")
			l := DefaultV2Limits(1024, 64<<20)
			s := v2Open(t, path, l, testStart)
			v2Close(t, s)
			switch name {
			case "format":
				if err := os.WriteFile(filepath.Join(path, "FORMAT"), []byte("wrong"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown-root":
				if err := os.WriteFile(filepath.Join(path, "unknown"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "extra-record":
				if err := os.WriteFile(filepath.Join(path, "records", "unknown"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "public-root":
				if err := os.Chmod(path, 0o755); err != nil {
					t.Fatal(err)
				}
			case "link-root":
				alias := filepath.Join(v2Temp(t), "alias")
				if err := os.Symlink(path, alias); err != nil {
					t.Fatal(err)
				}
				path = alias
			}
			if _, err := OpenV2Store(path, l, testStart, V2OpenOptions{}); err == nil {
				t.Fatal("invalid storage accepted")
			}
		})
	}
}
func TestV2RecordsExpireAndFreeBothShares(t *testing.T) {
	s := newV2Store(DefaultV2Limits(16, 4<<20))
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	agent, _ := parseAgentText(r.agentID)
	for i := range 4 {
		e := r.seal(t, testPacket(1), now+3600)
		if v2Deposit(t, s, r, e, v2Loopback(i+1), now, nil) != depositCreated {
			t.Fatal("share refused below cap")
		}
		if _, err := s.ack(t.Context(), agent, e.id, now); err != nil {
			t.Fatal(err)
		}
	}
	if s.Usage().StrangerEntries != 4 {
		t.Fatal("tombstones not held")
	}
	if err := s.Sweep(testStart.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := s.Usage(); got.StrangerEntries != 0 || got.StrangerBytes != 0 || len(s.strangers) != 0 || len(s.sites) != 0 {
		t.Fatal("expiry did not free quota", got)
	}
}

func TestV2HolderCannotReplaceDefaultLane(t *testing.T) {
	r := newRecipient(t)
	wire, holder := v2Credential(t, r)
	next := v2TestKey("lane-switch")
	child, err := agenttransport.AppendCredentialBlock(wire, holder, next.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.LaneCaveat([16]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	checked := v2Checked(t, child, next, r.agentID, uint64(testStart.Unix()), 1)
	if _, err = checkedV2Lane(checked); !errors.Is(err, agenttransport.ErrCredentialScope) {
		t.Fatal("holder moved a default lane", err)
	}
	explicit, holder := v2Credential(t, r, agenttransport.LaneCaveat([16]byte{1}))
	child, err = agenttransport.AppendCredentialBlock(explicit, holder, next.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.LaneCaveat([16]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	checked = v2Checked(t, child, next, r.agentID, uint64(testStart.Unix()), 2)
	if lane, err := checkedV2Lane(checked); err != nil || lane.Tag != v2ExplicitLane {
		t.Fatal("repeated issued lane refused", err)
	}
}

func TestV2DroppedProofStaysRefusedAfterBackwardClock(t *testing.T) {
	path := filepath.Join(v2Temp(t), "v2")
	s := v2Open(t, path, DefaultV2Limits(1024, 64<<20), testStart)
	defer v2Close(t, s)
	r := newRecipient(t)
	wire, holder := v2Credential(t, r)
	now := uint64(testStart.Unix())
	old := v2Checked(t, wire, holder, r.agentID, now, 1)
	if err := s.replay.Claim(old, now); err != nil {
		t.Fatal(err)
	}
	later := v2Checked(t, wire, holder, r.agentID, now+121, 2)
	if err := s.replay.Claim(later, now+121); err != nil {
		t.Fatal(err)
	}
	if err := s.replay.Record(now - 100); err != nil {
		t.Fatal(err)
	}
	if err := s.replay.Claim(old, now); !errors.Is(err, agenttransport.ErrProofFloor) {
		t.Fatal("backward clock revived dropped proof", err)
	}
}
func TestV2ClosedMailboxAndContactEnvelopeScope(t *testing.T) {
	s := newV2Store(DefaultV2Limits(1024, 64<<20))
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	e := r.seal(t, testPacket(1), now+3600)
	header, err := agentpacketseal.ParseEnvelope(e.envelope)
	if err != nil {
		t.Fatal(err)
	}
	input := depositInput{header, e.envelope, v2Loopback(1), now, now + 3600}
	if status, err := s.deposit(t.Context(), input, nil, v2Usage{}); err != nil || status != depositQuota {
		t.Fatal("closed stranger lane accepted", status, err)
	}
	wire, holder := v2Credential(t, r, agenttransport.MaxEnvelopeBytesCaveat(1))
	checked := v2Checked(t, wire, holder, r.agentID, now, 1)
	if _, err := s.deposit(t.Context(), input, &checked, v2Usage{}); !errors.Is(err, agenttransport.ErrCredentialScope) {
		t.Fatal("envelope size caveat not scoped", err)
	}
	wire, holder = v2Credential(t, r)
	checked = v2Checked(t, wire, holder, r.agentID, now, 2)
	if status, err := s.deposit(t.Context(), input, &checked, v2Usage{}); err != nil || status != depositCreated {
		t.Fatal("closed stranger policy blocked contact", status, err)
	}
}
func FuzzV2RecordDecoder(f *testing.F) {
	r := newRecipient(f)
	now := uint64(testStart.Unix())
	e := r.seal(f, testPacket(1), now+3600)
	header, err := agentpacketseal.ParseEnvelope(e.envelope)
	if err != nil {
		f.Fatal(err)
	}
	rec := v2Record{Version: "tos.service.relay-envelope.v2", Agent: r.agentID, ID: e.id, KeyID: header.RecipientKeyID, Received: now, Expires: now + 3600, Client: v2Loopback(1), Size: int64(len(e.envelope)), Sum: sha256.Sum256(e.envelope), Body: e.envelope}
	raw, err := encodeV2(rec)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(v2Format))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxV2RecordBytes {
			return
		}
		var decoded v2Record
		if decodeV2(data, &decoded) != nil || decoded.validate() != nil {
			return
		}
		encoded, err := encodeV2(decoded)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatal("accepted record did not preserve exact bytes", err)
		}
	})
}

func TestV2ContactMailboxCountAndBytes(t *testing.T) {
	now := uint64(testStart.Unix())
	r := newRecipient(t)
	t.Run("count", func(t *testing.T) {
		s := newV2Store(DefaultV2Limits(4096, 256<<20))
		for lane := range 5 {
			wire, holder := v2Credential(t, r, agenttransport.LaneCaveat([16]byte{byte(lane + 1)}))
			checked := v2Checked(t, wire, holder, r.agentID, now, byte(lane))
			n := 64
			if lane == 4 {
				n = 1
			}
			for range n {
				got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), v2Loopback(lane+1), now, &checked)
				want := depositCreated
				if lane == 4 {
					want = depositQuota
				}
				if got != want {
					t.Fatal("mailbox count cap", lane, got)
				}
			}
		}
		agent, _ := parseAgentText(r.agentID)
		entries, err := s.list(t.Context(), agent, now)
		if err != nil || len(entries) != 256 {
			t.Fatal("full listing lost entries", len(entries), err)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		s := newV2Store(DefaultV2Limits(4096, 256<<20))
		for lane := range 2 {
			wire, holder := v2Credential(t, r, agenttransport.LaneCaveat([16]byte{byte(lane + 1)}))
			checked := v2Checked(t, wire, holder, r.agentID, now, byte(lane))
			n := 64
			if lane == 1 {
				n = 1
			}
			for range n {
				e := r.seal(t, testPacket(agentpacketseal.MaxPacketJSONBytes-len(testPacket(0))), now+3600)
				if len(e.envelope) != MaxEnvelopeBytes {
					t.Fatal("bound fixture is not maximal", len(e.envelope))
				}
				got := v2Deposit(t, s, r, e, v2Loopback(lane+1), now, &checked)
				want := depositCreated
				if lane == 1 {
					want = depositQuota
				}
				if got != want {
					t.Fatal("mailbox byte cap", lane, got)
				}
			}
		}
	})
}
func TestV2IPv6AddressesShareTheir64(t *testing.T) {
	s := newV2Store(DefaultV2Limits(4096, 64<<20))
	now := uint64(testStart.Unix())
	for i := range 65 {
		r := newRecipient(t)
		var bytes [16]byte
		bytes[0] = 0xfd
		bytes[1] = 1
		bytes[15] = byte(i + 1)
		want := depositCreated
		if i == 64 {
			want = depositQuota
		}
		if got := v2Deposit(t, s, r, r.seal(t, testPacket(1), now+3600), netip.AddrFrom16(bytes), now, nil); got != want {
			t.Fatal("IPv6 addresses escaped /64", i, got)
		}
	}
}

func TestV2UsedStoreNeverRecreatesMissingDataDirectory(t *testing.T) {
	for _, name := range []string{"records", "controls", "tmp"} {
		t.Run(name, func(t *testing.T) {
			root := v2Temp(t)
			path := filepath.Join(root, "v2")
			l := DefaultV2Limits(1024, 64<<20)
			s := v2Open(t, path, l, testStart)
			v2Close(t, s)
			if err := os.Rename(filepath.Join(path, name), filepath.Join(root, "saved-"+name)); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenV2Store(path, l, testStart, V2OpenOptions{}); err == nil {
				t.Fatal("missing used directory was silently initialized")
			}
		})
	}
}
func TestV2InvalidReplayConfigDoesNotCreateState(t *testing.T) {
	path := filepath.Join(v2Temp(t), "v2")
	if _, err := OpenV2Store(path, DefaultV2Limits(1024, 64<<20), testStart, V2OpenOptions{Replay: agenttransport.ReplayConfig{Entries: -1}}); err == nil {
		t.Fatal("invalid replay bounds accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid configuration touched storage")
	}
}

func TestV2FailedWritesDoNotAccumulateTemporaryFiles(t *testing.T) {
	s := v2Open(t, filepath.Join(v2Temp(t), "v2"), DefaultV2Limits(1024, 64<<20), testStart)
	defer v2Close(t, s)
	s.disk.beforeRename = func(string) error { return errors.New("injected pre-rename refusal") }
	for range 100 {
		if err := s.Replay().Record(uint64(testStart.Unix())); err == nil {
			t.Fatal("write refusal ignored")
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.disk.root, "tmp"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed writes leaked temporary files: %d, %v", len(entries), err)
	}
}

func TestV2RecoveryAuditMustSucceedBeforeOpen(t *testing.T) {
	path := filepath.Join(v2Temp(t), "v2")
	limits := DefaultV2Limits(1024, 64<<20)
	s := v2Open(t, path, limits, testStart)
	v2Close(t, s)
	floor := uint64(testStart.Unix()) + 200
	opened, err := OpenV2Store(path, limits, testStart, V2OpenOptions{
		RecoveryFloor: &floor,
		RecoveryAudit: func(uint64) error { return errors.New("audit sink unavailable") },
	})
	if err == nil {
		v2Close(t, opened)
		t.Fatal("recovery served without its audit")
	}
	// A failed audit may already have persisted a higher mark; a normal restart
	// must preserve it, rather than rolling back to the last successfully logged one.
	s = v2Open(t, path, limits, testStart)
	defer v2Close(t, s)
	restored, _, _ := s.Replay().State()
	if restored != floor {
		t.Fatalf("audit failure lost the durable floor: %d", restored)
	}
}

// Persisted metadata is validated independently of its checksum: a well-formed
// checksum cannot make a malformed envelope or accounting record trustworthy.
func TestV2RecordMetadataRefusals(t *testing.T) {
	r := newRecipient(t)
	now := uint64(testStart.Unix())
	e := r.seal(t, testPacket(1), now+3600)
	header, err := agentpacketseal.ParseEnvelope(e.envelope)
	if err != nil {
		t.Fatal(err)
	}
	valid := v2Record{Version: "tos.service.relay-envelope.v2", Agent: r.agentID, ID: e.id, KeyID: header.RecipientKeyID, Received: now, Expires: now + 3600, Client: v2Loopback(1), Size: int64(len(e.envelope)), Sum: sha256.Sum256(e.envelope), Body: e.envelope}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*v2Record){
		"version":       func(r *v2Record) { r.Version = "unknown" },
		"agent":         func(r *v2Record) { r.Agent = "invalid" },
		"zero-id":       func(r *v2Record) { r.ID = [32]byte{} },
		"client":        func(r *v2Record) { r.Client = netip.Addr{} },
		"client-64":     func(r *v2Record) { r.Client = netip.MustParseAddr("2001:db8::1") },
		"stranger-lane": func(r *v2Record) { r.Lane.Tag = v2DefaultLane },
		"lane-tag":      func(r *v2Record) { r.Contact = true; r.Lane.Tag = 3 },
		"received-zero": func(r *v2Record) { r.Received = 0 },
		"expires":       func(r *v2Record) { r.Expires = r.Received },
		"retention":     func(r *v2Record) { r.Received = r.Expires - 86401 },
		"size":          func(r *v2Record) { r.Size++ },
		"checksum":      func(r *v2Record) { r.Sum[0] ^= 1 },
		"envelope-id":   func(r *v2Record) { r.ID[0] ^= 1 },
		"key-id":        func(r *v2Record) { r.KeyID[0] ^= 1 },
		"header-expiry": func(r *v2Record) { r.Expires++ },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			rec := valid
			change(&rec)
			raw, err := encodeV2(rec)
			if err != nil {
				t.Fatal(err)
			}
			var decoded v2Record
			if err = decodeV2(raw, &decoded); err != nil {
				t.Fatal("checksum fixture failed before metadata validation", err)
			}
			if err = decoded.validate(); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}
