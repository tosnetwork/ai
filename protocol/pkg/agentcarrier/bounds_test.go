package agentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func TestUsedInventoryRequiresBothCollections(t *testing.T) {
	for _, which := range []string{"keys", "deliveries"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t)
			index, err := f.lane.inventory()
			if err != nil {
				t.Fatal(err)
			}
			if which == "keys" {
				index.Keys = nil
			} else {
				index.Deliveries = nil
			}
			if err = f.lane.disk.write("identity", index); err != nil {
				t.Fatal(err)
			}
			if err = f.lane.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = Open(t.Context(), f.config); err == nil {
				t.Fatal("missing collection was treated as empty")
			}
		})
	}
}
func TestInventoryAdmitsQueueBeforeItReturns(t *testing.T) {
	f := newFixture(t)
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	yes, err := f.lane.indexed(deliveryName("id"))
	if err != nil || !yes {
		t.Fatal("queue returned before inventory admission", yes, err)
	}
}
func TestStateDirectoryMustBePrivate(t *testing.T) {
	f := newFixture(t)
	c := f.config
	c.StateDir = t.TempDir()
	if err := os.Chmod(c.StateDir, 0755); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(t.Context(), c); err == nil {
		if err = l.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("public state directory accepted")
	}
}
func TestStorageRefusesAnInternalSymlink(t *testing.T) {
	f := newFixture(t)
	if err := f.lane.disk.write("target", map[string]string{"value": "present"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(f.config.StateDir, string(Rail), "alias")); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := f.lane.disk.read("target", &out); err != nil {
		t.Fatal("instrument cannot read its regular target", err)
	}
	if err := f.lane.disk.read("alias", &out); err == nil {
		t.Fatal("followed an internal symlink")
	}
}
func TestOwnerCredentialCannotSubstituteAnotherDelegationOfTheSameAgent(t *testing.T) {
	f := newFixture(t)
	d, err := agenttransport.DecodeDelegation(f.alice.wire)
	if err != nil {
		t.Fatal(err)
	}
	other := testKey("other-owner-delegation")
	copy(d.TransportKey[:], other[32:])
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := agenttransport.IssueCredential(raw, other, f.alice.holder.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotBeforeCaveat(start - 1), agenttransport.NotAfterCaveat(start + 3600), agenttransport.OperationsCaveat(agenttransport.OperationList | agenttransport.OperationFetch)})
	if err != nil {
		t.Fatal(err)
	}
	f.auth.owner, err = NewCredential(wire, f.alice.holder)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Poll(t.Context()); err == nil {
		t.Fatal("another delegation was used for owner reads")
	}
	for _, r := range f.relays {
		if r.lists != 0 {
			t.Fatal("owner binding checked after listing")
		}
	}
}
func TestCredentialConstructorRejectsTamperedSignature(t *testing.T) {
	f := newFixture(t)
	raw := bytes.Clone(f.auth.owner.wire)
	raw[len(raw)-1] ^= 1
	if _, err := NewCredential(raw, f.alice.holder); err == nil {
		t.Fatal("unverified credential became a capability")
	}
}
func TestPermanentRelayerRefusalsAndGone(t *testing.T) {
	for _, code := range []int{403, 409, 410, 422} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newFixture(t)
			route := f.peerRoute()
			if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
				t.Fatal(err)
			}
			text := "forbidden"
			if code == 409 {
				text = "conflict"
			}
			if code == 410 {
				text = "gone"
			}
			if code == 422 {
				text = "expiry_out_of_bounds"
			}
			f.relays[relayOne].error = &agentpacketrelay.StatusError{StatusCode: code, Code: text}
			result, err := f.lane.Attempt(t.Context(), "id", route, 0)
			if code == 410 {
				if err != nil || !result.Accepted {
					t.Fatal("gone is not recognized as acceptance", result, err)
				}
				return
			}
			if err == nil || result.Accepted {
				t.Fatal("permanent refusal counted as success")
			}
			if _, err = f.lane.Attempt(t.Context(), "id", route, 0); !errors.Is(err, ErrRefused) || len(f.relays[relayOne].deposits) != 1 {
				t.Fatal("permanent refusal retried", err)
			}
		})
	}
}
func TestAttemptCounterDoesNotWrap(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	f.relays[relayOne].error = ErrUnavailable
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Attempt(t.Context(), "id", route, 0); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	r, err := f.lane.readDelivery(deliveryName("id"))
	if err != nil {
		t.Fatal(err)
	}
	r.Generations[0].Targets[0].Attempts = math.MaxUint32
	if err = f.lane.disk.write(deliveryName("id"), r); err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Attempt(t.Context(), "id", route, 0); !errors.Is(err, ErrCapacity) || len(f.relays[relayOne].deposits) != 1 {
		t.Fatal("attempt counter wrapped", err)
	}
}
func TestEnvelopeExpiryIsBoundedByBusinessDeadlineAndOneDay(t *testing.T) {
	for _, seconds := range []uint64{7200, 2 * 86400} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+seconds); err != nil {
				t.Fatal(err)
			}
			if _, err := f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0); err != nil {
				t.Fatal(err)
			}
			h, err := agentpacketseal.ParseEnvelope(f.relays[relayOne].deposits[0])
			if err != nil || h.ExpiresAtUnix != start+min(seconds, 86400) {
				t.Fatal("envelope exceeded a deadline", h.ExpiresAtUnix, err)
			}
		})
	}
}
func TestForeignRecipientPacketIsRefusedBeforeStore(t *testing.T) {
	f := newFixture(t)
	sealed := inbound(t, f, f.message(f.alice, f.bob))
	putEnvelope(t, f.relays[relayOne], sealed)
	v, err := f.lane.Poll(t.Context())
	if err != nil || v.Refused != 1 || v.Acknowledged != 1 || len(f.inbox) != 0 {
		t.Fatal("foreign recipient reached the inbox", v, err)
	}
}
func TestUnknownKeysAreNeverFetched(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	p, err := agentpacket.DecodeJSON(route.CardPacket)
	if err != nil {
		t.Fatal(err)
	}
	card, err := agentpacketseal.DecodeKeyCard(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	secret[0] = 1
	raw, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{AgentID: f.alice.agent, KeyID: card.KeyID, PublicKey: card.PublicKey}, secret, f.message(f.bob, f.alice), start+3600)
	if err != nil {
		t.Fatal(err)
	}
	putEnvelope(t, f.relays[relayOne], raw)
	if _, err = f.lane.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.relays[relayOne].fetches != 0 || len(f.relays[relayOne].acked) != 0 {
		t.Fatal("unknown key caused a download or ACK")
	}
}
func TestNewSealChoosesNewestCardKnownForTheLane(t *testing.T) {
	f := newFixture(t)
	old, newer := f.peerRoute(), f.peerRoute()
	p, err := agentpacket.DecodeJSON(newer.CardPacket)
	if err != nil {
		t.Fatal(err)
	}
	card, err := agentpacketseal.DecodeKeyCard(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	card.NotBeforeUnix = start
	signed := f.cardPacket(f.bob, card)
	record, err := agenttransport.DecodeHintRecord(old.HintRecord)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agenttransport.HintObjectDigest(agenttransport.RailCard, signed)
	if err != nil {
		t.Fatal(err)
	}
	record.Hint.Objects = []agenttransport.HintObjectRef{{Kind: agenttransport.RailCard, Length: uint32(len(signed)), Digest: digest}}
	record.Objects = []agenttransport.HintObject{{Kind: agenttransport.RailCard, Bytes: signed}}
	record.Hint, err = agenttransport.SignHint(record.Hint, f.bob.transport)
	if err != nil {
		t.Fatal(err)
	}
	old.HintRecord, err = record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Attempt(t.Context(), "id", old, 0); err != nil {
		t.Fatal(err)
	}
	h, err := agentpacketseal.ParseEnvelope(f.relays[relayOne].deposits[0])
	if err != nil || h.RecipientKeyID != card.KeyID {
		t.Fatal("older card selected despite a verified newer lane card", err)
	}
}
func TestQueueRechecksDeadlineAfterVerification(t *testing.T) {
	f := newFixture(t)
	verify := f.lane.config.VerifyPacket
	f.lane.config.VerifyPacket = func(ctx context.Context, p agentpacket.Packet) error { f.clock.n.Add(61); return verify(ctx, p) }
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+60); !errors.Is(err, ErrExpired) {
		t.Fatal("expired queue was persisted", err)
	}
	if _, err := os.Stat(filepath.Join(f.config.StateDir, string(Rail), deliveryName("id"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired packet consumed outbox capacity", err)
	}
}
func TestPruneKeepsIdempotencyUntilEnvelopeRetentionHasEnded(t *testing.T) {
	f := newFixture(t)
	if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+60); err != nil {
		t.Fatal(err)
	}
	f.clock.n.Store(int64(start+60) + int64(KeyRetention/time.Second) - 1)
	if err := f.lane.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Status(t.Context(), "id"); err != nil {
		t.Fatal("delivery forgotten too early", err)
	}
	f.clock.n.Add(1)
	if err := f.lane.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	yes, err := f.lane.indexed(deliveryName("id"))
	if err != nil || yes {
		t.Fatal("expired delivery remains indexed", yes, err)
	}
}

func TestQueuePacketBoundFitsTheFrozenEnvelope(t *testing.T) {
	f := newFixture(t)
	base := f.message(f.alice, f.bob)
	raw := append(bytes.Clone(base), bytes.Repeat([]byte(" "), agentpacketseal.MaxPacketJSONBytes-len(base))...)
	if _, err := f.lane.Queue(t.Context(), "max", raw, start+7200); err != nil {
		t.Fatal("largest sealable packet refused", err)
	}
	if _, err := f.lane.Attempt(t.Context(), "max", f.peerRoute(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.relays[relayOne].deposits[0]) != agentpacketseal.MaxEnvelopeBytes {
		t.Fatal("boundary did not reach the full envelope")
	}
	if _, err := f.lane.Queue(t.Context(), "oversize", append(bytes.Clone(raw), ' '), start+7200); !errors.Is(err, ErrRefused) {
		t.Fatal("unsealable packet consumed a journal slot", err)
	}
}
func TestMaximumRecordBudgetIncludesEveryGeneration(t *testing.T) {
	f := newFixture(t)
	r := delivery{Identity: f.lane.identity(), ID: strings.Repeat("\x00", 128), Packet: make([]byte, agentpacketseal.MaxPacketJSONBytes), Deadline: math.MaxUint64, State: "abandoned", Code: "retention-exceeded", ResolveAfter: math.MaxUint64, ResolveBackoff: 600}
	for i := 0; i < MaxGenerations; i++ {
		g := generation{Number: math.MaxUint32, Created: math.MaxUint64, Envelope: make([]byte, agentpacketseal.MaxEnvelopeBytes), Card: make([]byte, agenttransport.MaxHintCardBytes), Hint: make([]byte, agenttransport.MaxHintRecordSize), Stopped: true}
		for j := range g.Secret {
			g.Secret[j] = 255
		}
		for j := 0; j < MaxTargets; j++ {
			g.Targets = append(g.Targets, target{URL: "https://" + strings.Repeat("a", 248), State: "abandoned", Attempts: math.MaxUint32})
		}
		r.Generations = append(r.Generations, g)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := json.Marshal(checkedRecord{"tos.service.carrier.checked.v2", strings.Repeat("f", 64), raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(checked) > MaxRecordBytes {
		t.Fatal("legal field maxima can exceed the record bound", len(checked), MaxRecordBytes)
	}
	t.Logf("upper-bound record: %d bytes under %d", len(checked), MaxRecordBytes)
}

func TestAValidHintForAnotherAgentIsNotARoute(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	d, err := agenttransport.DecodeDelegation(f.alice.wire)
	if err != nil {
		t.Fatal(err)
	}
	hint, err := agenttransport.SignHint(agenttransport.Hint{Delegation: d, IssuedAt: start, ExpiresAt: start + 3600, Relays: []string{relayOne, relayTwo}}, f.alice.transport)
	if err != nil {
		t.Fatal(err)
	}
	route.HintRecord, err = (agenttransport.HintRecord{Hint: hint, Objects: []agenttransport.HintObject{}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Attempt(t.Context(), "id", route, 0); !errors.Is(err, ErrRefused) || len(f.relays[relayOne].deposits) != 0 {
		t.Fatal("another Agent controlled the recipient route", err)
	}
}

func TestUnusedLaneEvidenceIsNeverUsedAsAuthority(t *testing.T) {
	f := newFixture(t)
	route := f.peerRoute()
	record, err := agenttransport.DecodeHintRecord(route.HintRecord)
	if err != nil {
		t.Fatal(err)
	}
	opaque := []byte("not-consumed-as-identity-by-this-lane")
	digest, err := agenttransport.HintObjectDigest(agenttransport.MessengerEvidence, opaque)
	if err != nil {
		t.Fatal(err)
	}
	record.Hint.Objects = []agenttransport.HintObjectRef{{Kind: agenttransport.MessengerEvidence, Length: uint32(len(opaque)), Digest: digest}}
	record.Objects = []agenttransport.HintObject{{Kind: agenttransport.MessengerEvidence, Bytes: opaque}}
	record.Hint, err = agenttransport.SignHint(record.Hint, f.bob.transport)
	if err != nil {
		t.Fatal(err)
	}
	route.HintRecord, err = record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Attempt(t.Context(), "id", route, 0); err != nil {
		t.Fatal("unconsumed opaque evidence became a dependency", err)
	}
}
