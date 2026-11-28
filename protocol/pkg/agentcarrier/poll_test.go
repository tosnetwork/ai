package agentcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func inbound(t *testing.T, f *fixture, raw []byte) []byte {
	t.Helper()
	card, err := f.lane.CurrentCard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	secret[0] = 9
	sealed, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{AgentID: f.alice.agent, KeyID: card.Card.KeyID, PublicKey: card.Card.PublicKey}, secret, raw, start+3600)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
func putEnvelope(t *testing.T, r *fakeRelay, raw []byte) {
	t.Helper()
	h, err := agentpacketseal.ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.envelopes[h.EnvelopeID] = bytes.Clone(raw)
}
func TestPollStoresDurablyBeforeAcknowledgingAndDeduplicatesRelays(t *testing.T) {
	f := newFixture(t)
	raw := f.message(f.bob, f.alice)
	sealed := inbound(t, f, raw)
	receipt := filepath.Join(t.TempDir(), "inbox")
	store := f.lane.config.Store
	var storeMu sync.Mutex
	f.lane.config.Store = func(ctx context.Context, raw []byte) error {
		storeMu.Lock()
		defer storeMu.Unlock()
		if existing, err := os.ReadFile(receipt); err == nil {
			if !bytes.Equal(existing, raw) {
				return ErrRefused
			}
			return store(ctx, raw)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		file, err := os.OpenFile(receipt, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(raw)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
		return store(ctx, raw)
	}
	for _, relay := range f.relays {
		relay.beforeAck = func([32]byte) error {
			saved, err := os.ReadFile(receipt)
			if err != nil || !bytes.Equal(saved, raw) {
				return errors.New("ack before durable inbox")
			}
			return nil
		}
		putEnvelope(t, relay, sealed)
	}
	// The same packet is duplicate-safe even if two relays are polled concurrently.
	v, err := f.lane.Poll(t.Context())
	if err != nil || v.Acknowledged != 2 || len(f.inbox) != 1 {
		t.Fatal("durable delivery did not settle both copies", v, err)
	}
	h, err := agentpacketseal.ParseEnvelope(sealed)
	if err != nil {
		t.Fatal(err)
	}
	for _, relay := range f.relays {
		if !relay.acked[h.EnvelopeID] {
			t.Fatal("a relay was not acknowledged")
		}
	}
}
func TestCorruptCopyDoesNotSuppressTheGoodCopyElsewhere(t *testing.T) {
	f := newFixture(t)
	sealed := inbound(t, f, f.message(f.bob, f.alice))
	bad := bytes.Clone(sealed)
	bad[len(bad)-1] ^= 1
	putEnvelope(t, f.relays[relayOne], bad)
	putEnvelope(t, f.relays[relayTwo], sealed)
	held, err := f.lane.keysForPoll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.lane.pollRelay(t.Context(), relayOne, held, 0)
	if err != nil || v.Refused != 1 || len(f.relays[relayOne].acked) != 0 {
		t.Fatal("corrupt copy acknowledged", v, err)
	}
	v, err = f.lane.pollRelay(t.Context(), relayTwo, held, 0)
	if err != nil || v.Stored != 1 || v.Acknowledged != 1 {
		t.Fatal("bad copy suppressed good copy", v, err)
	}
	before := f.relays[relayOne].fetches
	v, err = f.lane.pollRelay(t.Context(), relayOne, held, 0)
	if err != nil || v.Acknowledged != 1 || f.relays[relayOne].fetches != before {
		t.Fatal("settled ID was downloaded again", v, err)
	}
}
func TestTransientVerifyOrStoreFailureNeverAcknowledges(t *testing.T) {
	for _, where := range []string{"verification", "storage"} {
		t.Run(where, func(t *testing.T) {
			f := newFixture(t)
			sealed := inbound(t, f, f.message(f.bob, f.alice))
			putEnvelope(t, f.relays[relayOne], sealed)
			if where == "verification" {
				f.lane.config.VerifyPacket = func(context.Context, agentpacket.Packet) error { return ErrUnavailable }
			} else {
				f.lane.config.Store = func(context.Context, []byte) error { return ErrUnavailable }
			}
			v, err := f.lane.Poll(t.Context())
			if err == nil || v.Acknowledged != 0 || len(f.relays[relayOne].acked) != 0 {
				t.Fatal("transient refusal acknowledged", v, err)
			}
		})
	}
}
func TestPermanentPacketRefusalIsRelayLocal(t *testing.T) {
	f := newFixture(t)
	raw := f.message(f.bob, f.alice)
	sealed := inbound(t, f, raw)
	putEnvelope(t, f.relays[relayOne], sealed)
	putEnvelope(t, f.relays[relayTwo], sealed)
	held, err := f.lane.keysForPoll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	verify := f.lane.config.VerifyPacket
	f.lane.config.VerifyPacket = func(context.Context, agentpacket.Packet) error { return ErrRefused }
	v, err := f.lane.pollRelay(t.Context(), relayOne, held, 0)
	if err != nil || v.Refused != 1 || v.Acknowledged != 1 || len(f.lane.settled) != 0 {
		t.Fatal("permanent refusal settled globally", v, err)
	}
	f.lane.config.VerifyPacket = verify
	v, err = f.lane.pollRelay(t.Context(), relayTwo, held, 0)
	if err != nil || v.Stored != 1 {
		t.Fatal("refusal at one relay suppressed another", v, err)
	}
}
func TestReceiveMemoryIsBounded(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < MaxEnvelopeMemory+1; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprint(i)))
		f.lane.remember(f.lane.refused, fmt.Sprintf("%x", sum), [32]byte{}, start+3600, start)
	}
	if len(f.lane.refused) != MaxEnvelopeMemory {
		t.Fatal("unbounded memory", len(f.lane.refused))
	}
	f.lane.remember(f.lane.refused, "expired", [32]byte{}, start+3601, start+3600)
	if len(f.lane.refused) != 1 {
		t.Fatal("expired entries not reclaimed")
	}
}

func TestPollRechecksOwnerCredentialAfterTheAnswer(t *testing.T) {
	f := newFixture(t)
	raw := inbound(t, f, f.message(f.bob, f.alice))
	putEnvelope(t, f.relays[relayOne], raw)
	f.relays[relayOne].afterList = func() { f.clock.n.Store(int64(start + 3601)) }
	held, err := f.lane.keysForPoll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.pollRelay(t.Context(), relayOne, held, 0); !errors.Is(err, ErrRefused) || f.relays[relayOne].fetches != 0 {
		t.Fatal("expired owner credential reached fetch", err)
	}
}
func TestEnvelopeExpiryIsReadAfterFetchAndBeforeStorage(t *testing.T) {
	for _, stage := range []string{"fetch", "verification"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			raw := inbound(t, f, f.message(f.bob, f.alice))
			putEnvelope(t, f.relays[relayOne], raw)
			if stage == "fetch" {
				f.relays[relayOne].afterFetch = func() { f.clock.n.Store(int64(start + 3601)) }
			} else {
				f.lane.config.VerifyPacket = func(context.Context, agentpacket.Packet) error { f.clock.n.Store(int64(start + 3601)); return nil }
			}
			held, err := f.lane.keysForPoll(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			v, err := f.lane.pollRelay(t.Context(), relayOne, held, 0)
			if err != nil || v.Stored != 0 || len(f.inbox) != 0 || v.Refused != 1 {
				t.Fatal("expired envelope reached storage", v, err)
			}
			wantAck := 1
			if stage == "fetch" {
				wantAck = 0
			}
			if v.Acknowledged != wantAck {
				t.Fatal("expiry was checked at the wrong receive boundary", v)
			}
		})
	}
}
