package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// TestPublicIDRace is the section 8.6 attack: an observer of relay A learns
// an envelope ID from A's open listing and deposits junk under it at relay B
// first. The honest deposit at B gets 409 and is abandoned there, A holds
// the genuine copy, the recipient polling B first fails to open B's copy
// and still opens the genuine one from A in the same cycle, and its
// acknowledgement (sent to every relay that listed the ID) removes both.
func TestPublicIDRace(t *testing.T) {
	store, err := NewMemoryStore(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	clock := newClock()
	relayA := newTestRelayWithStore(t, store, clock)
	storeB, err := NewMemoryStore(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	relayB := newTestRelayWithStore(t, storeB, clock)
	alice := newRecipient(t)
	ctx := context.Background()
	genuine := alice.seal(t, testPacket(300), clock.unix()+3600)

	if outcome, err := relayA.client.Deposit(ctx, genuine.envelope); err != nil || outcome.Result != DepositStored {
		t.Fatalf("deposit at A = %+v, %v", outcome, err)
	}
	// The observer lists A and builds junk under the same header.
	listing, err := relayA.client.List(ctx, alice.agentID)
	if err != nil || len(listing.Envelopes) != 1 {
		t.Fatal(err)
	}
	observed := listing.Envelopes[0].EnvelopeID
	junk := append([]byte(nil), genuine.envelope[:agentpacketseal.EnvelopeHeaderSize]...)
	tail := make([]byte, len(genuine.envelope)-agentpacketseal.EnvelopeHeaderSize)
	if _, err := rand.Read(tail); err != nil {
		t.Fatal(err)
	}
	junk = append(junk, tail...)
	if header, err := agentpacketseal.ParseEnvelope(junk); err != nil || header.EnvelopeID != observed {
		t.Fatalf("junk header: %v", err)
	}
	if outcome, err := relayB.client.Deposit(ctx, junk); err != nil || outcome.Result != DepositStored {
		t.Fatalf("junk deposit at B = %+v, %v", outcome, err)
	}

	// The honest sender's deposit at B: 409, never acceptance.
	outcome, err := relayB.client.Deposit(ctx, genuine.envelope)
	if err != nil || outcome.Result != DepositConflict || outcome.Accepted() || outcome.StatusCode != http.StatusConflict ||
		outcome.Code != CodeConflict || outcome.Err == nil {
		t.Fatalf("honest deposit at B = %+v, %v", outcome, err)
	}

	// The recipient polls B first, then A. Failed opens are remembered per
	// (relay, ID), never per ID alone, so B's junk does not suppress A's
	// copy.
	type relayClient struct {
		name   string
		client *Client
	}
	failed := map[string]bool{}
	listedAt := map[[32]byte][]relayClient{}
	var opened *agentpacketseal.Opened
	for _, relay := range []relayClient{{"B", relayB.client}, {"A", relayA.client}} {
		mailbox, err := relay.client.List(ctx, alice.agentID)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range mailbox.Envelopes {
			listedAt[entry.EnvelopeID] = append(listedAt[entry.EnvelopeID], relay)
			key := relay.name + "/" + fmt.Sprintf("%x", entry.EnvelopeID)
			if failed[key] || opened != nil && opened.Header.EnvelopeID == entry.EnvelopeID {
				continue
			}
			raw, err := relay.client.Download(ctx, alice.agentID, entry.EnvelopeID)
			if err != nil {
				t.Fatal(err)
			}
			result, err := agentpacketseal.Open(alice.key, raw)
			if err != nil {
				if relay.name != "B" || !errors.Is(err, agentpacketseal.ErrEnvelopeOpen) {
					t.Fatalf("open at %s: %v", relay.name, err)
				}
				failed[key] = true
				continue
			}
			opened = &result
		}
	}
	if opened == nil || !bytes.Equal(opened.PacketJSON, genuine.packet) || !failed["B/"+fmt.Sprintf("%x", observed)] {
		t.Fatal("the genuine packet was not opened from A in the same poll cycle")
	}
	for _, relay := range listedAt[observed] {
		if err := relay.client.Ack(ctx, alice.agentID, observed, opened.AckSecret); err != nil {
			t.Fatalf("ack at %s: %v", relay.name, err)
		}
	}
	for _, s := range []*Store{store, storeB} {
		if usage := s.Usage(); usage.Envelopes != 0 || usage.Tombstones != 1 {
			t.Fatalf("usage after ack = %+v", usage)
		}
	}
}

// TestConcurrentOperations drives deposits, duplicates, conflicts,
// acknowledgements, listings, downloads and sweeps at once (run under
// -race), then checks that the accounting equals a recount and that no
// quota was exceeded.
func TestConcurrentOperations(t *testing.T) {
	limits := testLimits()
	limits.PerRecipientMaxEnvelopes = 40
	limits.GlobalMaxEntries = 100
	relay := newTestRelay(t, limits)
	recipients := []recipient{newRecipient(t), newRecipient(t), newRecipient(t)}
	ctx := context.Background()

	var envelopes []sealed
	for index := range 150 {
		envelopes = append(envelopes, recipients[index%3].seal(t, testPacket(index), relay.clock.unix()+uint64(60+index)))
	}
	var created, duplicates, conflicts, quota atomic.Int64
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index, env := range envelopes {
				if index%8 != worker && index%3 != 0 {
					continue
				}
				outcome, err := relay.client.Deposit(ctx, env.envelope)
				if err != nil {
					t.Error(err)
					return
				}
				switch outcome.StatusCode {
				case 201:
					created.Add(1)
				case 200:
					duplicates.Add(1)
				case 410:
				case 507:
					quota.Add(1)
				default:
					t.Errorf("deposit status %d", outcome.StatusCode)
				}
				if index%5 == 0 {
					junk := append([]byte(nil), env.envelope...)
					junk[len(junk)-1] ^= 0xff
					if outcome, err := relay.client.Deposit(ctx, junk); err != nil ||
						(outcome.StatusCode != 409 && outcome.StatusCode != 507 && outcome.StatusCode != 201 && outcome.StatusCode != 410) {
						t.Errorf("junk deposit = %+v, %v", outcome, err)
					} else if outcome.StatusCode == 409 {
						conflicts.Add(1)
					}
				}
				if index%4 == 0 {
					err := relay.client.Ack(ctx, recipients[index%3].agentID, env.id, env.secret)
					if err != nil && !errors.Is(err, ErrNotFound) {
						t.Errorf("ack: %v", err)
					}
				}
			}
		}()
	}
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := range 30 {
				for _, r := range recipients {
					mailbox, err := relay.client.List(ctx, r.agentID)
					if err != nil {
						t.Error(err)
						return
					}
					if len(mailbox.Envelopes) > limits.PerRecipientMaxEnvelopes {
						t.Errorf("mailbox holds %d", len(mailbox.Envelopes))
					}
					for _, entry := range mailbox.Envelopes {
						if _, err := relay.client.Download(ctx, r.agentID, entry.EnvelopeID); err != nil && !errors.Is(err, ErrNotFound) {
							t.Errorf("download: %v", err)
						}
					}
				}
				if round%5 == 0 {
					relay.clock.Advance(time.Second)
					if err := relay.store.Sweep(relay.clock.Now()); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()
	if created.Load() == 0 || duplicates.Load() == 0 || conflicts.Load() == 0 || quota.Load() == 0 {
		t.Fatalf("the run did not reach every path: created %d duplicates %d conflicts %d quota %d",
			created.Load(), duplicates.Load(), conflicts.Load(), quota.Load())
	}
	checkAccounting(t, relay.store)
}

// checkAccounting recomputes the store's counters from its maps.
func checkAccounting(t *testing.T, s *Store) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.busy) != 0 {
		t.Fatalf("%d operations still marked in flight", len(s.busy))
	}
	var total int64
	perRecipient := map[agentDigest]int{}
	perClient := map[agentDigest]map[netipAddr]int{}
	for key, rec := range s.envelopes {
		if !rec.committed || rec.key() != key {
			t.Fatal("uncommitted or misfiled record")
		}
		if _, ok := s.tombstones[key]; ok {
			t.Fatal("an ID is both stored and tombstoned")
		}
		total += rec.size
		perRecipient[rec.agent]++
		if perClient[rec.agent] == nil {
			perClient[rec.agent] = map[netipAddr]int{}
		}
		perClient[rec.agent][rec.client]++
	}
	if s.entries != len(s.envelopes)+len(s.tombstones) || s.bytes != total || s.entries > s.limits.GlobalMaxEntries ||
		s.bytes > s.limits.GlobalMaxBytes {
		t.Fatalf("entries %d bytes %d, recount %d/%d", s.entries, s.bytes, len(s.envelopes)+len(s.tombstones), total)
	}
	for agent, usage := range s.recipients {
		if len(usage.ids) != perRecipient[agent] || len(usage.ids) > s.limits.PerRecipientMaxEnvelopes {
			t.Fatalf("recipient count %d, recount %d", len(usage.ids), perRecipient[agent])
		}
		var bytesUsed int64
		for id := range usage.ids {
			bytesUsed += s.envelopes[entryKey{agent: agent, id: id}].size
		}
		if usage.bytes != bytesUsed || usage.bytes > s.limits.PerRecipientMaxBytes {
			t.Fatalf("recipient bytes %d, recount %d", usage.bytes, bytesUsed)
		}
		for client, count := range usage.byClient {
			if perClient[agent][client] != count || count > s.limits.PerClientRecipientMaxEnvelopes {
				t.Fatalf("client count %d, recount %d", count, perClient[agent][client])
			}
		}
	}
	if len(s.recipients) != len(perRecipient) {
		t.Fatal("recipient table holds empty mailboxes or misses one")
	}
}

// TestConcurrentSameID deposits one envelope from many goroutines: exactly
// one 201, every other answer 200.
func TestConcurrentSameID(t *testing.T) {
	relay := newTestRelay(t, testLimits())
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(1000), relay.clock.unix()+600)
	var created, duplicate atomic.Int64
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := relay.client.Deposit(context.Background(), env.envelope)
			if err != nil {
				t.Error(err)
				return
			}
			switch outcome.Result {
			case DepositStored:
				created.Add(1)
			case DepositDuplicate:
				duplicate.Add(1)
			default:
				t.Errorf("outcome %+v", outcome)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 || duplicate.Load() != 31 {
		t.Fatalf("created %d duplicate %d", created.Load(), duplicate.Load())
	}
	checkAccounting(t, relay.store)
}

// TestPersistenceFailure leaves the index unchanged when a write fails, and
// answers 503.
func TestPersistenceFailure(t *testing.T) {
	backend := newMemoryBackend()
	store, err := newStore(testLimits(), backend)
	if err != nil {
		t.Fatal(err)
	}
	relay := newTestRelayWithStore(t, store, newClock())
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	backend.mu.Lock()
	backend.failWrites = true
	backend.mu.Unlock()
	expectStatus(t, relay.putSealed(env), 503)
	if usage := store.Usage(); usage != (Usage{}) {
		t.Fatalf("a failed write left usage %+v", usage)
	}
	backend.mu.Lock()
	backend.failWrites = false
	backend.mu.Unlock()
	expectStatus(t, relay.putSealed(env), 201)
	backend.mu.Lock()
	backend.failWrites = true
	backend.mu.Unlock()
	expectStatus(t, relay.ackRaw(alice.agentID, env.id, env.secret[:]), 503)
	if _, err := relay.client.Download(context.Background(), alice.agentID, env.id); err != nil {
		t.Fatalf("a failed tombstone write deleted the envelope: %v", err)
	}
	checkAccounting(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, relay.putSealed(alice.seal(t, testPacket(8), relay.clock.unix()+600)), 503)
}
