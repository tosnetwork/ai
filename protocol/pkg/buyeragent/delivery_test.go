package buyeragent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

const providerCardSeed = 1

// deliveryFixture is a carrier with a provider card learned and an
// admitted call to deliver.
func deliveryFixture(t *testing.T) (*carrierFixture, TaskDelivery) {
	t.Helper()
	f := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	f.learn(t, providerCardFor(t, fxProvider, providerCardSeed, fxNow.Add(-time.Hour), 7*24*time.Hour))
	id := uint64(7)
	record := f.record
	record.RequestID, record.CallTransactionLT, record.CallTransactionHex = &id, 4242, strings.Repeat("9a", 32)
	record.Actor = "0:" + strings.Repeat("77", 32)
	record.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("3c", 32)
	return f, TaskDelivery{Record: record, Archive: f.archive, ExecutionNonce: strings.Repeat("5e", 32),
		ProviderAgentID: fxProvider, ResponseDeadline: fxNow.Add(time.Hour), RetentionSeconds: 86400, ChainTime: fxNow}
}

// later moves the checkpoint chain time of the next round on; the host
// clock stays, since delivery never reads it.
func later(task *TaskDelivery, d time.Duration) {
	task.ChainTime = task.ChainTime.Add(d)
}

func providerKey(t *testing.T) agentpacketseal.PrivateKey {
	t.Helper()
	key, err := agentpacketseal.NewPrivateKey(fxProvider, bytes.Repeat([]byte{providerCardSeed}, agentpacketseal.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// openDeposits opens every envelope a relay holds with the provider's key
// and returns the packets.
func openDeposits(t *testing.T, f *carrierFixture, relay string) []agentpacket.Packet {
	t.Helper()
	key := providerKey(t)
	f.relays.mu.Lock()
	defer f.relays.mu.Unlock()
	var packets []agentpacket.Packet
	for _, envelope := range f.relays.deposits[relay] {
		opened, err := agentpacketseal.Open(key, envelope)
		if err != nil {
			t.Fatalf("an envelope does not open with the provider's key: %v", err)
		}
		packet, err := agentpacket.DecodeJSON(opened.PacketJSON)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, packet)
	}
	return packets
}

func TestATaskIsSignedSealedAndDepositedFramePerPacket(t *testing.T) {
	f, task := deliveryFixture(t)
	// An archive over one frame's data makes a message of three frames.
	task.Archive = bytes.Repeat([]byte{'s'}, 2*railwork.MaxChunkData)
	view, err := f.carrier.DeliverTask(context.Background(), task)
	if err != nil || !view.Sealed || view.Generation != 1 || view.Envelopes != 3 || view.Delivered != 3 {
		t.Fatalf("delivery %+v %v", view, err)
	}
	packets := openDeposits(t, f, providerRelay)
	if len(packets) != 3 {
		t.Fatalf("%d packets deposited", len(packets))
	}
	var frames []railwork.Frame
	for _, packet := range packets {
		if packet.SenderAgentID != fxBuyerAgent || packet.RecipientAgentID != fxProvider ||
			packet.CapabilityID != fxCapability || packet.QuoteCommitment != task.Record.QuoteCommitment ||
			packet.CreatedAtUnix != uint64(fxNow.Unix()) {
			t.Fatalf("packet fields %+v", packet)
		}
		if err := agentpacket.VerifySender(context.Background(), keycardtest.Keys, f.chain, packet); err != nil {
			t.Fatalf("a task packet is not signed by the buyer's packet controller: %v", err)
		}
		frame, err := railwork.DecodeFrame(packet.Payload)
		if err != nil || frame.Kind != railwork.KindTask || frame.Binding.RequestID != 7 {
			t.Fatalf("frame %+v %v", frame, err)
		}
		frames = append(frames, frame)
	}
	message, err := railwork.JoinFrames(frames)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := railwork.DecodeTask(message)
	if err != nil {
		t.Fatal(err)
	}
	header := decoded.Header
	if header.RequestID != 7 || header.CallLT != 4242 || header.CallHash != task.Record.CallTransactionHex ||
		header.ExecutionNonce != task.ExecutionNonce || header.BuyerAgentID != fxBuyerAgent ||
		!bytes.Equal(decoded.Archive, task.Archive) || len(decoded.BuyerKeyCard) == 0 {
		t.Fatalf("task header %+v", header)
	}
	// Every envelope expires at the response deadline.
	for _, envelope := range f.relays.deposits[providerRelay] {
		parsed, err := agentpacketseal.ParseEnvelope(envelope)
		if err != nil || parsed.ExpiresAtUnix != uint64(task.ResponseDeadline.Unix()) {
			t.Fatalf("envelope expiry %d %v", parsed.ExpiresAtUnix, err)
		}
	}
}

// Within TaskResendInterval the generation stands and an accepted envelope
// is not deposited again; after it a fresh generation is signed and sealed.
func TestATaskIsResentAsAFreshGenerationEveryTenMinutes(t *testing.T) {
	f, task := deliveryFixture(t)
	if _, err := f.carrier.DeliverTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	first := openDeposits(t, f, providerRelay)
	later(&task, TaskResendInterval-time.Second)
	view, err := f.carrier.DeliverTask(context.Background(), task)
	if err != nil || view.Sealed || view.Generation != 1 || f.relays.attempts[providerRelay] != 1 {
		t.Fatalf("inside the interval: %+v %v, %d deposits", view, err, f.relays.attempts[providerRelay])
	}
	later(&task, time.Second)
	view, err = f.carrier.DeliverTask(context.Background(), task)
	if err != nil || !view.Sealed || view.Generation != 2 {
		t.Fatalf("after the interval: %+v %v", view, err)
	}
	second := openDeposits(t, f, providerRelay)
	if len(second) != 2 || second[1].Nonce == first[0].Nonce || second[1].CreatedAtUnix == first[0].CreatedAtUnix {
		t.Fatal("the resend reused the first generation's packet")
	}
	if TaskResendInterval != 600*time.Second {
		t.Fatal("the task is resent every 600 seconds")
	}
}

// A retryable relay answer leaves the envelope for the next round, which
// deposits the same journaled bytes; a conflict or a rejection abandons
// that relay for the envelope.
func TestARetryableDepositIsRetriedWithTheSameBytes(t *testing.T) {
	f, task := deliveryFixture(t)
	f.relays.answer = map[string]agentpacketrelay.DepositResult{providerRelay: agentpacketrelay.DepositRetryable}
	view, err := f.carrier.DeliverTask(context.Background(), task)
	if !errors.Is(err, ErrNoRelayAccepted) || view.Delivered != 0 {
		t.Fatalf("a retryable answer: %+v %v", view, err)
	}
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || len(generations) != 1 {
		t.Fatalf("the generation was not journaled before the deposit: %v", err)
	}
	journaled := generations[0].Envelopes[0].EnvelopeBase64
	delete(f.relays.answer, providerRelay)
	later(&task, time.Minute)
	view, err = f.carrier.DeliverTask(context.Background(), task)
	if err != nil || view.Sealed || view.Delivered != 1 {
		t.Fatalf("the retry: %+v %v", view, err)
	}
	if got := base64.StdEncoding.EncodeToString(f.relays.deposits[providerRelay][0]); got != journaled {
		t.Fatal("the retry deposited other bytes than the journaled envelope")
	}
	g, gtask := deliveryFixture(t)
	g.relays.answer = map[string]agentpacketrelay.DepositResult{providerRelay: agentpacketrelay.DepositRejected}
	if _, err := g.carrier.DeliverTask(context.Background(), gtask); !errors.Is(err, ErrNoRelayAccepted) {
		t.Fatalf("a rejection: %v", err)
	}
	later(&gtask, time.Minute)
	if _, err := g.carrier.DeliverTask(context.Background(), gtask); !errors.Is(err, ErrNoRelayAccepted) ||
		g.relays.attempts[providerRelay] != 1 {
		t.Fatalf("a rejecting relay was tried again (%d attempts): %v", g.relays.attempts[providerRelay], err)
	}
}

// A 409 means another copy holds the envelope ID at that relay (relay
// 8.6): when no relay accepted the envelope, the same packet is re-sealed
// at once under a fresh envelope ID, journaled, and deposited again in the
// same round, not 600 seconds later.
func TestAConflictedEnvelopeIsResealedUnderAFreshIDInTheSameRound(t *testing.T) {
	f, task := deliveryFixture(t)
	f.relays.conflicts = map[string]int{providerRelay: 1}
	view, err := f.carrier.DeliverTask(context.Background(), task)
	if err != nil || view.Delivered != 1 || view.Generation != 1 || f.relays.attempts[providerRelay] != 2 {
		t.Fatalf("a conflicted envelope was not re-sealed in the round: %+v %v, %d deposits", view, err,
			f.relays.attempts[providerRelay])
	}
	conflicted, err := agentpacketseal.ParseEnvelope(f.relays.conflicted[0])
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := agentpacketseal.ParseEnvelope(f.relays.deposits[providerRelay][0])
	if err != nil || accepted.EnvelopeID == conflicted.EnvelopeID || accepted.ExpiresAtUnix != conflicted.ExpiresAtUnix {
		t.Fatalf("the re-seal did not carry a fresh envelope ID: %v", err)
	}
	// The packet inside is the same signed packet.
	key := providerKey(t)
	before, err := agentpacketseal.Open(key, f.relays.conflicted[0])
	if err != nil {
		t.Fatal(err)
	}
	after, err := agentpacketseal.Open(key, f.relays.deposits[providerRelay][0])
	if err != nil || !bytes.Equal(before.PacketJSON, after.PacketJSON) {
		t.Fatalf("the re-seal changed the packet: %v", err)
	}
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || generations[0].Envelopes[0].EnvelopeBase64 != base64.StdEncoding.EncodeToString(f.relays.deposits[providerRelay][0]) ||
		generations[0].Envelopes[0].Relays[providerRelay] != relayAccepted {
		t.Fatalf("the fresh envelope was not journaled: %v", err)
	}
	// One re-seal per round: a second 409 waits for the next round, which
	// re-seals again.
	g, gtask := deliveryFixture(t)
	g.relays.conflicts = map[string]int{providerRelay: 2}
	if _, err := g.carrier.DeliverTask(context.Background(), gtask); !errors.Is(err, ErrNoRelayAccepted) ||
		g.relays.attempts[providerRelay] != 2 {
		t.Fatalf("two conflicts: %v, %d deposits", err, g.relays.attempts[providerRelay])
	}
	later(&gtask, time.Minute)
	view, err = g.carrier.DeliverTask(context.Background(), gtask)
	if err != nil || view.Sealed || view.Delivered != 1 || g.relays.attempts[providerRelay] != 3 {
		t.Fatalf("the next round did not re-seal: %+v %v, %d deposits", view, err, g.relays.attempts[providerRelay])
	}
}

// An envelope another relay accepted is not re-sealed for a 409 elsewhere:
// that relay is only unusable for this envelope.
func TestAConflictIsNotResealedOnceAnotherRelayAccepted(t *testing.T) {
	f, task := deliveryFixture(t)
	f.learn(t, keycardtest.JSON(t, keycardtest.Spec{AgentID: fxProvider, Controller: providerController,
		Seed: providerCardSeed, NotBeforeUnix: uint64(fxNow.Add(-30 * time.Minute).Unix()),
		NotAfterUnix: uint64(fxNow.Add(7 * 24 * time.Hour).Unix()), Relays: []string{providerRelay, secondRelay}}))
	f.relays.conflicts = map[string]int{secondRelay: 1}
	view, err := f.carrier.DeliverTask(context.Background(), task)
	if err != nil || view.Delivered != 1 || f.relays.attempts[providerRelay] != 1 || f.relays.attempts[secondRelay] != 1 {
		t.Fatalf("an accepted envelope was re-sealed: %+v %v, deposits %v", view, err, f.relays.attempts)
	}
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || generations[0].Envelopes[0].Relays[secondRelay] != relayConflict {
		t.Fatalf("the conflicting relay was not marked: %v", err)
	}
}

const secondRelay = "https://second-relay.example"

// The round's clock is the checkpoint's chain time, never the host clock:
// it decides the deadline and is the packets' signing time.
func TestDeliveryRunsOnTheCheckpointsChainTime(t *testing.T) {
	f, task := deliveryFixture(t)
	// The host clock is past the deadline; the chain is not.
	f.clock.advance(time.Hour + time.Minute)
	task.ChainTime = fxNow.Add(10 * time.Minute)
	if _, err := f.carrier.DeliverTask(context.Background(), task); err != nil {
		t.Fatalf("a task inside its deadline by chain time: %v", err)
	}
	for _, packet := range openDeposits(t, f, providerRelay) {
		if packet.CreatedAtUnix != uint64(task.ChainTime.Unix()) {
			t.Fatalf("a packet signed at %d, not the chain time", packet.CreatedAtUnix)
		}
	}
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || generations[0].CreatedUnix != task.ChainTime.Unix() {
		t.Fatalf("the generation is not stamped with the chain time: %v", err)
	}
	// The chain is at the deadline while the host clock is before it.
	g, gtask := deliveryFixture(t)
	gtask.ChainTime = gtask.ResponseDeadline
	if _, err := g.carrier.DeliverTask(context.Background(), gtask); !errors.Is(err, ErrTaskDeadlinePassed) {
		t.Fatalf("a task at its deadline by chain time: %v", err)
	}
	// A round without the chain time is refused.
	for _, missing := range []time.Time{{}, time.Unix(0, 0)} {
		h, htask := deliveryFixture(t)
		htask.ChainTime = missing
		if _, err := h.carrier.DeliverTask(context.Background(), htask); err == nil ||
			!strings.Contains(err.Error(), "chain time") || len(h.relays.deposits[providerRelay]) != 0 {
			t.Fatalf("a round without the chain time: %v", err)
		}
	}
}

// The fresh envelope is journaled before its first deposit: a round that
// stops during that deposit leaves the journal holding the bytes it was
// depositing.
func TestAResealedEnvelopeIsJournaledBeforeItsDeposit(t *testing.T) {
	f, task := deliveryFixture(t)
	f.relays.conflicts = map[string]int{providerRelay: 1}
	f.relays.crashOn = 2
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the planted crash did not happen")
			}
		}()
		_, _ = f.carrier.DeliverTask(context.Background(), task)
	}()
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || generations[0].Envelopes[0].EnvelopeBase64 != base64.StdEncoding.EncodeToString(f.relays.crashed) {
		t.Fatalf("the re-sealed envelope was not journaled before its deposit: %v", err)
	}
}

// A re-seal uses only the journaled packet and provider key, and refuses
// a journal whose key does not match its key ID or whose packet is not
// Base64.
func TestAResealRefusesATamperedJournal(t *testing.T) {
	other, err := agentpacketseal.NewPrivateKey(fxProvider, bytes.Repeat([]byte{9}, agentpacketseal.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := other.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(*generationRecord){
		"another key":    func(g *generationRecord) { g.ProviderPublicKey = base64.StdEncoding.EncodeToString(otherPublic) },
		"packet not b64": func(g *generationRecord) { g.Envelopes[0].PacketBase64 = "e30=!" },
	} {
		f, task := deliveryFixture(t)
		f.relays.answer = map[string]agentpacketrelay.DepositResult{providerRelay: agentpacketrelay.DepositRetryable}
		if _, err := f.carrier.DeliverTask(context.Background(), task); !errors.Is(err, ErrNoRelayAccepted) {
			t.Fatal(err)
		}
		path := f.carrier.generationPath(task.Record.RequestHash, 1)
		var record generationRecord
		if err := readJSON(path, &record); err != nil {
			t.Fatal(err)
		}
		tamper(&record)
		if err := writeJSON(path, record, false); err != nil {
			t.Fatal(err)
		}
		delete(f.relays.answer, providerRelay)
		f.relays.conflicts = map[string]int{providerRelay: 1}
		later(&task, time.Minute)
		if _, err := f.carrier.DeliverTask(context.Background(), task); err == nil || errors.Is(err, ErrNoRelayAccepted) ||
			len(f.relays.deposits[providerRelay]) != 0 {
			t.Errorf("%s: a tampered journal was re-sealed: %v", name, err)
		}
	}
}

// The task is sealed to a card whose not_after covers the response
// deadline, even when a newer card does not; only without such a card is
// the best card valid now used.
func TestATaskIsSealedToACardCoveringTheDeadline(t *testing.T) {
	const shortSeed = 2
	f, task := deliveryFixture(t)
	f.learn(t, providerCardFor(t, fxProvider, shortSeed, fxNow.Add(-30*time.Minute), time.Hour))
	if _, err := f.carrier.DeliverTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	covering := providerKey(t)
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || generations[0].ProviderKeyID != hex.EncodeToString(covering.KeyID[:]) {
		t.Fatalf("the task was not sealed to the card covering the deadline: %v", err)
	}
	// Only the short card is held: it is used.
	g := newCarrierFixture(t, agentPackets(t, nativecore.MaxAgentPacketTransportRequestBytes))
	g.learn(t, providerCardFor(t, fxProvider, shortSeed, fxNow.Add(-30*time.Minute), time.Hour))
	gtask := task
	gtask.Record.RequestHash = g.record.RequestHash
	if _, err := g.carrier.DeliverTask(context.Background(), gtask); err != nil {
		t.Fatalf("no fallback to the card valid now: %v", err)
	}
	short, err := agentpacketseal.NewPrivateKey(fxProvider, bytes.Repeat([]byte{shortSeed}, agentpacketseal.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agentpacketseal.Open(short, g.relays.deposits[providerRelay][0]); err != nil {
		t.Fatalf("the fallback envelope does not open with the short card's key: %v", err)
	}
}

// An envelope never outlives its card's key retention (not_after + 86,400
// + 300 s), nor the response deadline, nor 86,100 s after signing.
func TestAnEnvelopeExpiryIsCappedByTheCardsKeyRetention(t *testing.T) {
	deadline := fxNow.Add(5 * 24 * time.Hour)
	notAfter := uint64(fxNow.Add(-2 * time.Hour).Unix())
	if got := envelopeExpiry(deadline, fxNow, notAfter); got != notAfter+86400+300 {
		t.Fatalf("expiry %d not capped at the key retention", got)
	}
	if got := envelopeExpiry(deadline, fxNow, uint64(fxNow.Unix())); got != uint64(fxNow.Add(MaxPacketLifetime).Unix()) {
		t.Fatalf("expiry %d not capped at the packet lifetime", got)
	}
	near := fxNow.Add(time.Hour)
	if got := envelopeExpiry(near, fxNow, notAfter); got != uint64(near.Unix()) {
		t.Fatalf("expiry %d past the response deadline", got)
	}
	if got := envelopeExpiry(deadline, fxNow, math.MaxUint64); got != uint64(fxNow.Add(MaxPacketLifetime).Unix()) {
		t.Fatalf("an overflowing retention bound changed the expiry to %d", got)
	}
	if keyRetentionWindow != 86700*time.Second {
		t.Fatal("keys are retained 86,400 + 300 seconds past not_after")
	}
}

// The generation is journaled before its first deposit: a round that stops
// during the deposit leaves the sealed envelopes for the next round.
func TestAGenerationIsJournaledBeforeItsFirstDeposit(t *testing.T) {
	f, task := deliveryFixture(t)
	f.relays.crash = true
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the planted crash did not happen")
			}
		}()
		_, _ = f.carrier.DeliverTask(context.Background(), task)
	}()
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || len(generations) != 1 || len(generations[0].Envelopes) != 1 {
		t.Fatalf("a round that stopped mid-deposit left no generation: %v", err)
	}
	f.relays.crash = false
	view, err := f.carrier.DeliverTask(context.Background(), task)
	if err != nil || view.Sealed || view.Delivered != 1 {
		t.Fatalf("the next round did not deliver the journaled generation: %+v %v", view, err)
	}
}

func TestNoTaskIsSentAfterItsDeadlineAndPacketsExpireWithinADay(t *testing.T) {
	f, task := deliveryFixture(t)
	task.ResponseDeadline = fxNow
	if _, err := f.carrier.DeliverTask(context.Background(), task); !errors.Is(err, ErrTaskDeadlinePassed) {
		t.Fatalf("a task at its deadline: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dir, "outbox")); len(entries) != 0 {
		t.Fatal("a task past its deadline was journaled")
	}
	g, far := deliveryFixture(t)
	far.ResponseDeadline = fxNow.Add(5 * 24 * time.Hour)
	if _, err := g.carrier.DeliverTask(context.Background(), far); err != nil {
		t.Fatal(err)
	}
	parsed, err := agentpacketseal.ParseEnvelope(g.relays.deposits[providerRelay][0])
	if err != nil || parsed.ExpiresAtUnix != uint64(fxNow.Add(MaxPacketLifetime).Unix()) {
		t.Fatalf("a far deadline was not capped at 86,100 seconds: %d %v", parsed.ExpiresAtUnix, err)
	}
	if MaxPacketLifetime != 86100*time.Second {
		t.Fatal("packets live at most 86,100 seconds")
	}
}

func TestOnlyFourGenerationsAreKept(t *testing.T) {
	f, task := deliveryFixture(t)
	for round := 0; round < 6; round++ {
		if _, err := f.carrier.DeliverTask(context.Background(), task); err != nil {
			t.Fatal(err)
		}
		later(&task, TaskResendInterval)
	}
	entries, err := os.ReadDir(f.carrier.outboxDir(task.Record.RequestHash))
	if err != nil || len(entries) != maxGenerations {
		t.Fatalf("%d generations kept: %v", len(entries), err)
	}
	generations, err := f.carrier.generations(task.Record.RequestHash)
	if err != nil || generations[0].Generation != 3 || generations[3].Generation != 6 {
		t.Fatalf("the oldest generations were not the ones dropped: %v", err)
	}
}

func TestATaskOfACallThatIsNotAdmittedIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*TaskDelivery){
		"no request ID":           func(task *TaskDelivery) { task.Record.RequestID = nil },
		"no call transaction":     func(task *TaskDelivery) { task.Record.CallTransactionLT = 0 },
		"short call hash":         func(task *TaskDelivery) { task.Record.CallTransactionHex = "9a" },
		"masterchain actor":       func(task *TaskDelivery) { task.Record.Actor = "-1:" + strings.Repeat("77", 32) },
		"actor without workchain": func(task *TaskDelivery) { task.Record.Actor = strings.Repeat("77", 32) },
		"bad request hash":        func(task *TaskDelivery) { task.Record.RequestHash = "../x" },
	} {
		f, task := deliveryFixture(t)
		edit(&task)
		if _, err := f.carrier.DeliverTask(context.Background(), task); err == nil {
			t.Errorf("%s: a task was delivered", name)
		}
		if len(f.relays.deposits[providerRelay]) != 0 {
			t.Errorf("%s: something was deposited", name)
		}
	}
}

// A journaled generation of another purchase in the outbox is refused.
func TestAJournaledGenerationOfAnotherPurchaseIsRefused(t *testing.T) {
	f, task := deliveryFixture(t)
	if _, err := f.carrier.DeliverTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	path := f.carrier.generationPath(task.Record.RequestHash, 1)
	var record generationRecord
	if err := readJSON(path, &record); err != nil {
		t.Fatal(err)
	}
	record.RequestHash = strings.Repeat("cd", 32)
	if err := writeJSON(path, record, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.carrier.DeliverTask(context.Background(), task); err == nil {
		t.Fatal("a generation of another purchase was used")
	}
}

// fakeDeliverer records the deliveries the duty round asks for.
type fakeDeliverer struct {
	mu    sync.Mutex
	tasks []TaskDelivery
	err   error
}

func (d *fakeDeliverer) DeliverTask(_ context.Context, task TaskDelivery) (DeliveryView, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tasks = append(d.tasks, task)
	return DeliveryView{Generation: len(d.tasks), Envelopes: 1, Delivered: 1}, d.err
}

// The duty round delivers the task of a pending request, and only of a
// pending one.
func TestTheDutyRoundDeliversThePendingTask(t *testing.T) {
	f := newFixture(t)
	deliverer := &fakeDeliverer{}
	f.agent.config.Delivery = deliverer
	view := f.paid(t, keyA)
	f.buyer.responseDeadline = uint64(fxNow.Add(time.Hour).Unix())
	f.buyer.chainTime = fxNow.Add(-3 * time.Minute).Unix()
	f.setStatus(serviceactor.StatusPending)
	out, err := f.agent.RefundNow(context.Background(), view.RequestHash)
	if err != nil || out.Delivery == nil || out.Delivery.Generation != 1 || out.Sent {
		t.Fatalf("a pending request: %+v %v", out, err)
	}
	task := deliverer.tasks[0]
	if task.ProviderAgentID != fxProvider || task.Record.RequestHash != view.RequestHash || len(task.Archive) == 0 ||
		task.ExecutionNonce == "" || !task.ResponseDeadline.Equal(fxNow.Add(time.Hour)) || task.RetentionSeconds != 86400 ||
		!task.ChainTime.Equal(fxNow.Add(-3*time.Minute)) {
		t.Fatalf("delivery request %+v", task)
	}
	deliverer.err = ErrNoRelayAccepted
	if _, err := f.agent.RefundNow(context.Background(), view.RequestHash); err == nil || codeOf(t, err) != CodeDependencyUnavailable {
		t.Fatalf("an undelivered task: %v", err)
	}
	deliverer.err = nil
	f.setStatus(serviceactor.StatusResponded)
	out, err = f.agent.RefundNow(context.Background(), view.RequestHash)
	if err != nil || out.Delivery != nil || len(deliverer.tasks) != 2 {
		t.Fatalf("a responded request was delivered: %+v %v", out, err)
	}
	// A tampered archive copy is never delivered.
	f.setStatus(serviceactor.StatusPending)
	if err := writePrivate(f.agent.store.archivePath(view.RequestHash), []byte("other"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.agent.RefundNow(context.Background(), view.RequestHash); err == nil || len(deliverer.tasks) != 2 {
		t.Fatalf("a tampered archive was delivered: %v", err)
	}
}
