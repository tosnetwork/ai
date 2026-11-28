package buyeragent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
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
		!bytes.Equal(decoded.Archive, task.Archive) || len(decoded.BuyerKeyCard) == 0 || decoded.Header.Contact == "" {
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

func TestTaskWaitsForHintThenRetriesSecondCopy(t *testing.T) {
	f, task := deliveryFixture(t)
	const other = "https://another-provider-relay.example"
	f.relays.directory.relays = nil
	view, err := f.carrier.DeliverTask(t.Context(), task)
	if !errors.Is(err, ErrNoRelayAccepted) || view.Envelopes == 0 || !view.Sealed || len(f.relays.deposits[providerRelay]) != 0 {
		t.Fatalf("missing hint: %+v %v", view, err)
	}
	f.relays.directory.relays = []string{providerRelay, other}
	f.relays.down[other] = true
	f.clock.advance(time.Minute)
	view, err = f.carrier.DeliverTask(t.Context(), task)
	if err != nil || view.Sealed || view.Delivered != view.Envelopes || len(f.relays.deposits[providerRelay]) != view.Envelopes {
		t.Fatalf("one relay available: %+v %v", view, err)
	}
	f.relays.down[other] = false
	f.clock.advance(time.Minute)
	view, err = f.carrier.DeliverTask(t.Context(), task)
	if err != nil || view.Sealed || len(f.relays.deposits[other]) != view.Envelopes || len(f.relays.deposits[providerRelay]) != view.Envelopes {
		t.Fatalf("second copy: %+v %v", view, err)
	}
	for i, envelope := range f.relays.deposits[other] {
		if !bytes.Equal(envelope, f.relays.deposits[providerRelay][i]) {
			t.Fatal("the second relay did not receive the same sealed bytes")
		}
	}
}

func TestDeliveryRunsOnTheCheckpointsChainTime(t *testing.T) {
	f, task := deliveryFixture(t)
	task.ChainTime = task.ResponseDeadline
	if _, err := f.carrier.DeliverTask(t.Context(), task); !errors.Is(err, ErrTaskDeadlinePassed) {
		t.Fatalf("a round at the finalized deadline returned %v", err)
	}
	if len(f.relays.deposits[providerRelay]) != 0 {
		t.Fatal("an expired task was deposited")
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
