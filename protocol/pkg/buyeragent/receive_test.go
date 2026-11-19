package buyeragent

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

const otherAgent = "agent_6666666666666666666666666666666666666666666666666666666666666666"

// receiveFixture is a delivery fixture whose buyer holds a relay key and
// card, with the purchase's Receipt binding and a lookup of it.
type receiveFixture struct {
	*carrierFixture
	task    TaskDelivery
	receipt railwork.ReceiptBinding
	binding railwork.Binding
}

func newReceiveFixture(t *testing.T) *receiveFixture {
	t.Helper()
	f, task := deliveryFixture(t)
	if _, err := f.carrier.BuyerCard(context.Background(), fxNow.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	binding, err := taskBinding(task.Record)
	if err != nil {
		t.Fatal(err)
	}
	var executionID, inputDigest [32]byte
	copy(executionID[:], bytes.Repeat([]byte{0xcd}, 32))
	copy(inputDigest[:], bytes.Repeat([]byte{0xef}, 32))
	receipt := railwork.ReceiptBinding{QuoteCommitment: task.Record.QuoteCommitment, ExecutionID: executionID,
		InputDigest: inputDigest, SourceDigest: "sha256:" + strings.Repeat("12", 32), Price: big.NewInt(1_000_000),
		ProviderAgentID: fxProvider, ToolchainDigest: "sha256:" + strings.Repeat("34", 32),
		SandboxDigest: "sha256:" + strings.Repeat("56", 32)}
	return &receiveFixture{carrierFixture: f, task: task, receipt: receipt, binding: binding}
}

func (f *receiveFixture) lookup(requestHash string) (InboundPurchase, bool, error) {
	if requestHash != f.task.Record.RequestHash {
		return InboundPurchase{}, false, nil
	}
	return InboundPurchase{ProviderAgentID: fxProvider, CapabilityID: fxCapability,
		QuoteCommitment: f.task.Record.QuoteCommitment, Binding: f.binding}, true, nil
}

// round is the result round at a chain time, for a finalized response hash.
func (f *receiveFixture) round(responseHash [32]byte, chainTime time.Time) ResultRound {
	return ResultRound{Record: f.task.Record, ProviderAgentID: fxProvider, Receipt: f.receipt, ResponseHash: responseHash,
		ResponseDeadline: f.task.ResponseDeadline, RetentionSeconds: 86400, ChainTime: chainTime}
}

// providerResult is what a provider delivers: the result message and the
// Receipt's response hash.
type providerResult struct {
	message      []byte
	responseHash [32]byte
	artifact     []byte
}

func artifactTar(t *testing.T, output string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, member := range [][2]string{{"output.log", output}, {"report.json", `{"ok":true}`}} {
		if err := writer.WriteHeader(&tar.Header{Name: member[0], Mode: 0o644, Size: int64(len(member[1])),
			Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(member[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func digestText(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// result builds the provider's result for the purchase, with output as the
// artifact's output and card, if any, as the carried provider card.
func (f *receiveFixture) result(t *testing.T, output string, card []byte) providerResult {
	t.Helper()
	artifact := artifactTar(t, output)
	report := []byte(`{"ok":true}`)
	root, hash, err := railwork.BuildReceipt(f.receipt, railwork.Outcome{ResultDigest: digestText([]byte(output)),
		ArtifactDigest: digestText(artifact), ReportDigest: digestText(report), CompletedAtUnix: uint64(fxNow.Unix())})
	if err != nil {
		t.Fatal(err)
	}
	message, err := railwork.EncodeResult(hash, root.ToBOC(), artifact, card)
	if err != nil {
		t.Fatal(err)
	}
	return providerResult{message: message, responseHash: hash, artifact: artifact}
}

// deliver signs a message's frames as the sender and seals each to the
// buyer's held key, holding the envelopes at the buyer's relay. It returns
// the envelopes.
func (f *receiveFixture) deliver(t *testing.T, sender string, kind railwork.Kind, binding railwork.Binding,
	message []byte) [][]byte {
	t.Helper()
	frames, err := railwork.EncodeMessageFrames(kind, binding, message)
	if err != nil {
		t.Fatal(err)
	}
	var envelopes [][]byte
	for index, frame := range frames {
		envelopes = append(envelopes, f.seal(t, sender, fxCapability, frame, uint64(index+1)))
	}
	for _, envelope := range envelopes {
		f.relays.hold(buyerRelay, envelope)
	}
	return envelopes
}

// seal signs one payload as sender's packet to the buyer and seals it to
// the buyer's held key.
func (f *receiveFixture) seal(t *testing.T, sender, capability string, payload []byte, sequence uint64) []byte {
	t.Helper()
	controller := providerController
	var nonce [32]byte
	nonce[0], nonce[1] = byte(sequence), byte(len(payload))
	nonce[2] = payload[len(payload)-1]
	packet, err := agentpacket.Sign(context.Background(), keycardtest.Keys, controller, agentpacket.Packet{
		SenderAgentID: sender, RecipientAgentID: fxBuyerAgent, CapabilityID: capability,
		QuoteCommitment: f.task.Record.QuoteCommitment, Sequence: sequence + uint64(time.Now().UnixNano()), Nonce: nonce,
		Payload: payload, CreatedAtUnix: uint64(fxNow.Unix()), SenderKeyID: controllerID(t, controller)})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	return f.sealRaw(t, raw)
}

// sealPacket seals the provider's packet of the purchase's first result
// frame, edited before signing, or tampered with after it.
func (f *receiveFixture) sealPacket(t *testing.T, edit func(*agentpacket.Packet), tamper bool) []byte {
	t.Helper()
	frames, err := railwork.EncodeMessageFrames(railwork.KindResult, f.binding, f.result(t, "x", nil).message)
	if err != nil {
		t.Fatal(err)
	}
	packet := agentpacket.Packet{SenderAgentID: fxProvider, RecipientAgentID: fxBuyerAgent, CapabilityID: fxCapability,
		QuoteCommitment: f.task.Record.QuoteCommitment, Sequence: 1, Nonce: [32]byte{9}, Payload: frames[0],
		CreatedAtUnix: uint64(fxNow.Unix()), SenderKeyID: controllerID(t, providerController)}
	if edit != nil {
		edit(&packet)
	}
	signed, err := agentpacket.Sign(context.Background(), keycardtest.Keys, providerController, packet)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		signed.Sequence++
	}
	raw, err := agentpacket.EncodeJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	return f.sealRaw(t, raw)
}

func (f *receiveFixture) sealRaw(t *testing.T, raw []byte) []byte {
	t.Helper()
	keys, _, err := f.carrier.HeldKeys()
	if err != nil || len(keys) == 0 {
		t.Fatalf("no held buyer key: %v", err)
	}
	public, err := keys[0].PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var secret [agentpacketseal.AckSecretSize]byte
	copy(secret[:], raw[len(raw)-16:])
	secret[31] = byte(len(raw))
	secret[30] = raw[len(raw)/2]
	envelope, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{AgentID: fxBuyerAgent, KeyID: keys[0].KeyID,
		PublicKey: public}, secret, raw, uint64(fxNow.Add(12*time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func (f *receiveFixture) poll(t *testing.T) PollView {
	t.Helper()
	view, failures := f.carrier.Poll(context.Background(), f.lookup)
	if len(failures) != 0 {
		t.Fatalf("poll failures: %v", failures)
	}
	return view
}

// sentKinds decodes the messages the buyer deposited at the provider's
// relay since index from, by kind.
func (f *receiveFixture) sent(t *testing.T, from int) []railwork.Frame {
	t.Helper()
	var frames []railwork.Frame
	packets := openDeposits(t, f.carrierFixture, providerRelay)
	for _, packet := range packets[from:] {
		frame, err := railwork.DecodeFrame(packet.Payload)
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func idOf(t *testing.T, envelope []byte) [32]byte {
	t.Helper()
	header, err := agentpacketseal.ParseEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return header.EnvelopeID
}

func TestAResultIsPolledAcceptedStoredAndAcknowledged(t *testing.T) {
	f := newReceiveFixture(t)
	// An output over one frame's data makes a result of three frames.
	result := f.result(t, strings.Repeat("o", 2*railwork.MaxChunkData), nil)
	envelopes := f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	if len(envelopes) != 3 {
		t.Fatalf("%d envelopes", len(envelopes))
	}
	view := f.poll(t)
	if view.Relays != 1 || view.Stored != 3 || view.Acknowledged != 3 {
		t.Fatalf("poll %+v", view)
	}
	box := f.relays.box(buyerRelay)
	for _, envelope := range envelopes {
		if !box.acked[idOf(t, envelope)] {
			t.Fatal("a stored envelope was not acknowledged")
		}
	}
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, fxNow.Add(2*time.Hour)))
	if err != nil || !out.Accepted || out.Examined != 1 || !out.AckSent || out.ResultRequested ||
		out.ResponseHash != hex.EncodeToString(result.responseHash[:]) {
		t.Fatalf("result round %+v %v", out, err)
	}
	stored, err := readPrivate(f.carrier.ArtifactPath(f.task.Record.RequestHash))
	if err != nil || !bytes.Equal(stored, result.artifact) {
		t.Fatalf("the accepted artifact was not stored: %v", err)
	}
	frames := f.sent(t, 0)
	if len(frames) != 1 || frames[0].Kind != railwork.KindResultAck || frames[0].Binding != f.binding {
		t.Fatalf("sent %+v", frames)
	}
	ack, err := railwork.DecodeAck(frames[0].Data)
	if err != nil || ack.Header.ResponseHash != out.ResponseHash || len(ack.BuyerKeyCard) == 0 {
		t.Fatalf("ack %+v %v", ack, err)
	}
	// The ack expires 3,600 s after signing.
	parsed, err := agentpacketseal.ParseEnvelope(f.relays.deposits[providerRelay][0])
	if err != nil || parsed.ExpiresAtUnix != uint64(fxNow.Add(2*time.Hour+AckLifetime).Unix()) {
		t.Fatalf("ack expiry %d %v", parsed.ExpiresAtUnix, err)
	}
	if entries, _ := f.carrier.inboxMessages(f.task.Record.RequestHash); len(entries) != 0 {
		t.Fatal("the accepted message stayed in the inbox")
	}
	// A further round sends nothing.
	out, err = f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, fxNow.Add(3*time.Hour)))
	if err != nil || !out.Accepted || out.AckSent || len(f.relays.deposits[providerRelay]) != 1 {
		t.Fatalf("a quiet round: %+v %v", out, err)
	}
	if AckLifetime != 3600*time.Second {
		t.Fatal("acks live 3,600 seconds")
	}
}

// An incomplete delivery waits in the inbox, unexamined, until its other
// frames arrive.
func TestAnIncompleteDeliveryWaitsForItsFrames(t *testing.T) {
	f := newReceiveFixture(t)
	result := f.result(t, strings.Repeat("o", 2*railwork.MaxChunkData), nil)
	envelopes := f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	box := f.relays.box(buyerRelay)
	held := box.held
	box.held = held[:1]
	f.poll(t)
	chain := fxNow.Add(2 * time.Hour)
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, chain))
	if err != nil || out.Examined != 0 || out.Accepted || out.FailedDeliveries != 0 {
		t.Fatalf("an incomplete delivery: %+v %v", out, err)
	}
	box.held = held
	f.clock.advance(PollInterval + PollInterval/5)
	f.poll(t)
	out, err = f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, chain.Add(time.Minute)))
	if err != nil || !out.Accepted || len(envelopes) != 3 {
		t.Fatalf("the completed delivery: %+v %v", out, err)
	}
}

// Stored frames that do not join into one message fail that delivery.
func TestFramesThatDoNotJoinFailTheDelivery(t *testing.T) {
	f := newReceiveFixture(t)
	result := f.result(t, strings.Repeat("o", 2*railwork.MaxChunkData), nil)
	frames, err := railwork.EncodeMessageFrames(railwork.KindResult, f.binding, result.message)
	if err != nil {
		t.Fatal(err)
	}
	first, err := railwork.DecodeFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := railwork.DecodeFrame(frames[1])
	if err != nil {
		t.Fatal(err)
	}
	second.TotalLength++
	raw, err := railwork.EncodeFrame(second)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := f.task.Record.RequestHash
	if err := f.carrier.storeFrame(requestHash, first, frames[0]); err != nil {
		t.Fatal(err)
	}
	if err := f.carrier.storeFrame(requestHash, second, raw); err != nil {
		t.Fatal(err)
	}
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, fxNow.Add(2*time.Hour)))
	if err != nil || out.Examined != 1 || out.FailedDeliveries != 1 || out.Accepted {
		t.Fatalf("frames that do not join: %+v %v", out, err)
	}
}

// A message a 409 refused is re-sealed once in the round (relay 8.6), and
// without a provider card the round sends nothing and fails nothing.
func TestAResultRequestIsResealedOnConflictAndWaitsForACard(t *testing.T) {
	f := newReceiveFixture(t)
	hash := f.result(t, "built", nil).responseHash
	f.relays.conflicts = map[string]int{providerRelay: 1}
	chain := fxNow.Add(2 * time.Hour)
	if out, err := f.carrier.ReceiveResult(context.Background(), f.round(hash, chain)); err != nil || !out.ResultRequested {
		t.Fatalf("a conflicted request: %+v %v", out, err)
	}
	g := newReceiveFixture(t)
	// Moving the Capability's cards away leaves the carrier holding none.
	cards := g.carrier.cardDir() + "/" + fxCapability
	if err := os.Rename(cards, cards+".moved"); err != nil {
		t.Fatal(err)
	}
	if out, err := g.carrier.ReceiveResult(context.Background(), g.round(hash, chain)); err != nil || out.ResultRequested {
		t.Fatalf("no provider card: %+v %v", out, err)
	}
}

// A redelivery after acceptance is answered with the ack again.
func TestARedeliveryIsAnsweredWithTheAckAgain(t *testing.T) {
	f := newReceiveFixture(t)
	result := f.result(t, "built", nil)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	f.poll(t)
	chain := fxNow.Add(2 * time.Hour)
	if out, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, chain)); err != nil || !out.AckSent {
		t.Fatalf("%+v %v", out, err)
	}
	f.clock.advance(time.Minute)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	f.poll(t)
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, chain.Add(time.Minute)))
	if err != nil || !out.Accepted || !out.AckSent || len(f.relays.deposits[providerRelay]) != 2 {
		t.Fatalf("a redelivery: %+v %v", out, err)
	}
}

// A result that does not pass 7.2 is discarded and counted; the purchase
// stays open, and a later passing delivery is accepted.
func TestAFailingDeliveryIsDiscardedAndALaterOneAccepted(t *testing.T) {
	f := newReceiveFixture(t)
	good := f.result(t, "built", nil)
	other := f.result(t, "forged", nil)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, other.message)
	f.poll(t)
	chain := fxNow.Add(2 * time.Hour)
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(good.responseHash, chain))
	if err != nil || out.Accepted || out.Examined != 1 || out.FailedDeliveries != 1 || !out.ResultRequested {
		t.Fatalf("a failing delivery: %+v %v", out, err)
	}
	if entries, _ := f.carrier.inboxMessages(f.task.Record.RequestHash); len(entries) != 0 {
		t.Fatal("a failing delivery stayed in the inbox")
	}
	f.clock.advance(time.Minute)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, good.message)
	f.poll(t)
	out, err = f.carrier.ReceiveResult(context.Background(), f.round(good.responseHash, chain.Add(time.Minute)))
	if err != nil || !out.Accepted || out.FailedDeliveries != 1 {
		t.Fatalf("the later delivery: %+v %v", out, err)
	}
}

// At most MaxFailedDeliveries failing deliveries are examined; later ones
// are discarded unexamined.
func TestFailingDeliveriesAreExaminedAtMostSixteenTimes(t *testing.T) {
	f := newReceiveFixture(t)
	good := f.result(t, "built", nil)
	state := receivedRecord{Schema: receivedSchema, RequestHash: f.task.Record.RequestHash,
		FailedDeliveries: MaxFailedDeliveries - 1, LastResultRequestUnix: fxNow.Unix()}
	if err := writeJSON(f.carrier.receivedPath(f.task.Record.RequestHash), state, false); err != nil {
		t.Fatal(err)
	}
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, f.result(t, "forged", nil).message)
	f.poll(t)
	chain := fxNow.Add(2 * time.Hour)
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(good.responseHash, chain))
	if err != nil || out.FailedDeliveries != MaxFailedDeliveries || !out.Exhausted || out.Examined != 1 {
		t.Fatalf("the sixteenth failure: %+v %v", out, err)
	}
	f.clock.advance(time.Minute)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, good.message)
	f.poll(t)
	out, err = f.carrier.ReceiveResult(context.Background(), f.round(good.responseHash, chain.Add(time.Minute)))
	if err != nil || out.Accepted || out.Examined != 0 || !out.Exhausted {
		t.Fatalf("a delivery past the bound was examined: %+v %v", out, err)
	}
	if entries, _ := f.carrier.inboxMessages(f.task.Record.RequestHash); len(entries) != 0 {
		t.Fatal("a delivery past the bound stayed in the inbox")
	}
	if MaxFailedDeliveries != 16 {
		t.Fatal("16 failing deliveries are examined")
	}
}

// With the respond finalized and no result, a result-request carrying the
// buyer card goes out at once and then at most every 21,600 s, expiring at
// the retention end at the latest.
func TestAResultRequestIsSentAtOnceThenEverySixHours(t *testing.T) {
	f := newReceiveFixture(t)
	hash := f.result(t, "built", nil).responseHash
	chain := fxNow.Add(2 * time.Hour)
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(hash, chain))
	if err != nil || !out.ResultRequested {
		t.Fatalf("no result-request at once: %+v %v", out, err)
	}
	frames := f.sent(t, 0)
	if len(frames) != 1 || frames[0].Kind != railwork.KindResultRequest || frames[0].Binding != f.binding {
		t.Fatalf("sent %+v", frames)
	}
	request, err := railwork.DecodeResultRequest(frames[0].Data)
	if err != nil || len(request.BuyerKeyCard) == 0 {
		t.Fatalf("result-request %+v %v", request, err)
	}
	// It expires at the retention end, which is before signing + 86,100 s.
	end := f.task.ResponseDeadline.Add(86400 * time.Second)
	parsed, err := agentpacketseal.ParseEnvelope(f.relays.deposits[providerRelay][0])
	if err != nil || parsed.ExpiresAtUnix != uint64(end.Unix()) {
		t.Fatalf("result-request expiry %d %v", parsed.ExpiresAtUnix, err)
	}
	out, err = f.carrier.ReceiveResult(context.Background(), f.round(hash, chain.Add(ResultRequestInterval-time.Second)))
	if err != nil || out.ResultRequested || len(f.relays.deposits[providerRelay]) != 1 {
		t.Fatalf("inside the interval: %+v %v", out, err)
	}
	out, err = f.carrier.ReceiveResult(context.Background(), f.round(hash, chain.Add(ResultRequestInterval)))
	if err != nil || !out.ResultRequested || len(f.relays.deposits[providerRelay]) != 2 {
		t.Fatalf("after the interval: %+v %v", out, err)
	}
	if ResultRequestInterval != 21600*time.Second {
		t.Fatal("result-requests are sent at most every 21,600 seconds")
	}
}

// A result-request no relay accepted is sent again in the next round.
func TestAnUndeliveredResultRequestIsRetried(t *testing.T) {
	f := newReceiveFixture(t)
	hash := f.result(t, "built", nil).responseHash
	f.relays.answer = map[string]agentpacketrelay.DepositResult{providerRelay: agentpacketrelay.DepositRetryable}
	chain := fxNow.Add(2 * time.Hour)
	if out, err := f.carrier.ReceiveResult(context.Background(), f.round(hash, chain)); err != nil || out.ResultRequested {
		t.Fatalf("%+v %v", out, err)
	}
	delete(f.relays.answer, providerRelay)
	if out, err := f.carrier.ReceiveResult(context.Background(), f.round(hash, chain.Add(time.Minute))); err != nil ||
		!out.ResultRequested {
		t.Fatalf("the retry: %+v %v", out, err)
	}
}

// After the retention end nothing is sent and the inbox is dropped.
func TestNothingIsSentAfterTheRetentionEnd(t *testing.T) {
	f := newReceiveFixture(t)
	result := f.result(t, "built", nil)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	f.poll(t)
	end := f.task.ResponseDeadline.Add(86400 * time.Second)
	out, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, end))
	if err != nil || !out.RetentionEnded || out.Accepted || out.ResultRequested || len(f.relays.deposits[providerRelay]) != 0 {
		t.Fatalf("at the retention end: %+v %v", out, err)
	}
	if entries, _ := f.carrier.inboxMessages(f.task.Record.RequestHash); len(entries) != 0 {
		t.Fatal("the inbox outlived the retention")
	}
}

// A provider card carried in a result of the purchase's provider is learned.
func TestAProviderCardInAResultIsLearned(t *testing.T) {
	f := newReceiveFixture(t)
	card := providerCardFor(t, fxProvider, 3, fxNow.Add(-time.Minute), 20*24*time.Hour)
	result := f.result(t, "built", card)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, result.message)
	f.poll(t)
	if _, err := f.carrier.ReceiveResult(context.Background(), f.round(result.responseHash, fxNow.Add(2*time.Hour))); err != nil {
		t.Fatal(err)
	}
	learned, err := f.carrier.ProviderCard(context.Background(), fxCapability, fxProvider, fxNow.Add(15*24*time.Hour))
	if err != nil || learned.Source != buyersdk.ProviderCardFromResult {
		t.Fatalf("the result's card was not learned: %+v %v", learned.Source, err)
	}
}

// Packets that open but fail for good are acknowledged without storing:
// another sender, another kind, an unknown purchase, another Capability.
func TestAPacketRefusedForGoodIsAcknowledgedUnstored(t *testing.T) {
	for name, deliver := range map[string]func(*receiveFixture, *testing.T) [][]byte{
		"from another Agent": func(f *receiveFixture, t *testing.T) [][]byte {
			f.chain.agents[otherAgent] = keycardtest.Agent(otherAgent, providerController)
			return f.deliver(t, otherAgent, railwork.KindResult, f.binding, f.result(t, "x", nil).message)
		},
		"not a result": func(f *receiveFixture, t *testing.T) [][]byte {
			message, err := railwork.EncodeResultRequest(nil)
			if err != nil {
				t.Fatal(err)
			}
			return f.deliver(t, fxProvider, railwork.KindResultRequest, f.binding, message)
		},
		"another purchase": func(f *receiveFixture, t *testing.T) [][]byte {
			other := f.binding
			other.RequestHash[0] ^= 1
			return f.deliver(t, fxProvider, railwork.KindResult, other, f.result(t, "x", nil).message)
		},
		"another request id": func(f *receiveFixture, t *testing.T) [][]byte {
			other := f.binding
			other.RequestID++
			return f.deliver(t, fxProvider, railwork.KindResult, other, f.result(t, "x", nil).message)
		},
		"another capability": func(f *receiveFixture, t *testing.T) [][]byte {
			frames, err := railwork.EncodeMessageFrames(railwork.KindResult, f.binding, f.result(t, "x", nil).message)
			if err != nil {
				t.Fatal(err)
			}
			envelope := f.seal(t, fxProvider, "cap_"+strings.Repeat("99", 32), frames[0], 1)
			f.relays.hold(buyerRelay, envelope)
			return [][]byte{envelope}
		},
		"addressed to another Agent": func(f *receiveFixture, t *testing.T) [][]byte {
			f.chain.agents[otherAgent] = keycardtest.Agent(otherAgent, providerController)
			envelope := f.sealPacket(t, func(p *agentpacket.Packet) { p.RecipientAgentID = otherAgent }, false)
			f.relays.hold(buyerRelay, envelope)
			return [][]byte{envelope}
		},
		"a bad signature": func(f *receiveFixture, t *testing.T) [][]byte {
			envelope := f.sealPacket(t, nil, true)
			f.relays.hold(buyerRelay, envelope)
			return [][]byte{envelope}
		},
		"not a frame": func(f *receiveFixture, t *testing.T) [][]byte {
			envelope := f.seal(t, fxProvider, fxCapability, []byte("not a frame"), 1)
			f.relays.hold(buyerRelay, envelope)
			return [][]byte{envelope}
		},
		"not a packet": func(f *receiveFixture, t *testing.T) [][]byte {
			envelope := f.sealRaw(t, []byte(`{"schema":"other"}`))
			f.relays.hold(buyerRelay, envelope)
			return [][]byte{envelope}
		},
		"over the bound": func(f *receiveFixture, t *testing.T) [][]byte {
			envelope := f.sealRaw(t, bytes.Repeat([]byte{' '}, MaxInboundPacketJSON+1))
			f.relays.hold(buyerRelay, envelope)
			return [][]byte{envelope}
		},
	} {
		f := newReceiveFixture(t)
		envelopes := deliver(f, t)
		view := f.poll(t)
		if view.Stored != 0 || view.Refused != len(envelopes) || view.Acknowledged != len(envelopes) {
			t.Errorf("%s: %+v", name, view)
		}
		if entries, _ := os.ReadDir(f.carrier.inboxDir(f.task.Record.RequestHash)); len(entries) != 0 {
			t.Errorf("%s: a refused packet was stored", name)
		}
	}
}

// A packet whose finalized verification is unavailable is neither stored
// nor acknowledged, and is taken on a later poll.
func TestATransientVerificationFailureIsRetried(t *testing.T) {
	f := newReceiveFixture(t)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, f.result(t, "built", nil).message)
	f.chain.unavailable = true
	view, failures := f.carrier.Poll(context.Background(), f.lookup)
	if len(failures) != 1 || view.Stored != 0 || view.Acknowledged != 0 {
		t.Fatalf("a transient failure: %+v %v", view, failures)
	}
	f.chain.unavailable = false
	f.clock.advance(PollInterval + PollInterval/5)
	if view := f.poll(t); view.Stored != 1 || view.Acknowledged != 1 {
		t.Fatalf("the retry: %+v", view)
	}
}

// A lookup failure is transient too; an unknown purchase is refused.
func TestALookupFailureIsRetried(t *testing.T) {
	f := newReceiveFixture(t)
	f.deliver(t, fxProvider, railwork.KindResult, f.binding, f.result(t, "built", nil).message)
	broken := func(string) (InboundPurchase, bool, error) { return InboundPurchase{}, false, errors.New("store busy") }
	if view, failures := f.carrier.Poll(context.Background(), broken); len(failures) != 1 || view.Acknowledged != 0 {
		t.Fatalf("a lookup failure: %+v %v", view, failures)
	}
}

// An envelope that does not open, or other bytes than the listed ID, is
// never acknowledged and is not downloaded again from that relay; an
// envelope for a key not held is not downloaded at all.
func TestAnEnvelopeThatDoesNotOpenIsRememberedPerRelay(t *testing.T) {
	f := newReceiveFixture(t)
	envelope := f.deliver(t, fxProvider, railwork.KindResult, f.binding, f.result(t, "built", nil).message)[0]
	other := f.seal(t, fxProvider, fxCapability, []byte("other"), 9)
	box := f.relays.box(buyerRelay)
	box.serve[idOf(t, envelope)] = other
	view := f.poll(t)
	if view.Refused != 1 || view.Acknowledged != 0 || box.acked[idOf(t, envelope)] || box.downloads != 1 {
		t.Fatalf("other bytes than the listed ID: %+v, %d downloads", view, box.downloads)
	}
	f.clock.advance(PollInterval + PollInterval/5)
	f.poll(t)
	if box.downloads != 1 {
		t.Fatal("an envelope that did not open was downloaded again from the same relay")
	}
	// The same ID at another relay is still downloaded and opened (8.6).
	f.relays.hold(secondRelay, envelope)
	f.learnBuyerRelay(t, secondRelay)
	f.clock.advance(PollInterval + PollInterval/5)
	if view := f.poll(t); view.Stored != 1 || !f.relays.box(secondRelay).acked[idOf(t, envelope)] {
		t.Fatalf("a failed open at one relay suppressed another: %+v", view)
	}
	// A key not held is skipped without a download.
	g := newReceiveFixture(t)
	foreign := receiveForeignKey(t, g)
	g.relays.hold(buyerRelay, foreign)
	if view := g.poll(t); view.Refused != 0 || g.relays.box(buyerRelay).downloads != 0 {
		t.Fatalf("an envelope for a key not held: %+v", view)
	}
}

// learnBuyerRelay issues a further buyer card naming relay, so the poller
// lists it too.
func (f *receiveFixture) learnBuyerRelay(t *testing.T, relay string) {
	t.Helper()
	f.carrier.config.Relays = []string{relay}
	if _, err := f.carrier.BuyerCard(context.Background(), fxNow.Add(49*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func receiveForeignKey(t *testing.T, f *receiveFixture) []byte {
	t.Helper()
	key, err := agentpacketseal.NewPrivateKey(fxBuyerAgent, bytes.Repeat([]byte{7}, agentpacketseal.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var secret [agentpacketseal.AckSecretSize]byte
	secret[0] = 1
	envelope, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{AgentID: fxBuyerAgent, KeyID: key.KeyID, PublicKey: public},
		secret, []byte(`{}`), uint64(fxNow.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// An envelope settled at one relay is acknowledged at every relay that
// lists it, without another download.
func TestASettledEnvelopeIsAcknowledgedAtEveryRelay(t *testing.T) {
	f := newReceiveFixture(t)
	envelope := f.deliver(t, fxProvider, railwork.KindResult, f.binding, f.result(t, "built", nil).message)[0]
	f.poll(t)
	f.relays.hold(secondRelay, envelope)
	f.learnBuyerRelay(t, secondRelay)
	f.clock.advance(PollInterval + PollInterval/5)
	f.poll(t)
	second := f.relays.box(secondRelay)
	if !second.acked[idOf(t, envelope)] || second.downloads != 0 {
		t.Fatalf("a settled envelope at another relay: acked %v, %d downloads", second.acked[idOf(t, envelope)], second.downloads)
	}
}

// Frames are stored durably and deduplicated; other bytes for a held index
// are a frame conflict, and a purchase's inbox holds at most
// MaxOpenMessages messages.
// A frame refused as inbox-full is never acknowledged: it stays at the
// relay and is stored on a later pass once the inbox has room.
func TestAFullInboxLeavesTheEnvelopeAtTheRelay(t *testing.T) {
	f := newReceiveFixture(t)
	requestHash := f.task.Record.RequestHash
	frames, err := railwork.EncodeMessageFrames(railwork.KindResult, f.binding, f.result(t, "held", nil).message)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := railwork.DecodeFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < MaxOpenMessages; index++ {
		filler := frame
		filler.MessageDigest[0] ^= byte(index + 1)
		if err := f.carrier.storeFrame(requestHash, filler, frames[0]); err != nil {
			t.Fatal(err)
		}
	}
	envelope := f.deliver(t, fxProvider, railwork.KindResult, f.binding, f.result(t, "built", nil).message)[0]
	view, failures := f.carrier.Poll(context.Background(), f.lookup)
	box := f.relays.box(buyerRelay)
	if len(failures) != 1 || view.Stored != 0 || view.Acknowledged != 0 || box.acked[idOf(t, envelope)] {
		t.Fatalf("a full inbox: %+v %v", view, failures)
	}
	if err := f.carrier.clearInbox(requestHash); err != nil {
		t.Fatal(err)
	}
	// Until InboxFullRetry has passed it is not downloaded again, even with
	// room in the inbox.
	downloads := box.downloads
	f.clock.advance(PollInterval + PollInterval/5)
	if view := f.poll(t); view.Stored != 0 || box.downloads != downloads {
		t.Fatalf("a deferred envelope was taken again early: %+v, %d downloads", view, box.downloads-downloads)
	}
	f.clock.advance(InboxFullRetry)
	if view := f.poll(t); view.Stored != 1 || !box.acked[idOf(t, envelope)] {
		t.Fatalf("the later pass: %+v", view)
	}
	if InboxFullRetry != 5*time.Minute {
		t.Fatal("a full inbox defers an envelope for 5 minutes")
	}
}

// A frame that conflicts with a held frame is refused for good: it is
// acknowledged without storing.
func TestAConflictingFrameIsAcknowledgedUnstored(t *testing.T) {
	f := newReceiveFixture(t)
	message := f.result(t, "built", nil).message
	frames, err := railwork.EncodeMessageFrames(railwork.KindResult, f.binding, message)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := railwork.DecodeFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	held := append(append([]byte(nil), frames[0][:len(frames[0])-1]...), frames[0][len(frames[0])-1]^1)
	if err := f.carrier.storeFrame(f.task.Record.RequestHash, frame, held); err != nil {
		t.Fatal(err)
	}
	envelope := f.deliver(t, fxProvider, railwork.KindResult, f.binding, message)[0]
	if view := f.poll(t); view.Stored != 0 || view.Refused != 1 || !f.relays.box(buyerRelay).acked[idOf(t, envelope)] {
		t.Fatalf("a conflicting frame: %+v", view)
	}
}

func TestTheInboxDeduplicatesAndIsBounded(t *testing.T) {
	f := newReceiveFixture(t)
	frames, err := railwork.EncodeMessageFrames(railwork.KindResult, f.binding, f.result(t, "built", nil).message)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := railwork.DecodeFrame(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	requestHash := f.task.Record.RequestHash
	if err := f.carrier.storeFrame(requestHash, frame, frames[0]); err != nil {
		t.Fatal(err)
	}
	if err := f.carrier.storeFrame(requestHash, frame, frames[0]); err != nil {
		t.Fatalf("a duplicate frame: %v", err)
	}
	other := append(append([]byte(nil), frames[0][:len(frames[0])-1]...), frames[0][len(frames[0])-1]^1)
	if err := f.carrier.storeFrame(requestHash, frame, other); !errors.Is(err, railwork.ErrFrameConflict) {
		t.Fatalf("a conflicting frame: %v", err)
	}
	for index := 1; index < MaxOpenMessages; index++ {
		next := frame
		next.MessageDigest[0] = byte(index)
		if err := f.carrier.storeFrame(requestHash, next, frames[0]); err != nil {
			t.Fatal(err)
		}
	}
	full := frame
	full.MessageDigest[0] = 0xff
	if err := f.carrier.storeFrame(requestHash, full, frames[0]); !errors.Is(err, errInboxFull) {
		t.Fatalf("a ninth message: %v", err)
	}
	if MaxOpenMessages != 8 {
		t.Fatal("8 messages per purchase")
	}
}

// A failed listing backs the relay off from 30 s doubling to 5 minutes,
// and at least the relay's Retry-After; a good listing returns to 15 s
// with at most 20 % jitter.
func TestAFailedListingBacksTheRelayOff(t *testing.T) {
	f := newReceiveFixture(t)
	box := f.relays.box(buyerRelay)
	box.listErr = errors.New("unreachable")
	for _, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		view, failures := f.carrier.Poll(context.Background(), f.lookup)
		if len(failures) != 1 || !view.Next.Equal(f.clock.Now().Add(want)) {
			t.Fatalf("backoff %v, want %v: %v", view.Next.Sub(f.clock.Now()), want, failures)
		}
		// Not listed again before the backoff ends.
		lists := box.lists
		f.carrier.Poll(context.Background(), f.lookup)
		if box.lists != lists {
			t.Fatal("a backed-off relay was listed early")
		}
		f.clock.advance(want)
	}
	box.listErr = &agentpacketrelay.StatusError{StatusCode: 429, RetryAfter: 20 * time.Minute}
	if view, _ := f.carrier.Poll(context.Background(), f.lookup); !view.Next.Equal(f.clock.Now().Add(20 * time.Minute)) {
		t.Fatalf("Retry-After not honoured: %v", view.Next.Sub(f.clock.Now()))
	}
	f.clock.advance(20 * time.Minute)
	box.listErr = nil
	view := f.poll(t)
	if wait := view.Next.Sub(f.clock.Now()); wait < PollInterval || wait > PollInterval+PollInterval/5 {
		t.Fatalf("the interval after a good listing is %v", wait)
	}
	if PollInterval != 15*time.Second || MaxPollBackoff != 5*time.Minute {
		t.Fatal("relays are listed every 15 seconds, backing off to 5 minutes")
	}
}

func TestEnvelopeMemoryForgetsAtExpiryAndWhenFull(t *testing.T) {
	memory := newEnvelopeMemory(2)
	var secret [agentpacketseal.AckSecretSize]byte
	memory.put("a", secret, fxNow.Add(time.Minute), fxNow)
	memory.put("b", secret, fxNow.Add(time.Hour), fxNow)
	if _, ok := memory.get("a", fxNow.Add(time.Minute)); ok {
		t.Fatal("an entry outlived its expiry")
	}
	memory.put("a", secret, fxNow.Add(2*time.Hour), fxNow)
	memory.put("c", secret, fxNow.Add(3*time.Hour), fxNow)
	if _, ok := memory.get("b", fxNow); ok {
		t.Fatal("a full memory did not forget the entry expiring first")
	}
	if _, ok := memory.get("c", fxNow); !ok {
		t.Fatal("the new entry was not kept")
	}
}
