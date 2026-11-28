package daemon

import (
	"context"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

// withEvidence re-frames a frame with other evidence, as a sender would that
// still held older evidence of its own.
func withEvidence(t *testing.T, raw, evidence []byte) []byte {
	t.Helper()
	frame, err := relayframe.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	frame.Evidence = evidence
	encoded, err := relayframe.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func ackOutcome(t *testing.T, response carrierapi.Response) relayframe.Ack {
	t.Helper()
	frame, err := relayframe.Decode(ackFrameOf(t, response))
	if err != nil {
		t.Fatal(err)
	}
	ack, err := relayframe.DecodeAck(frame.Part)
	if err != nil {
		t.Fatal(err)
	}
	return ack
}

func TestDescriptorExpiredAckIsSignedOnlyForAKnownPeer(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"}, [2]string{"5", "6"})
	a, b, stranger := nodes[0], nodes[1], nodes[2]
	importContact(t, a, b)
	importContact(t, b, a)
	importContact(t, stranger, b)

	// A, admitted at B by contact import, sends with expired evidence: B
	// signs a descriptor-expired rejection so A learns to renew.
	sendText(t, a, b, "from a", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	stale := withEvidence(t, onlyFrame(t, a).frame, oldEvidence(t, a, now))
	answer := deliver(t, a, b, stale)
	if ack := ackOutcome(t, answer); ack.Outcome != relayframe.OutcomeRejected || ack.Code != fault.CodeDescriptorExpired {
		t.Fatalf("admitted peer: %+v", ack)
	}

	// A stranger with expired evidence gets the relay ack only.
	sendText(t, stranger, b, "from a stranger", "b", now)
	if _, err := stranger.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	strangerStale := withEvidence(t, onlyFrame(t, stranger).frame, oldEvidence(t, stranger, now))
	refused := deliver(t, stranger, b, strangerStale)
	if refused.Result != carrierapi.ResultRefused || refused.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("stranger with expired evidence: %s/%s", refused.Result, refused.Code)
	}
	if _, found, _ := b.d.journal.LoadRelayEvidence(stranger.d.config.AgentID); found {
		t.Fatal("a stranger's evidence was stored")
	}
	if _, found, _ := b.d.journal.LoadRelayPull(stranger.d.config.AgentID); found {
		t.Fatal("a stranger's frame was written")
	}
}

func otherCard(t *testing.T, agentID string) []byte {
	t.Helper()
	card, err := agentpacket.EncodeJSON(agentpacket.Packet{SenderAgentID: agentID,
		RecipientAgentID: "agent_" + strings.Repeat("f", 64), CapabilityID: "cap_" + strings.Repeat("e", 64),
		Sequence: 2, Nonce: [32]byte{2}, Payload: []byte("rotated chat key card body"), CreatedAtUnix: 2,
		SenderKeyID: [mldsa44.KeyIDSize]byte{2}, Signature: make([]byte, mldsa44.SignatureSize)})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

func TestALateAckAfterACardRotationDoesNotStopTheCard(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	sendText(t, a, b, "rotating", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	firstGeneration := onlyFrame(t, a).frame
	// The card rotates, and the copy is re-deposited with the new card.
	if err := os.WriteFile(a.cardPath, otherCard(t, a.d.config.AgentID), 0o600); err != nil {
		t.Fatal(err)
	}
	later := now.Add(MinRelayRedepositInterval + time.Minute)
	a.d.now = func() time.Time { return later }
	if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
		t.Fatalf("re-deposit: %+v %v", summary, err)
	}
	if second := onlyFrame(t, a); second.withdraw == "" {
		t.Fatal("the second generation does not withdraw the first")
	}
	// The ack of the first generation arrives late.
	answer := deliver(t, a, b, firstGeneration)
	if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, answer)); applied.Result != carrierapi.ResultApplied {
		t.Fatalf("late ack: %s", applied.Result)
	}
	pull, _, err := a.d.journal.LoadRelayPull(b.d.config.AgentID)
	if err != nil || pull.AckedCardDigest != "" {
		t.Fatalf("an ack of an unidentified generation recorded card %q (%v)", pull.AckedCardDigest, err)
	}
	sendText(t, a, b, "still carrying the card", "b", later)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	next, err := relayframe.Decode(onlyFrame(t, a).frame)
	if err != nil || len(next.Card) == 0 {
		t.Fatal("the card stopped riding after an ambiguous ack")
	}
}

func TestAnAckAnsweredBeforeCarriedIsRecordedSettlesTheCopy(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	// The carrier's deposit is delivered and acknowledged before Carry
	// returns, so the ack meets a sealed copy not yet recorded as carried.
	a.carrier.onCarry = func(record carried) {
		answer := b.d.relay.Deliver(context.Background(), a.d.config.AgentID, record.frame)
		if answer.Result != carrierapi.ResultAck {
			return
		}
		raw := ackFrameOf(t, answer)
		if applied := a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, raw); applied.Result != carrierapi.ResultApplied {
			t.Errorf("ack before Carried: %s/%s", applied.Result, applied.Code)
		}
	}
	first := sendText(t, a, b, "one", "a", now)
	second := sendText(t, a, b, "two", "b", now)
	summary, err := a.d.dispatch.Sweep(context.Background(), 0)
	if err != nil || summary.Sent != 2 || summary.Carried != 0 {
		t.Fatalf("sweep with acks before Carried: %+v %v", summary, err)
	}
	for _, eventID := range []string{first, second} {
		if state := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateDelivered {
			t.Fatalf("copy %s: %+v", eventID, state)
		}
	}
}

// Copies that are already sealed go through the gate again before every
// deposit: a revoked device, a withdrawn delegation, or a copy pending after
// a descriptor-expired ack is held, keeps its generation and is not carried.
func TestSealedCopiesAreGatedBeforeEveryDeposit(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	later := now.Add(MinRelayRedepositInterval + time.Minute)
	carry := func(t *testing.T) (*relayNode, *relayNode, string) {
		t.Helper()
		nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
		a, b := nodes[0], nodes[1]
		importContact(t, a, b)
		importContact(t, b, a)
		eventID := sendText(t, a, b, "sealed", "a", now)
		if summary, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil || summary.Carried != 1 {
			t.Fatalf("first deposit: %+v %v", summary, err)
		}
		a.carrier.take()
		return a, b, eventID
	}
	held := func(t *testing.T, a, b *relayNode, eventID string, code fault.Code) {
		t.Helper()
		summary, err := a.d.dispatch.Sweep(context.Background(), 0)
		if err != nil || summary.Deferred != 1 || summary.Carried != 0 {
			t.Fatalf("gated deposit: %+v %v", summary, err)
		}
		state := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
		if state.State != eventlog.StatePending || state.Generation != 1 || state.LastCode != code {
			t.Fatalf("gated copy: state=%s generation=%d code=%s", state.State, state.Generation, state.LastCode)
		}
		if frames := a.carrier.take(); len(framesOfKind(t, frames, relayframe.KindCopy)) != 0 {
			t.Fatal("a gated copy was carried")
		}
	}
	t.Run("device revoked by a newer descriptor", func(t *testing.T) {
		a, b, eventID := carry(t)
		replaced := evidenceFor(t, b, "dev_"+strings.Repeat("8", 64), uint64(now.Add(time.Minute).Unix()),
			uint64(now.Add(50*time.Minute).Unix()))
		peer, err := a.d.discovery.relay.CheckContact(b.d.config.AgentID, replaced, later)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.d.discovery.relay.CommitPeer(peer, later); err != nil {
			t.Fatal(err)
		}
		a.d.now = func() time.Time { return later }
		held(t, a, b, eventID, fault.CodeDeviceRevoked)
	})
	t.Run("delegation withdrawn", func(t *testing.T) {
		a, b, eventID := carry(t)
		a.d.discovery.resolver.(phaseAResolver).states[b.d.config.AgentID].GetAgent().DelegationAdmissions =
			[]*nativev1.DelegationAdmissionV1{{Digest: "sha256:" + strings.Repeat("9", 64), AdmissionEpoch: 1}}
		a.d.now = func() time.Time { return later }
		held(t, a, b, eventID, fault.CodeDelegationUncommitted)
		// Moved back to pending, its last envelope may still be stored and
		// still counts against the per-peer cap.
		index, err := a.d.relay.buildIndex(later)
		if err != nil || index.envelopes[b.d.config.AgentID] != 1 || len(index.onEvidence[b.d.config.AgentID]) != 1 {
			t.Fatalf("index after deferral: %+v %v", index, err)
		}
	})
	t.Run("pending after descriptor-expired", func(t *testing.T) {
		a, b, eventID := carry(t)
		delivery := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
		ciphertext, _ := delivery.Ciphertext()
		ack := relayframe.Ack{EventID: eventID, SessionID: delivery.SessionID, RecipientEndpointID: b.d.config.EndpointID,
			RecipientDeviceID: b.d.config.DeviceID, CiphertextDigest: canon.Digest(ciphertext),
			Outcome: relayframe.OutcomeRejected, Code: fault.CodeDescriptorExpired, AcceptedAtUnix: uint64(now.Unix())}
		older := delivery
		older.Generations[0].DescriptorDigest = "sha256:" + strings.Repeat("6", 64)
		older.Generations[0].DescriptorIssuedAtUnix--
		if err := a.d.relay.applyAck(b.d.config.AgentID, delivery.Key(), older, ack, eventlog.RelayAckMatch{SessionID: delivery.SessionID,
			DeviceID: b.d.config.DeviceID, CiphertextDigest: ack.CiphertextDigest}, now); err != nil {
			t.Fatal(err)
		}
		a.d.discovery.resolver.(phaseAResolver).states[b.d.config.AgentID].GetAgent().DelegationAdmissions =
			[]*nativev1.DelegationAdmissionV1{{Digest: "sha256:" + strings.Repeat("9", 64), AdmissionEpoch: 1}}
		held(t, a, b, eventID, fault.CodeDelegationUncommitted)
	})
}

func TestARejectedFirstContactCommitsNoEvidence(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	strict := func(config *Config) {
		config.Admission.Rule = admission.RuleAllowList
		config.Admission.Unknown = admission.TellThem
	}
	nodes := newRelayNodesWith(t, now, strict, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	sendText(t, a, b, "not on the allow list", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	answer := deliver(t, a, b, onlyFrame(t, a).frame)
	if ack := ackOutcome(t, answer); ack.Outcome != relayframe.OutcomeRejected {
		t.Fatalf("first contact from an unknown sender: %+v", ack)
	}
	if _, found, _ := b.d.journal.LoadRelayEvidence(a.d.config.AgentID); found {
		t.Fatal("a rejected sender's evidence was committed")
	}
	if _, found, _ := b.d.discovery.devices.Record(a.d.config.EndpointID); found {
		t.Fatal("a rejected sender's set reached the rollback boundary")
	}
}

func TestAnAckThatSettlesACopyWhoseAttemptFailsDoesNotStopTheSweep(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	// The deposit is delivered and acknowledged, but the carrier's answer to
	// this attempt is retry: the attempt's failure meets a settled copy.
	a.carrier.answer = &carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultRetry}
	a.carrier.onCarry = func(record carried) {
		answer := b.d.relay.Deliver(context.Background(), a.d.config.AgentID, record.frame)
		if answer.Result == carrierapi.ResultAck {
			a.d.relay.DeliveryAck(context.Background(), b.d.config.AgentID, ackFrameOf(t, answer))
		}
	}
	first := sendText(t, a, b, "one", "a", now)
	second := sendText(t, a, b, "two", "b", now)
	summary, err := a.d.dispatch.Sweep(context.Background(), 0)
	if err != nil || summary.Sent != 2 || summary.Retried != 0 {
		t.Fatalf("sweep: %+v %v", summary, err)
	}
	for _, eventID := range []string{first, second} {
		if state := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID); state.State != eventlog.StateDelivered {
			t.Fatalf("copy %s: %s", eventID, state.State)
		}
	}
}

func TestTheGateOutsideASweepKeepsNoIndex(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	nodes := newRelayNodes(t, now, [2]string{"2", "4"}, [2]string{"7", "9"})
	a, b := nodes[0], nodes[1]
	importContact(t, a, b)
	importContact(t, b, a)
	eventID := sendText(t, a, b, "one", "a", now)
	if _, err := a.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if a.d.relay.index != nil {
		t.Fatal("a finished sweep left its index behind")
	}
	delivery := copyState(t, a, eventID, b.d.config.EndpointID, b.d.config.DeviceID)
	gate := relayGate{relay: a.d.relay}
	if err := gate.CheckCopy(context.Background(), delivery, false); err != nil {
		t.Fatal(err)
	}
	if a.d.relay.index != nil {
		t.Fatal("a check outside a sweep cached an index")
	}
}
