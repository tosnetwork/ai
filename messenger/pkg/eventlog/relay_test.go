package eventlog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

const relayPeerDevice = "dev_" + "9999999999999999999999999999999999999999999999999999999999999999"

func relayCopy(t *testing.T, journal *Journal, now time.Time) (string, []byte) {
	t.Helper()
	copyID, err := NewDeliveryCopyID(eventA, endpoint, relayPeerDevice)
	if err != nil {
		t.Fatal(err)
	}
	request := outbound(eventA)
	request.DeliveryID, request.RecipientDeviceID = copyID, relayPeerDevice
	if _, _, err := journal.Enqueue(request); err != nil {
		t.Fatal(err)
	}
	ciphertext := []byte("sealed relay copy bytes")
	if _, err := journal.CommitSealed(session(0x11), algorithm, 0, e2ee.State("advanced"), copyID,
		heldAttempt(t, journal, copyID, now), ciphertext, now); err != nil {
		t.Fatal(err)
	}
	return copyID, ciphertext
}

func generation(number uint32, issued uint64) RelayGeneration {
	return RelayGeneration{Generation: number, DescriptorDigest: "sha256:" + strings.Repeat("7", 64),
		DescriptorIssuedAtUnix: issued, CardDigest: "sha256:" + strings.Repeat("8", 64)}
}

func TestCarriedMovesToDeliveredOnlyOnAMatchingAck(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, ciphertext := relayCopy(t, journal, now)
	attempt := "send_" + strings.Repeat("c", 64)

	carried, err := journal.Carried(copyID, attempt, generation(1, acceptAt), now.Add(time.Hour), now)
	if err != nil || carried.State != StateCarried || carried.Generation != 1 || carried.NextRedepositAtUnix != acceptAt+3600 {
		t.Fatalf("carried: %+v %v", carried, err)
	}
	// Recording the same generation again, as after a crash, is accepted;
	// skipping a generation is not.
	if _, err := journal.Carried(copyID, attempt, generation(1, acceptAt), now.Add(time.Hour), now); err == nil {
		t.Fatal("a carried copy was recorded without holding the attempt")
	}
	if due, err := journal.Due(now.Add(30 * time.Minute)); err != nil || len(due) != 0 {
		t.Fatalf("carried copy due before its re-deposit time: %+v %v", due, err)
	}
	due, err := journal.Due(now.Add(time.Hour))
	if err != nil || len(due) != 1 || due[0].Key() != copyID {
		t.Fatalf("carried copy is not due at its re-deposit time: %+v %v", due, err)
	}
	later := now.Add(time.Hour)
	if _, err := journal.ClaimForSend(copyID, attempt, later, time.Minute); err != nil {
		t.Fatalf("claim re-deposit: %v", err)
	}
	if _, err := journal.Carried(copyID, attempt, generation(3, acceptAt), later.Add(time.Hour), later); err == nil {
		t.Fatal("a skipped generation was recorded")
	}
	if _, err := journal.Carried(copyID, attempt, generation(2, acceptAt+10), later.Add(time.Hour), later); err != nil {
		t.Fatalf("second generation: %v", err)
	}

	match := RelayAckMatch{SessionID: session(0x11), DeviceID: relayPeerDevice, CiphertextDigest: canon.Digest(ciphertext)}
	for name, wrong := range map[string]RelayAckMatch{
		"session":    {SessionID: session(0x22), DeviceID: match.DeviceID, CiphertextDigest: match.CiphertextDigest},
		"device":     {SessionID: match.SessionID, DeviceID: "dev_" + strings.Repeat("1", 64), CiphertextDigest: match.CiphertextDigest},
		"ciphertext": {SessionID: match.SessionID, DeviceID: match.DeviceID, CiphertextDigest: canon.Digest([]byte("other"))},
	} {
		if _, _, err := journal.DeliveredByAck(copyID, wrong, later); !errors.Is(err, ErrAckMismatch) {
			t.Fatalf("ack with another %s settled the copy: %v", name, err)
		}
	}
	if record, _, _ := journal.LookupDeliveryCopy(copyID); record.State != StateCarried {
		t.Fatalf("a mismatched ack changed the copy: %+v", record)
	}
	settled, changed, err := journal.DeliveredByAck(copyID, match, later)
	if err != nil || !changed || settled.State != StateDelivered || len(settled.Generations) != 2 {
		t.Fatalf("delivered: %+v changed=%v %v", settled, changed, err)
	}
	if _, changed, err := journal.DeliveredByAck(copyID, match, later); err != nil || changed {
		t.Fatalf("a second ack changed a delivered copy: changed=%v %v", changed, err)
	}
	if _, _, err := journal.DeliveredByAck("cpy_"+strings.Repeat("0", 64), match, later); !errors.Is(err, ErrUnknown) {
		t.Fatalf("ack for an unknown copy: %v", err)
	}
}

func TestDescriptorExpiredRejectionKeepsTheCopyPendingWithItsRetryTime(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, ciphertext := relayCopy(t, journal, now)
	attempt := "send_" + strings.Repeat("c", 64)
	if _, err := journal.Carried(copyID, attempt, generation(1, acceptAt), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	match := RelayAckMatch{SessionID: session(0x11), DeviceID: relayPeerDevice, CiphertextDigest: canon.Digest(ciphertext)}
	refused := "sha256:" + strings.Repeat("7", 64)
	if _, err := journal.RelayRejected(copyID, match, fault.CodeDescriptorExpired, "", now, now); err == nil {
		t.Fatal("descriptor-expired without the refused descriptor was recorded")
	}
	pending, err := journal.RelayRejected(copyID, match, fault.CodeDescriptorExpired, refused, now.Add(time.Minute), now)
	if err != nil || pending.State != StatePending || pending.LastCode != fault.CodeDescriptorExpired ||
		pending.RejectedDescriptorDigest != refused || pending.NextAttemptAtUnix != acceptAt+60 || pending.Generation != 1 {
		t.Fatalf("descriptor-expired: %+v %v", pending, err)
	}
	if ciphertext, err := pending.Ciphertext(); err != nil || ciphertext == nil {
		t.Fatal("a rejected copy lost its ciphertext; a retry would re-seal")
	}
	// A late accepted ack for the earlier generation still settles it.
	if settled, changed, err := journal.DeliveredByAck(copyID, match, now); err != nil || !changed || settled.State != StateDelivered {
		t.Fatalf("late accepted ack: %+v %v", settled, err)
	}
}

func TestOtherRejectionsTakeTheirCodesDisposition(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, ciphertext := relayCopy(t, journal, now)
	if _, err := journal.Carried(copyID, "send_"+strings.Repeat("c", 64), generation(1, acceptAt), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	match := RelayAckMatch{SessionID: session(0x11), DeviceID: relayPeerDevice, CiphertextDigest: canon.Digest(ciphertext)}
	abandoned, err := journal.RelayRejected(copyID, match, fault.CodeClassNotDelegated, "", now, now)
	if err != nil || abandoned.State != StateAbandoned || abandoned.LastCode != fault.CodeClassNotDelegated {
		t.Fatalf("permanent rejection: %+v %v", abandoned, err)
	}
}

func TestDeferReleasesTheAttemptWithoutCountingIt(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, _ := relayCopy(t, journal, now)
	attempt := "send_" + strings.Repeat("c", 64)
	if _, err := journal.Carried(copyID, attempt, generation(1, acceptAt), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	if _, err := journal.ClaimForSend(copyID, attempt, later, time.Minute); err != nil {
		t.Fatal(err)
	}
	deferred, err := journal.Defer(copyID, attempt, fault.CodeDescriptorExpired, later.Add(time.Minute), later)
	if err != nil || deferred.State != StatePending || deferred.Attempts != 0 || deferred.Generation != 1 ||
		deferred.NextAttemptAtUnix != uint64(later.Add(time.Minute).Unix()) || deferred.AttemptID != "" {
		t.Fatalf("deferred: %+v %v", deferred, err)
	}
	if _, err := journal.Defer(copyID, attempt, fault.CodeDescriptorExpired, later.Add(time.Minute), later); err == nil {
		t.Fatal("a deferral without the attempt was recorded")
	}
	woken, err := journal.WakeDeliveries([]string{copyID, "cpy_" + strings.Repeat("0", 64)}, later)
	if err != nil || woken != 1 {
		t.Fatalf("wake: %d %v", woken, err)
	}
	if due, err := journal.Due(later); err != nil || len(due) != 1 {
		t.Fatalf("woken copy is not due: %+v %v", due, err)
	}
}

func TestCarriedCopyPastItsExpiryIsAbandonedWithRetentionExceeded(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, _ := relayCopy(t, journal, now)
	if _, err := journal.Carried(copyID, "send_"+strings.Repeat("c", 64), generation(1, acceptAt), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	expired, err := journal.ExpireDeliveries(now.Add(48 * time.Hour))
	if err != nil || expired != 1 {
		t.Fatalf("expire: %d %v", expired, err)
	}
	record, _, err := journal.LookupDeliveryCopy(copyID)
	if err != nil || record.State != StateAbandoned || record.LastCode != fault.CodeRetentionExceeded {
		t.Fatalf("expired carried copy: %+v %v", record, err)
	}
}

func TestEventCommittedInSessionRecognisesEveryCommittedEvent(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.CommitInbound(session(0x11), algorithm, 0, e2ee.State("one"), entry(eventA, endpoint), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.CommitInbound(session(0x11), algorithm, 1, e2ee.State("two"), entry(eventB, endpoint), now); err != nil {
		t.Fatal(err)
	}
	record, _, _ := journal.SessionState(session(0x11))
	if record.LastInboundEventID != eventB {
		t.Fatalf("last inbound %s", record.LastInboundEventID)
	}
	for _, test := range []struct {
		session, event string
		want           bool
	}{
		{session(0x11), eventA, true},
		{session(0x11), eventB, true},
		{session(0x22), eventA, false},
		{session(0x11), "evt_" + strings.Repeat("c", 64), false},
	} {
		got, err := journal.EventCommittedInSession(test.session, test.event)
		if err != nil || got != test.want {
			t.Fatalf("%s in %s: %v %v", test.event, test.session, got, err)
		}
	}
	if _, err := journal.EventCommittedInSession("ses_x", eventA); err == nil {
		t.Fatal("invalid session accepted")
	}
}

func TestRelayEvidenceStoreComparesAndSwaps(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	peer := "agent_" + strings.Repeat("7", 64)
	if _, found, err := journal.LoadRelayEvidence(peer); err != nil || found {
		t.Fatalf("empty store: %v %v", found, err)
	}
	first, second := []byte("first evidence"), []byte("second evidence")
	if err := journal.StoreRelayEvidence(peer, first, canon.Digest([]byte("none")), now); !errors.Is(err, ErrRelayEvidenceConflict) {
		t.Fatalf("store over nothing with a previous digest: %v", err)
	}
	if err := journal.StoreRelayEvidence(peer, first, "", now); err != nil {
		t.Fatal(err)
	}
	if err := journal.StoreRelayEvidence(peer, second, "", now); !errors.Is(err, ErrRelayEvidenceConflict) {
		t.Fatalf("a stale writer replaced stored evidence: %v", err)
	}
	if err := journal.StoreRelayEvidence(peer, second, canon.Digest(first), now); err != nil {
		t.Fatal(err)
	}
	stored, found, err := journal.LoadRelayEvidence(peer)
	if err != nil || !found || !bytes.Equal(stored, second) {
		t.Fatalf("stored: %q %v %v", stored, found, err)
	}
	for _, bad := range [][]byte{nil, make([]byte, maxRelayEvidenceBytes+1)} {
		if err := journal.StoreRelayEvidence(peer, bad, canon.Digest(second), now); err == nil {
			t.Fatalf("evidence of %d bytes stored", len(bad))
		}
	}
	if err := journal.StoreRelayEvidence("agent_x", first, "", now); err == nil {
		t.Fatal("invalid Agent stored")
	}
}

func TestRelayPullRecordRoundTrips(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	peer := "agent_" + strings.Repeat("7", 64)
	pull, found, err := journal.LoadRelayPull(peer)
	if err != nil || found || pull.Requested {
		t.Fatalf("fresh pull: %+v %v %v", pull, found, err)
	}
	pull.Requested = true
	if err := journal.PutRelayPull(pull, now); err == nil {
		t.Fatal("an outstanding request without a schedule was stored")
	}
	pull.RequestNextAtUnix = acceptAt
	if err := journal.PutRelayPull(pull, now); err != nil {
		t.Fatal(err)
	}
	listed, err := journal.ListRelayPulls()
	if err != nil || len(listed) != 1 || listed[0].AgentID != peer {
		t.Fatalf("listed: %+v %v", listed, err)
	}
	pull.Requested, pull.RequestNextAtUnix = false, 0
	if err := journal.PutRelayPull(pull, now); err != nil {
		t.Fatal(err)
	}
	if listed, err := journal.ListRelayPulls(); err != nil || len(listed) != 0 {
		t.Fatalf("an ended request is still listed: %+v %v", listed, err)
	}
}

func TestAPreRelayDeliveryJournalIsRefused(t *testing.T) {
	journal, root := openJournal(t)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"schema":"tos.messaging.delivery-journal.v1","event_id":"` + eventA + `"}`)
	if err := os.WriteFile(filepath.Join(root, outboundDir, "legacy.json"), legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); !errors.Is(err, ErrPreRelayDeliveryJournal) || err.Error() != "pre-relay delivery journal; reset state" {
		t.Fatalf("open over a v1 delivery record: %v", err)
	}
}

func TestAnAckForASealedCopyNotYetRecordedAsCarriedSettlesIt(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, ciphertext := relayCopy(t, journal, now)
	match := RelayAckMatch{SessionID: session(0x11), DeviceID: relayPeerDevice, CiphertextDigest: canon.Digest(ciphertext)}
	settled, changed, err := journal.DeliveredByAck(copyID, match, now)
	if err != nil || !changed || settled.State != StateDelivered || settled.Generation != 0 {
		t.Fatalf("ack before Carried: %+v %v", settled, err)
	}
	// The attempt that was carrying it then finds nothing to record.
	if _, err := journal.Carried(copyID, "send_"+strings.Repeat("c", 64), generation(1, acceptAt), now.Add(time.Hour), now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("Carried after the ack: %v", err)
	}
	// An unsealed copy has no ciphertext an ack could bind, and is refused.
	unsealed, err := NewDeliveryCopyID(eventB, endpoint, relayPeerDevice)
	if err != nil {
		t.Fatal(err)
	}
	request := outbound(eventB)
	request.DeliveryID, request.RecipientDeviceID = unsealed, relayPeerDevice
	if _, _, err := journal.Enqueue(request); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.DeliveredByAck(unsealed, match, now); !errors.Is(err, ErrAckMismatch) {
		t.Fatalf("ack for an unsealed copy: %v", err)
	}
}

func TestDescriptorExpiredPastTheCopysExpiryIsRetentionExceeded(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	copyID, ciphertext := relayCopy(t, journal, now)
	if _, err := journal.Carried(copyID, "send_"+strings.Repeat("c", 64), generation(1, acceptAt), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	match := RelayAckMatch{SessionID: session(0x11), DeviceID: relayPeerDevice, CiphertextDigest: canon.Digest(ciphertext)}
	abandoned, err := journal.RelayRejected(copyID, match, fault.CodeDescriptorExpired, "sha256:"+strings.Repeat("7", 64),
		now.Add(48*time.Hour), now)
	if err != nil || abandoned.State != StateAbandoned || abandoned.LastCode != fault.CodeRetentionExceeded {
		t.Fatalf("descriptor-expired past expiry: %+v %v", abandoned, err)
	}
}
