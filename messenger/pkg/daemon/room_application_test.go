package daemon

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// Application objects are sealed in-process (no sender side exists yet): the
// authority seals through its own controller, and a joined member C through
// the driver on the state its Welcome made. Each receiver check is red
// controlled by an object made to fail exactly that check.

// sealer seals application objects as one member at its current epochs.
type sealer struct {
	t      *testing.T
	member roomMember
	// seal encrypts under the member's current MLS state.
	seal func(aad, plaintext []byte) []byte
	// epochs reports the member's room epoch, MLS epoch and epoch
	// authenticator.
	epochs func() (uint64, uint64, []byte)
}

// authoritySealer seals as the test authority.
func authoritySealer(t *testing.T, authority *testAuthority) *sealer {
	return &sealer{t: t, member: authority.member,
		seal: func(aad, plaintext []byte) []byte {
			t.Helper()
			message, record, err := authority.controller.Seal(testRoomID, aad, plaintext)
			if err != nil {
				t.Fatalf("authority seal: %v", err)
			}
			authority.record = record
			return message
		},
		epochs: func() (uint64, uint64, []byte) {
			authenticator, _ := authority.record.EpochAuthenticatorAt(authority.record.MLSEpoch)
			return authority.record.RoomEpoch, authority.record.MLSEpoch, authenticator
		}}
}

// memberSealer joins member C through its Welcome from the scene's Add and
// seals on the state it holds.
func memberSealer(t *testing.T, scene *joinedScene) *sealer {
	t.Helper()
	state, err := scene.driver.Join(scene.c.identity.State, scene.addC.Welcomes[scene.c.leaf.KeyPackageRef])
	if err != nil {
		t.Fatalf("C joins: %v", err)
	}
	roomEpoch := scene.addC.Transition.Next.Clock.RoomEpoch
	return &sealer{t: t, member: scene.c,
		seal: func(aad, plaintext []byte) []byte {
			t.Helper()
			next, message, err := scene.driver.Seal(state, aad, plaintext)
			if err != nil {
				t.Fatalf("member seal: %v", err)
			}
			state = next
			return message
		},
		epochs: func() (uint64, uint64, []byte) {
			info, err := scene.driver.Inspect(state)
			if err != nil {
				t.Fatal(err)
			}
			return roomEpoch, info.Epoch, info.EpochAuthenticator
		}}
}

// sealed is one application object and the Event it carries.
type sealed struct {
	object []byte
	event  envelope.Event
}

// sealOptions change what a sealed object binds, each to fail one check.
type sealOptions struct {
	// aad changes the AAD fields before encoding; raw the encoded bytes.
	aad func(*relayframe.RoomAAD)
	raw func([]byte) []byte
	// event changes the Event before its ID is derived.
	event func(*envelope.Event)
}

// roomEvent is a room.message of a member with a sequence.
func roomEvent(t *testing.T, member roomMember, roomEpoch, sequence uint64, body string, now time.Time) envelope.Event {
	t.Helper()
	content, err := payload.Encode(payload.RoomMessage{RoomID: testRoomID, Epoch: roomEpoch, MediaType: "text/plain; charset=utf-8",
		Body: body, Sequence: sequence})
	if err != nil {
		t.Fatal(err)
	}
	return envelope.Event{Network: member.delegation.Network, ConversationID: "conv_" + strings.Repeat("c3", 32),
		SenderAgentID: member.agent(), SenderEndpointID: member.delegation.EndpointID,
		SenderDeviceID: member.node.d.config.DeviceID, RoomID: testRoomID, CreatedAtUnix: uint64(now.Unix()),
		Kind: "room.message", Content: content}
}

// message seals one room.message at the sealer's current epochs.
func (s *sealer) message(sequence uint64, body string, now time.Time, options sealOptions) sealed {
	s.t.Helper()
	roomEpoch, mlsEpoch, authenticator := s.epochs()
	draft := roomEvent(s.t, s.member, roomEpoch, sequence, body, now)
	if options.event != nil {
		options.event(&draft)
	}
	event, err := envelope.NewEvent(draft)
	if err != nil {
		s.t.Fatal(err)
	}
	fields := relayframe.RoomAAD{RoomID: testRoomID, RoomEpoch: roomEpoch, MLSEpoch: mlsEpoch,
		EpochAuthenticator: authenticator, SenderAgentID: s.member.agent(), EventID: event.EventID}
	if options.aad != nil {
		options.aad(&fields)
	}
	aad, err := relayframe.EncodeRoomAAD(fields)
	if err != nil {
		s.t.Fatal(err)
	}
	if options.raw != nil {
		aad = options.raw(aad)
	}
	plaintext, err := envelope.EncodeEventJSON(event)
	if err != nil {
		s.t.Fatal(err)
	}
	object, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: relayframe.RoomApplication, RoomID: testRoomID,
		RoomEpoch: roomEpoch, MLSEpoch: mlsEpoch, Body: s.seal(aad, plaintext)})
	if err != nil {
		s.t.Fatal(err)
	}
	return sealed{object: object, event: event}
}

// deliverApplication sends an application object from a packet sender (whose
// card and evidence go in part 0) and returns the answer.
func deliverApplication(t *testing.T, receiver *relayNode, from roomMember, object []byte) carrierapi.Response {
	t.Helper()
	frames := framesOf(t, from, object, 0)
	if len(frames) != 1 {
		t.Fatalf("an application object was cut into %d parts", len(frames))
	}
	return send(t, receiver, from.agent(), frames)
}

// committed reports whether the receiver journaled an Event.
func committed(t *testing.T, receiver *relayNode, eventID string) bool {
	t.Helper()
	_, found, err := receiver.d.journal.Lookup(eventID)
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// seenAt reports whether the receiver marked an object's digest received.
func seenAt(t *testing.T, receiver *relayNode, sender string, object []byte) bool {
	t.Helper()
	seen, err := receiver.d.journal.RoomApplicationSeen(testRoomID, sender, eventlog.RoomObjectDigest(object), receiver.d.clock())
	if err != nil {
		t.Fatal(err)
	}
	return seen
}

// requireOpened requires an object to have been admitted, its Event journaled,
// its digest marked and the receiver's ratchet advanced.
func requireOpened(t *testing.T, receiver *relayNode, response carrierapi.Response, sender string, message sealed,
	before eventlog.RoomMLSRecord) {
	t.Helper()
	if response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("answered %s/%s, want admitted", response.Result, response.Code)
	}
	if !committed(t, receiver, message.event.EventID) {
		t.Fatal("the opened Event was not journaled")
	}
	if !seenAt(t, receiver, sender, message.object) {
		t.Fatal("the opened object was not marked received")
	}
	if after, _ := fused(t, receiver); after.StateDigest == before.StateDigest {
		t.Fatal("opening spent no ratchet step")
	}
}

// requireRefusedUnspent requires a refusal that journaled nothing, marked
// nothing and left the receiver's MLS state as it was.
func requireRefusedUnspent(t *testing.T, receiver *relayNode, response carrierapi.Response, result carrierapi.Result,
	sender string, message sealed, before eventlog.RoomMLSRecord) {
	t.Helper()
	if response.Result != result {
		t.Fatalf("answered %s/%s, want %s", response.Result, response.Code, result)
	}
	if committed(t, receiver, message.event.EventID) {
		t.Fatal("a refused object's Event was journaled")
	}
	if seenAt(t, receiver, sender, message.object) {
		t.Fatal("a refused object was marked received")
	}
	if after, _ := fused(t, receiver); after.StateDigest != before.StateDigest {
		t.Fatal("a refused object spent the ratchet step")
	}
}

// gapsOf lists the receiver's gap records of the room.
func gapsOf(t *testing.T, receiver *relayNode) []eventlog.RoomGap {
	t.Helper()
	gaps, err := receiver.d.journal.RoomGaps(testRoomID, 0)
	if err != nil {
		t.Fatal(err)
	}
	return gaps
}

// requireGap requires exactly one gap record of the sender with the reason
// and dropped count.
func requireGap(t *testing.T, receiver *relayNode, sender string, reason eventlog.RoomGapReason, dropped uint32) {
	t.Helper()
	var found []eventlog.RoomGap
	for _, gap := range gapsOf(t, receiver) {
		if gap.SenderAgentID == sender && gap.Reason == reason {
			found = append(found, gap)
		}
	}
	if len(found) != 1 || found[0].Dropped != dropped {
		t.Fatalf("gaps of %s for %s: %+v, want one with %d dropped", sender, reason, found, dropped)
	}
}

// A member's application object at the current epoch is opened, admitted
// under D11, journaled once and marked; its redelivery is dropped before the
// driver runs, spending nothing and raising no notice. A member other than
// the authority is opened the same way.
func TestRoomApplicationOpensAdmitsAndDropsItsReplay(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	a := authoritySealer(t, scene.authority)
	before, _ := fused(t, b)
	first := a.message(1, "hello from the authority", scene.clock.now(), sealOptions{})
	requireOpened(t, b, deliverApplication(t, b, scene.a, first.object), scene.a.agent(), first, before)
	replayed, _ := fused(t, b)
	if response := deliverApplication(t, b, scene.a, first.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("the replay answered %s/%s", response.Result, response.Code)
	}
	if after, _ := fused(t, b); after.StateDigest != replayed.StateDigest {
		t.Fatal("the replay spent a ratchet step")
	}
	if n := reports.count(func(err error) bool { return errors.Is(err, ErrRoomForkSuspected) }); n != 0 {
		t.Fatalf("the replay raised %d fork notices", n)
	}
	c := memberSealer(t, scene)
	from := c.message(1, "hello from C", scene.clock.now(), sealOptions{})
	requireOpened(t, b, deliverApplication(t, b, scene.c, from.object), scene.c.agent(), from, replayed)
	// A missing sequence of the authority becomes a gap T after a later one.
	third := a.message(3, "the authority skipped 2", scene.clock.now(), sealOptions{})
	opened, _ := fused(t, b)
	requireOpened(t, b, deliverApplication(t, b, scene.a, third.object), scene.a.agent(), third, opened)
	b.d.relay.rooms.maintain()
	if gaps := gapsOf(t, b); len(gaps) != 0 {
		t.Fatalf("a range was declared before T: %+v", gaps)
	}
	scene.clock.set(scene.clock.now().Add(testRoomGapDelay))
	b.d.relay.rooms.maintain()
	gaps := gapsOf(t, b)
	if len(gaps) != 1 || gaps[0].SenderAgentID != scene.a.agent() || gaps[0].Reason != eventlog.RoomGapNotArrived ||
		gaps[0].FirstSequence != 2 || gaps[0].LastSequence != 2 {
		t.Fatalf("the declared gap: %+v", gaps)
	}
}

// Each of the six AAD bindings, and the strict decoding, is checked after the
// open: an object whose AAD fails one is refused not-authentic, and the
// state the driver returned is discarded, so nothing is journaled, marked or
// spent. A correct object opens afterwards.
func TestRoomApplicationAADMustBindTheObject(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	other := "room_" + strings.Repeat("5e", 32)
	variants := []struct {
		name    string
		options sealOptions
	}{
		{"room", sealOptions{aad: func(aad *relayframe.RoomAAD) { aad.RoomID = other }}},
		{"room epoch", sealOptions{aad: func(aad *relayframe.RoomAAD) { aad.RoomEpoch-- }}},
		{"MLS epoch", sealOptions{aad: func(aad *relayframe.RoomAAD) { aad.MLSEpoch-- }}},
		{"epoch authenticator", sealOptions{aad: func(aad *relayframe.RoomAAD) { aad.EpochAuthenticator = bytes.Repeat([]byte{9}, 32) }}},
		{"sender", sealOptions{aad: func(aad *relayframe.RoomAAD) { aad.SenderAgentID = scene.c.agent() }}},
		{"event", sealOptions{aad: func(aad *relayframe.RoomAAD) { aad.EventID = "evt_" + strings.Repeat("e1", 32) }}},
		{"trailing byte", sealOptions{raw: func(aad []byte) []byte { return append(aad, 0) }}},
	}
	for index, variant := range variants {
		before, _ := fused(t, b)
		message := a.message(uint64(index+1), "variant "+variant.name, scene.clock.now(), variant.options)
		response := deliverApplication(t, b, scene.a, message.object)
		if response.Code != carrierapi.CodeNotAccepted {
			t.Fatalf("%s: answered %s/%s", variant.name, response.Result, response.Code)
		}
		requireRefusedUnspent(t, b, response, carrierapi.ResultRefused, scene.a.agent(), message, before)
	}
	before, _ := fused(t, b)
	control := a.message(uint64(len(variants)+1), "bound to the object", scene.clock.now(), sealOptions{})
	requireOpened(t, b, deliverApplication(t, b, scene.a, control.object), scene.a.agent(), control, before)
}

// D11 judges the opened Event: one naming another room than the object's is
// refused after the open, discarded like an AAD failure.
func TestRoomApplicationEventNamingAnotherRoomIsRefusedUnspent(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	before, _ := fused(t, b)
	message := a.message(1, "names another room", scene.clock.now(), sealOptions{event: func(event *envelope.Event) {
		event.RoomID = "room_" + strings.Repeat("5e", 32)
	}})
	requireRefusedUnspent(t, b, deliverApplication(t, b, scene.a, message.object), carrierapi.ResultRefused,
		scene.a.agent(), message, before)
}

// An authenticated current member's object that opens as another leaf's, or
// does not open, is room-fork-suspected: one owner notice, relay-acknowledged,
// nothing journaled or spent.
func TestRoomApplicationOfAnotherLeafOrUnopenableIsForkSuspected(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	a := authoritySealer(t, scene.authority)
	before, _ := fused(t, b)
	// C, a member whose credential B knows, carries a message A sealed.
	carried := a.message(1, "sealed by A, carried by C", scene.clock.now(), sealOptions{aad: func(aad *relayframe.RoomAAD) {
		aad.SenderAgentID = scene.c.agent()
	}})
	requireRefusedUnspent(t, b, deliverApplication(t, b, scene.c, carried.object), carrierapi.ResultIgnored,
		scene.c.agent(), carried, before)
	if n := reports.count(func(err error) bool { return errors.Is(err, ErrRoomForkSuspected) }); n != 1 {
		t.Fatalf("%d fork notices, want 1", n)
	}
	// A's own message, damaged after sealing, does not open.
	damaged := a.message(2, "damaged", scene.clock.now(), sealOptions{})
	decoded, err := relayframe.DecodeRoomObject(damaged.object)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Body[len(decoded.Body)-1] ^= 0x01
	if damaged.object, err = relayframe.EncodeRoomObject(decoded); err != nil {
		t.Fatal(err)
	}
	requireRefusedUnspent(t, b, deliverApplication(t, b, scene.a, damaged.object), carrierapi.ResultIgnored,
		scene.a.agent(), damaged, before)
	if n := reports.count(func(err error) bool { return errors.Is(err, ErrRoomForkSuspected) }); n != 1 {
		t.Fatalf("%d fork notices after the second, want still 1 (one per room)", n)
	}
	if gaps := gapsOf(t, b); len(gaps) != 0 {
		t.Fatalf("a fork-suspected object recorded gaps: %+v", gaps)
	}
}

// The e/r rules: e = r + 1 is held and opened once its Commit applies; r - 1
// opens with the retained secrets; e < r - 2 and e > r + 4 are dropped as
// gaps, relay-acknowledged.
func TestRoomApplicationEpochRules(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	now := scene.clock.now()
	early := a.message(1, "sealed at r", now, sealOptions{})
	commit := func() []byte {
		result, membership := scene.authority.commit()
		return scene.authority.commitObject(result, membership)
	}
	apply := func(object []byte) {
		t.Helper()
		if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, object, 0))); ack.Outcome != relayframe.OutcomeAccepted {
			t.Fatalf("B applies a refresh: %+v", ack)
		}
	}
	third := commit()
	ahead := a.message(2, "sealed at r + 1", now, sealOptions{})
	old := a.message(3, "sealed at r + 1, opened too late", now, sealOptions{})
	before, _ := fused(t, b)
	if response := deliverApplication(t, b, scene.a, ahead.object); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("a next-epoch object answered %s/%s", response.Result, response.Code)
	}
	if committed(t, b, ahead.event.EventID) {
		t.Fatal("a next-epoch object was opened before its Commit")
	}
	requireUnmoved(t, b, before)
	apply(third)
	if !committed(t, b, ahead.event.EventID) || !seenAt(t, b, scene.a.agent(), ahead.object) {
		t.Fatal("the held object was not opened once its Commit applied")
	}
	// r - 1 opens with the retained secrets.
	before, _ = fused(t, b)
	requireOpened(t, b, deliverApplication(t, b, scene.a, early.object), scene.a.agent(), early, before)
	// e > r + 4: A moves 5 epochs ahead of B.
	var pending [][]byte
	for range eventlog.RoomBufferLookahead + 1 {
		pending = append(pending, commit())
	}
	far := a.message(4, "sealed beyond r + 4", now, sealOptions{})
	before, _ = fused(t, b)
	requireRefusedUnspent(t, b, deliverApplication(t, b, scene.a, far.object), carrierapi.ResultIgnored, scene.a.agent(), far, before)
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapEpochTooNew, 1)
	// B catches up: the next sequence the authority sends fixes the dropped
	// object's range (3 has not arrived either), and an object of an epoch
	// more than two behind B is dropped as epoch-too-old.
	for _, object := range pending {
		apply(object)
	}
	next := a.message(5, "after the catch-up", now, sealOptions{})
	before, _ = fused(t, b)
	requireOpened(t, b, deliverApplication(t, b, scene.a, next.object), scene.a.agent(), next, before)
	gaps := gapsOf(t, b)
	if len(gaps) != 1 || gaps[0].FirstSequence != 3 || gaps[0].LastSequence != 4 {
		t.Fatalf("the dropped object's range: %+v", gaps)
	}
	before, _ = fused(t, b)
	requireRefusedUnspent(t, b, deliverApplication(t, b, scene.a, old.object), carrierapi.ResultIgnored, scene.a.agent(), old, before)
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapEpochTooOld, 1)
}

// buffered lists the receiver's buffered objects of the room it could open.
func buffered(t *testing.T, receiver *relayNode) (openable, awaiting int) {
	t.Helper()
	ready, _, err := receiver.d.journal.OpenableRoomObjects(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	waiting, _, err := receiver.d.journal.RoomObjectsAwaitingCredential(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	return len(ready), len(waiting)
}

// An object at the current epoch from a member whose leaf credential is not
// known yet (its roster has not arrived) is held, its evidence checked
// against its own Endpoint and device, and nothing of it renews the sender;
// it is opened once the roster teaches the credential (section 11.8).
func TestRoomApplicationOfAnUnknownCredentialIsHeldUntilItsRoster(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	c := memberSealer(t, scene)
	before, _ := fused(t, b)
	held := c.message(1, "before C's roster", scene.clock.now(), sealOptions{})
	if response := deliverApplication(t, b, scene.c, held.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("an unknown credential's object answered %s/%s", response.Result, response.Code)
	}
	if committed(t, b, held.event.EventID) {
		t.Fatal("an object was opened before its sender's credential was known")
	}
	if _, waiting := buffered(t, b); waiting != 1 {
		t.Fatalf("%d objects await the credential, want 1", waiting)
	}
	if _, found, err := b.d.journal.LoadRelayEvidence(scene.c.agent()); err != nil || found {
		t.Fatalf("unpinned evidence was committed: %v %v", found, err)
	}
	requireUnmoved(t, b, before)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, scene.added, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the roster of added members: %+v", ack)
	}
	if !committed(t, b, held.event.EventID) || !seenAt(t, b, scene.c.agent(), held.object) {
		t.Fatal("the held object was not opened once the roster taught its credential")
	}
	if ready, waiting := buffered(t, b); ready != 0 || waiting != 0 {
		t.Fatalf("the opened object stayed buffered: %d %d", ready, waiting)
	}
}

// A held object whose sender the next roster does not teach is refused
// not-authentic and released, and nothing of it is opened (section 11.8).
func TestRoomApplicationOfAnUnknownCredentialIsRefusedAfterARosterWithoutIt(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	c := memberSealer(t, scene)
	held := c.message(1, "never authenticated", scene.clock.now(), sealOptions{})
	if response := deliverApplication(t, b, scene.c, held.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("an unknown credential's object answered %s/%s", response.Result, response.Code)
	}
	// The roster for the room epoch carries only the authority's entry.
	roster := scene.authority.rosterObject(scene.authority.record.Membership(), rosterEntry(t, scene.a))
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, roster, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a roster without C: %+v", ack)
	}
	if committed(t, b, held.event.EventID) || seenAt(t, b, scene.c.agent(), held.object) {
		t.Fatal("an object of an untaught sender was opened")
	}
	if ready, waiting := buffered(t, b); ready != 0 || waiting != 0 {
		t.Fatalf("the refused object stayed buffered: %d %d", ready, waiting)
	}
}

// A buffered object has no frame evidence: it is opened against the
// sender's stored evidence, pinned to its credential. A roster whose entry
// for the sender carries stale evidence teaches the credential but commits no
// evidence, so the object stays held; once evidence is committed (as a
// kind-4 pull would), the maintenance pass opens it.
func TestRoomApplicationHeldUntilTheSendersStoredEvidenceChecks(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	c := memberSealer(t, scene)
	held := c.message(1, "waits for evidence", scene.clock.now(), sealOptions{})
	if response := deliverApplication(t, b, scene.c, held.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("an unknown credential's object answered %s/%s", response.Result, response.Code)
	}
	entry := rosterEntry(t, scene.c)
	entry.Evidence = evidenceFor(t, scene.c.node, scene.c.node.d.config.DeviceID, uint64(scene.start.Add(-30*time.Second).Unix()),
		uint64(scene.start.Add(30*time.Second).Unix()))
	scene.clock.set(scene.start.Add(2 * time.Minute))
	roster := scene.authority.rosterObject(scene.authority.record.Membership(), entry)
	if ack := roomAckOf(t, b, send(t, b, scene.a.agent(), framesOf(t, scene.a, roster, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("a roster with C's stale evidence: %+v", ack)
	}
	if _, found := credentialOf(t, b, scene.c.agent()); !found {
		t.Fatal("the stale evidence dropped C's verifying credential")
	}
	if committed(t, b, held.event.EventID) {
		t.Fatal("an object was opened without stored evidence pinned to its credential")
	}
	if ready, _ := buffered(t, b); ready != 1 {
		t.Fatalf("%d openable objects, want the held one", ready)
	}
	b.d.relay.rooms.maintain()
	if committed(t, b, held.event.EventID) {
		t.Fatal("the maintenance pass opened an object without stored evidence")
	}
	pin, err := directory.LeafPin(scene.c.agent(), scene.c.credential, scene.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := b.d.relay.verifier.CheckPeer(scene.c.agent(), scene.c.evidence, pin, scene.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.d.relay.verifier.CommitPeer(peer, scene.clock.now()); err != nil {
		t.Fatal(err)
	}
	b.d.relay.rooms.maintain()
	if !committed(t, b, held.event.EventID) {
		t.Fatal("the held object was not opened once the stored evidence checked")
	}
}

// An application object arriving at end + skew is refused room-ended: one
// owner notice, and a gap of its sender, recorded before it is
// relay-acknowledged (D18).
func TestRoomApplicationAfterTheEndIsARoomEndedGap(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	reports := &recordingReports{}
	b.d.observer = reports
	a := authoritySealer(t, scene.authority)
	late := a.message(1, "sealed before the end", scene.clock.now(), sealOptions{})
	record, _ := fused(t, b)
	scene.clock.set(time.Unix(int64(record.RoomEndsAtUnix), 0).Add(5 * time.Minute))
	for range 2 {
		response := deliverApplication(t, b, scene.a, late.object)
		if response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeNotAccepted {
			t.Fatalf("a late object answered %s/%s", response.Result, response.Code)
		}
	}
	if committed(t, b, late.event.EventID) {
		t.Fatal("a late object was opened")
	}
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapRoomEnded, 2)
	if n := reports.count(func(err error) bool { return errors.Is(err, ErrRoomEnded) }); n != 1 {
		t.Fatalf("%d room-ended notices, want 1", n)
	}
}

// A member removed from the room still opens objects sealed in the epochs it
// was a member of, and drops later ones as gaps without holding them
// (section 11.4).
func TestRoomRemovedMemberReadsUpToItsRemovalEpoch(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	inFlight := a.message(1, "sealed before the removal", scene.clock.now(), sealOptions{})
	removal := removeCommit(t, scene, scene.b)
	if response := send(t, b, scene.a.agent(), framesOf(t, scene.a, removal, 0)); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("the removal Commit: %s/%s", response.Result, response.Code)
	}
	after := a.message(2, "sealed after the removal", scene.clock.now(), sealOptions{})
	before, _ := fused(t, b)
	requireOpened(t, b, deliverApplication(t, b, scene.a, inFlight.object), scene.a.agent(), inFlight, before)
	opened, _ := fused(t, b)
	requireRefusedUnspent(t, b, deliverApplication(t, b, scene.a, after.object), carrierapi.ResultIgnored, scene.a.agent(), after, opened)
	if _, waiting := buffered(t, b); waiting != 0 {
		t.Fatal("an object of an epoch after the removal was held")
	}
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapEpochTooNew, 1)
}

// A sender's share of the future-epoch buffer holds 16 objects; the next is
// dropped as a buffer-full gap.
func TestRoomApplicationBeyondTheSendersBufferShareIsABufferFullGap(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	scene.authority.commit()
	for index := range eventlog.MaxRoomBufferSenderObjects {
		message := a.message(uint64(index+1), "ahead", scene.clock.now(), sealOptions{})
		if response := deliverApplication(t, b, scene.a, message.object); response.Result != carrierapi.ResultAdmitted {
			t.Fatalf("object %d answered %s/%s", index, response.Result, response.Code)
		}
	}
	if gaps := gapsOf(t, b); len(gaps) != 0 {
		t.Fatalf("gaps inside the share: %+v", gaps)
	}
	over := a.message(eventlog.MaxRoomBufferSenderObjects+1, "beyond the share", scene.clock.now(), sealOptions{})
	if response := deliverApplication(t, b, scene.a, over.object); response.Result != carrierapi.ResultIgnored {
		t.Fatalf("the object beyond the share answered %s/%s", response.Result, response.Code)
	}
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapBufferFull, 1)
}

// A held object whose Commit never comes is dropped after 24 h 5 min by the
// maintenance pass, as a buffer-expired gap.
func TestRoomApplicationHeldTooLongIsABufferExpiredGap(t *testing.T) {
	scene := newJoinedScene(t, roomRetention)
	b := scene.nodes[1]
	a := authoritySealer(t, scene.authority)
	scene.authority.commit()
	held := a.message(1, "its Commit never comes", scene.clock.now(), sealOptions{})
	if response := deliverApplication(t, b, scene.a, held.object); response.Result != carrierapi.ResultAdmitted {
		t.Fatalf("a next-epoch object answered %s/%s", response.Result, response.Code)
	}
	scene.clock.set(scene.clock.now().Add(eventlog.RoomBufferLifetime - time.Second))
	b.d.relay.rooms.maintain()
	if gaps := gapsOf(t, b); len(gaps) != 0 {
		t.Fatalf("a held object expired early: %+v", gaps)
	}
	scene.clock.set(scene.clock.now().Add(time.Second))
	b.d.relay.rooms.maintain()
	requireGap(t, b, scene.a.agent(), eventlog.RoomGapBufferExpired, 1)
}

// Without a known credential to pin to, part 0's evidence is still checked,
// against its own Endpoint and device: an object of a member whose credential
// is not known yet, carried with another Agent's evidence, is refused at
// intake and nothing of it is held.
func TestRoomApplicationOfAnUnknownCredentialStillHasItsEvidenceChecked(t *testing.T) {
	scene := newAddedScene(t, roomRetention)
	b := scene.nodes[1]
	c := memberSealer(t, scene)
	message := c.message(1, "with another Agent's evidence", scene.clock.now(), sealOptions{})
	forged := scene.c
	forged.evidence = scene.a.evidence
	response := send(t, b, scene.c.agent(), framesOf(t, forged, message.object, 0))
	if response.Result != carrierapi.ResultRefused || response.Code != carrierapi.CodeEvidenceRefused {
		t.Fatalf("an object with another Agent's evidence answered %s/%s", response.Result, response.Code)
	}
	if ready, waiting := buffered(t, b); ready != 0 || waiting != 0 {
		t.Fatalf("an object whose evidence failed was held: %d %d", ready, waiting)
	}
}
