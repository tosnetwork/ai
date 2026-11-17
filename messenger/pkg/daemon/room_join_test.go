package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/payload"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// pendingScene is a room A made and B accepted A's invite to, its Welcome
// not yet delivered.
type pendingScene struct {
	*roomScene
	authority *testAuthority
	a, b      roomMember
	welcome   []byte
	result    eventlog.CommitResult
}

func newPendingScene(t *testing.T, invited func(a roomMember) roomMember) *pendingScene {
	t.Helper()
	scene := newRoomScene(t, 2, roomRetention, 0)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	held := a
	if invited != nil {
		held = invited(a)
	}
	invite(t, b, held, scene.start)
	result, membership := authority.commit(b)
	return &pendingScene{roomScene: scene, authority: authority, a: a, b: b, result: result,
		welcome: authority.welcomeObject(result, membership, b)}
}

// requireStatelessRejection requires the joiner's only state-free answer: a
// rejection carrying no MLS epoch or authenticator.
func requireStatelessRejection(t *testing.T, receiver *relayNode, response carrierapi.Response, code fault.Code) {
	t.Helper()
	ack := requireRejected(t, receiver, response, code)
	if ack.MLSEpoch != 0 || len(ack.EpochAuthenticator) != 0 {
		t.Fatalf("a joiner's rejection carried MLS state: %+v", ack)
	}
}

// requireStillPending requires the receiver to hold no room and its join to
// be pending still.
func requireStillPending(t *testing.T, scene *pendingScene) {
	t.Helper()
	receiver := scene.nodes[1]
	if _, found := fused(t, receiver); found {
		t.Fatal("a refused Welcome installed the room")
	}
	if _, found, err := receiver.d.journal.AcceptedRoomJoin(testRoomID, scene.clock.now()); err != nil || !found {
		t.Fatalf("the pending join ended: %v %v", found, err)
	}
}

// The header's end is outside the authorization's signature: a Welcome
// naming another end than the invite's authority credential is refused.
func TestRoomWelcomeNamingAnotherEndIsRefusedStatelessly(t *testing.T) {
	scene := newPendingScene(t, nil)
	receiver := scene.nodes[1]
	header := scene.authority.header(scene.authority.record.Membership())
	header.EndsAtUnix--
	clock := scene.result.Transition.Next.Clock
	object := scene.authority.object(relayframe.RoomWelcome, clock.RoomEpoch, clock.MLSEpoch, header,
		scene.result.Welcomes[scene.b.leaf.KeyPackageRef])
	requireStatelessRejection(t, receiver, send(t, receiver, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	requireStillPending(t, scene)
	if ack := roomAckOf(t, receiver, send(t, receiver, scene.a.agent(), framesOf(t, scene.a, scene.welcome, 0))); ack.Outcome != relayframe.OutcomeAccepted {
		t.Fatalf("the Welcome with the room's end: %+v", ack)
	}
}

// A Welcome whose header leaves the joiner out is refused: the header's
// membership is the one the install records.
func TestRoomWelcomeWhoseHeaderLeavesTheJoinerOutIsRefused(t *testing.T) {
	scene := newPendingScene(t, nil)
	receiver := scene.nodes[1]
	clock := scene.result.Transition.Next.Clock
	without := room.Membership{RoomID: testRoomID, Epoch: clock.RoomEpoch, Members: []string{scene.a.agent()}}
	digest, err := room.Digest(testRoomID, without.Epoch, without.Members)
	if err != nil {
		t.Fatal(err)
	}
	without.Digest = digest
	object := scene.authority.object(relayframe.RoomWelcome, clock.RoomEpoch, clock.MLSEpoch, scene.authority.header(without),
		scene.result.Welcomes[scene.b.leaf.KeyPackageRef])
	requireStatelessRejection(t, receiver, send(t, receiver, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	requireStillPending(t, scene)
}

// A Welcome is taken only from the leaf the invite's authority credential
// binds: authored by any other leaf of the same Agent, it is refused and
// nothing is installed.
func TestRoomWelcomeByAnotherLeafThanTheInvitesIsRefused(t *testing.T) {
	scene := newPendingScene(t, func(a roomMember) roomMember {
		// The invite carried another credential of A's, for another leaf key.
		return newRoomMember(t, openMLSDriver(t), a.node, time.Unix(1_900_000_000, 0), time.Unix(1_900_000_000, 0).Add(40*time.Minute))
	})
	receiver := scene.nodes[1]
	requireStatelessRejection(t, receiver, send(t, receiver, scene.a.agent(), framesOf(t, scene.a, scene.welcome, 0)), fault.CodeNotAuthentic)
	requireStillPending(t, scene)
}

// The Welcome's authorization is checked in the relay window like a Commit's.
func TestRoomWelcomeOutsideTheRelayWindowIsRefused(t *testing.T) {
	scene := newPendingScene(t, nil)
	receiver := scene.nodes[1]
	scene.clock.set(scene.start.Add(20 * time.Minute))
	header := scene.authority.header(scene.authority.record.Membership())
	clock := scene.result.Transition.Next.Clock
	object := scene.authority.object(relayframe.RoomWelcome, clock.RoomEpoch, clock.MLSEpoch, header,
		scene.result.Welcomes[scene.b.leaf.KeyPackageRef])
	scene.clock.set(scene.start)
	requireStatelessRejection(t, receiver, send(t, receiver, scene.a.agent(), framesOf(t, scene.a, object, 0)), fault.CodeNotAuthentic)
	requireStillPending(t, scene)
}

// Past the invite credential's expiry plus skew the room has ended for a
// joiner too: its Welcome is refused room-ended, without state.
func TestRoomWelcomeAfterTheEndIsRefusedRoomEnded(t *testing.T) {
	scene := newPendingScene(t, nil)
	receiver := scene.nodes[1]
	scene.clock.set(time.Unix(int64(scene.a.credential.ExpiresAtUnix), 0).Add(5 * time.Minute))
	requireStatelessRejection(t, receiver, send(t, receiver, scene.a.agent(), framesOf(t, scene.a, scene.welcome, 0)), fault.CodeRoomEnded)
	requireStillPending(t, scene)
}

// An invited room the owner has not joined takes no Welcome: no part of it
// is held.
func TestRoomWelcomeWithoutAnAcceptedJoinIsNotHeld(t *testing.T) {
	scene := newRoomScene(t, 2, roomRetention, 0)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	authority := newTestAuthority(t, scene.driver, a, scene.clock)
	receiver := scene.nodes[1]
	if _, err := receiver.d.journal.RecordRoomInvite(testRoomID, a.agent(), "evt_"+strings.Repeat("7", 64), a.binding,
		scene.start.Add(time.Hour), scene.start); err != nil {
		t.Fatal(err)
	}
	result, membership := authority.commit(b)
	response := send(t, receiver, a.agent(), framesOf(t, a, authority.welcomeObject(result, membership, b), 0))
	if response.Code != carrierapi.CodeNotAdmitted {
		t.Fatalf("a Welcome before the owner joined: %s/%s", response.Result, response.Code)
	}
}

// inviteEvent is a room.invite from A to B carrying a credential.
func inviteEvent(t *testing.T, from, to roomMember, credential group.LeafCredential, now time.Time) envelope.Event {
	t.Helper()
	raw, err := group.EncodeLeafCredential(credential)
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.RoomInvite{RoomID: testRoomID, InviteeAgentID: to.agent(), Purpose: "work",
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), AuthorityLeafCredential: raw})
	if err != nil {
		t.Fatal(err)
	}
	return envelope.Event{Kind: "room.invite", Content: content, SenderAgentID: from.agent(),
		EventID: "evt_" + strings.Repeat("6", 64), CreatedAtUnix: uint64(now.Unix())}
}

func senderOf(t *testing.T, member roomMember) verifiedPeer {
	t.Helper()
	decoded, err := relayframe.DecodeEvidence(member.evidence)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		t.Fatal(err)
	}
	return verifiedPeer{Delegation: member.delegation, EndpointID: member.delegation.EndpointID, Bundles: bundles}
}

// A received room.invite records a pending join only once its authority
// credential verifies on the room path, device set included; otherwise it
// is refused not-authentic and nothing is stored.
func TestRoomInviteRecordsAPendingJoinOnlyForAVerifiedCredential(t *testing.T) {
	scene := newRoomScene(t, 2, roomRetention, 0)
	a := scene.member(t, 0, 40*time.Minute)
	b := scene.member(t, 1, 50*time.Minute)
	receiver := scene.nodes[1]
	now := scene.start
	stale := newRoomMemberWith(t, scene.driver, a.node, now, now.Add(40*time.Minute), func(c *group.LeafCredential) {
		c.DeviceSetDigest = "sha256:" + strings.Repeat("5", 64)
	})
	refused := receiver.d.roomInviteStep(admission.RouteRelay, inviteEvent(t, a, b, stale.credential, now), senderOf(t, a), now)
	if refused == nil {
		t.Fatal("a room.invite on the relay route needs its step")
	}
	if err := refused(); fault.CodeOf(err) != fault.CodeNotAuthentic {
		t.Fatalf("an invite naming another device set: %v", err)
	}
	if _, found, err := receiver.d.journal.PendingRoomJoinFor(testRoomID, a.agent(), now); err != nil || found {
		t.Fatalf("a refused invite recorded a pending join: %v %v", found, err)
	}
	// An invite for another invitee is not this installation's.
	other := inviteEvent(t, a, a, a.credential, now)
	if err := receiver.d.roomInviteStep(admission.RouteRelay, other, senderOf(t, a), now)(); fault.CodeOf(err) != fault.CodePayloadMalformed {
		t.Fatalf("an invite for another invitee: %v", err)
	}
	// Only the relay route records it here.
	if receiver.d.roomInviteStep(admission.RouteHTTPS, inviteEvent(t, a, b, a.credential, now), senderOf(t, a), now) != nil {
		t.Fatal("a step was made off the relay route")
	}
	if err := receiver.d.roomInviteStep(admission.RouteRelay, inviteEvent(t, a, b, a.credential, now), senderOf(t, a), now)(); err != nil {
		t.Fatalf("a verified invite: %v", err)
	}
	join, found, err := receiver.d.journal.PendingRoomJoinFor(testRoomID, a.agent(), now)
	if err != nil || !found || join.State != eventlog.JoinInvited {
		t.Fatalf("the pending join: %+v %v %v", join, found, err)
	}
	credential, err := join.AuthorityCredential()
	if err != nil || credential.ExpiresAtUnix != a.credential.ExpiresAtUnix || !credential.LeafSignaturePublicKey.Equal(a.credential.LeafSignaturePublicKey) {
		t.Fatalf("the join's authority credential: %v", err)
	}
}
