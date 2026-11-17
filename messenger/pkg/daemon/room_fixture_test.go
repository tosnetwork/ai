package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/dispatch"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// The room receive tests build every object in-process with a test
// authority: its own journal and MLS controller, signing as the authority
// node's Endpoint, so each receiver check is exercised against an object
// made to fail exactly that check.

// testRoomGapDelay is T for 1 h test relays.
const testRoomGapDelay = time.Hour + eventlog.RoomGapGrace

const testRoomID = "room_" + "4d" + "000000000000000000000000000000000000000000000000000000000000c3"

func openMLSDriver(t *testing.T) *group.OpenMLSSidecar {
	t.Helper()
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make messenger-test-openmls")
	}
	return &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 20 * time.Second}
}

// testClock is a receiver's mutable clock.
type testClock struct {
	mutex sync.Mutex
	at    time.Time
}

func (c *testClock) now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.at
}

func (c *testClock) set(at time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.at = at
}

// roomCardsCarrier records carrier.room-cards admissions.
type roomCardsCarrier struct {
	mutex     sync.Mutex
	admitted  map[string][]string
	forgotten map[string][]string
	// ends holds the room end each admission named, in call order.
	ends map[string][]uint64
	// failForgets makes that many forget calls fail, as an unreachable
	// carrier would.
	failForgets int
}

func (c *roomCardsCarrier) RoomCards(_ context.Context, roomID string, roomEndsAtUnix uint64,
	cards []carrierapi.RoomCard) (carrierapi.Response, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// The client refuses an admission without a room end, before it
	// reaches the carrier.
	if err := carrierapi.ValidateRequest(carrierapi.Request{Schema: carrierapi.RequestSchema, Op: carrierapi.OpRoomCards,
		RoomID: roomID, RoomCardsAction: carrierapi.RoomCardsAdmit, RoomEndsAtUnix: roomEndsAtUnix, RoomCards: cards}); err != nil {
		return carrierapi.Response{}, err
	}
	if c.admitted == nil {
		c.admitted = map[string][]string{}
		c.ends = map[string][]uint64{}
	}
	c.ends[roomID] = append(c.ends[roomID], roomEndsAtUnix)
	for _, card := range cards {
		c.admitted[roomID] = append(c.admitted[roomID], card.AgentID)
	}
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied}, nil
}

func (c *roomCardsCarrier) ForgetRoomCards(_ context.Context, roomID string, agentIDs []string) (carrierapi.Response, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// The client refuses a request naming more Agents than one may hold,
	// before it reaches the carrier.
	if err := carrierapi.ValidateRequest(carrierapi.Request{Schema: carrierapi.RequestSchema, Op: carrierapi.OpRoomCards,
		RoomID: roomID, RoomCardsAction: carrierapi.RoomCardsForget, ForgetAgentIDs: agentIDs}); err != nil {
		return carrierapi.Response{}, err
	}
	if c.failForgets > 0 {
		c.failForgets--
		return carrierapi.Response{}, errors.New("the carrier is unreachable")
	}
	if c.forgotten == nil {
		c.forgotten = map[string][]string{}
	}
	c.forgotten[roomID] = append(c.forgotten[roomID], agentIDs...)
	if c.admitted == nil {
		c.admitted = map[string][]string{}
	}
	kept := c.admitted[roomID][:0:0]
	for _, agentID := range c.admitted[roomID] {
		if !containsAgent(agentIDs, agentID) {
			kept = append(kept, agentID)
		}
	}
	c.admitted[roomID] = kept
	return carrierapi.Response{Schema: carrierapi.ResponseSchema, Result: carrierapi.ResultApplied}, nil
}

func (c *roomCardsCarrier) forgottenIn(roomID string) []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]string(nil), c.forgotten[roomID]...)
}

func (c *roomCardsCarrier) endsOf(roomID string) []uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]uint64(nil), c.ends[roomID]...)
}

func (c *roomCardsCarrier) of(roomID string) []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]string(nil), c.admitted[roomID]...)
}

// roomMember is one node's relay room leaf, made as a joiner makes it: a
// fresh leaf signature key, the Endpoint-signed leaf credential naming it
// and the node's real device set, the KeyPackage under the compact identity
// naming that credential, and the DeviceCredential of that KeyPackage.
type roomMember struct {
	node       *relayNode
	delegation identity.Delegation
	set        e2ee.SetSummary
	evidence   []byte
	card       []byte
	credential group.LeafCredential
	binding    group.LeafBinding
	identity   group.OpenMLSIdentity
	deviceJSON []byte
	leaf       group.Leaf
}

func (m roomMember) agent() string { return m.node.d.config.AgentID }

// evidenceOf returns a node's current relay evidence, card and device set.
func evidenceOf(t *testing.T, node *relayNode) ([]byte, []byte, e2ee.SetSummary) {
	t.Helper()
	evidence, _, _, err := node.d.relay.sink.Current()
	if err != nil {
		t.Fatal(err)
	}
	card, err := node.d.relay.sink.Card()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		t.Fatal(err)
	}
	set, err := e2ee.Summarize(bundles)
	if err != nil {
		t.Fatal(err)
	}
	return evidence, card, set
}

func newRoomMember(t *testing.T, driver *group.OpenMLSSidecar, node *relayNode, issued, expires time.Time) roomMember {
	t.Helper()
	return newRoomMemberWith(t, driver, node, issued, expires, nil)
}

// newRoomMemberWith makes a member whose credential mutate may change before
// it is signed; the binding is then made only if the changed credential
// still verifies.
func newRoomMemberWith(t *testing.T, driver *group.OpenMLSSidecar, node *relayNode, issued, expires time.Time,
	mutate func(*group.LeafCredential)) roomMember {
	t.Helper()
	evidence, card, set := evidenceOf(t, node)
	delegation := node.d.prekeys.planner.delegation
	signer, err := driver.NewLeafSigner()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := group.LeafCredential{Network: delegation.Network, AgentID: node.d.config.AgentID,
		EndpointID: node.d.config.EndpointID, DeviceID: node.d.config.DeviceID, DeviceSetDigest: set.Digest,
		LeafSignaturePublicKey: signer.LeafSignaturePublicKey,
		IssuedAtUnix:           uint64(issued.Unix()), ExpiresAtUnix: uint64(expires.Unix())}
	if mutate != nil {
		mutate(&unsigned)
	}
	credential, err := group.SignLeafCredential(unsigned, node.key)
	if err != nil {
		t.Fatal(err)
	}
	member := roomMember{node: node, delegation: delegation, set: set, evidence: evidence, card: card, credential: credential}
	identityBytes, err := group.EncodeLeafIdentity(credential)
	if err != nil {
		t.Fatal(err)
	}
	made, err := driver.NewIdentityForSigner(signer, identityBytes)
	if err != nil {
		t.Fatal(err)
	}
	member.identity = made
	device, err := group.SignDeviceCredential(group.DeviceCredential{Network: delegation.Network, AgentID: credential.AgentID,
		EndpointID: credential.EndpointID, DeviceID: credential.DeviceID, DeviceSetDigest: credential.DeviceSetDigest,
		LeafSignaturePublicKey: signer.LeafSignaturePublicKey, KeyPackage: made.KeyPackage,
		IssuedAtUnix: credential.IssuedAtUnix, ExpiresAtUnix: credential.ExpiresAtUnix}, node.key)
	if err != nil {
		t.Fatal(err)
	}
	if member.leaf, err = group.LeafFromCredentials(device, credential); err != nil {
		t.Fatal(err)
	}
	if member.deviceJSON, err = group.EncodeDeviceCredentialJSON(device); err != nil {
		t.Fatal(err)
	}
	if binding, err := group.VerifyRoomLeafCredential(delegation, credential, set, credential.ExpiresAtUnix, issued); err == nil {
		member.binding = binding
	}
	return member
}

// testAuthority is the room's authority, run in-process on its own journal.
type testAuthority struct {
	t          *testing.T
	member     roomMember
	journal    *eventlog.Journal
	ledger     *eventlog.RoomMLSLedger
	controller *eventlog.RoomMLSController
	groupID    []byte
	record     eventlog.RoomMLSRecord
	clock      *testClock
}

func newTestAuthority(t *testing.T, driver *group.OpenMLSSidecar, member roomMember, clock *testClock) *testAuthority {
	t.Helper()
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "authority"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	ledger, err := journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	controller, err := eventlog.NewRoomMLSController(ledger, driver, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := group.MLSGroupID(member.delegation.Network, testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	authority := &testAuthority{t: t, member: member, journal: journal, ledger: ledger, controller: controller,
		groupID: groupID, clock: clock}
	founding, err := room.Found(testRoomID, []string{member.agent()})
	if err != nil {
		t.Fatal(err)
	}
	binding := group.State{RoomID: testRoomID, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founding.Digest}
	record, err := controller.CreateRoom(binding, authority.proof(founding), member.identity.State, member.identity.KeyPackage,
		groupID, member.leaf.KeyPackageRef, member.binding)
	if err != nil {
		t.Fatalf("create the room: %v", err)
	}
	authority.record = record
	return authority
}

func (a *testAuthority) authorization(membership room.Membership, issued time.Time) room.MembershipAuthorization {
	a.t.Helper()
	value, err := room.SignMembershipAuthorization(room.MembershipAuthorization{Network: a.member.delegation.Network,
		RoomID: membership.RoomID, Epoch: membership.Epoch, MembershipDigest: membership.Digest,
		Authority:    room.Authority{AgentID: a.member.agent(), EndpointID: a.member.delegation.EndpointID},
		IssuedAtUnix: uint64(issued.Unix()), ExpiresAtUnix: min(uint64(issued.Add(time.Hour).Unix()), a.member.delegation.ExpiresAtUnix)},
		a.member.node.key)
	if err != nil {
		a.t.Fatal(err)
	}
	return value
}

func (a *testAuthority) proof(membership room.Membership) eventlog.RoomAuthorityProof {
	return eventlog.RoomAuthorityProof{Membership: membership, Authorization: a.authorization(membership, a.clock.now()),
		Delegation: a.member.delegation}
}

// header is the room header of a membership, with the room's end.
func (a *testAuthority) header(membership room.Membership) *relayframe.RoomHeader {
	return &relayframe.RoomHeader{Membership: membership, Authorization: a.authorization(membership, a.clock.now()),
		EndsAtUnix: a.record.RoomEndsAtUnix}
}

// commit makes the authority's next Commit: it adds the joiners (none for
// an MLS-only refresh) and returns the driver output and the membership.
func (a *testAuthority) commit(joiners ...roomMember) (eventlog.CommitResult, room.Membership) {
	a.t.Helper()
	membership := a.record.Membership()
	var operations []group.LeafOperation
	var proof *eventlog.RoomAuthorityProof
	roomEpoch := a.record.RoomEpoch
	if len(joiners) > 0 {
		agents := make([]string, 0, len(joiners))
		for _, joiner := range joiners {
			agents = append(agents, joiner.agent())
			leaf := joiner.leaf
			operations = append(operations, group.LeafOperation{Kind: group.LeafAdd, Next: &leaf})
		}
		next, err := membership.Add(agents)
		if err != nil {
			a.t.Fatal(err)
		}
		membership = next
		roomEpoch = next.Epoch
		value := a.proof(membership)
		proof = &value
	}
	template := group.Transition{Prior: a.record.Binding(), Membership: membership,
		Next: group.State{RoomID: testRoomID, Clock: group.Clock{RoomEpoch: roomEpoch, MLSEpoch: a.record.MLSEpoch + 1},
			MembershipDigest: membership.Digest}}
	result, record, err := a.controller.Commit(template, proof, operations, func(result eventlog.CommitResult) ([]eventlog.StagedRoomObject, error) {
		clock := result.Transition.Next.Clock
		return []eventlog.StagedRoomObject{{Type: eventlog.RoomObjectCommit, RoomEpoch: clock.RoomEpoch, MLSEpoch: clock.MLSEpoch,
			Object: result.Commit, Recipients: []eventlog.RoomRecipient{{AgentID: "agent_" + strings.Repeat("9", 64)}}}}, nil
	}, a.clock.now().Add(7*24*time.Hour))
	if err != nil {
		a.t.Fatalf("authority commit: %v", err)
	}
	a.record = record
	return result, membership
}

// object encodes one room object.
func (a *testAuthority) object(kind uint8, roomEpoch, mlsEpoch uint64, header *relayframe.RoomHeader, body []byte) []byte {
	a.t.Helper()
	raw, err := relayframe.EncodeRoomObject(relayframe.RoomObject{Type: kind, RoomID: testRoomID, RoomEpoch: roomEpoch,
		MLSEpoch: mlsEpoch, Header: header, Body: body})
	if err != nil {
		a.t.Fatal(err)
	}
	return raw
}

// welcomeObject is the Welcome a Commit made for one joiner.
func (a *testAuthority) welcomeObject(result eventlog.CommitResult, membership room.Membership, joiner roomMember) []byte {
	a.t.Helper()
	welcome, made := result.Welcomes[joiner.leaf.KeyPackageRef]
	if !made {
		a.t.Fatal("the Commit made no Welcome for the joiner")
	}
	clock := result.Transition.Next.Clock
	return a.object(relayframe.RoomWelcome, clock.RoomEpoch, clock.MLSEpoch, a.header(membership), welcome)
}

// commitObject is a Commit as members receive it: with the header when it
// changes the room epoch.
func (a *testAuthority) commitObject(result eventlog.CommitResult, membership room.Membership) []byte {
	a.t.Helper()
	clock := result.Transition.Next.Clock
	var header *relayframe.RoomHeader
	if clock.RoomEpoch != result.Transition.Prior.Clock.RoomEpoch {
		header = a.header(membership)
	}
	return a.object(relayframe.RoomCommit, clock.RoomEpoch, clock.MLSEpoch, header, result.Commit)
}

// rosterEntry is a member's roster entry with its own card, evidence and
// leaf credential.
func rosterEntry(t *testing.T, member roomMember) relayframe.RosterEntry {
	t.Helper()
	credential, err := group.EncodeLeafCredential(member.credential)
	if err != nil {
		t.Fatal(err)
	}
	return relayframe.RosterEntry{AgentID: member.agent(), Card: member.card, Evidence: member.evidence, Credential: credential}
}

// rosterObject is a roster describing a room epoch of the authority's.
func (a *testAuthority) rosterObject(membership room.Membership, entries ...relayframe.RosterEntry) []byte {
	a.t.Helper()
	sortRoster(entries)
	body, err := relayframe.EncodeRoster(entries)
	if err != nil {
		a.t.Fatal(err)
	}
	return a.object(relayframe.RoomRoster, membership.Epoch, a.record.MLSEpoch, a.header(membership), body)
}

func sortRoster(entries []relayframe.RosterEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].AgentID < entries[j-1].AgentID; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
}

// frames cuts an object into kind-3 frames carrying the sender's card and
// evidence in part 0.
func framesOf(t *testing.T, sender roomMember, object []byte, partBytes int) [][]byte {
	t.Helper()
	frames, err := relayframe.SplitRoomObject(object, sender.card, sender.evidence, partBytes)
	if err != nil {
		t.Fatal(err)
	}
	return frames
}

// send delivers every frame of an object from a sender Agent and returns
// the answer to the last.
func send(t *testing.T, receiver *relayNode, senderAgentID string, frames [][]byte) carrierapi.Response {
	t.Helper()
	var response carrierapi.Response
	for index, frame := range frames {
		response = receiver.d.relay.Deliver(context.Background(), senderAgentID, frame)
		if err := carrierapi.ValidateResponse(carrierapi.OpDeliver, response); err != nil {
			t.Fatalf("invalid answer %s/%s: %v", response.Result, response.Code, err)
		}
		if index < len(frames)-1 && response.Result != carrierapi.ResultAdmitted {
			t.Fatalf("part %d answered %s/%s", index, response.Result, response.Code)
		}
	}
	return response
}

// roomAckOf decodes and verifies the receiver's room ack.
func roomAckOf(t *testing.T, receiver *relayNode, response carrierapi.Response) relayframe.RoomAck {
	t.Helper()
	if response.Result != carrierapi.ResultAck {
		t.Fatalf("no room ack: %s/%s", response.Result, response.Code)
	}
	raw, err := base64.StdEncoding.DecodeString(response.AckFrameBase64)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := relayframe.Decode(raw)
	if err != nil || frame.Kind != relayframe.KindDeliveryAck || !relayframe.IsRoomAck(frame.Part) {
		t.Fatalf("room ack frame: %v", err)
	}
	ack, err := relayframe.DecodeRoomAck(frame.Part)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayframe.VerifyRoomAck(ack, receiver.key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("room ack signature: %v", err)
	}
	if ack.Outcome != response.AckOutcome {
		t.Fatalf("ack outcome %s answered as %s", ack.Outcome, response.AckOutcome)
	}
	return ack
}

// roomScene is one authority and its receivers, every receiver running the
// room runtime.
type roomScene struct {
	driver *group.OpenMLSSidecar
	clock  *testClock
	start  time.Time
	nodes  []*relayNode
	cards  []*roomCardsCarrier
}

// newRoomScene builds relay nodes sharing one finalized view; every node but
// the first (the authority) runs the room runtime under the given
// handshake retention and test part size.
func newRoomScene(t *testing.T, count int, retention time.Duration, partBytes int) *roomScene {
	t.Helper()
	driver := openMLSDriver(t)
	start := time.Unix(1_900_000_000, 0)
	digits := [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}, {"d", "4"}}[:count]
	nodes := newRelayNodes(t, start, digits...)
	scene := &roomScene{driver: driver, clock: &testClock{at: start}, start: start, nodes: nodes}
	for index, node := range nodes {
		node.d.now = scene.clock.now
		cards := &roomCardsCarrier{}
		scene.cards = append(scene.cards, cards)
		if index == 0 {
			continue
		}
		if err := node.d.installRoomRuntime(roomRuntimeSettings{driver: driver, cards: cards, skew: 5 * time.Minute,
			retention: retention, gapDelay: testRoomGapDelay, partBytes: partBytes}); err != nil {
			t.Fatalf("install the room runtime: %v", err)
		}
	}
	return scene
}

// member makes node index's room leaf, valid from the scene start for the
// given lifetime.
func (s *roomScene) member(t *testing.T, index int, lifetime time.Duration) roomMember {
	t.Helper()
	return newRoomMember(t, s.driver, s.nodes[index], s.start, s.start.Add(lifetime))
}

// invite records, at the receiver, the authority's invite and the owner's
// join: the accepted pending join the Welcome is taken through.
func invite(t *testing.T, receiver roomMember, authority roomMember, now time.Time) {
	t.Helper()
	journal := receiver.node.d.journal
	if _, err := journal.RecordRoomInvite(testRoomID, authority.agent(), "evt_"+strings.Repeat("7", 64), authority.binding,
		now.Add(time.Hour), now); err != nil {
		t.Fatalf("record the invite: %v", err)
	}
	if _, err := journal.BeginRoomJoin(testRoomID, authority.agent(), receiver.identity.State, receiver.deviceJSON, now); err != nil {
		t.Fatalf("join: %v", err)
	}
}

// fused returns a receiver's fused record of the test room.
func fused(t *testing.T, node *relayNode) (eventlog.RoomMLSRecord, bool) {
	t.Helper()
	ledger, err := node.d.journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	record, found, err := ledger.Current(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	return record, found
}

// recordingReports collects the owner notices a node raises.
type recordingReports struct {
	mutex sync.Mutex
	errs  []error
}

func (r *recordingReports) Swept(dispatch.Summary)               {}
func (r *recordingReports) Maintained(int, eventlog.PruneReport) {}
func (r *recordingReports) Failed(_ string, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.errs = append(r.errs, err)
}

// count reports how many notices matched.
func (r *recordingReports) count(match func(error) bool) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	n := 0
	for _, err := range r.errs {
		if match(err) {
			n++
		}
	}
	return n
}
