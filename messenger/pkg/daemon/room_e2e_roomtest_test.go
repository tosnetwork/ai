//go:build roomtest

package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/admission"
	"github.com/tosnetwork/ai/messenger/pkg/carrierapi"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The room e2e runs the M-R2 gate scenarios (section 8) between four real
// daemons in one process, each with its own journal and room runtime, the
// room settings taken from a roomtest configuration. Between them a mailbox
// stands in for the relays: a carry stores an envelope under its
// idempotency key until its TTL, a withdrawal removes it, and the test
// drains the mailboxes, handing each envelope to its recipient's
// carrier.deliver and each answer's ack back to the sender's
// carrier.delivery-ack, as two carriers would. Nothing is delivered inside
// a carry: the authority deposits while it holds its handling lock.

// e2eTTL is the relay TTL every recipient's card reports, and the own
// relays' TTL each node is configured with.
const e2eTTL = 10 * time.Minute

// The roomtest settings the scene runs with: a part size that splits a full
// roster into several parts and still cuts every handshake object within 8
// parts (a roster entry is about 11 KiB), a handshake retention W within
// which a catch-up can outlast the relay TTL, and an authorization lifetime
// a stopped member outlives.
const (
	e2ePartBytes     = 4 * relayframe.MinTestPartBytes
	e2eRetention     = 20 * time.Minute
	e2eAuthorization = 2 * time.Minute
)

// Indexes of the scene's daemons: A is the authority.
const (
	nodeA = iota
	nodeB
	nodeC
	nodeD
)

// mailEnvelope is one stored envelope of the mailbox.
type mailEnvelope struct {
	order    uint64
	from, to string
	key      string
	kind     uint8
	frame    []byte
	expires  time.Time
	// ack is a delivery-ack frame going back to the original sender.
	ack bool
}

// mailAnswer is a recipient's answer to one delivered envelope.
type mailAnswer struct {
	envelope mailEnvelope
	response carrierapi.Response
}

// mailbox is the relays of the scene.
type mailbox struct {
	mutex  sync.Mutex
	clock  *testClock
	next   uint64
	stored []mailEnvelope
	// withdrawals records every withdrawal asked for, by a carry or by
	// carrier.withdraw, stored or not; withdrawn and expired record what
	// left the mailbox undelivered.
	withdrawals []mailEnvelope
	withdrawn   []mailEnvelope
	expired     []mailEnvelope
	// peakRoom and peakAll are the most kind-3 and chat envelopes one
	// sender held at one recipient at once; perMinute counts each sender's
	// kind-3 deposits per minute.
	peakRoom  map[[2]string]int
	peakAll   map[[2]string]int
	perMinute map[string]int
	// hold keeps matching envelopes in the mailbox, undelivered.
	hold func(mailEnvelope) bool
	// loseAnswer discards a recipient's answer to a matching envelope, as a
	// recipient killed after handling it but before its carrier answered.
	loseAnswer func(mailEnvelope) bool
}

func newMailbox(clock *testClock) *mailbox {
	return &mailbox{clock: clock, peakRoom: map[[2]string]int{}, peakAll: map[[2]string]int{}, perMinute: map[string]int{}}
}

// mailCarrier is one node's carrier over the mailbox.
type mailCarrier struct {
	box  *mailbox
	from string
}

func (c mailCarrier) Carry(_ context.Context, recipient, key, withdraw string, expiresAtUnix uint64,
	frame []byte) (carrierapi.Response, error) {
	decoded, err := relayframe.Decode(frame)
	if err != nil {
		return carrierapi.Response{}, err
	}
	box := c.box
	box.mutex.Lock()
	defer box.mutex.Unlock()
	now := box.clock.now()
	if withdraw != "" {
		box.withdrawLocked(c.from, recipient, withdraw)
	}
	pair := [2]string{c.from, recipient}
	rooms, all := 0, 0
	for _, stored := range box.stored {
		if stored.ack || stored.from != c.from || stored.to != recipient {
			continue
		}
		if stored.key == key {
			return carrierapi.Carried(uint64(e2eTTL / time.Second)), nil
		}
		all++
		if stored.kind == relayframe.KindRoom {
			rooms++
		}
	}
	// The carrier's per-peer caps: 16 kind-3 envelopes out of 24.
	if all >= carrierapi.MaxPeerEnvelopes || decoded.Kind == relayframe.KindRoom && rooms >= carrierapi.MaxPeerRoomEnvelopes {
		return carrierapi.Refusal(carrierapi.CodePeerCap), nil
	}
	expires := now.Add(e2eTTL)
	if expiresAtUnix != 0 && time.Unix(int64(expiresAtUnix), 0).Before(expires) {
		expires = time.Unix(int64(expiresAtUnix), 0)
	}
	box.next++
	box.stored = append(box.stored, mailEnvelope{order: box.next, from: c.from, to: recipient, key: key, kind: decoded.Kind,
		frame: append([]byte(nil), frame...), expires: expires})
	all++
	if decoded.Kind == relayframe.KindRoom {
		rooms++
		box.perMinute[c.from+"/"+now.Truncate(time.Minute).String()]++
	}
	box.peakAll[pair] = max(box.peakAll[pair], all)
	box.peakRoom[pair] = max(box.peakRoom[pair], rooms)
	return carrierapi.Carried(uint64(e2eTTL / time.Second)), nil
}

func (c mailCarrier) Withdraw(_ context.Context, recipient, key string) (carrierapi.Response, error) {
	c.box.mutex.Lock()
	defer c.box.mutex.Unlock()
	c.box.withdrawLocked(c.from, recipient, key)
	return carrierapi.Withdrawn(), nil
}

func (b *mailbox) withdrawLocked(from, to, key string) {
	b.withdrawals = append(b.withdrawals, mailEnvelope{from: from, to: to, key: key})
	kept := b.stored[:0]
	for _, stored := range b.stored {
		if !stored.ack && stored.from == from && stored.to == to && stored.key == key {
			b.withdrawn = append(b.withdrawn, stored)
			continue
		}
		kept = append(kept, stored)
	}
	b.stored = kept
}

// post stores a recipient's ack for the original sender.
func (b *mailbox) post(from, to string, frame []byte) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.next++
	b.stored = append(b.stored, mailEnvelope{order: b.next, from: from, to: to, kind: relayframe.KindDeliveryAck,
		frame: append([]byte(nil), frame...), expires: b.clock.now().Add(e2eTTL), ack: true})
}

// take removes the first deliverable envelope: unexpired, not held, to a
// running recipient. Expired envelopes leave the mailbox on the way.
func (b *mailbox) take(running func(string) bool) (mailEnvelope, bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	now := b.clock.now()
	kept := b.stored[:0]
	var taken mailEnvelope
	found := false
	for _, stored := range b.stored {
		if !now.Before(stored.expires) {
			b.expired = append(b.expired, stored)
			continue
		}
		if !found && running(stored.to) && (b.hold == nil || !b.hold(stored)) {
			taken, found = stored, true
			continue
		}
		kept = append(kept, stored)
	}
	b.stored = kept
	return taken, found
}

// held returns the stored envelopes match selects, leaving them stored.
func (b *mailbox) held(match func(mailEnvelope) bool) []mailEnvelope {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	var found []mailEnvelope
	for _, stored := range b.stored {
		if match(stored) {
			found = append(found, stored)
		}
	}
	return found
}

// remove takes one stored envelope out of the mailbox.
func (b *mailbox) remove(order uint64) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	kept := b.stored[:0]
	for _, stored := range b.stored {
		if stored.order != order {
			kept = append(kept, stored)
		}
	}
	b.stored = kept
}

// crashingDriver is the OpenMLS driver of an authority that is killed right
// after the driver made a Commit, before the fused record is written: once
// armed, the next Commit takes the node off the network and returns the
// driver's output to nobody.
type crashingDriver struct {
	*group.OpenMLSSidecar
	mutex sync.Mutex
	crash bool
	// killed takes the node off the network the moment it dies.
	killed func()
}

func (d *crashingDriver) Commit(state []byte, operations []group.LeafOperation) ([]byte, []byte, map[string][]byte, error) {
	next, commit, welcomes, err := d.OpenMLSSidecar.Commit(state, operations)
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if err == nil && d.crash {
		d.crash = false
		d.killed()
		return nil, nil, nil, errors.New("the authority was killed after the driver's Commit")
	}
	return next, commit, welcomes, err
}

func (d *crashingDriver) crashNextCommit() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.crash = true
}

// e2eScene is the four daemons, their mailbox and their clock.
type e2eScene struct {
	t        *testing.T
	clock    *testClock
	start    time.Time
	box      *mailbox
	nodes    []*relayNode
	roots    []string
	running  []bool
	reports  []*recordingReports
	cards    []*roomCardsCarrier
	drivers  []*crashingDriver
	resolver phaseAResolver
	chain    identity.ChainPolicy
	answers  []mailAnswer

	// commits maps every Commit digest the authority staged to its MLS
	// epoch; phase is the start of the catch-up phases; staleWelcome is D's
	// first Welcome generation, kept to hand it over late; laterFromC is
	// C's message B gets after the one it misses.
	commits      map[string]uint64
	phase        time.Time
	staleWelcome []mailEnvelope
	laterFromC   string
}

func e2eDriverPath(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		// A roomtest build is asked for on purpose; skipping would let its
		// gate scenarios look green without running.
		t.Fatal("a roomtest build needs TOS_OPENMLS_DRIVER (make messenger-test-roomtest sets it)")
	}
	return binary
}

// e2eRoomConfig is the relay carriage configuration of every node: private
// rooms with the scene's test settings and own relay TTL.
func e2eRoomConfig(driver string) *RelayCarriageConfig {
	return &RelayCarriageConfig{MLSDriverPath: driver, OwnRelayMaxTTLSeconds: uint64(e2eTTL / time.Second),
		RoomPartBytes: uint64Of(e2ePartBytes), RoomHandshakeRetentionSeconds: uint64Of(uint64(e2eRetention / time.Second)),
		RoomAuthorizationSeconds: uint64Of(uint64(e2eAuthorization / time.Second))}
}

func newE2EScene(t *testing.T) *e2eScene {
	t.Helper()
	binary := e2eDriverPath(t)
	start := time.Unix(1_900_000_000, 0)
	clock := &testClock{at: start}
	scene := &e2eScene{t: t, clock: clock, start: start, box: newMailbox(clock), commits: map[string]uint64{},
		chain: identity.ChainPolicy{RegistryCodeHashes: []string{registryCode}, Locator: phaseALocator{}}}
	authority := "agent_" + strings.Repeat("a", 64)
	digits := [][2]string{{"a", "1"}, {"b", "2"}, {"c", "3"}, {"d", "4"}}
	daemons := make([]*Daemon, 0, len(digits))
	for _, pair := range digits {
		daemons = append(daemons, relayDaemon(t, start, pair[0], pair[1], func(config *Config) {
			// C admits only its known contact A (D11, item 12): a 1:1 copy
			// from any other Agent meets that policy.
			if config.AgentID == "agent_"+strings.Repeat("c", 64) {
				config.Admission = AdmissionConfig{Rule: admission.RuleAllowList, Unknown: admission.TellThem,
					KnownAgentIDs: []string{authority}, MaxContentBytes: config.Admission.MaxContentBytes,
					MaxClockSkewSeconds: config.Admission.MaxClockSkewSeconds}
			}
		}))
	}
	scene.resolver = relayResolver(daemons...)
	for _, d := range daemons {
		root := t.TempDir()
		scene.roots = append(scene.roots, root)
		scene.reports = append(scene.reports, &recordingReports{})
		scene.cards = append(scene.cards, &roomCardsCarrier{})
		index := len(scene.nodes)
		scene.drivers = append(scene.drivers, &crashingDriver{OpenMLSSidecar: &group.OpenMLSSidecar{Command: []string{binary},
			Timeout: 20 * time.Second}, killed: func() { scene.stop(index) }})
		scene.running = append(scene.running, true)
		scene.nodes = append(scene.nodes, scene.assemble(len(scene.nodes), d))
	}
	// A is everyone's contact; the members are not each other's.
	for _, member := range []int{nodeB, nodeC, nodeD} {
		importContact(t, scene.nodes[nodeA], scene.nodes[member])
		importContact(t, scene.nodes[member], scene.nodes[nodeA])
	}
	return scene
}

// assemble installs a node's relay route over the mailbox and its room
// runtime from its roomtest configuration.
func (s *e2eScene) assemble(index int, d *Daemon) *relayNode {
	t := s.t
	t.Helper()
	d.now = s.clock.now
	d.observer = s.reports[index]
	d.config.RelayCarriage = e2eRoomConfig(s.drivers[index].Command[0])
	node := assembleRelayNode(t, d, s.resolver, s.chain, s.roots[index])
	node.d.relay.carrier = mailCarrier{box: s.box, from: d.config.AgentID}
	settings, err := node.d.configuredRoomSettings(s.drivers[index], s.cards[index])
	if err != nil {
		t.Fatalf("room settings of node %d: %v", index, err)
	}
	if settings.partBytes != e2ePartBytes || settings.retention != e2eRetention || settings.authorization != e2eAuthorization {
		t.Fatalf("node %d runs %+v", index, settings)
	}
	if err := node.d.installRoomRuntime(settings); err != nil {
		t.Fatalf("install the room runtime of node %d: %v", index, err)
	}
	return node
}

// stop takes a node off the network: nothing is delivered to it and its
// timers do not run until restart reopens it.
func (s *e2eScene) stop(index int) { s.running[index] = false }

// restart kills a node and reopens it over the same state directory, keys
// and configuration: everything it holds afterwards is what its journal
// kept.
func (s *e2eScene) restart(index int) {
	t := s.t
	t.Helper()
	old := s.nodes[index]
	config := old.d.config
	delegation := old.d.prekeys.planner.delegation
	if err := old.d.journal.Close(); err != nil {
		t.Fatalf("close node %d: %v", index, err)
	}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("reopen node %d: %v", index, err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	prekeys, err := newPrekeyRuntime(config, delegation, journal, s.clock.now)
	if err != nil {
		t.Fatalf("prekeys of node %d: %v", index, err)
	}
	if err := prekeys.configureLocalDevice(config.DeviceID, old.key); err != nil {
		t.Fatalf("configure prekeys of node %d: %v", index, err)
	}
	config.RelayCarriage = nil
	s.nodes[index] = s.assemble(index, &Daemon{config: config, journal: journal, prekeys: prekeys})
	s.running[index] = true
}

func (s *e2eScene) agent(index int) string { return s.nodes[index].d.config.AgentID }

func (s *e2eScene) rooms(index int) *roomRuntime { return s.nodes[index].d.relay.rooms }

func (s *e2eScene) indexOf(agentID string) int {
	for index := range s.nodes {
		if s.agent(index) == agentID {
			return index
		}
	}
	s.t.Fatalf("no node is %s", agentID)
	return -1
}

func (s *e2eScene) isRunning(agentID string) bool { return s.running[s.indexOf(agentID)] }

// tick runs a node's timers: the dispatcher's sweep and the relay
// maintenance (evidence pulls and expiry, the room runtime).
func (s *e2eScene) tick(index int) {
	t := s.t
	t.Helper()
	node := s.nodes[index]
	if _, err := node.d.dispatch.Sweep(context.Background(), 0); err != nil {
		t.Fatalf("sweep node %d: %v", index, err)
	}
	node.d.relay.sweepPulls(context.Background())
	node.d.relay.sweepEvidence()
	node.d.relay.rooms.maintain()
}

// hand delivers one envelope to its recipient and posts the ack its
// carrier would deposit for the sender.
func (s *e2eScene) hand(envelope mailEnvelope) carrierapi.Response {
	t := s.t
	t.Helper()
	to := s.nodes[s.indexOf(envelope.to)]
	var response carrierapi.Response
	if envelope.ack {
		response = to.d.relay.DeliveryAck(context.Background(), envelope.from, envelope.frame)
	} else {
		response = to.d.relay.Deliver(context.Background(), envelope.from, envelope.frame)
		response.Schema = carrierapi.ResponseSchema
		if err := carrierapi.ValidateResponse(carrierapi.OpDeliver, response); err != nil {
			t.Fatalf("invalid answer %s/%s to %s: %v", response.Result, response.Code, envelope.to, err)
		}
	}
	s.answers = append(s.answers, mailAnswer{envelope: envelope, response: response})
	// A recipient that died while handling the envelope answers nothing.
	if !s.isRunning(envelope.to) || s.box.loseAnswer != nil && s.box.loseAnswer(envelope) {
		return response
	}
	if response.Result == carrierapi.ResultAck {
		raw, err := base64.StdEncoding.DecodeString(response.AckFrameBase64)
		if err != nil {
			t.Fatal(err)
		}
		s.box.post(envelope.to, envelope.from, raw)
	}
	return response
}

// settle runs every running node's timers and drains the mailbox until
// nothing moves.
func (s *e2eScene) settle() {
	t := s.t
	t.Helper()
	for round := 0; round < 64; round++ {
		for index := range s.nodes {
			if s.running[index] {
				s.tick(index)
			}
		}
		moved := 0
		for {
			envelope, found := s.box.take(s.isRunning)
			if !found {
				break
			}
			s.hand(envelope)
			moved++
		}
		if moved == 0 {
			s.requireCaps()
			return
		}
	}
	t.Fatal("the scene did not settle")
}

// at moves the clock to start + offset and settles.
func (s *e2eScene) at(offset time.Duration) {
	s.t.Helper()
	s.clock.set(s.start.Add(offset))
	s.settle()
}

// requireCaps checks the counters of gate item 9: no peer ever held more
// than 16 kind-3 or 24 chat envelopes of one sender, and no sender
// deposited more than 30 kind-3 envelopes in a minute.
func (s *e2eScene) requireCaps() {
	t := s.t
	t.Helper()
	s.box.mutex.Lock()
	defer s.box.mutex.Unlock()
	for pair, peak := range s.box.peakRoom {
		if peak > carrierapi.MaxPeerRoomEnvelopes || s.box.peakAll[pair] > carrierapi.MaxPeerEnvelopes {
			t.Fatalf("%s held %d kind-3 and %d chat envelopes for %s", pair[0], peak, s.box.peakAll[pair], pair[1])
		}
	}
	for minute, count := range s.box.perMinute {
		if count > 30 {
			t.Fatalf("%d kind-3 deposits in the minute %s", count, minute)
		}
	}
}

// withdrawalAsked reports whether a node asked its carrier to withdraw an
// envelope.
func (s *e2eScene) withdrawalAsked(from int, to, key string) bool {
	s.box.mutex.Lock()
	defer s.box.mutex.Unlock()
	for _, withdrawal := range s.box.withdrawals {
		if withdrawal.from == s.agent(from) && withdrawal.to == to && withdrawal.key == key {
			return true
		}
	}
	return false
}

// roomObjectType tells part 0's object type of a stored kind-3 envelope; a
// later part has none.
func roomObjectType(t *testing.T, envelope mailEnvelope) (uint8, bool) {
	t.Helper()
	decoded, err := relayframe.Decode(envelope.frame)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != relayframe.KindRoom || decoded.PartIndex != 0 {
		return 0, false
	}
	_, kind, err := relayframe.RoomObjectPrefix(decoded.Part)
	if err != nil {
		t.Fatal(err)
	}
	return kind, true
}

// objectEnvelopes groups stored kind-3 envelopes by object, in part order,
// keeping only objects of the given type.
func objectEnvelopes(t *testing.T, envelopes []mailEnvelope, kind uint8) [][]mailEnvelope {
	t.Helper()
	byDigest := map[[32]byte][]mailEnvelope{}
	types := map[[32]byte]uint8{}
	var order [][32]byte
	for _, envelope := range envelopes {
		decoded, err := relayframe.Decode(envelope.frame)
		if err != nil {
			t.Fatal(err)
		}
		if _, seen := byDigest[decoded.ObjectDigest]; !seen {
			order = append(order, decoded.ObjectDigest)
		}
		byDigest[decoded.ObjectDigest] = append(byDigest[decoded.ObjectDigest], envelope)
		if objectType, ok := roomObjectType(t, envelope); ok {
			types[decoded.ObjectDigest] = objectType
		}
	}
	var objects [][]mailEnvelope
	for _, digest := range order {
		if types[digest] != kind {
			continue
		}
		parts := byDigest[digest]
		sort.Slice(parts, func(i, j int) bool {
			left, _ := relayframe.Decode(parts[i].frame)
			right, _ := relayframe.Decode(parts[j].frame)
			return left.PartIndex < right.PartIndex
		})
		objects = append(objects, parts)
	}
	return objects
}

// roomComposition is a room message of the test room at a membership
// epoch, under the idempotency key of one digit.
func roomComposition(record eventlog.RoomMLSRecord, body, idemDigit string, now time.Time) localapi.RoomComposition {
	return localapi.RoomComposition{RoomID: testRoomID, ConversationID: "conv_" + strings.Repeat("c3", 32),
		MediaType: "text/plain; charset=utf-8", Body: body, IdempotencyKey: idem(idemDigit),
		MembershipEpoch: record.RoomEpoch, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
}

// compose seals a room message at a node in its current room epoch.
func (s *e2eScene) compose(index int, body, idemDigit string) (string, error) {
	s.t.Helper()
	record, _ := fused(s.t, s.nodes[index])
	eventID, _, err := s.rooms(index).ComposeRoomMessage(context.Background(), roomComposition(record, body, idemDigit, s.clock.now()))
	return eventID, err
}

// requireJournaled requires every listed node to hold an Event in its
// journal.
func (s *e2eScene) requireJournaled(eventID string, indexes ...int) {
	t := s.t
	t.Helper()
	for _, index := range indexes {
		if _, found, err := s.nodes[index].d.journal.Lookup(eventID); err != nil || !found {
			t.Fatalf("node %d does not hold %s: %v", index, eventID, err)
		}
	}
}

func (s *e2eScene) requireNotJournaled(eventID string, indexes ...int) {
	t := s.t
	t.Helper()
	for _, index := range indexes {
		if _, found, err := s.nodes[index].d.journal.Lookup(eventID); err != nil || found {
			t.Fatalf("node %d holds %s: %v", index, eventID, err)
		}
	}
}

// requireQueueEmpty requires every handshake object to a member to have
// been delivered on a verified room ack.
func (s *e2eScene) requireQueueEmpty(member int) {
	t := s.t
	t.Helper()
	heads, err := s.nodes[nodeA].d.journal.RoomMemberQueue(testRoomID, s.agent(member))
	if err != nil || len(heads) != 0 {
		t.Fatalf("the authority still queues %d objects for node %d: %v", len(heads), member, err)
	}
}

// requireInEpoch requires the listed nodes to be at the authority's room
// and MLS epochs.
func (s *e2eScene) requireInEpoch(indexes ...int) eventlog.RoomMLSRecord {
	t := s.t
	t.Helper()
	authority, _ := fused(t, s.nodes[nodeA])
	for _, index := range indexes {
		record, found := fused(t, s.nodes[index])
		if !found || record.RoomEpoch != authority.RoomEpoch || record.MLSEpoch != authority.MLSEpoch ||
			record.RoomEndsAtUnix != authority.RoomEndsAtUnix {
			t.Fatalf("node %d is at %d/%d (found %v), the authority at %d/%d", index, record.RoomEpoch, record.MLSEpoch,
				found, authority.RoomEpoch, authority.MLSEpoch)
		}
	}
	return authority
}

// TestRoomTestFourDaemonsWalkTheGate drives gate items 2, 3, 4, 5, 8, 9,
// 12, 14, 15, 18 and 19 of section 8 as steps between real daemons. Item 2's
// split of C's Welcome is shown on C's full roster instead: no test part
// size splits the Welcome of a three-member room (about 1.9 KiB) and still
// cuts its full roster (about 22 KiB) within 8 parts.
func TestRoomTestFourDaemonsWalkTheGate(t *testing.T) {
	s := newE2EScene(t)
	s.founded()
	s.addsTwoMembersAcrossCrashes()
	s.exchangesAmongNonContacts()
	s.catchesUpAcrossTheAuthorizationWindow()
	s.catchesUpBeyondTheRelayTTL()
	s.removesAMember()
	s.ends()
}

// founded is item 2's start: A founds the room and adds B through the 1:1
// room.invite and room.key-package; B installs the Welcome and the full
// roster, each delivered on a verified room ack (item 8).
func (s *e2eScene) founded() {
	t := s.t
	t.Helper()
	if err := s.rooms(nodeA).CreateRoom(context.Background(), testRoomID); err != nil {
		t.Fatalf("create: %v", err)
	}
	record, _ := fused(t, s.nodes[nodeA])
	if record.RoomEndsAtUnix != uint64(s.start.Add(time.Hour).Unix()) {
		t.Fatalf("the room ends at %d, not at the authority credential's expiry", record.RoomEndsAtUnix)
	}
	s.add(nodeB)
	if added := s.requireInEpoch(nodeB); added.RoomEpoch != 2 || len(added.Members) != 2 {
		t.Fatalf("after B's Add: %+v", added)
	}
	s.requireQueueEmpty(nodeB)
}

// head returns the authority's staged object of a type for a member.
func (s *e2eScene) head(kind eventlog.RoomObjectType, member int) (eventlog.RoomOutboxHead, eventlog.RoomMemberDelivery) {
	t := s.t
	t.Helper()
	heads, err := s.nodes[nodeA].d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		t.Fatal(err)
	}
	for _, head := range heads {
		if delivery, found := head.Member(s.agent(member)); found && head.Type == kind {
			return head, delivery
		}
	}
	t.Fatalf("no staged object of type %d for node %d", kind, member)
	return eventlog.RoomOutboxHead{}, eventlog.RoomMemberDelivery{}
}

// envelopeDigest is the object digest of a kind-3 envelope, as the outbox
// names it.
func envelopeDigest(t *testing.T, envelope mailEnvelope) string {
	t.Helper()
	decoded, err := relayframe.Decode(envelope.frame)
	if err != nil {
		t.Fatal(err)
	}
	return eventlogDigest(decoded.ObjectDigest)
}

// addsTwoMembersAcrossCrashes is item 2 with C, under item 15's member
// windows. C's full roster, split at the test part size, is cut off after
// all but its last part by a crash and completed from the durable part
// store after the restart; C is then killed after handling it but before
// answering it, and the next generation, byte-identical, is answered
// duplicate and delivers it (D10, item 8). B, already joined, applies the
// Add Commit and the roster of the added member (item 18).
func (s *e2eScene) addsTwoMembersAcrossCrashes() {
	t := s.t
	t.Helper()
	c := s.agent(nodeC)
	toC := func(envelope mailEnvelope) bool { return envelope.to == c && envelope.kind == relayframe.KindRoom }
	s.box.hold = toC
	s.add(nodeC)
	// One object in flight: the Welcome, alone.
	if welcomes := objectEnvelopes(t, s.box.held(toC), relayframe.RoomWelcome); len(welcomes) != 1 ||
		len(s.box.held(toC)) != len(welcomes[0]) {
		t.Fatalf("%d Welcomes in flight to C", len(welcomes))
	}
	roster, _ := s.head(eventlog.RoomObjectRoster, nodeC)
	ofRoster := func(envelope mailEnvelope) bool {
		return toC(envelope) && envelopeDigest(t, envelope) == roster.ObjectDigest
	}
	s.box.hold = ofRoster
	s.settle()
	parts := s.box.held(ofRoster)
	if len(parts) < 2 {
		t.Fatalf("C's roster is not split at the test part size: %d parts of %d bytes", len(parts), roster.Length)
	}
	for _, part := range parts[:len(parts)-1] {
		s.box.remove(part.order)
		if answer := s.hand(part); answer.Result != carrierapi.ResultAdmitted {
			t.Fatalf("a roster part answered %s/%s", answer.Result, answer.Code)
		}
	}
	s.restart(nodeC)
	s.box.hold = nil
	s.box.loseAnswer = ofRoster
	s.settle()
	s.box.loseAnswer = nil
	s.restart(nodeC)
	added := s.requireInEpoch(nodeB, nodeC)
	if added.RoomEpoch != 3 || len(added.Members) != 3 {
		t.Fatalf("after C's Add: %+v", added)
	}
	_, pending := s.head(eventlog.RoomObjectRoster, nodeC)
	if pending.State != eventlog.RoomDeliveryCarried || pending.Generation != 1 {
		t.Fatalf("C's roster, answered to nobody: %+v", pending)
	}
	s.at(time.Unix(int64(pending.NextRedepositAtUnix), 0).Sub(s.start))
	s.requireQueueEmpty(nodeC)
	duplicates := 0
	for _, answer := range s.answers {
		if answer.envelope.to == c && answer.response.AckOutcome == relayframe.OutcomeDuplicate &&
			envelopeDigest(t, answer.envelope) == roster.ObjectDigest {
			duplicates++
		}
	}
	if duplicates != 1 {
		t.Fatalf("C answered its re-deposited roster duplicate %d times", duplicates)
	}
	// The second generation withdrew every part of the first.
	for index := range parts {
		first, err := relayframe.RoomIdempotencyKey(roster.ObjectDigest, c, 1, uint8(index))
		if err != nil {
			t.Fatal(err)
		}
		if !s.withdrawalAsked(nodeA, c, first) {
			t.Fatalf("the re-deposit did not withdraw part %d of the roster's first generation", index)
		}
	}
	// B learned C from the roster of the added member, with no contact
	// between them (item 18).
	b := s.nodes[nodeB]
	if !containsAgent(s.cards[nodeB].of(testRoomID), c) {
		t.Fatal("B's carrier was not given C's card")
	}
	if _, found, err := b.d.journal.LoadRelayEvidence(c); err != nil || !found {
		t.Fatalf("B holds no relay evidence of C: %v", err)
	}
	if _, found, err := s.rooms(nodeB).ledger.RoomCredential(testRoomID, c); err != nil || !found {
		t.Fatalf("B holds no leaf credential of C: %v", err)
	}
	for _, answer := range s.answers {
		if answer.envelope.to == b.d.config.AgentID && answer.response.Result == carrierapi.ResultAck &&
			answer.response.AckOutcome != relayframe.OutcomeAccepted {
			t.Fatalf("B answered a handshake object %s/%s", answer.response.AckOutcome, answer.response.Code)
		}
	}
}

// exchangesAmongNonContacts is item 2's messages, both ways among all
// three, each applied once, and item 12: B and C, no contacts, exchange room
// messages, while B's 1:1 copy to C meets C's allow list and is refused.
// Every application copy ends carried (item 8).
func (s *e2eScene) exchangesAmongNonContacts() {
	t := s.t
	t.Helper()
	members := []int{nodeA, nodeB, nodeC}
	for index, sender := range members {
		eventID, err := s.compose(sender, "hello from "+s.agent(sender)[:8], string(rune('1'+index)))
		if err != nil {
			t.Fatalf("node %d composes: %v", sender, err)
		}
		s.settle()
		for _, receiver := range members {
			if receiver != sender {
				s.requireJournaled(eventID, receiver)
			}
		}
		send, found, err := s.nodes[sender].d.journal.RoomApplicationSendFor(testRoomID, idem(string(rune('1'+index))))
		if err != nil || !found || len(send.Members) != 2 {
			t.Fatalf("node %d's application record: %+v %v", sender, send, err)
		}
		for _, member := range send.Members {
			if member.State != eventlog.RoomDeliveryCarried {
				t.Fatalf("node %d's copy to %s ended %s", sender, member.AgentID, member.State)
			}
		}
	}
	// Each opened copy is applied once: no receiver answered one twice.
	opened := map[string]int{}
	for _, answer := range s.answers {
		if answer.envelope.kind == relayframe.KindRoom && answer.response.Result == carrierapi.ResultAdmitted {
			if objectType, ok := roomObjectType(t, answer.envelope); ok && objectType == relayframe.RoomApplication {
				opened[answer.envelope.to+envelopeDigest(t, answer.envelope)]++
			}
		}
	}
	if len(opened) != 6 {
		t.Fatalf("%d application copies opened, want 6", len(opened))
	}
	for key, count := range opened {
		if count != 1 {
			t.Fatalf("copy %s opened %d times", key, count)
		}
	}
	// B's 1:1 copy to C meets C's normal policy.
	b, c := s.nodes[nodeB], s.nodes[nodeC]
	// B already holds C's evidence from the roster; the contact file adds
	// nothing newer, and C stays no contact of B's admission.
	importer := &contactImporter{verifier: b.d.discovery.relay, localAgentID: b.d.config.AgentID, now: b.d.clock}
	if _, err := importer.importFile(filepath.Join(c.export, directory.RelayContactFile)); err != nil {
		t.Fatalf("B reads C's contact file: %v", err)
	}
	direct := sendText(t, b, c, "not about the room", "9", s.clock.now())
	s.settle()
	s.requireNotJournaled(direct, nodeC)
	refused := false
	for _, answer := range s.answers {
		if answer.envelope.from == b.d.config.AgentID && answer.envelope.to == c.d.config.AgentID &&
			answer.envelope.kind == relayframe.KindCopy {
			refused = answer.response.Result == carrierapi.ResultRefused ||
				answer.response.AckOutcome == relayframe.OutcomeRejected
		}
	}
	if !refused {
		t.Fatal("C did not refuse B's 1:1 copy")
	}
}

// add runs rooms.add at the authority and rooms.join at the member, and
// settles.
func (s *e2eScene) add(member int) {
	t := s.t
	t.Helper()
	if err := s.rooms(nodeA).AddRoomMember(context.Background(), testRoomID, s.agent(member)); err != nil {
		t.Fatalf("add node %d: %v", member, err)
	}
	s.settle()
	if _, found, err := s.nodes[member].d.journal.PendingRoomJoinFor(testRoomID, s.agent(nodeA), s.clock.now()); err != nil || !found {
		t.Fatalf("node %d holds no pending join: %v", member, err)
	}
	if err := s.rooms(member).JoinRoom(context.Background(), testRoomID, s.agent(nodeA)); err != nil {
		t.Fatalf("join at node %d: %v", member, err)
	}
	s.settle()
}

// answeredCommits returns the Commits a member answered with a room ack, as
// object digests in answer order.
func (s *e2eScene) answeredCommits(member int) []string {
	t := s.t
	t.Helper()
	var digests []string
	for _, answer := range s.answers {
		if answer.envelope.to != s.agent(member) || answer.envelope.kind != relayframe.KindRoom ||
			answer.response.Result != carrierapi.ResultAck {
			continue
		}
		digest := envelopeDigest(t, answer.envelope)
		if s.isCommit(digest) {
			digests = append(digests, digest)
		}
	}
	return digests
}

// isCommit reports whether the authority staged an object digest as a
// Commit; s.commits remembers them after their heads are retired.
func (s *e2eScene) isCommit(digest string) bool {
	heads, err := s.nodes[nodeA].d.journal.RoomOutboxHeads(testRoomID)
	if err != nil {
		s.t.Fatal(err)
	}
	for _, head := range heads {
		if head.Type == eventlog.RoomObjectCommit {
			s.commits[head.ObjectDigest] = head.MLSEpoch
		}
	}
	_, found := s.commits[digest]
	return found
}

// catchesUpAcrossTheAuthorizationWindow is items 3 and 14 with item 15's
// authority window. B and C are stopped. A is killed right after its driver
// made D's Add Commit, before the fused record: after the restart the Add
// is committed once and published once. D is stopped before its Welcome
// arrives. A then removes D, its in-flight Welcome generation withdrawn, and
// seals a message in the new epoch. C, stopped longer than the
// authorization lifetime but less than the handshake retention, gets the
// second Commit only after acking the first, applies both in order, opens
// the message it held in its future-epoch buffer, and exchanges messages.
func (s *e2eScene) catchesUpAcrossTheAuthorizationWindow() {
	t := s.t
	t.Helper()
	s.phase = s.clock.now()
	s.stop(nodeB)
	// C's message B will miss (item 4).
	if _, err := s.compose(nodeC, "B misses this one", "4"); err != nil {
		t.Fatal(err)
	}
	s.settle()
	s.clock.set(s.phase.Add(30 * time.Second))
	s.stop(nodeC)
	before, _ := fused(t, s.nodes[nodeA])
	d := s.agent(nodeD)
	toD := func(envelope mailEnvelope) bool { return envelope.to == d && envelope.kind == relayframe.KindRoom }
	s.box.hold = toD
	s.drivers[nodeA].crashNextCommit()
	s.add(nodeD)
	if s.running[nodeA] {
		t.Fatal("D's KeyPackage did not reach A's Commit")
	}
	if after, _ := fused(t, s.nodes[nodeA]); after.MLSEpoch != before.MLSEpoch {
		t.Fatalf("A's killed Commit advanced the room to MLS epoch %d", after.MLSEpoch)
	}
	s.restart(nodeA)
	s.settle()
	added, _ := fused(t, s.nodes[nodeA])
	if added.MLSEpoch != before.MLSEpoch+1 || !added.Membership().Contains(d) {
		t.Fatalf("after the restart A's Add of D: %+v", added)
	}
	s.stop(nodeD)
	// Published once: one Commit for the epoch, one deposit to each member.
	commits := 0
	for _, head := range mustHeads(t, s.nodes[nodeA]) {
		if head.Type == eventlog.RoomObjectCommit && head.MLSEpoch == added.MLSEpoch {
			commits++
		}
	}
	if commits != 1 {
		t.Fatalf("%d Commits staged for MLS epoch %d", commits, added.MLSEpoch)
	}
	for _, member := range []int{nodeB, nodeC} {
		agent := s.agent(member)
		stored := objectEnvelopes(t, s.box.held(func(envelope mailEnvelope) bool { return envelope.to == agent }), relayframe.RoomCommit)
		if len(stored) != 1 {
			t.Fatalf("%d Add Commits wait for node %d", len(stored), member)
		}
	}
	s.staleWelcome = s.box.held(toD)
	if welcomes := objectEnvelopes(t, s.staleWelcome, relayframe.RoomWelcome); len(welcomes) != 1 {
		t.Fatalf("%d Welcomes wait for D", len(welcomes))
	}
	welcome, delivery := s.head(eventlog.RoomObjectWelcome, nodeD)
	if delivery.Generation != 1 {
		t.Fatalf("D's Welcome: %+v", delivery)
	}
	s.box.hold = nil

	// Past the authorization lifetime of the Add, A removes D.
	s.clock.set(s.phase.Add(3 * time.Minute))
	if err := s.rooms(nodeA).RemoveRoomMember(context.Background(), testRoomID, d); err != nil {
		t.Fatalf("remove D: %v", err)
	}
	s.settle()
	sizes, err := relayframe.RoomCut(uint8(welcome.Type), int(welcome.Length), e2ePartBytes)
	if err != nil {
		t.Fatal(err)
	}
	for index := range sizes {
		key, err := relayframe.RoomIdempotencyKey(welcome.ObjectDigest, d, 1, uint8(index))
		if err != nil {
			t.Fatal(err)
		}
		if !s.withdrawalAsked(nodeA, d, key) {
			t.Fatalf("D's in-flight Welcome part %d was not withdrawn", index)
		}
	}
	removed, _ := fused(t, s.nodes[nodeA])
	held, err := s.compose(nodeA, "sealed in the epoch C has not reached", "5")
	if err != nil {
		t.Fatal(err)
	}
	s.settle()

	// C, back after more than the authorization lifetime, catches up.
	s.clock.set(s.phase.Add(6 * time.Minute))
	if issued := s.phase.Add(30 * time.Second); !s.clock.now().After(issued.Add(e2eAuthorization)) {
		t.Fatal("C was not stopped beyond the authorization lifetime")
	}
	s.restart(nodeC)
	s.settle()
	if record := s.requireInEpoch(nodeC); record.MLSEpoch != removed.MLSEpoch || record.Membership().Contains(d) {
		t.Fatalf("C after its catch-up: %+v", record)
	}
	order := s.answeredCommits(nodeC)
	if len(order) < 2 || s.commits[order[len(order)-2]] != added.MLSEpoch || s.commits[order[len(order)-1]] != removed.MLSEpoch {
		t.Fatalf("C answered the Commits out of order: %v", order)
	}
	s.requireJournaled(held, nodeC)
	reply, err := s.compose(nodeC, "caught up", "6")
	if err != nil {
		t.Fatal(err)
	}
	s.settle()
	s.requireJournaled(reply, nodeA)
	s.requireQueueEmpty(nodeC)
	s.laterFromC = reply
}

// catchesUpBeyondTheRelayTTL is item 4: B, stopped beyond the relay TTL,
// applies the re-deposited Commits (generations and withdrawals recorded)
// and, T after C's later message arrived, records the gap of the one it
// missed. It is also item 14's refusal: D's Welcome, handed to D after the
// handshake retention, is refused, and D holds no room.
func (s *e2eScene) catchesUpBeyondTheRelayTTL() {
	t := s.t
	t.Helper()
	b := s.agent(nodeB)
	commit, delivery := s.head(eventlog.RoomObjectCommit, nodeB)
	s.at(time.Unix(int64(delivery.NextRedepositAtUnix), 0).Sub(s.start))
	if _, again := s.head(eventlog.RoomObjectCommit, nodeB); again.Generation != delivery.Generation+1 {
		t.Fatalf("B's Commit after its re-deposit time: %+v", again)
	}
	first, err := relayframe.RoomIdempotencyKey(commit.ObjectDigest, b, delivery.Generation, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !s.withdrawalAsked(nodeA, b, first) {
		t.Fatal("the re-deposit did not withdraw the previous generation")
	}
	back := s.phase.Add(e2eTTL + time.Minute)
	s.clock.set(back)
	s.restart(nodeB)
	s.settle()
	s.requireInEpoch(nodeB)
	s.requireQueueEmpty(nodeB)
	s.requireJournaled(s.laterFromC, nodeB)
	s.box.mutex.Lock()
	lost := 0
	for _, envelope := range s.box.expired {
		if envelope.from == s.agent(nodeC) && envelope.to == b && envelope.kind == relayframe.KindRoom {
			lost++
		}
	}
	s.box.mutex.Unlock()
	if lost != 1 {
		t.Fatalf("%d of C's envelopes to B expired at the relay, want 1", lost)
	}
	gapDelay, err := eventlog.RoomGapDelay(uint64(e2eTTL / time.Second))
	if err != nil {
		t.Fatal(err)
	}
	s.clock.set(back.Add(gapDelay - time.Second))
	s.settle()
	if gaps, err := s.nodes[nodeB].d.journal.RoomGaps(testRoomID, 16); err != nil || len(gaps) != 0 {
		t.Fatalf("a gap declared before T: %+v %v", gaps, err)
	}
	s.clock.set(back.Add(gapDelay))
	s.settle()
	gaps, err := s.nodes[nodeB].d.journal.RoomGaps(testRoomID, 16)
	if err != nil || len(gaps) != 1 || gaps[0].SenderAgentID != s.agent(nodeC) || gaps[0].Reason != eventlog.RoomGapNotArrived ||
		gaps[0].FirstSequence != 2 || gaps[0].LastSequence != 2 {
		t.Fatalf("B's gaps: %+v %v", gaps, err)
	}

	// D's Welcome, handed to it past its header's issue plus the handshake
	// retention plus the skew, is refused and leaves D's join pending.
	issued := s.phase.Add(30 * time.Second)
	s.clock.set(issued.Add(e2eRetention + 5*time.Minute + time.Second))
	s.restart(nodeD)
	frames := make([][]byte, 0, len(s.staleWelcome))
	for _, envelope := range s.staleWelcome {
		frames = append(frames, envelope.frame)
	}
	requireStatelessRejection(t, s.nodes[nodeD], send(t, s.nodes[nodeD], s.agent(nodeA), frames), fault.CodeNotAuthentic)
	if _, found := fused(t, s.nodes[nodeD]); found {
		t.Fatal("D installed a Welcome older than the handshake retention")
	}
	s.stop(nodeD)
}

// removesAMember is item 5: A removes C. C takes the removing Commit as its
// removal notice; later objects are not addressed to C, and one handed to
// it opens nothing; B, for whom C is no contact, forgets C's card and leaf
// credential.
func (s *e2eScene) removesAMember() {
	t := s.t
	t.Helper()
	c := s.agent(nodeC)
	if err := s.rooms(nodeA).RemoveRoomMember(context.Background(), testRoomID, c); err != nil {
		t.Fatalf("remove C: %v", err)
	}
	s.settle()
	if s.reports[nodeC].count(func(err error) bool { return errors.Is(err, ErrRoomRemoved) }) == 0 {
		t.Fatal("C raised no removal notice")
	}
	record := s.requireInEpoch(nodeB)
	if record.Membership().Contains(c) {
		t.Fatalf("C is still a member: %+v", record)
	}
	if !containsAgent(s.cards[nodeB].forgottenIn(testRoomID), c) {
		t.Fatal("B did not forget C's card")
	}
	if _, found, err := s.rooms(nodeB).ledger.RoomCredential(testRoomID, c); err != nil || found {
		t.Fatalf("B still holds C's leaf credential: %v", err)
	}
	s.box.hold = func(envelope mailEnvelope) bool {
		return envelope.from == s.agent(nodeA) && envelope.kind == relayframe.KindRoom
	}
	after, err := s.compose(nodeA, "not for C", "7")
	if err != nil {
		t.Fatal(err)
	}
	s.settle()
	held := s.box.held(s.box.hold)
	s.box.hold = nil
	for _, envelope := range held {
		if envelope.to == c {
			t.Fatal("A addressed a message of the epoch after the Remove to C")
		}
	}
	send, found, err := s.nodes[nodeA].d.journal.RoomApplicationSendFor(testRoomID, idem("7"))
	if err != nil || !found || len(send.Members) != 1 || send.Members[0].AgentID != s.agent(nodeB) {
		t.Fatalf("A's message after the Remove is addressed to %+v (%v)", send.Members, err)
	}
	if len(held) != 1 {
		t.Fatalf("%d envelopes held for the message after the Remove", len(held))
	}
	if answer := s.nodes[nodeC].d.relay.Deliver(context.Background(), s.agent(nodeA), held[0].frame); answer.Result == carrierapi.ResultAdmitted {
		t.Fatal("C admitted a message of the epoch after its removal")
	}
	s.requireNotJournaled(after, nodeC)
	if _, err := s.compose(nodeC, "removed", "8"); fault.CodeOf(err) != fault.CodeNotARoomMember {
		t.Fatalf("C composes after its removal: %v", err)
	}
	s.settle()
	s.requireJournaled(after, nodeB)
}

// ends is item 19: no membership change in the last re-deposit interval
// before the end minus the skew, no sealing from the end minus the skew, an
// application object sealed before the end arriving after the end plus the
// skew is a room-ended gap with the owner notice, and after the handshake
// retention every room store is retired.
func (s *e2eScene) ends() {
	t := s.t
	t.Helper()
	record, _ := fused(t, s.nodes[nodeA])
	end := time.Unix(int64(record.RoomEndsAtUnix), 0)
	skew := 5 * time.Minute
	s.clock.set(end.Add(-skew).Add(-MinRelayRedepositInterval))
	if err := s.rooms(nodeA).RemoveRoomMember(context.Background(), testRoomID, s.agent(nodeB)); !errors.Is(err, ErrRoomHandshakeTooLate) {
		t.Fatalf("a Remove in the last interval: %v", err)
	}
	s.clock.set(end.Add(-skew).Add(-time.Second))
	s.box.hold = func(envelope mailEnvelope) bool {
		return envelope.from == s.agent(nodeA) && envelope.kind == relayframe.KindRoom
	}
	late, err := s.compose(nodeA, "sealed just before the end", "9")
	if err != nil {
		t.Fatalf("a seal one second before the end minus the skew: %v", err)
	}
	s.settle()
	s.clock.set(end.Add(-skew))
	for _, index := range []int{nodeA, nodeB} {
		if _, err := s.compose(index, "too late", "a"); fault.CodeOf(err) != fault.CodeRoomEnded {
			t.Fatalf("node %d seals at the end minus the skew: %v", index, err)
		}
	}
	// The relay TTL here is shorter than twice the skew, so the harness keeps
	// the copy to B, as a relay with a longer TTL would, and hands it over at
	// the end plus the skew.
	copies := s.box.held(func(envelope mailEnvelope) bool { return s.box.hold(envelope) && envelope.to == s.agent(nodeB) })
	if len(copies) != 1 {
		t.Fatalf("%d copies of the last message to B", len(copies))
	}
	s.box.remove(copies[0].order)
	s.box.hold = nil
	s.clock.set(end.Add(skew))
	if answer := s.hand(copies[0]); answer.Result == carrierapi.ResultAdmitted {
		t.Fatal("B admitted a message arriving at the end plus the skew")
	}
	s.settle()
	s.requireNotJournaled(late, nodeB)
	gaps, err := s.nodes[nodeB].d.journal.RoomGaps(testRoomID, 16)
	if err != nil {
		t.Fatal(err)
	}
	ended := false
	for _, gap := range gaps {
		ended = ended || gap.SenderAgentID == s.agent(nodeA) && gap.Reason == eventlog.RoomGapRoomEnded
	}
	if !ended || s.reports[nodeB].count(func(err error) bool { return errors.Is(err, ErrRoomEnded) }) == 0 {
		t.Fatalf("B recorded no room-ended gap with its notice: %+v", gaps)
	}
	// Retirement at the end plus the retention plus the skew.
	s.clock.set(end.Add(e2eRetention).Add(skew).Add(-time.Second))
	s.settle()
	if _, found := fused(t, s.nodes[nodeB]); !found {
		t.Fatal("B retired the room before its retirement time")
	}
	s.clock.set(end.Add(e2eRetention).Add(skew))
	s.settle()
	for _, index := range []int{nodeA, nodeB, nodeC} {
		if records, err := s.rooms(index).ledger.List(); err != nil || len(records) != 0 {
			t.Fatalf("node %d still holds %d rooms: %v", index, len(records), err)
		}
		if heads, err := s.nodes[index].d.journal.RoomOutboxHeads(testRoomID); err != nil || len(heads) != 0 {
			t.Fatalf("node %d still holds %d outbox heads: %v", index, len(heads), err)
		}
	}
	if !containsAgent(s.cards[nodeB].forgottenIn(testRoomID), s.agent(nodeA)) {
		t.Fatal("B's retirement did not forget the room's card admissions")
	}
}
