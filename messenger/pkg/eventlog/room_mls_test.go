package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

const fusedRoom = "room_" + "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

func fusedAgent(index int) string { return fmt.Sprintf("agent_%064x", index+1) }

func fusedAuthenticator(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, group.MLSEpochAuthenticatorBytes)
}

type fusedFixture struct {
	t          *testing.T
	delegation identity.Delegation
	key        ed25519.PrivateKey
	now        time.Time
}

func newFusedFixture(t *testing.T) *fusedFixture {
	t.Helper()
	delegation, key := roomDelegation(t, fusedAgent(0), 0x61)
	return &fusedFixture{t: t, delegation: delegation, key: key, now: time.Unix(10_000, 0)}
}

func (f *fusedFixture) proof(membership room.Membership) RoomAuthorityProof {
	f.t.Helper()
	return RoomAuthorityProof{Membership: membership, Authorization: membershipAuthorization(f.t, membership, f.delegation, f.key, f.now), Delegation: f.delegation}
}

func (f *fusedFixture) founding() room.Membership {
	f.t.Helper()
	membership, err := room.Found(fusedRoom, []string{fusedAgent(0)})
	if err != nil {
		f.t.Fatal(err)
	}
	return membership
}

func openFused(t *testing.T, root string) (*Journal, *RoomMLSLedger) {
	t.Helper()
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := journal.OpenRoomMLS()
	if err != nil {
		t.Fatal(err)
	}
	return journal, ledger
}

func (f *fusedFixture) installFounder(ledger *RoomMLSLedger, state []byte) RoomMLSRecord {
	f.t.Helper()
	membership := f.founding()
	record, err := ledger.InstallFounder(RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: membership.Digest},
		Proof:   f.proof(membership), State: state, EpochAuthenticator: fusedAuthenticator(1),
		KeyPackageRef: canon.Digest([]byte("founder key package")),
	}, f.now)
	if err != nil {
		f.t.Fatal(err)
	}
	return record
}

func refreshTransition(current RoomMLSRecord, ref string) group.Transition {
	next := current.Binding()
	next.Clock.MLSEpoch++
	next.AcceptedCommitRef = ref
	return group.Transition{Prior: current.Binding(), Next: next, CommitRef: ref}
}

func addTransition(t *testing.T, current RoomMLSRecord, added []string, ref string) (group.Transition, room.Membership) {
	t.Helper()
	membership, err := current.Membership().Add(added)
	if err != nil {
		t.Fatal(err)
	}
	next := group.State{RoomID: current.RoomID, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: current.MLSEpoch + 1}, MembershipDigest: membership.Digest, AcceptedCommitRef: ref}
	return group.Transition{Prior: current.Binding(), Next: next, Membership: membership, CommitRef: ref}, membership
}

// A maximal fused record (32 members, a 128-byte network ID, every reference
// set, two retained memberships and three epoch authenticators) encodes well
// inside its 8,192-byte cap.
func TestFusedRecordMaximalEncodingFitsItsCap(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: strings.Repeat("n", 128), GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
	members := make([]string, group.MaxPrivateRoomAgents)
	for index := range members {
		members[index] = fusedAgent(index)
	}
	digest, err := room.Digest(fusedRoom, ^uint64(0), members)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(label string) string { return canon.Digest([]byte(label)) }
	record := RoomMLSRecord{
		Schema: RoomMLSRecordSchema, RoomID: fusedRoom, RoomEpoch: ^uint64(0), MLSEpoch: ^uint64(0),
		MembershipDigest: digest, Members: members, PriorMemberships: []string{ref("m1"), ref("m2")},
		AuthorityAgentID: members[0], AuthorityEndpointID: "mep_" + strings.Repeat("e", 64),
		Authorization: encodeAuthorization(room.MembershipAuthorization{
			Network: network, RoomID: fusedRoom, Epoch: ^uint64(0), MembershipDigest: digest,
			Authority:    room.Authority{AgentID: members[0], EndpointID: "mep_" + strings.Repeat("e", 64)},
			IssuedAtUnix: ^uint64(0) - 1, ExpiresAtUnix: ^uint64(0), EndpointSignature: bytes.Repeat([]byte{0xff}, ed25519.SignatureSize),
		}),
		PriorCommitRef: ref("prior"), AcceptedCommitRef: ref("accepted"),
		StateDigest: ref("state"), StateChunks: []string{ref("c1"), ref("c2")},
		DelegationDigest: ref("delegation"), KeyPackageRef: ref("kp"), WelcomeRef: ref("welcome"),
		EpochAuthenticators: []EpochAuthenticator{
			{MLSEpoch: ^uint64(0), AuthenticatorHex: hex.EncodeToString(fusedAuthenticator(3))},
			{MLSEpoch: ^uint64(0) - 1, AuthenticatorHex: hex.EncodeToString(fusedAuthenticator(2))},
			{MLSEpoch: ^uint64(0) - 2, AuthenticatorHex: hex.EncodeToString(fusedAuthenticator(1))},
		},
		UpdatedAtUnix: ^uint64(0),
	}
	encoded, err := encodeRoomMLSRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxRoomMLSRecordBytes {
		t.Fatalf("maximal record is %d bytes", len(encoded))
	}
	t.Logf("maximal fused record: %d of %d bytes", len(encoded), MaxRoomMLSRecordBytes)
	decoded, err := decodeRoomMLSRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := json.Marshal(decoded); !bytes.Equal(again, encoded) {
		t.Fatal("maximal record does not round-trip")
	}
}

// A fused record above the cap is refused when written and when read.
func TestFusedRecordOverCapIsRefusedOnWriteAndRead(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("founder state"))
	encoded, err := encodeRoomMLSRecord(record)
	if err != nil {
		t.Fatal(err)
	}

	// The current record fits the lowered cap; the next one, which adds a
	// member and a retained membership, does not, and is refused on write.
	saved := roomMLSRecordCap
	roomMLSRecordCap = len(encoded)
	defer func() { roomMLSRecordCap = saved }()
	add, membership := addTransition(t, record, []string{fusedAgent(1)}, canon.Digest([]byte("grows")))
	proof := fixture.proof(membership)
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: add, Proof: &proof, ExpectedStateDigest: record.StateDigest, State: []byte("next state"), EpochAuthenticator: fusedAuthenticator(2)}, fixture.now); !errors.Is(err, ErrRoomMLSRecordTooLarge) {
		t.Fatalf("over-cap write: %v", err)
	}
	// Lowered below the stored record, the cap refuses the read.
	roomMLSRecordCap = len(encoded) - 1
	if _, _, err := ledger.Current(fusedRoom); !errors.Is(err, ErrRoomMLSRecordTooLarge) {
		t.Fatalf("over-cap read: %v", err)
	}
	if _, err := decodeRoomMLSRecord(encoded); !errors.Is(err, ErrRoomMLSRecordTooLarge) {
		t.Fatalf("over-cap decode: %v", err)
	}
	roomMLSRecordCap = saved
	if current, _, err := ledger.Current(fusedRoom); err != nil || current.StateDigest != record.StateDigest {
		t.Fatalf("the refused write changed the record: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	// An over-cap file on disk is refused before it is parsed.
	path := filepath.Join(root, roomMLSDir, fusedRoom[len("room_"):]+".json")
	padded := append(bytes.TrimSuffix(encoded, []byte("\n")), bytes.Repeat([]byte(" "), MaxRoomMLSRecordBytes)...)
	if err := os.WriteFile(path, padded, 0o600); err != nil {
		t.Fatal(err)
	}
	journal, ledger = openFused(t, root)
	defer journal.Close()
	if _, _, err := ledger.Current(fusedRoom); !errors.Is(err, ErrRoomMLSRecordTooLarge) {
		t.Fatalf("over-cap file: %v", err)
	}
}

func TestFusedLedgerAdvancesSurvivesRestartAndRetainsEpochs(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	record := fixture.installFounder(ledger, []byte("epoch zero"))

	refresh := refreshTransition(record, canon.Digest([]byte("refresh-1")))
	fresh, record, err := ledger.Advance(RoomMLSAdvance{Transition: refresh, ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2)}, fixture.now)
	if err != nil || !fresh || record.RoomEpoch != 1 || record.MLSEpoch != 1 {
		t.Fatalf("MLS-only refresh: %v %v %+v", fresh, err, record.Binding())
	}

	add, membership := addTransition(t, record, []string{fusedAgent(1)}, canon.Digest([]byte("add-bob")))
	proof := fixture.proof(membership)
	fresh, record, err = ledger.Advance(RoomMLSAdvance{Transition: add, Proof: &proof, ExpectedStateDigest: record.StateDigest, State: []byte("epoch two"), EpochAuthenticator: fusedAuthenticator(3)}, fixture.now)
	if err != nil || !fresh || record.RoomEpoch != 2 || record.MLSEpoch != 2 || len(record.Members) != 2 {
		t.Fatalf("room advance: %v %v", fresh, err)
	}
	// The exact repeat is a no-op answered as not fresh.
	if fresh, _, err := ledger.Advance(RoomMLSAdvance{Transition: add, Proof: &proof, ExpectedStateDigest: canon.Digest([]byte("stale")), State: []byte("another state"), EpochAuthenticator: fusedAuthenticator(9)}, fixture.now); err != nil || fresh {
		t.Fatalf("exact repeat: %v %v", fresh, err)
	}

	refresh = refreshTransition(record, canon.Digest([]byte("refresh-3")))
	if _, record, err = ledger.Advance(RoomMLSAdvance{Transition: refresh, ExpectedStateDigest: record.StateDigest, State: []byte("epoch three"), EpochAuthenticator: fusedAuthenticator(4)}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if len(record.EpochAuthenticators) != RetainedRoomEpochs {
		t.Fatalf("retained %d epoch authenticators", len(record.EpochAuthenticators))
	}
	if _, kept := record.EpochAuthenticatorAt(0); kept {
		t.Fatal("an epoch beyond the window kept its authenticator")
	}
	if value, kept := record.EpochAuthenticatorAt(1); !kept || !bytes.Equal(value, fusedAuthenticator(2)) {
		t.Fatal("epoch 1 authenticator missing")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	journal, ledger = openFused(t, root)
	defer journal.Close()
	restarted, found, err := ledger.Current(fusedRoom)
	if err != nil || !found || restarted.Binding() != record.Binding() {
		t.Fatalf("restart: %v %v", found, err)
	}
	state, err := ledger.State(restarted)
	if err != nil || string(state) != "epoch three" {
		t.Fatalf("restarted state %q: %v", state, err)
	}
	earlier, found, err := ledger.MembershipAt(fusedRoom, 1)
	if err != nil || !found || len(earlier.Members) != 1 || earlier.Members[0] != fusedAgent(0) {
		t.Fatalf("retained epoch-1 membership: %v %v %+v", found, err, earlier)
	}
	if _, found, err := ledger.MembershipAt(fusedRoom, 7); err != nil || found {
		t.Fatalf("unknown epoch: %v %v", found, err)
	}
}

func TestFusedLedgerRefusesForkGapRollbackAndForeignAuthority(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("epoch zero"))
	first := refreshTransition(record, canon.Digest([]byte("first")))
	_, advanced, err := ledger.Advance(RoomMLSAdvance{Transition: first, ExpectedStateDigest: record.StateDigest, State: []byte("epoch one"), EpochAuthenticator: fusedAuthenticator(2)}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}

	competing := refreshTransition(record, canon.Digest([]byte("competing")))
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: competing, ExpectedStateDigest: advanced.StateDigest, State: []byte("other child"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); !errors.Is(err, ErrMLSFork) {
		t.Fatalf("competing child: %v", err)
	}
	stale := refreshTransition(advanced, canon.Digest([]byte("from stale state")))
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: stale, ExpectedStateDigest: record.StateDigest, State: []byte("x"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); !errors.Is(err, ErrMLSFork) {
		t.Fatalf("stale state digest: %v", err)
	}
	gap := refreshTransition(advanced, canon.Digest([]byte("gap")))
	gap.Prior.Clock.MLSEpoch++
	gap.Next.Clock.MLSEpoch++
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: gap, ExpectedStateDigest: advanced.StateDigest, State: []byte("x"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); !errors.Is(err, ErrMLSGap) {
		t.Fatalf("gap: %v", err)
	}

	// A membership change signed by anyone but the recorded authority.
	other, otherKey := roomDelegation(t, fusedAgent(1), 0x62)
	add, membership := addTransition(t, advanced, []string{fusedAgent(1)}, canon.Digest([]byte("foreign")))
	foreign := RoomAuthorityProof{Membership: membership, Authorization: membershipAuthorization(t, membership, other, otherKey, fixture.now), Delegation: other}
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: add, Proof: &foreign, ExpectedStateDigest: advanced.StateDigest, State: []byte("x"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); !errors.Is(err, ErrNotRoomAuthority) {
		t.Fatalf("a non-authority advanced membership: %v", err)
	}
	// A room change without its authorization, and an MLS-only one with one.
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: add, ExpectedStateDigest: advanced.StateDigest, State: []byte("x"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); err == nil {
		t.Fatal("room change without authorization accepted")
	}
	proof := fixture.proof(membership)
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: refreshTransition(advanced, canon.Digest([]byte("r"))), Proof: &proof, ExpectedStateDigest: advanced.StateDigest, State: []byte("x"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); err == nil {
		t.Fatal("MLS-only advance with an authorization accepted")
	}
	// A tampered authorization signature.
	tampered := fixture.proof(membership)
	tampered.Authorization.EndpointSignature = append([]byte(nil), tampered.Authorization.EndpointSignature...)
	tampered.Authorization.EndpointSignature[0] ^= 1
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: add, Proof: &tampered, ExpectedStateDigest: advanced.StateDigest, State: []byte("x"), EpochAuthenticator: fusedAuthenticator(5)}, fixture.now); err == nil {
		t.Fatal("tampered authorization accepted")
	}
	if current, _, err := ledger.Current(fusedRoom); err != nil || current.Binding() != advanced.Binding() || current.StateDigest != advanced.StateDigest {
		t.Fatalf("a refused advance changed the record: %v", err)
	}
}

func TestFusedLedgerKeyPackageIsOneTimeAndWelcomeReplayIsRefused(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	membership := fixture.founding()
	kp := canon.Digest([]byte("one-time key package"))
	welcome := canon.Digest([]byte("welcome"))
	install := RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 3}, MembershipDigest: membership.Digest},
		Proof:   fixture.proof(membership), State: []byte("joined"), EpochAuthenticator: fusedAuthenticator(1),
		KeyPackageRef: kp, WelcomeRef: welcome,
	}
	if _, err := ledger.InstallWelcome(install, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.InstallWelcome(install, fixture.now); !errors.Is(err, ErrWelcomeReplay) {
		t.Fatalf("Welcome replay: %v", err)
	}
	other := install
	other.WelcomeRef = canon.Digest([]byte("other welcome"))
	if _, err := ledger.InstallWelcome(other, fixture.now); !errors.Is(err, ErrKeyPackageConsumed) {
		t.Fatalf("KeyPackage reuse in the same room: %v", err)
	}

	secondRoom := "room_" + strings.Repeat("6", 64)
	second, err := room.Found(secondRoom, []string{fusedAgent(0)})
	if err != nil {
		t.Fatal(err)
	}
	cross := RoomMLSInstall{
		Binding: group.State{RoomID: secondRoom, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: second.Digest},
		Proof:   fixture.proof(second), State: []byte("second room"), EpochAuthenticator: fusedAuthenticator(1),
		KeyPackageRef: kp, WelcomeRef: canon.Digest([]byte("second welcome")),
	}
	if _, err := ledger.InstallWelcome(cross, fixture.now); !errors.Is(err, ErrKeyPackageConsumed) {
		t.Fatalf("KeyPackage reuse across rooms: %v", err)
	}
	// The scan fails closed: an unreadable fused record refuses every install.
	if err := os.WriteFile(filepath.Join(journal.root, roomMLSDir, fusedRoom[len("room_"):]+".json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cross.KeyPackageRef = canon.Digest([]byte("fresh key package"))
	if _, err := ledger.InstallWelcome(cross, fixture.now); err == nil {
		t.Fatal("install proceeded past an unreadable fused record")
	}
}

// A chunk whose bytes do not reproduce its digest, or chunks that do not
// reassemble the named state, fail the read closed.
func TestFusedLedgerStateChunkDamageFailsClosed(t *testing.T) {
	fixture := newFusedFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openFused(t, root)
	defer journal.Close()
	state := bytes.Repeat([]byte("s"), MLSStateChunkBytes+1000)
	record := fixture.installFounder(ledger, state)
	if len(record.StateChunks) != 2 {
		t.Fatalf("a %d-byte state took %d chunks", len(state), len(record.StateChunks))
	}
	if loaded, err := ledger.State(record); err != nil || !bytes.Equal(loaded, state) {
		t.Fatalf("intact state: %v", err)
	}

	path, err := journal.roomStatePath(fusedRoom, record.StateChunks[1])
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var chunk roomChunkRecord
	if err := json.Unmarshal(original, &chunk); err != nil {
		t.Fatal(err)
	}
	// The same record name and digest field, other bytes.
	forged := chunk
	forged.DataBase64 = "Zm9yZ2Vk"
	encoded, _ := json.Marshal(forged)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.State(record); !errors.Is(err, ErrRoomChunkDigest) {
		t.Fatalf("forged chunk bytes: %v", err)
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	// Chunks that are each intact but reassemble another state.
	swapped := record
	swapped.StateChunks = []string{record.StateChunks[0], record.StateChunks[0]}
	if _, err := ledger.State(swapped); !errors.Is(err, ErrRoomChunkDigest) {
		t.Fatalf("state digest mismatch: %v", err)
	}
	// The delegation record is verified by its digest alone, with no larger
	// digest behind it.
	delegationPath, err := journal.roomBlobPath(delegationBlobPrefix, record.DelegationDigest)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := os.ReadFile(delegationPath)
	if err != nil {
		t.Fatal(err)
	}
	var delegationChunk roomChunkRecord
	if err := json.Unmarshal(delegationRaw, &delegationChunk); err != nil {
		t.Fatal(err)
	}
	otherDelegation, _ := roomDelegation(t, fusedAgent(0), 0x63)
	otherJSON, _ := json.Marshal(otherDelegation)
	delegationChunk.DataBase64 = base64.StdEncoding.EncodeToString(otherJSON)
	forgedDelegation, _ := json.Marshal(delegationChunk)
	if err := os.WriteFile(delegationPath, forgedDelegation, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Current(fusedRoom); !errors.Is(err, ErrRoomChunkDigest) {
		t.Fatalf("substituted delegation: %v", err)
	}
	if err := os.WriteFile(delegationPath, delegationRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	// A missing chunk.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.State(record); err == nil {
		t.Fatal("missing chunk accepted")
	}
}

// A successful fused write deletes the state chunks it superseded, and keeps
// a chunk the new state shares.
func TestFusedLedgerDeletesSupersededStateChunks(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	shared := bytes.Repeat([]byte("A"), MLSStateChunkBytes)
	first := fixture.installFounder(ledger, append(append([]byte(nil), shared...), []byte("first tail")...))
	_, second, err := ledger.Ratchet(fusedRoom, first.StateDigest, append(append([]byte(nil), shared...), []byte("second tail")...), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.StateChunks[0] != second.StateChunks[0] || first.StateChunks[1] == second.StateChunks[1] {
		t.Fatal("test states do not share exactly their first chunk")
	}
	for _, check := range []struct {
		digest string
		exists bool
	}{{first.StateChunks[0], true}, {first.StateChunks[1], false}, {second.StateChunks[1], true}} {
		path, err := journal.roomStatePath(fusedRoom, check.digest)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(path); (err == nil) != check.exists {
			t.Fatalf("chunk %s exists=%v, want %v", check.digest, err == nil, check.exists)
		}
	}
	if loaded, err := ledger.State(second); err != nil || !bytes.HasSuffix(loaded, []byte("second tail")) {
		t.Fatalf("current state after deletion: %v", err)
	}
}

// The logical room ledger answers for a private room from its fused record,
// and neither ledger takes over a room the other holds.
func TestRoomLedgerAnswersForFusedRoomAndRefusesToAdvanceIt(t *testing.T) {
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	record := fixture.installFounder(ledger, []byte("state"))
	add, membership := addTransition(t, record, []string{fusedAgent(1)}, canon.Digest([]byte("add")))
	proof := fixture.proof(membership)
	if _, _, err := ledger.Advance(RoomMLSAdvance{Transition: add, Proof: &proof, ExpectedStateDigest: record.StateDigest, State: []byte("state 2"), EpochAuthenticator: fusedAuthenticator(2)}, fixture.now); err != nil {
		t.Fatal(err)
	}
	rooms, err := journal.OpenRooms()
	if err != nil {
		t.Fatal(err)
	}
	if standing, err := rooms.JudgeMember(fusedRoom, fusedAgent(1)); err != nil || standing != RoomMember {
		t.Fatalf("member standing: %v %v", standing, err)
	}
	if standing, err := rooms.JudgeMember(fusedRoom, fusedAgent(2)); err != nil || standing != RoomNotMember {
		t.Fatalf("stranger standing: %v %v", standing, err)
	}
	delegation, found, err := rooms.CurrentAuthorityDelegation(fusedRoom)
	if err != nil || !found || delegation.EndpointID != fixture.delegation.EndpointID {
		t.Fatalf("authority delegation: %v %v", found, err)
	}
	next, err := membership.Add([]string{fusedAgent(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rooms.Advance(next, membershipAuthorization(t, next, fixture.delegation, fixture.key, fixture.now), fixture.delegation, fixture.now); !errors.Is(err, ErrRoomKind) {
		t.Fatalf("logical advance of a private room: %v", err)
	}

	logical := "room_" + strings.Repeat("7", 64)
	founded, err := room.Found(logical, []string{fusedAgent(0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rooms.Advance(founded, membershipAuthorization(t, founded, fixture.delegation, fixture.key, fixture.now), fixture.delegation, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.InstallFounder(RoomMLSInstall{
		Binding: group.State{RoomID: logical, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founded.Digest},
		Proof:   fixture.proof(founded), State: []byte("s"), EpochAuthenticator: fusedAuthenticator(1),
		KeyPackageRef: canon.Digest([]byte("another key package")),
	}, fixture.now); !errors.Is(err, ErrRoomKind) {
		t.Fatalf("private install over a logical room: %v", err)
	}
}

// The fused-record decoder never panics, and whatever it accepts re-encodes
// within the cap and decodes to the same record.
func FuzzRoomMLSRecordDecode(f *testing.F) {
	membership, _ := room.Found(fusedRoom, []string{fusedAgent(0)})
	endpoint := "mep_" + strings.Repeat("e", 64)
	network := &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
	record := RoomMLSRecord{
		Schema: RoomMLSRecordSchema, RoomID: fusedRoom, RoomEpoch: 1, MembershipDigest: membership.Digest, Members: membership.Members,
		AuthorityAgentID: fusedAgent(0), AuthorityEndpointID: endpoint,
		Authorization: encodeAuthorization(room.MembershipAuthorization{Network: network, RoomID: fusedRoom, Epoch: 1, MembershipDigest: membership.Digest,
			Authority: room.Authority{AgentID: fusedAgent(0), EndpointID: endpoint}, IssuedAtUnix: 1, ExpiresAtUnix: 2, EndpointSignature: bytes.Repeat([]byte{1}, ed25519.SignatureSize)}),
		StateDigest: canon.Digest([]byte("s")), StateChunks: []string{canon.Digest([]byte("c"))}, DelegationDigest: canon.Digest([]byte("d")),
		KeyPackageRef: canon.Digest([]byte("k")), EpochAuthenticators: []EpochAuthenticator{{AuthenticatorHex: hex.EncodeToString(fusedAuthenticator(1))}}, UpdatedAtUnix: 1,
	}
	seed, err := json.Marshal(record)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := decodeRoomMLSRecord(seed); err != nil {
		f.Fatalf("the seed record is not accepted: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := decodeRoomMLSRecord(raw)
		if err != nil {
			return
		}
		encoded, err := encodeRoomMLSRecord(decoded)
		if err != nil || len(encoded) > MaxRoomMLSRecordBytes {
			t.Fatalf("an accepted record does not re-encode within its cap: %v", err)
		}
		again, err := decodeRoomMLSRecord(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if a, _ := json.Marshal(again); !bytes.Equal(a, encoded) {
			t.Fatal("an accepted record does not round-trip")
		}
	})
}
