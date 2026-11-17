package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

// keySwapDriver reports every committer and sender leaf with another
// signature key: the controller must refuse a leaf whose identity is right
// but whose key is not the verified credential's.
type keySwapDriver struct {
	*group.OpenMLSSidecar
	key ed25519.PublicKey
}

func (d keySwapDriver) ApplyAttributed(state, commit []byte) ([]byte, group.MLSMember, error) {
	next, committer, err := d.OpenMLSSidecar.ApplyAttributed(state, commit)
	committer.SignatureKey = d.key
	return next, committer, err
}

func (d keySwapDriver) OpenAttributed(state, aad, message []byte) ([]byte, []byte, group.MLSMember, error) {
	next, plaintext, sender, err := d.OpenMLSSidecar.OpenAttributed(state, aad, message)
	sender.SignatureKey = d.key
	return next, plaintext, sender, err
}

// relayLeaf makes member index's relay room leaf the way a joiner does: a
// fresh leaf signature key, the Endpoint-signed leaf credential naming it,
// then the KeyPackage under the compact identity naming that credential, and
// the DeviceCredential of that KeyPackage (sent as room.key-package), with
// its KeyPackage reference.
func relayLeaf(t *testing.T, driver *group.OpenMLSSidecar, index int) (group.OpenMLSIdentity, group.LeafBinding, []byte, string) {
	t.Helper()
	signer, err := driver.NewLeafSigner()
	if err != nil {
		t.Fatal(err)
	}
	// Member 0 is the fixture's authority, so its delegation is the
	// fixture's; the others have delegations of their own.
	seed := byte(0x70 + index)
	if index == 0 {
		seed = 0x61
	}
	delegation, endpointKey := roomDelegation(t, fusedAgent(index), seed)
	endpointID, deviceID := delegation.EndpointID, fmt.Sprintf("dev_%064x", index+1)
	credential, err := group.SignLeafCredential(group.LeafCredential{
		Network: delegation.Network, AgentID: fusedAgent(index), EndpointID: endpointID, DeviceID: deviceID,
		DeviceSetDigest: canon.Digest([]byte("set")), LeafSignaturePublicKey: signer.LeafSignaturePublicKey,
		IssuedAtUnix: 1_000, ExpiresAtUnix: testRoomEnd}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	set := e2ee.SetSummary{EndpointID: endpointID, Digest: credential.DeviceSetDigest, DeviceIDs: []string{deviceID}}
	binding, err := group.VerifyRoomLeafCredential(delegation, credential, set, credential.ExpiresAtUnix, time.Unix(10_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	made, err := driver.NewIdentityForSigner(signer, binding.Identity())
	if err != nil {
		t.Fatal(err)
	}
	device, err := group.SignDeviceCredential(group.DeviceCredential{Network: delegation.Network, AgentID: fusedAgent(index),
		EndpointID: endpointID, DeviceID: deviceID, DeviceSetDigest: credential.DeviceSetDigest,
		LeafSignaturePublicKey: signer.LeafSignaturePublicKey, KeyPackage: made.KeyPackage,
		IssuedAtUnix: credential.IssuedAtUnix, ExpiresAtUnix: credential.ExpiresAtUnix}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := group.LeafFromCredentials(device, credential)
	if err != nil {
		t.Fatal(err)
	}
	deviceJSON, err := group.EncodeDeviceCredentialJSON(device)
	if err != nil {
		t.Fatal(err)
	}
	return made, binding, deviceJSON, leaf.KeyPackageRef
}

func TestOpenMLSRoomControllerIntegrationFusedRestartAndAttribution(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make messenger-test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	identities := make([]group.OpenMLSIdentity, 3)
	leaves := make([]group.LeafBinding, 3)
	devices := make([][]byte, 3)
	refs := make([]string, 3)
	for index := range identities {
		identities[index], leaves[index], devices[index], refs[index] = relayLeaf(t, driver, index)
	}
	fixture := newFusedFixture(t)
	now := func() time.Time { return fixture.now }
	roots := []string{t.TempDir() + "/alice", t.TempDir() + "/bob", t.TempDir() + "/carol"}
	journals := make([]*Journal, 3)
	controllers := make([]*RoomMLSController, 3)
	ledgers := make([]*RoomMLSLedger, 3)
	open := func() {
		for index := range journals {
			journal, ledger := openFused(t, roots[index])
			controller, err := NewRoomMLSController(ledger, driver, now)
			if err != nil {
				t.Fatal(err)
			}
			journals[index], ledgers[index], controllers[index] = journal, ledger, controller
		}
	}
	closeAll := func() {
		for _, journal := range journals {
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	open()
	defer func() {
		for _, journal := range journals {
			_ = journal.Close()
		}
	}()

	groupID := bytes.Repeat([]byte{0x5a}, group.MLSGroupIDBytes)
	founding := fixture.founding()
	// The founder's KeyPackage must carry the founder's own leaf binding.
	foundingBinding := group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founding.Digest}
	if _, err := controllers[0].CreateRoom(foundingBinding, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, refs[0], leaves[1]); err == nil {
		t.Fatal("a founder KeyPackage was installed under another leaf")
	}
	if _, err := controllers[0].CreateRoom(foundingBinding, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, refs[0], group.LeafBinding{}); !errors.Is(err, ErrRoomLeafIdentity) {
		t.Fatalf("a founder without a verified binding: %v", err)
	}
	alice, err := controllers[0].CreateRoom(foundingBinding, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, refs[0], leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	// Bob and Carol were invited (the invite carried the authority's
	// credential) and their owners joined: each holds an accepted pending
	// join for the KeyPackage it sent.
	for _, index := range []int{1, 2} {
		if _, err := journals[index].RecordRoomInvite(fusedRoom, fusedAgent(0), inviteEvent, leaves[0], fixture.now.Add(time.Hour), fixture.now); err != nil {
			t.Fatal(err)
		}
		if _, err := journals[index].BeginRoomJoin(fusedRoom, fusedAgent(0), identities[index].State, devices[index], fixture.now); err != nil {
			t.Fatal(err)
		}
	}

	leaf := func(index int) group.LeafOperation {
		return group.LeafOperation{Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: leaves[index].Identity(), LeafSignaturePublicKey: identities[index].LeafSignaturePublicKey, KeyPackageRef: refs[index], KeyPackage: identities[index].KeyPackage}}
	}
	add := func(current RoomMLSRecord, index int, existing []RoomRecipient) (CommitResult, RoomMLSRecord, room.Membership) {
		t.Helper()
		membership, err := current.Membership().Add([]string{fusedAgent(index)})
		if err != nil {
			t.Fatal(err)
		}
		template := group.Transition{Prior: current.Binding(), Next: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: membership.Epoch, MLSEpoch: current.MLSEpoch + 1}, MembershipDigest: membership.Digest}, Membership: membership}
		proof := fixture.proof(membership)
		result, record, err := controllers[0].Commit(template, &proof, []group.LeafOperation{leaf(index)}, func(result CommitResult) ([]StagedRoomObject, error) {
			epoch := result.Transition.Next.Clock
			objects := []StagedRoomObject{{Type: RoomObjectWelcome, RoomEpoch: epoch.RoomEpoch, MLSEpoch: epoch.MLSEpoch, Object: result.Welcomes[refs[index]], Recipients: []RoomRecipient{{AgentID: fusedAgent(index)}}}}
			if len(existing) > 0 {
				objects = append(objects, StagedRoomObject{Type: RoomObjectCommit, RoomEpoch: epoch.RoomEpoch, MLSEpoch: epoch.MLSEpoch, Object: result.Commit, Recipients: existing})
			}
			return objects, nil
		}, fixture.now.Add(7*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return result, record, membership
	}
	join := func(index int, result CommitResult, membership room.Membership) RoomMLSRecord {
		t.Helper()
		binding := group.State{RoomID: fusedRoom, Clock: result.Transition.Next.Clock, MembershipDigest: membership.Digest}
		record, err := controllers[index].Join(binding, fixture.proof(membership), groupID, identities[index].State, result.Welcomes[refs[index]], refs[index], leaves[0])
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	// apply builds the member's own transition: its own binding as prior.
	apply := func(index int, result CommitResult, membership *room.Membership, committer group.LeafBinding) (bool, RoomMLSRecord, error) {
		current, _, err := ledgers[index].Current(fusedRoom)
		if err != nil {
			t.Fatal(err)
		}
		next := group.State{RoomID: fusedRoom, Clock: result.Transition.Next.Clock, MembershipDigest: result.Transition.Next.MembershipDigest, AcceptedCommitRef: result.Transition.CommitRef}
		transition := group.Transition{Prior: current.Binding(), Next: next, CommitRef: result.Transition.CommitRef}
		var proof *RoomAuthorityProof
		if membership != nil {
			transition.Membership = *membership
			value := fixture.proof(*membership)
			proof = &value
		}
		return controllers[index].Apply(transition, proof, result.Commit, committer)
	}

	// The founder's state before the Add, for a Commit made past the
	// controller below.
	founderState, err := ledgers[0].State(alice)
	if err != nil {
		t.Fatal(err)
	}
	addBob, alice, withBob := add(alice, 1, nil)
	// A Welcome into a tree holding a leaf whose identity is not the compact
	// binding (made with the driver directly, past the authority's own
	// check) is refused before anything is installed.
	{
		mallory, err := driver.NewIdentity([]byte("mallory-leaf"))
		if err != nil {
			t.Fatal(err)
		}
		_, _, welcomes, err := driver.Commit(founderState, []group.LeafOperation{leaf(1), {Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: []byte("mallory-leaf"),
			LeafSignaturePublicKey: mallory.LeafSignaturePublicKey, KeyPackageRef: canon.Digest(mallory.KeyPackage), KeyPackage: mallory.KeyPackage}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := controllers[1].Join(group.State{RoomID: fusedRoom, Clock: addBob.Transition.Next.Clock, MembershipDigest: withBob.Digest}, fixture.proof(withBob), groupID, identities[1].State, welcomes[refs[1]], refs[1], leaves[0]); !errors.Is(err, ErrRoomLeafIdentity) {
			t.Fatalf("a Welcome into a tree with a foreign identity: %v", err)
		}
	}
	// A Welcome is taken only from the leaf the invite's authority credential
	// expects: under another member's credential it is refused and nothing
	// is installed.
	if _, err := controllers[1].Join(group.State{RoomID: fusedRoom, Clock: addBob.Transition.Next.Clock, MembershipDigest: withBob.Digest}, fixture.proof(withBob), groupID, identities[1].State, addBob.Welcomes[refs[1]], refs[1], leaves[2]); !errors.Is(err, ErrMLSSenderMismatch) {
		t.Fatalf("a Welcome under another authority credential: %v", err)
	}
	if _, found, _ := ledgers[1].Current(fusedRoom); found {
		t.Fatal("a refused Welcome installed the room")
	}
	bob := join(1, addBob, withBob)
	if credential, found, err := ledgers[1].RoomCredential(fusedRoom, fusedAgent(0)); err != nil || !found || credential.ExpiresAtUnix != testRoomEnd || bob.RoomEndsAtUnix != testRoomEnd {
		t.Fatalf("the joiner's install did not root the authority credential: %v %v", found, err)
	}
	if bob.MLSEpoch != 1 || bob.RoomEpoch != 2 {
		t.Fatalf("Bob joined at %+v", bob.Binding())
	}
	if _, err := controllers[1].Join(group.State{RoomID: fusedRoom, Clock: addBob.Transition.Next.Clock, MembershipDigest: withBob.Digest}, fixture.proof(withBob), groupID, identities[1].State, addBob.Welcomes[refs[1]], refs[1], leaves[0]); err == nil {
		t.Fatal("a Welcome was installed twice")
	}

	// An Add whose leaf carries any identity but the compact binding is
	// refused before the driver runs.
	short := leaf(2)
	short.Next.CredentialIdentity = []byte("carol-leaf")
	if _, _, err := controllers[0].Commit(group.Transition{Prior: alice.Binding()}, nil, []group.LeafOperation{short}, func(CommitResult) ([]StagedRoomObject, error) { return nil, nil }, fixture.now); !errors.Is(err, ErrRoomLeafIdentity) {
		t.Fatalf("a short Add identity: %v", err)
	}
	addCarol, alice, withCarol := add(alice, 2, []RoomRecipient{{AgentID: fusedAgent(1)}})
	// A Commit attributed to anyone but the authority's leaf is refused, and
	// nothing is written: another leaf, the authority's identity under
	// another key, and no verified binding at all.
	if _, _, err := apply(1, addCarol, &withCarol, leaves[2]); !errors.Is(err, ErrMLSSenderMismatch) {
		t.Fatalf("wrong committer: %v", err)
	}
	swapped, err := NewRoomMLSController(ledgers[1], keySwapDriver{OpenMLSSidecar: driver, key: leaves[2].SignatureKey()}, now)
	if err != nil {
		t.Fatal(err)
	}
	{
		current, _, err := ledgers[1].Current(fusedRoom)
		if err != nil {
			t.Fatal(err)
		}
		next := group.State{RoomID: fusedRoom, Clock: addCarol.Transition.Next.Clock, MembershipDigest: addCarol.Transition.Next.MembershipDigest, AcceptedCommitRef: addCarol.Transition.CommitRef}
		proof := fixture.proof(withCarol)
		if _, _, err := swapped.Apply(group.Transition{Prior: current.Binding(), Next: next, Membership: withCarol, CommitRef: addCarol.Transition.CommitRef}, &proof, addCarol.Commit, leaves[0]); !errors.Is(err, ErrMLSSenderMismatch) {
			t.Fatalf("the authority's identity under another key: %v", err)
		}
	}
	if _, _, err := apply(1, addCarol, &withCarol, group.LeafBinding{}); !errors.Is(err, ErrRoomLeafIdentity) {
		t.Fatalf("a committer without a verified binding: %v", err)
	}
	if unchanged, _, _ := ledgers[1].Current(fusedRoom); unchanged.StateDigest != bob.StateDigest {
		t.Fatal("a refused Commit changed Bob's state")
	}
	fresh, bob, err := apply(1, addCarol, &withCarol, leaves[0])
	if err != nil || !fresh || bob.MLSEpoch != 2 || bob.RoomEpoch != 3 {
		t.Fatalf("Bob applies the Add: %v %v", fresh, err)
	}
	if fresh, _, err := apply(1, addCarol, &withCarol, leaves[0]); err != nil || fresh {
		t.Fatalf("exact repeat: %v %v", fresh, err)
	}
	// members reports the three leaves with the keys their credentials name.
	members, err := controllers[1].Members(fusedRoom)
	if err != nil || len(members) != 3 {
		t.Fatalf("members: %+v %v", members, err)
	}
	for index, member := range members {
		if !leaves[index].Matches(member) || member.Index != uint32(index) {
			t.Fatalf("member %d: %+v", index, member)
		}
	}
	carol := join(2, addCarol, withCarol)
	if !bytes.Equal(mustAuthenticator(t, alice, 2), mustAuthenticator(t, bob, 2)) || !bytes.Equal(mustAuthenticator(t, bob, 2), mustAuthenticator(t, carol, 2)) {
		t.Fatal("members of epoch 2 disagree on its authenticator")
	}

	// The authority's Commit that adds a leaf whose identity is not the
	// compact binding (made with the driver directly, past the authority's
	// own check) is refused by a member before anything is written: such a
	// tree would refuse every later members listing.
	{
		aliceState, err := ledgers[0].State(alice)
		if err != nil {
			t.Fatal(err)
		}
		mallory, err := driver.NewIdentity([]byte("mallory-leaf"))
		if err != nil {
			t.Fatal(err)
		}
		_, foreign, _, err := driver.Commit(aliceState, []group.LeafOperation{{Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: []byte("mallory-leaf"),
			LeafSignaturePublicKey: mallory.LeafSignaturePublicKey, KeyPackageRef: canon.Digest(mallory.KeyPackage), KeyPackage: mallory.KeyPackage}}})
		if err != nil {
			t.Fatal(err)
		}
		ref := canon.Digest(foreign)
		next := group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: bob.RoomEpoch, MLSEpoch: bob.MLSEpoch + 1}, MembershipDigest: bob.MembershipDigest, AcceptedCommitRef: ref}
		if _, _, err := controllers[1].Apply(group.Transition{Prior: bob.Binding(), Next: next, CommitRef: ref}, nil, foreign, leaves[0]); !errors.Is(err, ErrRoomLeafIdentity) {
			t.Fatalf("a Commit adding a foreign identity: %v", err)
		}
		if unchanged, _, _ := ledgers[1].Current(fusedRoom); unchanged.StateDigest != bob.StateDigest {
			t.Fatal("a refused Commit changed Bob's state")
		}
		if _, err := controllers[1].Members(fusedRoom); err != nil {
			t.Fatalf("Bob's tree after the refusal: %v", err)
		}
	}

	// Bob seals before the next Commit; the message is opened after it.
	aad := []byte("room binding")
	early, _, err := controllers[1].Seal(fusedRoom, aad, []byte("sealed in epoch 2"))
	if err != nil {
		t.Fatal(err)
	}
	template := group.Transition{Prior: alice.Binding(), Next: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: alice.RoomEpoch, MLSEpoch: alice.MLSEpoch + 1}, MembershipDigest: alice.MembershipDigest}}
	refresh, alice, err := controllers[0].Commit(template, nil, nil, func(result CommitResult) ([]StagedRoomObject, error) {
		return []StagedRoomObject{{Type: RoomObjectCommit, RoomEpoch: alice.RoomEpoch, MLSEpoch: result.Transition.Next.Clock.MLSEpoch, Object: result.Commit, Recipients: []RoomRecipient{{AgentID: fusedAgent(1)}, {AgentID: fusedAgent(2)}}}}, nil
	}, fixture.now.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		if _, _, err := apply(index, refresh, nil, leaves[0]); err != nil {
			t.Fatalf("member %d applies the refresh: %v", index, err)
		}
	}
	closeAll()
	open()

	carolBefore, _, _ := ledgers[2].Current(fusedRoom)
	if _, _, err := controllers[2].Open(fusedRoom, aad, early, leaves[0]); !errors.Is(err, ErrMLSSenderMismatch) {
		t.Fatalf("wrong sender: %v", err)
	}
	swappedCarol, err := NewRoomMLSController(ledgers[2], keySwapDriver{OpenMLSSidecar: driver, key: leaves[0].SignatureKey()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := swappedCarol.Open(fusedRoom, aad, early, leaves[1]); !errors.Is(err, ErrMLSSenderMismatch) {
		t.Fatalf("the sender's identity under another key: %v", err)
	}
	if after, _, _ := ledgers[2].Current(fusedRoom); after.StateDigest != carolBefore.StateDigest {
		t.Fatal("a refused message spent Carol's ratchet step")
	}
	plaintext, _, err := controllers[2].Open(fusedRoom, aad, early, leaves[1])
	if err != nil || string(plaintext) != "sealed in epoch 2" {
		t.Fatalf("past-epoch message after restart: %q %v", plaintext, err)
	}
	plaintext, _, err = controllers[0].Open(fusedRoom, aad, early, leaves[1])
	if err != nil || string(plaintext) != "sealed in epoch 2" {
		t.Fatalf("authority opens the past-epoch message: %q %v", plaintext, err)
	}
	heads, err := journals[0].RoomOutboxHeads(fusedRoom)
	if err != nil || len(heads) != 4 {
		t.Fatalf("authority outbox after restart: %d heads, %v", len(heads), err)
	}
}

func mustAuthenticator(t *testing.T, record RoomMLSRecord, mlsEpoch uint64) []byte {
	t.Helper()
	value, found := record.EpochAuthenticatorAt(mlsEpoch)
	if !found {
		t.Fatalf("no authenticator for epoch %d", mlsEpoch)
	}
	return value
}

// members refuses a tree holding a leaf identity that is not the compact
// binding: a relay room never holds one, so such a state is not a relay
// room's.
func TestOpenMLSRoomControllerMembersRefusesAnotherIdentity(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make messenger-test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	short, err := driver.NewIdentity([]byte("short-leaf"))
	if err != nil {
		t.Fatal(err)
	}
	groupID := bytes.Repeat([]byte{0x5b}, group.MLSGroupIDBytes)
	state, err := driver.CreateGroup(short.State, short.KeyPackage, groupID)
	if err != nil {
		t.Fatal(err)
	}
	info, err := driver.Inspect(state)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newFusedFixture(t)
	journal, ledger := openFused(t, t.TempDir()+"/state")
	defer journal.Close()
	founding := fixture.founding()
	if _, err := ledger.InstallFounder(RoomMLSInstall{
		Binding: group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founding.Digest},
		Proof:   fixture.proof(founding), State: state, EpochAuthenticator: info.EpochAuthenticator,
		KeyPackageRef: canon.Digest(short.KeyPackage),
		Credentials:   fixture.credentials(), EndsAtUnix: testRoomEnd,
	}, fixture.now); err != nil {
		t.Fatal(err)
	}
	controller, err := NewRoomMLSController(ledger, driver, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Members(fusedRoom); !errors.Is(err, ErrRoomLeafIdentity) {
		t.Fatalf("a tree with a short identity: %v", err)
	}
}
