package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/room"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// relayLeaf makes member index's relay room leaf the way a joiner does: a
// fresh leaf signature key, the Endpoint-signed leaf credential naming it,
// then the KeyPackage under the compact identity naming that credential.
func relayLeaf(t *testing.T, driver *group.OpenMLSSidecar, index int) (group.OpenMLSIdentity, group.LeafBinding) {
	t.Helper()
	signer, err := driver.NewLeafSigner()
	if err != nil {
		t.Fatal(err)
	}
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(0x70 + index)}, ed25519.SeedSize))
	credential, err := group.SignLeafCredential(group.LeafCredential{
		Network: &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		AgentID: fusedAgent(index), EndpointID: fmt.Sprintf("mep_%064x", index+1), DeviceID: fmt.Sprintf("dev_%064x", index+1),
		DeviceSetDigest: canon.Digest([]byte("set")), LeafSignaturePublicKey: signer.LeafSignaturePublicKey,
		IssuedAtUnix: 1_000, ExpiresAtUnix: 2_000_000}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := group.LeafBindingOf(credential)
	if err != nil {
		t.Fatal(err)
	}
	made, err := driver.NewIdentityForSigner(signer, binding.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return made, binding
}

func TestOpenMLSRoomControllerIntegrationFusedRestartAndAttribution(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make messenger-test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	identities := make([]group.OpenMLSIdentity, 3)
	leaves := make([]group.LeafBinding, 3)
	for index := range identities {
		identities[index], leaves[index] = relayLeaf(t, driver, index)
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
	if _, err := controllers[0].CreateRoom(foundingBinding, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, canon.Digest(identities[0].KeyPackage), leaves[1]); err == nil {
		t.Fatal("a founder KeyPackage was installed under another leaf")
	}
	if _, err := controllers[0].CreateRoom(foundingBinding, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, canon.Digest(identities[0].KeyPackage), group.LeafBinding{Identity: []byte("alice-leaf"), SignatureKey: leaves[0].SignatureKey}); !errors.Is(err, ErrRoomLeafIdentity) {
		t.Fatalf("a short founder identity: %v", err)
	}
	alice, err := controllers[0].CreateRoom(foundingBinding, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, canon.Digest(identities[0].KeyPackage), leaves[0])
	if err != nil {
		t.Fatal(err)
	}

	leaf := func(index int) group.LeafOperation {
		return group.LeafOperation{Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: leaves[index].Identity, LeafSignaturePublicKey: identities[index].LeafSignaturePublicKey, KeyPackageRef: canon.Digest(identities[index].KeyPackage), KeyPackage: identities[index].KeyPackage}}
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
			objects := []StagedRoomObject{{Type: RoomObjectWelcome, RoomEpoch: epoch.RoomEpoch, MLSEpoch: epoch.MLSEpoch, Object: result.Welcomes[canon.Digest(identities[index].KeyPackage)], Recipients: []RoomRecipient{{AgentID: fusedAgent(index)}}}}
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
		record, err := controllers[index].Join(binding, fixture.proof(membership), groupID, identities[index].State, result.Welcomes[canon.Digest(identities[index].KeyPackage)], canon.Digest(identities[index].KeyPackage))
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

	addBob, alice, withBob := add(alice, 1, nil)
	bob := join(1, addBob, withBob)
	if bob.MLSEpoch != 1 || bob.RoomEpoch != 2 {
		t.Fatalf("Bob joined at %+v", bob.Binding())
	}
	if _, err := controllers[1].Join(group.State{RoomID: fusedRoom, Clock: addBob.Transition.Next.Clock, MembershipDigest: withBob.Digest}, fixture.proof(withBob), groupID, identities[1].State, addBob.Welcomes[canon.Digest(identities[1].KeyPackage)], canon.Digest(identities[1].KeyPackage)); err == nil {
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
	// another key, and an identity that is not the compact binding.
	impostor := group.LeafBinding{Identity: leaves[0].Identity, SignatureKey: leaves[2].SignatureKey}
	for name, committer := range map[string]group.LeafBinding{"another leaf": leaves[2], "another key": impostor} {
		if _, _, err := apply(1, addCarol, &withCarol, committer); !errors.Is(err, ErrMLSSenderMismatch) {
			t.Fatalf("wrong committer (%s): %v", name, err)
		}
	}
	if _, _, err := apply(1, addCarol, &withCarol, group.LeafBinding{Identity: []byte("alice-leaf"), SignatureKey: leaves[0].SignatureKey}); !errors.Is(err, ErrRoomLeafIdentity) {
		t.Fatalf("a short committer identity: %v", err)
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
	for name, sender := range map[string]group.LeafBinding{"another leaf": leaves[0],
		"another key": {Identity: leaves[1].Identity, SignatureKey: leaves[0].SignatureKey}} {
		if _, _, err := controllers[2].Open(fusedRoom, aad, early, sender); !errors.Is(err, ErrMLSSenderMismatch) {
			t.Fatalf("wrong sender (%s): %v", name, err)
		}
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
