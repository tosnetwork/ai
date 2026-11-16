package eventlog

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/group"
	"github.com/tosnetwork/ai/messenger/pkg/room"
)

func TestOpenMLSRoomControllerIntegrationFusedRestartAndAttribution(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make messenger-test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	names := []string{"alice-leaf", "bob-leaf", "carol-leaf"}
	identities := make([]group.OpenMLSIdentity, len(names))
	for index, name := range names {
		value, err := driver.NewIdentity([]byte(name))
		if err != nil {
			t.Fatal(err)
		}
		identities[index] = value
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
	alice, err := controllers[0].CreateRoom(group.State{RoomID: fusedRoom, Clock: group.Clock{RoomEpoch: 1}, MembershipDigest: founding.Digest}, fixture.proof(founding), identities[0].State, identities[0].KeyPackage, groupID, canon.Digest(identities[0].KeyPackage))
	if err != nil {
		t.Fatal(err)
	}

	leaf := func(index int) group.LeafOperation {
		return group.LeafOperation{Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: []byte(names[index]), LeafSignaturePublicKey: identities[index].LeafSignaturePublicKey, KeyPackageRef: canon.Digest(identities[index].KeyPackage), KeyPackage: identities[index].KeyPackage}}
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
	apply := func(index int, result CommitResult, membership *room.Membership, committer string) (bool, RoomMLSRecord, error) {
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
		return controllers[index].Apply(transition, proof, result.Commit, []byte(committer))
	}

	addBob, alice, withBob := add(alice, 1, nil)
	bob := join(1, addBob, withBob)
	if bob.MLSEpoch != 1 || bob.RoomEpoch != 2 {
		t.Fatalf("Bob joined at %+v", bob.Binding())
	}
	if _, err := controllers[1].Join(group.State{RoomID: fusedRoom, Clock: addBob.Transition.Next.Clock, MembershipDigest: withBob.Digest}, fixture.proof(withBob), groupID, identities[1].State, addBob.Welcomes[canon.Digest(identities[1].KeyPackage)], canon.Digest(identities[1].KeyPackage)); err == nil {
		t.Fatal("a Welcome was installed twice")
	}

	addCarol, alice, withCarol := add(alice, 2, []RoomRecipient{{AgentID: fusedAgent(1)}})
	// A Commit attributed to anyone but the authority's leaf is refused, and
	// nothing is written.
	if _, _, err := apply(1, addCarol, &withCarol, "carol-leaf"); !errors.Is(err, ErrMLSSenderMismatch) {
		t.Fatalf("wrong committer: %v", err)
	}
	if unchanged, _, _ := ledgers[1].Current(fusedRoom); unchanged.StateDigest != bob.StateDigest {
		t.Fatal("a refused Commit changed Bob's state")
	}
	fresh, bob, err := apply(1, addCarol, &withCarol, "alice-leaf")
	if err != nil || !fresh || bob.MLSEpoch != 2 || bob.RoomEpoch != 3 {
		t.Fatalf("Bob applies the Add: %v %v", fresh, err)
	}
	if fresh, _, err := apply(1, addCarol, &withCarol, "alice-leaf"); err != nil || fresh {
		t.Fatalf("exact repeat: %v %v", fresh, err)
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
		if _, _, err := apply(index, refresh, nil, "alice-leaf"); err != nil {
			t.Fatalf("member %d applies the refresh: %v", index, err)
		}
	}
	closeAll()
	open()

	carolBefore, _, _ := ledgers[2].Current(fusedRoom)
	if _, _, err := controllers[2].Open(fusedRoom, aad, early, []byte("alice-leaf")); !errors.Is(err, ErrMLSSenderMismatch) {
		t.Fatalf("wrong sender: %v", err)
	}
	if after, _, _ := ledgers[2].Current(fusedRoom); after.StateDigest != carolBefore.StateDigest {
		t.Fatal("a refused message spent Carol's ratchet step")
	}
	plaintext, _, err := controllers[2].Open(fusedRoom, aad, early, []byte("bob-leaf"))
	if err != nil || string(plaintext) != "sealed in epoch 2" {
		t.Fatalf("past-epoch message after restart: %q %v", plaintext, err)
	}
	plaintext, _, err = controllers[0].Open(fusedRoom, aad, early, []byte("bob-leaf"))
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
