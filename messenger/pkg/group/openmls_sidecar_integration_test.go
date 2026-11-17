package group

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
)

func TestOpenMLSSidecarIntegrationThreeMemberRestartChat(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make test-openmls")
	}
	driver := &OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	alice, err := driver.NewIdentity([]byte("alice-authority"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := driver.NewIdentity([]byte("bob-authority"))
	if err != nil {
		t.Fatal(err)
	}
	charlie, err := driver.NewIdentity([]byte("charlie-authority"))
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.ValidateKeyPackage(bob.KeyPackage, []byte("bob-authority"), bob.LeafSignaturePublicKey); err != nil {
		t.Fatalf("validate Bob: %v", err)
	}
	if err := driver.ValidateKeyPackage(bob.KeyPackage, []byte("charlie-authority"), bob.LeafSignaturePublicKey); err == nil {
		t.Fatal("authority-substituted KeyPackage accepted")
	}

	groupID := bytes.Repeat([]byte{0x42}, MLSGroupIDBytes)
	aliceState, err := driver.CreateGroup(alice.State, alice.KeyPackage, groupID)
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("room + event + content binding")
	aliceState, beforeJoin, err := driver.Seal(aliceState, aad, []byte("founder history before Bob joined"))
	if err != nil {
		t.Fatal(err)
	}
	bobRef := canon.Digest(bob.KeyPackage)
	if _, _, _, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: bobRef, KeyPackage: bob.KeyPackage, CredentialIdentity: []byte("charlie-authority"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey}}}); err == nil {
		t.Fatal("authority-substituted add operation accepted")
	}
	aliceState, commit1, welcomes1, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: bobRef, KeyPackage: bob.KeyPackage, CredentialIdentity: []byte("bob-authority"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	bobState, err := driver.Join(bob.State, welcomes1[bobRef])
	if err != nil {
		t.Fatal(err)
	}
	// A joiner must not apply the commit represented by its Welcome again.
	if _, err := driver.Apply(bobState, commit1); err == nil {
		t.Fatal("Welcome commit replay accepted")
	}
	if _, _, err := driver.Open(bobState, aad, beforeJoin); err == nil {
		t.Fatal("joiner decrypted pre-join history")
	}
	aliceExporter, err := driver.Export(aliceState, "tos-room-test", []byte("same context"), 32)
	if err != nil {
		t.Fatal(err)
	}
	bobExporter, err := driver.Export(bobState, "tos-room-test", []byte("same context"), 32)
	if err != nil || !bytes.Equal(aliceExporter, bobExporter) {
		t.Fatalf("members disagree on exporter: %v", err)
	}
	separated, err := driver.Export(bobState, "tos-room-test-other", []byte("same context"), 32)
	if err != nil || bytes.Equal(aliceExporter, separated) {
		t.Fatal("exporter label did not separate secrets")
	}

	charlieRef := canon.Digest(charlie.KeyPackage)
	aliceState, commit2, welcomes2, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: charlieRef, KeyPackage: charlie.KeyPackage, CredentialIdentity: []byte("charlie-authority"), LeafSignaturePublicKey: charlie.LeafSignaturePublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	forgedCommit := append([]byte(nil), commit2...)
	forgedCommit[len(forgedCommit)-1] ^= 0x80
	if _, err := driver.Apply(bobState, forgedCommit); err == nil {
		t.Fatal("forged commit accepted")
	}
	bobState, err = driver.Apply(bobState, commit2)
	if err != nil {
		t.Fatalf("Bob apply Charlie commit: %v", err)
	}
	charlieState, err := driver.Join(charlie.State, welcomes2[charlieRef])
	if err != nil {
		t.Fatal(err)
	}

	oldAliceState := append([]byte(nil), aliceState...)
	beforeRefreshExporter, err := driver.Export(aliceState, "tos-room-test", []byte("same context"), 32)
	if err != nil {
		t.Fatal(err)
	}
	aliceState, refreshCommit, refreshWelcomes, err := driver.Commit(aliceState, nil)
	if err != nil || len(refreshWelcomes) != 0 {
		t.Fatalf("self refresh: welcomes=%d err=%v", len(refreshWelcomes), err)
	}
	bobState, err = driver.Apply(bobState, refreshCommit)
	if err != nil {
		t.Fatal(err)
	}
	charlieState, err = driver.Apply(charlieState, refreshCommit)
	if err != nil {
		t.Fatal(err)
	}
	afterRefreshExporter, err := driver.Export(aliceState, "tos-room-test", []byte("same context"), 32)
	if err != nil || bytes.Equal(beforeRefreshExporter, afterRefreshExporter) {
		t.Fatal("self update did not rotate exporter secret")
	}
	charlieState, postRefresh, err := driver.Seal(charlieState, aad, []byte("post-compromise epoch"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.Open(oldAliceState, aad, postRefresh); err == nil {
		t.Fatal("pre-refresh state decrypted a post-refresh message")
	}
	aliceState, plaintext, err := driver.Open(aliceState, aad, postRefresh)
	if err != nil || string(plaintext) != "post-compromise epoch" {
		t.Fatalf("current state missed post-refresh message: %q %v", plaintext, err)
	}

	bobState, encrypted, err := driver.Seal(bobState, aad, []byte("hello from Bob after every sidecar process restarted"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.Open(charlieState, []byte("wrong event"), encrypted); err == nil {
		t.Fatal("wrong authenticated data accepted")
	}
	charlieState, plaintext, err = driver.Open(charlieState, aad, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "hello from Bob after every sidecar process restarted" {
		t.Fatalf("wrong plaintext: %q", plaintext)
	}
	if _, _, err := driver.Open(charlieState, aad, encrypted); err == nil {
		t.Fatal("application message replay accepted")
	}

	charlieState, reply, err := driver.Seal(charlieState, aad, []byte("Charlie replies to the founder"))
	if err != nil {
		t.Fatal(err)
	}
	_ = charlieState
	aliceState, plaintext, err = driver.Open(aliceState, aad, reply)
	if err != nil || string(plaintext) != "Charlie replies to the founder" {
		t.Fatalf("founder did not receive reply: %q %v", plaintext, err)
	}
	aliceState, beforeReplacement, err := driver.Seal(aliceState, aad,
		[]byte("room history before Charlie replaces the device"))
	if err != nil {
		t.Fatal(err)
	}

	charlieV2, err := driver.NewIdentity([]byte("charlie-authority-v2"))
	if err != nil {
		t.Fatal(err)
	}
	charlieV2Ref := canon.Digest(charlieV2.KeyPackage)
	aliceState, replaceCommit, replacementWelcomes, err := driver.Commit(aliceState, []LeafOperation{{
		Kind:  LeafUpdate,
		Prior: &Leaf{CredentialIdentity: []byte("charlie-authority")},
		Next:  &Leaf{CredentialIdentity: []byte("charlie-authority-v2"), LeafSignaturePublicKey: charlieV2.LeafSignaturePublicKey, KeyPackageRef: charlieV2Ref, KeyPackage: charlieV2.KeyPackage},
	}})
	if err != nil {
		t.Fatalf("replace Charlie device: %v", err)
	}
	bobState, err = driver.Apply(bobState, replaceCommit)
	if err != nil {
		t.Fatalf("Bob apply replacement: %v", err)
	}
	if _, err := driver.Apply(charlieState, replaceCommit); err != nil {
		t.Fatalf("old Charlie apply own replacement: %v", err)
	}
	charlieV2State, err := driver.Join(charlieV2.State, replacementWelcomes[charlieV2Ref])
	if err != nil {
		t.Fatalf("new Charlie join: %v", err)
	}
	if _, _, err := driver.Open(charlieV2State, aad, beforeReplacement); err == nil {
		t.Fatal("replacement device decrypted pre-replacement room history")
	}
	charlieV2State, reply, err = driver.Seal(charlieV2State, aad, []byte("replacement device is live"))
	if err != nil {
		t.Fatal(err)
	}
	aliceState, plaintext, err = driver.Open(aliceState, aad, reply)
	if err != nil || string(plaintext) != "replacement device is live" {
		t.Fatalf("replacement device failed: %q %v", plaintext, err)
	}

	aliceState, removeCommit, removeWelcomes, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafRemove, Prior: &Leaf{CredentialIdentity: []byte("bob-authority")}}})
	if err != nil || len(removeWelcomes) != 0 {
		t.Fatalf("remove Bob: welcomes=%d err=%v", len(removeWelcomes), err)
	}
	charlieV2State, err = driver.Apply(charlieV2State, removeCommit)
	if err != nil {
		t.Fatalf("Charlie apply removal: %v", err)
	}
	bobState, err = driver.Apply(bobState, removeCommit)
	if err != nil {
		t.Fatalf("Bob apply own removal: %v", err)
	}
	if _, _, err := driver.Seal(bobState, aad, []byte("removed member")); err == nil {
		t.Fatal("removed member could still send")
	}
	_, finalMessage, err := driver.Seal(aliceState, aad, []byte("room survives removal"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.Open(bobState, aad, finalMessage); err == nil {
		t.Fatal("removed member decrypted a future message")
	}
	_, plaintext, err = driver.Open(charlieV2State, aad, finalMessage)
	if err != nil || string(plaintext) != "room survives removal" {
		t.Fatalf("remaining members failed after removal: %q %v", plaintext, err)
	}
}

// The sidecar names the committer and the sender of every processed message,
// reports the epoch authenticator, and opens messages of the two retained past
// epochs but not older ones.
func TestOpenMLSSidecarIntegrationAttributionAndPastEpochs(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make test-openmls")
	}
	driver := &OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	alice, err := driver.NewIdentity([]byte("alice-authority"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := driver.NewIdentity([]byte("bob-member"))
	if err != nil {
		t.Fatal(err)
	}
	aliceState, err := driver.CreateGroup(alice.State, alice.KeyPackage, bytes.Repeat([]byte{0x24}, MLSGroupIDBytes))
	if err != nil {
		t.Fatal(err)
	}
	bobRef := canon.Digest(bob.KeyPackage)
	aliceState, _, welcomes, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: bobRef, KeyPackage: bob.KeyPackage, CredentialIdentity: []byte("bob-member"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	bobState, err := driver.Join(bob.State, welcomes[bobRef])
	if err != nil {
		t.Fatal(err)
	}
	aliceInfo, err := driver.Inspect(aliceState)
	if err != nil {
		t.Fatal(err)
	}
	bobInfo, err := driver.Inspect(bobState)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceInfo.EpochAuthenticator) != MLSEpochAuthenticatorBytes || !bytes.Equal(aliceInfo.EpochAuthenticator, bobInfo.EpochAuthenticator) {
		t.Fatal("members of one epoch report different epoch authenticators")
	}

	aad := []byte("room binding")
	bobState, sealed, err := driver.Seal(bobState, aad, []byte("sealed before two commits"))
	if err != nil {
		t.Fatal(err)
	}
	refresh := func() {
		t.Helper()
		var commit []byte
		aliceState, commit, _, err = driver.Commit(aliceState, nil)
		if err != nil {
			t.Fatal(err)
		}
		var committer MLSMember
		bobState, committer, err = driver.ApplyAttributed(bobState, commit)
		if err != nil || string(committer.Identity) != "alice-authority" || !bytes.Equal(committer.SignatureKey, alice.LeafSignaturePublicKey) || committer.Index != 0 {
			t.Fatalf("committer %+v: %v", committer, err)
		}
	}
	refresh()
	refreshed, err := driver.Inspect(aliceState)
	if err != nil || bytes.Equal(refreshed.EpochAuthenticator, aliceInfo.EpochAuthenticator) {
		t.Fatalf("epoch authenticator did not change with the epoch: %v", err)
	}
	refresh()
	beforeThird := append([]byte(nil), aliceState...)
	_, plaintext, sender, err := driver.OpenAttributed(aliceState, aad, sealed)
	if err != nil || string(plaintext) != "sealed before two commits" || string(sender.Identity) != "bob-member" ||
		!bytes.Equal(sender.SignatureKey, bob.LeafSignaturePublicKey) || sender.Index != 1 {
		t.Fatalf("two-epoch-old message: %q from %+v: %v", plaintext, sender, err)
	}
	members, err := driver.Members(aliceState)
	if err != nil || len(members) != 2 || string(members[1].Identity) != "bob-member" || !bytes.Equal(members[1].SignatureKey, bob.LeafSignaturePublicKey) ||
		!bytes.Equal(members[0].SignatureKey, alice.LeafSignaturePublicKey) {
		t.Fatalf("members: %+v %v", members, err)
	}
	refresh()
	if _, _, _, err := driver.OpenAttributed(aliceState, aad, sealed); err == nil {
		t.Fatal("a message three epochs old was opened")
	}
	if _, _, _, err := driver.OpenAttributed(beforeThird, aad, sealed); err != nil {
		t.Fatalf("control: the same message opens two epochs later: %v", err)
	}
}
