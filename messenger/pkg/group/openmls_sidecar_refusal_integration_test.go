package group

import (
	"bytes"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
)

// A message damaged after sealing is input, not a driver fault: both open
// modes refuse it with a typed driver refusal (never a crashed driver, which
// a caller can only retry), and the state handed in still opens the genuine
// message.
func TestOpenMLSSidecarRefusesADamagedMessage(t *testing.T) {
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
	aliceState, err := driver.CreateGroup(alice.State, alice.KeyPackage, bytes.Repeat([]byte{0x26}, MLSGroupIDBytes))
	if err != nil {
		t.Fatal(err)
	}
	bobRef := canon.Digest(bob.KeyPackage)
	aliceState, _, welcomes, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: bobRef,
		KeyPackage: bob.KeyPackage, CredentialIdentity: []byte("bob-member"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	bobState, err := driver.Join(bob.State, welcomes[bobRef])
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("room binding")
	_, sealed, err := driver.Seal(bobState, aad, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	damaged := bytes.Clone(sealed)
	damaged[len(damaged)-1] ^= 0x01
	if _, _, _, _, err := driver.OpenAttributedReadback(aliceState, damaged); !errors.Is(err, ErrOpenMLSRefused) {
		t.Fatalf("readback of a damaged message: %v", err)
	}
	if _, _, _, err := driver.OpenAttributed(aliceState, aad, damaged); !errors.Is(err, ErrOpenMLSRefused) {
		t.Fatalf("compare open of a damaged message: %v", err)
	}
	if _, plaintext, _, _, err := driver.OpenAttributedReadback(aliceState, sealed); err != nil || string(plaintext) != "hello" {
		t.Fatalf("the genuine message after the refusals: %q %v", plaintext, err)
	}
}
