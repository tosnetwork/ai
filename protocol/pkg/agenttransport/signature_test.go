package agenttransport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"testing"

	"filippo.io/edwards25519"
)

// Public keys reject small order, but a valid signature may have identity R.
// Verification must use the specified cofactorless equation, not key validation
// on R. This test-only signer chooses nonce zero to exercise that distinction.
func TestReceiptCofactorlessIdentityR(t *testing.T) {
	f, _, key := hintSample(t)
	r := Receipt{RecipientAgent: f.d.AgentDigest, EnvelopeID: [32]byte{9}, Outcome: ReceiptStored, ReceivedAt: 1800000010}
	preimage, err := r.preimage()
	if err != nil {
		t.Fatal(err)
	}
	expanded := sha512.Sum512(key[:32])
	secret, err := new(edwards25519.Scalar).SetBytesWithClamping(expanded[:32])
	if err != nil {
		t.Fatal(err)
	}
	identity := edwards25519.NewIdentityPoint().Bytes()
	h := sha512.New()
	if _, err = h.Write(identity); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Write(f.d.TransportKey[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Write(preimage); err != nil {
		t.Fatal(err)
	}
	challenge, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	scalar := new(edwards25519.Scalar).Multiply(challenge, secret)
	signature := append(identity, scalar.Bytes()...)
	if !ed25519.Verify(f.d.TransportKey[:], preimage, signature) {
		t.Fatal("cofactorless control is invalid")
	}
	copy(r.Signature[:], signature)
	wire, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.verifier(t).VerifyReceipt(context.Background(), wire, f.wire, r.RecipientAgent, r.EnvelopeID); err != nil {
		t.Fatal(err)
	}
}
