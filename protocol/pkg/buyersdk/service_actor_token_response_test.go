package buyersdk

import (
	"bytes"
	"errors"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

func TestTokenAttestedResponseRequiresSnapshottedKeyAndVerification(t *testing.T) {
	s, r := loadTokenFixture(t, "respond")
	key := bytes.Repeat([]byte{0x61}, mldsa44.PublicKeySize)
	id, err := mldsa44.KeyID(key)
	if err != nil {
		t.Fatal(err)
	}
	s.Request.HasAttestor = true
	s.Request.AttestorKeyID = id
	s.RequestAttestorKey = key
	global := int32(3)
	s.GlobalID = &global
	r.Signature = bytes.Repeat([]byte{0x62}, mldsa44.SignatureSize)
	snapshot := nativecore.ServiceActorRequestSnapshotV1{RequestID: r.ID, Caller: s.Request.Caller, RequestHash: s.Request.RequestHash, ResponseDeadline: s.Request.ResponseDeadline, RefundClaimDeadline: s.Request.RefundClaimDeadline, TermsHash: s.Request.TermsHash, Terms: nativecore.ServiceActorTermsV1{PricePerCall: s.Request.Price}}
	expected, err := nativecore.ServiceActorResponseDomainHash(global, s.Actor, snapshot, r.ResponseHash)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.VerifyResponse = func(public, signature []byte, digest [32]byte) error {
		calls++
		if !bytes.Equal(public, key) || !bytes.Equal(signature, r.Signature) || digest != expected {
			t.Fatal("response verifier received different key, signature or SRP2")
		}
		return nil
	}
	if _, err = PrepareTokenMessage(s, r); err != nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	s.VerifyResponse = func([]byte, []byte, [32]byte) error { return errors.New("invalid signature") }
	if _, err = PrepareTokenMessage(s, r); err == nil {
		t.Fatal("invalid attested response accepted")
	}
	s.VerifyResponse = nil
	if _, err = PrepareTokenMessage(s, r); err == nil {
		t.Fatal("unverified attested response accepted")
	}
}

func TestTokenBuilderRejectsMissingLifecycleAmounts(t *testing.T) {
	for _, name := range []string{"respond", "claim-refund", "claim-returned", "recheck-payout"} {
		t.Run(name, func(t *testing.T) {
			s, r := loadTokenFixture(t, name)
			switch name {
			case "respond":
				s.Request.Price = nil
			case "claim-refund":
				s.Refund.Price = nil
			case "claim-returned":
				s.Returned.Amount = nil
			case "recheck-payout":
				s.Payout.Amount = nil
			}
			if _, err := PrepareTokenMessage(s, r); err == nil {
				t.Fatal("missing lifecycle amount accepted")
			}
		})
	}
}
