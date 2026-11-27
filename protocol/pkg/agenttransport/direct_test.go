package agenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func directSample(t testing.TB, role byte) (*fixture, Hello, HelloExpectation, ed25519.PrivateKey) {
	t.Helper()
	f, _, key := hintSample(t)
	h := Hello{Role: role, Delegation: f.d, IssuedAt: 1800000010, LocalADNL: [32]byte{1}, PeerADNL: [32]byte{2}, InitiatorNonce: [32]byte{3}}
	if role == HelloResponder {
		h.ResponderNonce = [32]byte{4}
	}
	e := HelloExpectation{Role: role, LocalADNL: h.PeerADNL, PeerADNL: h.LocalADNL, ExpectedAgent: f.d.AgentID(), InitiatorNonce: h.InitiatorNonce, AdmittedContact: func(agent string) bool { return agent == f.d.AgentID() }}
	return f, h, e, key
}
func helloWire(t testing.TB, h Hello, key ed25519.PrivateKey) []byte {
	t.Helper()
	h, err := SignHello(h, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestHelloFixedWireAndRoles(t *testing.T) {
	for _, role := range []byte{HelloInitiator, HelloResponder} {
		f, h, e, key := directSample(t, role)
		wire := helloWire(t, h, key)
		if len(wire) != 402 || len(wire) > 8192 {
			t.Fatal("hello does not fit one query")
		}
		if _, err := f.verifier(t).VerifyHello(context.Background(), wire, e); err != nil {
			t.Fatal(err)
		}
		for _, bad := range [][]byte{nil, wire[:len(wire)-1], append(bytes.Clone(wire), 0)} {
			if _, err := DecodeHello(bad); !errors.Is(err, ErrHello) {
				t.Fatalf("bad hello accepted %v", err)
			}
		}
		bad := bytes.Clone(wire)
		bad[0] ^= 1
		if _, err := DecodeHello(bad); err == nil {
			t.Fatal("hello domain ignored")
		}
	}
	_, h, _, _ := directSample(t, HelloInitiator)
	h.Role = 3
	if _, err := h.Encode(); err == nil {
		t.Fatal("unknown hello role accepted")
	}
	h.Role = HelloInitiator
	h.ResponderNonce = [32]byte{1}
	if _, err := h.Encode(); err == nil {
		t.Fatal("initiator response nonce accepted")
	}
}
func TestHelloBindsChannelAgentChallengeAndContact(t *testing.T) {
	cases := []struct {
		name   string
		change func(*HelloExpectation)
	}{
		{"role", func(e *HelloExpectation) { e.Role = HelloInitiator }},
		{"channel-peer", func(e *HelloExpectation) { e.PeerADNL[0]++ }},
		{"channel-local", func(e *HelloExpectation) { e.LocalADNL[0]++ }},
		{"expected-agent", func(e *HelloExpectation) { e.ExpectedAgent = "agent_other" }},
		{"missing-agent", func(e *HelloExpectation) { e.ExpectedAgent = "" }},
		{"challenge", func(e *HelloExpectation) { e.InitiatorNonce[0]++ }},
		{"no-admission", func(e *HelloExpectation) { e.AdmittedContact = nil }},
		{"removed-contact", func(e *HelloExpectation) { e.AdmittedContact = func(string) bool { return false } }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, h, e, key := directSample(t, HelloResponder)
			wire := helloWire(t, h, key)
			v := f.verifier(t)
			if _, err := v.VerifyHello(context.Background(), wire, e); err != nil {
				t.Fatal(err)
			}
			tc.change(&e)
			if _, err := v.VerifyHello(context.Background(), wire, e); err == nil {
				t.Fatal("hello binding ignored")
			}
		})
	}
	f, h, e, key := directSample(t, HelloInitiator)
	e.ExpectedAgent = ""
	if _, err := f.verifier(t).VerifyHello(context.Background(), helloWire(t, h, key), e); err != nil {
		t.Fatal(err)
	}
}
func TestHelloTimeWindowAndReadDelay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		issued uint64
		ok     bool
	}{{"past-edge", 1799999890, true}, {"past-over", 1799999889, false}, {"future-edge", 1800000130, true}, {"future-over", 1800000131, false}, {"overflow", ^uint64(0), false}} {
		t.Run(tc.name, func(t *testing.T) {
			f, h, e, key := directSample(t, HelloInitiator)
			h.IssuedAt = tc.issued
			_, err := f.verifier(t).VerifyHello(context.Background(), helloWire(t, h, key), e)
			if (err == nil) != tc.ok {
				t.Fatalf("window want %v got %v", tc.ok, err)
			}
		})
	}
	t.Run("during-read", func(t *testing.T) {
		f, h, e, key := directSample(t, HelloResponder)
		h.IssuedAt = 1799999890
		f.r.after = func() { f.clock.advance(time.Second) }
		if _, err := f.verifier(t).VerifyHello(context.Background(), helloWire(t, h, key), e); err == nil {
			t.Fatal("hello expired during read accepted")
		}
	})
}
func TestHelloSignatureAndDirectPurpose(t *testing.T) {
	f, h, e, key := directSample(t, HelloResponder)
	wire := helloWire(t, h, key)
	wire[len(wire)-1] ^= 1
	if _, err := f.verifier(t).VerifyHello(context.Background(), wire, e); err == nil {
		t.Fatal("hello signature ignored")
	}
	f, h, e, key = directSample(t, HelloResponder)
	f.d.Purposes = Hints
	f.reencode(t)
	h.Delegation = f.d
	if _, err := f.verifier(t).VerifyHello(context.Background(), helloWire(t, h, key), e); err == nil {
		t.Fatal("direct purpose ignored")
	}
}
func receiptWire(t testing.TB, r Receipt, d Delegation, key ed25519.PrivateKey) []byte {
	t.Helper()
	r, err := SignReceipt(r, d, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestReceiptOutcomesAndBindings(t *testing.T) {
	for _, outcome := range []ReceiptOutcome{ReceiptStored, ReceiptDuplicate, ReceiptRefused} {
		f, _, key := hintSample(t)
		receipt := Receipt{RecipientAgent: f.d.AgentDigest, EnvelopeID: [32]byte{5}, Outcome: outcome, ReceivedAt: 1800000010}
		wire := receiptWire(t, receipt, f.d, key)
		v := f.verifier(t)
		if len(wire) != ReceiptSize || len(wire) > 256 {
			t.Fatal("receipt bound")
		}
		if _, err := v.VerifyReceipt(context.Background(), wire, f.wire, receipt.RecipientAgent, receipt.EnvelopeID); err != nil {
			t.Fatal(err)
		}
		other := receipt.EnvelopeID
		other[0]++
		if _, err := v.VerifyReceipt(context.Background(), wire, f.wire, receipt.RecipientAgent, other); err == nil {
			t.Fatal("receipt envelope binding ignored")
		}
		agent := receipt.RecipientAgent
		agent[0]++
		if _, err := v.VerifyReceipt(context.Background(), wire, f.wire, agent, receipt.EnvelopeID); err == nil {
			t.Fatal("receipt Agent binding ignored")
		}
		bad := bytes.Clone(wire)
		bad[len(bad)-1] ^= 1
		if _, err := v.VerifyReceipt(context.Background(), bad, f.wire, receipt.RecipientAgent, receipt.EnvelopeID); err == nil {
			t.Fatal("receipt signature ignored")
		}
		for _, bad := range [][]byte{nil, wire[:len(wire)-1], append(bytes.Clone(wire), 0)} {
			if _, err := DecodeReceipt(bad); err == nil {
				t.Fatal("receipt size ignored")
			}
		}
		bad = bytes.Clone(wire)
		bad[0] ^= 1
		if _, err := DecodeReceipt(bad); err == nil {
			t.Fatal("receipt domain ignored")
		}
	}
	for _, outcome := range []ReceiptOutcome{0, 4} {
		if _, err := (Receipt{Outcome: outcome}).Encode(); err == nil {
			t.Fatal("receipt unknown outcome")
		}
	}
	f, _, key := hintSample(t)
	r := Receipt{RecipientAgent: f.d.AgentDigest, Outcome: ReceiptStored}
	r.RecipientAgent[0]++
	if _, err := SignReceipt(r, f.d, key); err == nil {
		t.Fatal("signed for another Agent")
	}
}
func TestReceiptRequiresPeerDelegation(t *testing.T) {
	f, _, key := hintSample(t)
	r := Receipt{RecipientAgent: f.d.AgentDigest, Outcome: ReceiptStored, EnvelopeID: [32]byte{1}}
	wire := receiptWire(t, r, f.d, key)
	f.d.Purposes = Hints
	f.reencode(t)
	if _, err := f.verifier(t).VerifyReceipt(context.Background(), wire, f.wire, r.RecipientAgent, r.EnvelopeID); err == nil {
		t.Fatal("receipt missing direct purpose accepted")
	}
	f, _, key = hintSample(t)
	r = Receipt{RecipientAgent: f.d.AgentDigest, Outcome: ReceiptStored, EnvelopeID: [32]byte{1}}
	wire = receiptWire(t, r, f.d, key)
	v := f.verifier(t)
	if _, err := v.VerifyReceipt(context.Background(), wire, f.wire, r.RecipientAgent, r.EnvelopeID); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(RefreshAfter)
	f.r.snapshot.State.GetAgent().Tombstoned = true
	if _, err := v.VerifyReceipt(context.Background(), wire, f.wire, r.RecipientAgent, r.EnvelopeID); err == nil {
		t.Fatal("revoked receipt accepted")
	}
	// An admitted delegation of another Agent with the same key still cannot be used.
	f, _, key = hintSample(t)
	wire = receiptWire(t, r, f.d, key)
	f.d.AgentDigest[0]++
	f.r.snapshot.State.GetAgent().AgentId = f.d.AgentID()
	f.reencode(t)
	if _, err := f.verifier(t).VerifyReceipt(context.Background(), wire, f.wire, r.RecipientAgent, r.EnvelopeID); err == nil {
		t.Fatal("peer delegation Agent ignored")
	}
}
func TestTransportSigningKeyRefusals(t *testing.T) {
	_, h, key := hintSample(t)
	for _, bad := range []ed25519.PrivateKey{nil, key[:32], ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))} {
		if _, err := SignHint(h, bad); err == nil {
			t.Fatal("signing key binding ignored")
		}
	}
	corrupt := bytes.Clone(key)
	corrupt[63] ^= 1
	if _, err := SignHint(h, corrupt); err == nil {
		t.Fatal("inconsistent signing key accepted")
	}
}
func TestSignedObjectDomainsDoNotCross(t *testing.T) {
	f, h, key := hintSample(t)
	hint := signRecord(t, h, nil, key)
	_, hello, _, _ := directSample(t, HelloResponder)
	hw := helloWire(t, hello, key)
	receipt := receiptWire(t, Receipt{RecipientAgent: f.d.AgentDigest, Outcome: ReceiptStored}, f.d, key)
	if _, err := DecodeHello(hint); err == nil {
		t.Fatal("hint as hello")
	}
	if _, err := DecodeReceipt(hw); err == nil {
		t.Fatal("hello as receipt")
	}
	if _, err := DecodeHintRecord(receipt); err == nil {
		t.Fatal("receipt as hint")
	}
}
func FuzzReachabilityObjects(f *testing.F) {
	fx, h, key := hintSample(f)
	f.Add(signRecord(f, h, nil, key))
	_, hello, _, _ := directSample(f, HelloResponder)
	f.Add(helloWire(f, hello, key))
	f.Add(receiptWire(f, Receipt{RecipientAgent: fx.d.AgentDigest, Outcome: ReceiptStored}, fx.d, key))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxHintRecordSize+1 {
			return
		}
		if r, err := DecodeHintRecord(raw); err == nil {
			b, err := r.Encode()
			if err != nil || !bytes.Equal(b, raw) {
				t.Fatalf("record canonicality %v", err)
			}
		}
		if h, err := DecodeHello(raw); err == nil {
			b, err := h.Encode()
			if err != nil || !bytes.Equal(b, raw) {
				t.Fatalf("hello canonicality %v", err)
			}
		}
		if r, err := DecodeReceipt(raw); err == nil {
			b, err := r.Encode()
			if err != nil || !bytes.Equal(b, raw) {
				t.Fatalf("receipt canonicality %v", err)
			}
		}
	})
}
