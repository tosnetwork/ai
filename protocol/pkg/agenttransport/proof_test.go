package agenttransport

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type proofKit struct {
	k       *credentialKit
	c       *Credential
	wire    []byte
	request ProofRequest
}

func newProofKit(t *testing.T) *proofKit {
	t.Helper()
	k := newCredentialKit(t)
	wire := k.chain(t, firstCaveats(OperationList|OperationDeposit), []Caveat{RelayCaveat(testRelay)})
	c := decode(t, wire)
	return &proofKit{k: k, c: c, wire: wire, request: ProofRequest{RelayURL: testRelay, Method: "GET", Path: "/v2/mailboxes/" + c.delegation.AgentID() + "/envelopes"}}
}

func (p *proofKit) sign(t *testing.T, issuedAt uint64, nonce byte) Proof {
	t.Helper()
	proof, err := SignRequest(p.c, p.k.holders[1], p.request, issuedAt, [32]byte{nonce})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (p *proofKit) check(proof string, change func(*Request)) error {
	r := Request{AgentID: p.c.delegation.AgentID(), Operation: OperationList, Proof: p.request, CredentialValue: EncodeCredentialHeader(p.wire), ProofValue: proof, Now: testNow}
	if change != nil {
		change(&r)
	}
	_, err := CheckRequest(r)
	return err
}

func TestRequestProof(t *testing.T) {
	p := newProofKit(t)
	good := p.sign(t, testNow, 1).Header()
	if err := p.check(good, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := SignRequest(p.c, p.k.holders[0], p.request, testNow, [32]byte{}); err == nil {
		t.Fatal("an earlier holder signed a proof")
	}
	invalidCases := map[string]func(*Request){
		"relay":            func(r *Request) { r.Proof.RelayURL = "https://relay-b.example" },
		"method":           func(r *Request) { r.Proof.Method = "PUT" },
		"path":             func(r *Request) { r.Proof.Path += "/x" },
		"body":             func(r *Request) { r.Proof.Body = []byte{1} },
		"path-query":       func(r *Request) { r.Proof.Path += "?x" },
		"method-lowercase": func(r *Request) { r.Proof.Method = "get" },
		"window-ahead":     func(r *Request) { r.Now = testNow - ProofWindowSeconds - 1 },
		"window-behind":    func(r *Request) { r.Now = testNow + ProofWindowSeconds + 1 },
		"padded-proof":     func(r *Request) { r.ProofValue += "=" },
		// A short credential header stays under its length bound, so only the
		// canonical re-encoding refuses the CR and LF the decoder skips.
		"line-break":      func(r *Request) { r.CredentialValue = r.CredentialValue[:4] + "\r\n" + r.CredentialValue[4:] },
		"short-proof":     func(r *Request) { r.ProofValue = r.ProofValue[:len(r.ProofValue)-4] },
		"long-credential": func(r *Request) { r.CredentialValue = strings.Repeat("A", maxCredentialHeader+1) },
		"noncanonical-credential": func(r *Request) {
			v := r.CredentialValue
			r.CredentialValue = v[:len(v)-1] + map[bool]string{true: "B", false: "A"}[v[len(v)-1] == 'A']
		},
	}
	for name, change := range invalidCases {
		t.Run(name, func(t *testing.T) {
			err := p.check(good, change)
			if name == "relay" {
				// The relay caveat is evaluated before the proof.
				wantClass(t, err, ErrCredentialScope)
				return
			}
			wantClass(t, err, ErrCredentialInvalid)
		})
	}
	t.Run("window-edges", func(t *testing.T) {
		for _, issued := range []uint64{testNow - ProofWindowSeconds, testNow + ProofWindowSeconds} {
			if err := p.check(p.sign(t, issued, 2).Header(), nil); err != nil {
				t.Fatalf("issued %d: %v", issued, err)
			}
		}
	})
	// The proof header's time and nonce are signed: changing either breaks it.
	t.Run("issued-at", func(t *testing.T) {
		proof := p.sign(t, testNow, 6)
		proof.IssuedAt++
		wantClass(t, p.check(proof.Header(), nil), ErrCredentialInvalid)
	})
	t.Run("nonce", func(t *testing.T) {
		proof := p.sign(t, testNow, 7)
		proof.Nonce[31] ^= 1
		wantClass(t, p.check(proof.Header(), nil), ErrCredentialInvalid)
	})
	t.Run("signature", func(t *testing.T) {
		proof := p.sign(t, testNow, 3)
		proof.Signature[0] ^= 1
		wantClass(t, p.check(proof.Header(), nil), ErrCredentialInvalid)
	})
	t.Run("relay-bound-without-caveat", func(t *testing.T) {
		// A credential without a relay caveat still binds each proof to its relay.
		openWire := p.k.chain(t, firstCaveats(OperationList))
		open := decode(t, openWire)
		proof, err := SignRequest(open, p.k.holders[0], p.request, testNow, [32]byte{4})
		if err != nil {
			t.Fatal(err)
		}
		r := Request{AgentID: open.delegation.AgentID(), Operation: OperationList, Proof: p.request, CredentialValue: EncodeCredentialHeader(openWire), ProofValue: proof.Header(), Now: testNow}
		if _, err = CheckRequest(r); err != nil {
			t.Fatal(err)
		}
		r.Proof.RelayURL = "https://relay-b.example"
		_, err = CheckRequest(r)
		wantClass(t, err, ErrCredentialInvalid)
	})
	scopeCases := map[string]func(*Request){
		"agent":     func(r *Request) { r.AgentID = "agent_" + strings.Repeat("0", 64) },
		"operation": func(r *Request) { r.Operation = OperationFetch },
		"expired":   func(r *Request) { r.Now = testBase + 3600 },
	}
	for name, change := range scopeCases {
		t.Run(name, func(t *testing.T) { wantClass(t, p.check(good, change), ErrCredentialScope) })
	}
	t.Run("chain", func(t *testing.T) {
		// Caveats do not enter the chain values, so a rewritten relay caveat
		// keeps the credential id and holder: only the block signature refuses.
		raw := bytes.Replace(p.wire, []byte("relay-a"), []byte("relay-b"), 1)
		forged, err := DecodeCredential(raw)
		if err != nil || idOf(t, forged) != idOf(t, p.c) {
			t.Fatalf("forgery setup: %v", err)
		}
		moved := p.request
		moved.RelayURL = "https://relay-b.example"
		proof, err := SignRequest(forged, p.k.holders[1], moved, testNow, [32]byte{5})
		if err != nil {
			t.Fatal(err)
		}
		err = p.check(proof.Header(), func(r *Request) { r.CredentialValue = EncodeCredentialHeader(raw); r.Proof = moved })
		wantClass(t, err, ErrCredentialInvalid)
		if errors.Is(err, ErrCredentialScope) {
			t.Fatal("two classes")
		}
	})
}

func TestProofHeaderBounds(t *testing.T) {
	p := newProofKit(t)
	header := p.sign(t, testNow, 1).Header()
	if len(header) != rawURL.EncodedLen(ProofHeaderSize) {
		t.Fatalf("proof header is %d characters", len(header))
	}
	if _, err := DecodeProofHeader(header + "A"); err == nil {
		t.Fatal("over-long proof accepted")
	}
	maximal := strings.Repeat("A", maxCredentialHeader)
	if _, err := DecodeCredentialHeader(maximal); err != nil {
		t.Fatalf("maximal credential header refused: %v", err)
	}
	if _, err := DecodeCredentialHeader(maximal + "A"); err == nil {
		t.Fatal("over-long credential header accepted")
	}
	if _, err := ProofPreimage([32]byte{}, ProofRequest{RelayURL: testRelay, Method: strings.Repeat("A", 256), Path: "/"}, 1, [32]byte{}); err == nil {
		t.Fatal("method of 256 bytes accepted")
	}
	if _, err := ProofPreimage([32]byte{}, ProofRequest{RelayURL: testRelay, Method: strings.Repeat("A", 255), Path: "/" + strings.Repeat("a", maxPathSize-1)}, 1, [32]byte{}); err != nil {
		t.Fatalf("maximal method and path refused: %v", err)
	}
	if _, err := ProofPreimage([32]byte{}, ProofRequest{RelayURL: testRelay, Method: "GET", Path: "/" + strings.Repeat("a", maxPathSize)}, 1, [32]byte{}); err == nil {
		t.Fatal("path over u16 accepted")
	}
}

func TestProofInputRules(t *testing.T) {
	good := ProofRequest{RelayURL: testRelay, Method: "GET", Path: "/v2/x"}
	if _, err := ProofPreimage([32]byte{}, good, 1, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ProofRequest){
		"relay-noncanonical": func(r *ProofRequest) { r.RelayURL += "/" },
		"method-empty":       func(r *ProofRequest) { r.Method = "" },
		"method-long":        func(r *ProofRequest) { r.Method = strings.Repeat("A", 256) },
		"method-lowercase":   func(r *ProofRequest) { r.Method = "get" },
		"path-empty":         func(r *ProofRequest) { r.Path = "" },
		"path-relative":      func(r *ProofRequest) { r.Path = "v2/x" },
		"path-query":         func(r *ProofRequest) { r.Path += "?a" },
		"path-fragment":      func(r *ProofRequest) { r.Path += "#a" },
		"path-space":         func(r *ProofRequest) { r.Path += " a" },
		"path-long":          func(r *ProofRequest) { r.Path = "/" + strings.Repeat("a", maxPathSize) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := good
			change(&r)
			_, err := ProofPreimage([32]byte{}, r, 1, [32]byte{})
			wantClass(t, err, ErrCredentialInvalid)
		})
	}
	t.Run("short-proof", func(t *testing.T) {
		_, err := DecodeProofHeader("AAAA")
		wantClass(t, err, ErrCredentialInvalid)
	})
}
