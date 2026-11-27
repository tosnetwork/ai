package agenttransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	testBase  = 1800000000
	testNow   = testBase + 100
	testRelay = "https://relay-a.example"
)

type credentialKit struct {
	delegation []byte
	transport  ed25519.PrivateKey
	holders    []ed25519.PrivateKey
}

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("credential-test-key-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func newCredentialKit(t testing.TB) *credentialKit {
	t.Helper()
	k := &credentialKit{transport: testKey("transport")}
	for i := range MaxCredentialBlocks {
		k.holders = append(k.holders, testKey(fmt.Sprintf("holder-%d", i)))
	}
	d := Delegation{AgentDigest: sha256.Sum256([]byte("credential-test-agent")), Purposes: 7, NotBefore: testBase - 86400, NotAfter: testBase + 86400*30, MaxCredentialSeconds: MaxCredentialSeconds}
	copy(d.TransportKey[:], pub(k.transport))
	var err error
	if k.delegation, err = d.Encode(); err != nil {
		t.Fatal(err)
	}
	return k
}

func firstCaveats(ops Operation) []Caveat {
	return []Caveat{NotBeforeCaveat(testBase), NotAfterCaveat(testBase + 3600), OperationsCaveat(ops)}
}

// chain issues block 0 and appends one block per extra caveat list.
func (k *credentialKit) chain(t testing.TB, blocks ...[]Caveat) []byte {
	t.Helper()
	wire, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), blocks[0])
	if err != nil {
		t.Fatal(err)
	}
	for i, caveats := range blocks[1:] {
		if wire, err = AppendCredentialBlock(wire, k.holders[i], pub(k.holders[i+1]), caveats); err != nil {
			t.Fatal(err)
		}
	}
	return wire
}

func decode(t testing.TB, wire []byte) *Credential {
	t.Helper()
	c, err := DecodeCredential(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.VerifyChain(); err != nil {
		t.Fatal(err)
	}
	return c
}

func wantClass(t *testing.T, err, class error) {
	t.Helper()
	if !errors.Is(err, class) {
		t.Fatalf("want %v, got %v", class, err)
	}
}

func TestCredentialRoundTripAndChain(t *testing.T) {
	k := newCredentialKit(t)
	wire := k.chain(t, firstCaveats(OperationList), []Caveat{RelayCaveat(testRelay)})
	c := decode(t, wire)
	encoded, err := c.Encode()
	if err != nil || !bytes.Equal(encoded, wire) {
		t.Fatalf("re-encoding: %v", err)
	}
	values := c.ChainValues()
	digest := sha256.Sum256(k.delegation)
	if len(values) != 3 || values[0] != sha256.Sum256(append([]byte(credentialChainDomain), digest[:]...)) {
		t.Fatal("chain_0 is not SHA-256(domain || delegation_digest)")
	}
	if c.CredentialID() != values[2] || c.HolderKey() != [32]byte(pub(k.holders[1])) {
		t.Fatal("credential id or holder key")
	}
}

// TestCredentialBounds pins every size and count limit at and past its edge.
func TestCredentialBounds(t *testing.T) {
	k := newCredentialKit(t)
	full := func(relay string) []Caveat {
		return []Caveat{NotBeforeCaveat(testBase), NotAfterCaveat(testBase + MaxCredentialSeconds), RelayCaveat(relay), OperationsCaveat(allOperations), LaneCaveat([16]byte{1}), MaxEnvelopesCaveat(64), MaxEnvelopeBytesCaveat(MaxEnvelopeBytes), MaxLaneBytesCaveat(1)}
	}
	maxRelay := "https://relay.example/" + strings.Repeat("p", MaxRelayURLBytes-len("https://relay.example/"))
	t.Run("blocks", func(t *testing.T) {
		wire := k.chain(t, full(maxRelay), full(maxRelay), full(maxRelay), full(maxRelay))
		if len(wire) != 1916 {
			t.Fatalf("maximal credential is %d bytes", len(wire))
		}
		decode(t, wire)
		if _, err := AppendCredentialBlock(wire, k.holders[3], pub(k.holders[3]), full(maxRelay)); err == nil {
			t.Fatal("fifth block appended")
		}
		// Five complete small blocks fit in the size limit; only the count refuses.
		small := k.chain(t, firstCaveats(1), []Caveat{OperationsCaveat(1)}, []Caveat{OperationsCaveat(1)}, []Caveat{OperationsCaveat(1)})
		last := small[len(small)-(2+32+1+5+64):]
		five := append(append([]byte{}, small...), last...)
		five[credentialHeaderSize-1] = 5
		if len(five) > MaxCredentialSize {
			t.Fatal("five-block control exceeds the size limit")
		}
		_, err := DecodeCredential(five)
		wantClass(t, err, ErrCredentialInvalid)
		_, err = DecodeCredential(append(append([]byte{}, small[:credentialHeaderSize-1]...), 0))
		wantClass(t, err, ErrCredentialInvalid)
	})
	t.Run("size", func(t *testing.T) {
		wire := k.chain(t, full(maxRelay))
		over := append(append([]byte{}, wire...), make([]byte, MaxCredentialSize+1-len(wire))...)
		_, err := DecodeCredential(over)
		if !errors.Is(err, ErrCredentialInvalid) || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversize: %v", err)
		}
	})
	t.Run("caveats", func(t *testing.T) {
		if _, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), append(full(testRelay), MaxLaneBytesCaveat(2))); err == nil {
			t.Fatal("nine caveats issued")
		}
		if _, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), nil); err == nil {
			t.Fatal("zero caveats issued")
		}
	})
	t.Run("relay-url", func(t *testing.T) {
		if _, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), append(firstCaveats(1), RelayCaveat(maxRelay))); err != nil {
			t.Fatal(err)
		}
		_, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), append(firstCaveats(1), RelayCaveat(maxRelay+"q")))
		wantClass(t, err, ErrCredentialInvalid)
	})
	t.Run("envelope-bytes", func(t *testing.T) {
		for n, ok := range map[uint32]bool{0: false, 1: true, MaxEnvelopeBytes: true, MaxEnvelopeBytes + 1: false} {
			_, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), append(firstCaveats(1), MaxEnvelopeBytesCaveat(n)))
			if (err == nil) != ok {
				t.Fatalf("max_envelope_bytes %d: %v", n, err)
			}
		}
	})
	t.Run("lifetime", func(t *testing.T) {
		d, err := DecodeDelegation(k.delegation)
		if err != nil {
			t.Fatal(err)
		}
		d.MaxCredentialSeconds = 3600
		short, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = IssueCredential(short, k.transport, pub(k.holders[0]), firstCaveats(1)); err != nil {
			t.Fatal(err)
		}
		_, err = IssueCredential(short, k.transport, pub(k.holders[0]), []Caveat{NotBeforeCaveat(testBase), NotAfterCaveat(testBase + 3601), OperationsCaveat(1)})
		wantClass(t, err, ErrCredentialInvalid)
	})
}

func TestBuilderRefusals(t *testing.T) {
	k := newCredentialKit(t)
	if _, err := IssueCredential(k.delegation, k.holders[0], pub(k.holders[0]), firstCaveats(1)); err == nil {
		t.Fatal("block 0 signed by a key other than the transport key")
	}
	if _, err := IssueCredential(k.delegation, k.transport[:31], pub(k.holders[0]), firstCaveats(1)); err == nil {
		t.Fatal("short signing key accepted")
	}
	if _, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0])[:31], firstCaveats(1)); err == nil {
		t.Fatal("short next key accepted")
	}
	wire := k.chain(t, firstCaveats(1))
	if _, err := AppendCredentialBlock(wire, k.holders[0], pub(k.holders[1])[:31], []Caveat{RelayCaveat(testRelay)}); err == nil {
		t.Fatal("short next key appended")
	}
	if _, err := AppendCredentialBlock(wire, k.transport, pub(k.holders[1]), []Caveat{RelayCaveat(testRelay)}); err == nil {
		t.Fatal("block appended by a key other than the holder")
	}
	if _, err := AppendCredentialBlock(wire, k.holders[0], pub(k.holders[1]), []Caveat{RelayCaveat(testRelay), RelayCaveat(testRelay)}); err == nil {
		t.Fatal("repeated caveat type accepted")
	}
	laned := k.chain(t, append(firstCaveats(1), LaneCaveat([16]byte{1})))
	if _, err := AppendCredentialBlock(laned, k.holders[0], pub(k.holders[1]), []Caveat{LaneCaveat([16]byte{2})}); err == nil {
		t.Fatal("second lane value appended")
	}
	if _, err := AppendCredentialBlock(laned, k.holders[0], pub(k.holders[1]), []Caveat{LaneCaveat([16]byte{1})}); err != nil {
		t.Fatalf("repeating the same lane: %v", err)
	}
}

// rawSigned signs blocks without the builder, for decode-valid credentials
// the builder refuses to make.
func (k *credentialKit) rawSigned(t testing.TB, blocks ...[]Caveat) *Credential {
	t.Helper()
	signers := append([]ed25519.PrivateKey{k.transport}, k.holders...)
	var out []Block
	for i, caveats := range blocks {
		b := Block{Caveats: caveats, NextPublicKey: [32]byte(pub(k.holders[i]))}
		preimage, err := BlockSigningPreimage(k.delegation, out, b)
		if err != nil {
			t.Fatal(err)
		}
		copy(b.Signature[:], ed25519.Sign(signers[i], preimage))
		out = append(out, b)
	}
	d, err := DecodeDelegation(k.delegation)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := (&Credential{Delegation: d, DelegationBytes: k.delegation, Blocks: out}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, wire)
}

func TestScopeEveryBlock(t *testing.T) {
	k := newCredentialKit(t)
	c := decode(t, k.chain(t, firstCaveats(allOperations), []Caveat{RelayCaveat(testRelay), OperationsCaveat(OperationDeposit)}, []Caveat{NotAfterCaveat(testBase + 600)}))
	cases := []struct {
		name  string
		now   uint64
		relay string
		op    Operation
		ok    bool
	}{
		{"granted", testNow, testRelay, OperationDeposit, true},
		{"operation", testNow, testRelay, OperationList, false},
		{"relay", testNow, "https://relay-b.example", OperationDeposit, false},
		{"not-before-edge", testBase - ClockSkewSeconds, testRelay, OperationDeposit, true},
		{"not-before", testBase - ClockSkewSeconds - 1, testRelay, OperationDeposit, false},
		{"not-after-edge", testBase + 599, testRelay, OperationDeposit, true},
		{"not-after", testBase + 600, testRelay, OperationDeposit, false},
		{"composite-operation", testNow, testRelay, OperationDeposit | OperationList, false},
		{"unknown-operation", testNow, testRelay, 1 << 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.CheckScope(tc.now, tc.relay, tc.op)
			if (err == nil) != tc.ok {
				t.Fatalf("want ok=%v, got %v", tc.ok, err)
			}
			if err != nil {
				wantClass(t, err, ErrCredentialScope)
			}
		})
	}
	t.Run("zero-time", func(t *testing.T) {
		// A credential valid from time 0 still refuses a request with no time.
		zero := decode(t, k.chain(t, []Caveat{NotBeforeCaveat(0), NotAfterCaveat(3600), OperationsCaveat(OperationDeposit)}))
		if err := zero.CheckScope(1, testRelay, OperationDeposit); err != nil {
			t.Fatal(err)
		}
		wantClass(t, zero.CheckScope(0, testRelay, OperationDeposit), ErrCredentialScope)
	})
	t.Run("lane-conflict", func(t *testing.T) {
		conflict := k.rawSigned(t, append(firstCaveats(OperationDeposit), LaneCaveat([16]byte{1})), []Caveat{LaneCaveat([16]byte{2})})
		wantClass(t, conflict.CheckScope(testNow, testRelay, OperationDeposit), ErrCredentialScope)
		if _, _, err := conflict.Lane(); err == nil {
			t.Fatal("two lanes reported a lane")
		}
	})
	t.Run("not-before-overflow", func(t *testing.T) {
		far := k.rawSigned(t, firstCaveats(OperationDeposit), []Caveat{NotBeforeCaveat(^uint64(0))})
		wantClass(t, far.CheckScope(testNow, testRelay, OperationDeposit), ErrCredentialScope)
	})
}

func TestDepositEveryBlock(t *testing.T) {
	k := newCredentialKit(t)
	c := decode(t, k.chain(t,
		append(firstCaveats(OperationDeposit), MaxEnvelopesCaveat(64), MaxEnvelopeBytesCaveat(MaxEnvelopeBytes), MaxLaneBytesCaveat(1<<40)),
		[]Caveat{MaxEnvelopesCaveat(3), MaxEnvelopeBytesCaveat(1000), MaxLaneBytesCaveat(4000)},
		[]Caveat{MaxEnvelopesCaveat(64)}))
	cases := []struct {
		name string
		u    LaneUsage
		ok   bool
	}{
		{"granted", LaneUsage{0, 0, 1}, true},
		{"envelopes-edge", LaneUsage{2, 0, 1}, true},
		{"envelopes", LaneUsage{3, 0, 1}, false},
		{"envelope-bytes-edge", LaneUsage{0, 0, 1000}, true},
		{"envelope-bytes", LaneUsage{0, 0, 1001}, false},
		{"lane-bytes-edge", LaneUsage{1, 3000, 1000}, true},
		{"lane-bytes", LaneUsage{1, 3001, 1000}, false},
		{"lane-bytes-overflow", LaneUsage{1, ^uint64(0), 1}, false},
		{"empty-envelope", LaneUsage{0, 0, 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.CheckDeposit(tc.u)
			if (err == nil) != tc.ok {
				t.Fatalf("want ok=%v, got %v", tc.ok, err)
			}
			if err != nil {
				wantClass(t, err, ErrCredentialScope)
			}
		})
	}
	t.Run("contact-lane-cap", func(t *testing.T) {
		open := decode(t, k.chain(t, firstCaveats(OperationDeposit)))
		if err := open.CheckDeposit(LaneUsage{MaxContactLaneEnvelopes - 1, 0, MaxEnvelopeBytes}); err != nil {
			t.Fatal(err)
		}
		wantClass(t, open.CheckDeposit(LaneUsage{MaxContactLaneEnvelopes, 0, 1}), ErrCredentialScope)
		wantClass(t, open.CheckDeposit(LaneUsage{0, 0, MaxEnvelopeBytes + 1}), ErrCredentialScope)
	})
}

func TestChainRefusesSpliceReorderDrop(t *testing.T) {
	k := newCredentialKit(t)
	a := decode(t, k.chain(t, firstCaveats(allOperations), []Caveat{RelayCaveat(testRelay)}, []Caveat{OperationsCaveat(1)}, []Caveat{MaxEnvelopesCaveat(1)}))
	b := decode(t, k.chain(t, firstCaveats(allOperations), []Caveat{RelayCaveat("https://relay-b.example")}, []Caveat{OperationsCaveat(2)}, []Caveat{MaxEnvelopesCaveat(2)}))
	rebuilt := func(blocks ...Block) *Credential {
		c := &Credential{Delegation: a.Delegation, DelegationBytes: a.DelegationBytes, Blocks: blocks}
		wire, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		out, err := DecodeCredential(wire)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for name, c := range map[string]*Credential{
		"reorder": rebuilt(a.Blocks[0], a.Blocks[2], a.Blocks[1], a.Blocks[3]),
		"drop":    rebuilt(a.Blocks[0], a.Blocks[2], a.Blocks[3]),
		"splice":  rebuilt(a.Blocks[0], b.Blocks[1], a.Blocks[2], a.Blocks[3]),
		"tail":    rebuilt(a.Blocks[0], a.Blocks[1], a.Blocks[2], b.Blocks[3]),
	} {
		t.Run(name, func(t *testing.T) { wantClass(t, c.VerifyChain(), ErrCredentialInvalid) })
	}
	t.Run("other-delegation", func(t *testing.T) {
		d := a.Delegation
		d.AuthorizationEpoch++
		other, err := d.Encode()
		if err != nil {
			t.Fatal(err)
		}
		c := &Credential{Delegation: d, DelegationBytes: other, Blocks: a.Blocks}
		wire, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		moved, err := DecodeCredential(wire)
		if err != nil {
			t.Fatal(err)
		}
		wantClass(t, moved.VerifyChain(), ErrCredentialInvalid)
	})
}

func TestDecodeRefusals(t *testing.T) {
	k := newCredentialKit(t)
	wire := k.chain(t, append(firstCaveats(1), MaxEnvelopesCaveat(1)))
	block := credentialHeaderSize
	caveats := block + 2 + 32 + 1
	cases := map[string]func([]byte) []byte{
		"truncated":      func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":       func(b []byte) []byte { return append(b, 0) },
		"domain":         func(b []byte) []byte { b[0] ^= 1; return b },
		"delegation":     func(b []byte) []byte { b[32+146] = 0; return b }, // purposes
		"block-length":   func(b []byte) []byte { b[block+1]++; return b },
		"caveat-count":   func(b []byte) []byte { b[caveats-1] = 0; return b },
		"caveat-count-9": func(b []byte) []byte { b[caveats-1] = 9; return b },
		"unknown-type":   func(b []byte) []byte { b[caveats+11+11+5] = 9; return b },
		"order": func(b []byte) []byte {
			// Swap the whole not_before and not_after entries: descending types.
			first := append([]byte{}, b[caveats:caveats+11]...)
			copy(b[caveats:], b[caveats+11:caveats+22])
			copy(b[caveats+11:], first)
			return b
		},
		"value-length":    func(b []byte) []byte { b[caveats+2] = 7; return b },
		"next-key":        func(b []byte) []byte { clear(b[block+2 : block+34]); return b },
		"next-key-order":  func(b []byte) []byte { clear(b[block+2 : block+34]); b[block+2] = 1; return b },
		"operations-bits": func(b []byte) []byte { b[caveats+22+3] = 0x20; return b },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeCredential(change(append([]byte{}, wire...)))
			wantClass(t, err, ErrCredentialInvalid)
		})
	}
	t.Run("caveat-count-short", func(t *testing.T) {
		// Three of four caveats counted: the fourth would sit unparsed.
		b := append([]byte{}, wire...)
		b[caveats-1] = 3
		_, err := DecodeCredential(b)
		wantClass(t, err, ErrCredentialInvalid)
	})
	t.Run("empty-later-block", func(t *testing.T) {
		b := append([]byte{}, wire...)
		b[credentialHeaderSize-1] = 2
		b = binary.BigEndian.AppendUint16(b, 32+1+64)
		b = append(b, pub(k.holders[1])...)
		b = append(b, 0)
		b = append(b, make([]byte, 64)...)
		_, err := DecodeCredential(b)
		wantClass(t, err, ErrCredentialInvalid)
	})
}

func TestCaveatValueRules(t *testing.T) {
	cases := map[string]Caveat{
		"time-length":            {Type: CaveatNotBefore, Value: make([]byte, 7)},
		"relay-empty":            {Type: CaveatRelay},
		"relay-noncanonical":     RelayCaveat(testRelay + "/"),
		"operations-length":      {Type: CaveatOperations, Value: []byte{1}},
		"operations-bits":        OperationsCaveat(1 << 5),
		"lane-zero":              {Type: CaveatLane, Value: make([]byte, 16)},
		"lane-length":            {Type: CaveatLane, Value: make([]byte, 15)},
		"max-envelopes-zero":     MaxEnvelopesCaveat(0),
		"max-envelopes-length":   {Type: CaveatMaxEnvelopes, Value: make([]byte, 8)},
		"envelope-bytes-zero":    MaxEnvelopeBytesCaveat(0),
		"envelope-bytes-over":    MaxEnvelopeBytesCaveat(MaxEnvelopeBytes + 1),
		"envelope-bytes-length":  {Type: CaveatMaxEnvelopeBytes, Value: make([]byte, 2)},
		"lane-bytes-zero":        MaxLaneBytesCaveat(0),
		"lane-bytes-length":      {Type: CaveatMaxLaneBytes, Value: make([]byte, 4)},
		"unknown-type-0":         {Type: 0},
		"unknown-type-9":         {Type: 9, Value: binary.BigEndian.AppendUint16(nil, 1)},
		"not-after-length":       {Type: CaveatNotAfter, Value: make([]byte, 9)},
		"operations-zero-length": {Type: CaveatOperations},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) { wantClass(t, c.validate(), ErrCredentialInvalid) })
	}
	if err := OperationsCaveat(0).validate(); err != nil {
		t.Fatalf("an empty operations mask is a valid, unsatisfiable bound: %v", err)
	}
}
