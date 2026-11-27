package agenttransport

import (
	"crypto/ed25519"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

// The narrowing property of section 6.4 (acceptance A2): a request satisfies
// a credential exactly when every caveat of every block holds on its own, so
// appending a block can only remove requests. The oracle below is written
// independently of CheckScope and CheckDeposit.

const narrowingSeed = 0x6d747632_70723341

var (
	narrowRelays = []string{"https://relay-a.example", "https://relay-b.example"}
	narrowLanes  = [][16]byte{{1}, {2}}
)

type narrowRequest struct {
	now   uint64
	relay string
	op    Operation
	usage LaneUsage
}

func randomCaveats(r *rand.Rand, first bool, lane *[16]byte) []Caveat {
	var out []Caveat
	window := func() uint64 { return testBase - 400 + r.Uint64N(1200) }
	pick := func() bool { return r.IntN(3) == 0 }
	if first || pick() {
		out = append(out, NotBeforeCaveat(window()))
	}
	if first {
		out = append(out, NotAfterCaveat(decodeU64(out[0])+1+r.Uint64N(800)))
	} else if pick() {
		out = append(out, NotAfterCaveat(window()))
	}
	if pick() {
		out = append(out, RelayCaveat(narrowRelays[r.IntN(2)]))
	}
	if first || pick() {
		out = append(out, OperationsCaveat(Operation(r.Uint32N(32))))
	}
	if pick() {
		// At most one lane value per chain: a holder cannot move lanes.
		if *lane == ([16]byte{}) {
			*lane = narrowLanes[r.IntN(2)]
		}
		out = append(out, LaneCaveat(*lane))
	}
	if pick() {
		out = append(out, MaxEnvelopesCaveat(1+r.Uint32N(8)))
	}
	if pick() {
		out = append(out, MaxEnvelopeBytesCaveat(1+r.Uint32N(4096)))
	}
	if pick() {
		out = append(out, MaxLaneBytesCaveat(1+r.Uint64N(16384)))
	}
	if len(out) == 0 {
		out = append(out, RelayCaveat(narrowRelays[r.IntN(2)]))
	}
	return out
}

func randomRequest(r *rand.Rand) narrowRequest {
	ops := []Operation{OperationDeposit, OperationList, OperationFetch, OperationPublish, OperationRevoke}
	return narrowRequest{
		now:   testBase - 400 + r.Uint64N(1600),
		relay: narrowRelays[r.IntN(2)],
		op:    ops[r.IntN(len(ops))],
		usage: LaneUsage{StoredEnvelopes: r.Uint64N(10), StoredBytes: r.Uint64N(16384), EnvelopeBytes: 1 + r.Uint64N(4096)},
	}
}

// oracleBlock is one block's verdict, evaluated alone.
func oracleBlock(caveats []Caveat, q narrowRequest) bool {
	for _, c := range caveats {
		switch c.Type {
		case CaveatNotBefore:
			if decodeU64(c) > q.now+ClockSkewSeconds {
				return false
			}
		case CaveatNotAfter:
			if q.now >= decodeU64(c) {
				return false
			}
		case CaveatRelay:
			if string(c.Value) != q.relay {
				return false
			}
		case CaveatOperations:
			if uint16(q.op)&(uint16(c.Value[0])<<8|uint16(c.Value[1])) == 0 {
				return false
			}
		case CaveatMaxEnvelopes:
			if q.op == OperationDeposit && q.usage.StoredEnvelopes >= decodeU32(c) {
				return false
			}
		case CaveatMaxEnvelopeBytes:
			if q.op == OperationDeposit && q.usage.EnvelopeBytes > decodeU32(c) {
				return false
			}
		case CaveatMaxLaneBytes:
			if q.op == OperationDeposit && q.usage.StoredBytes+q.usage.EnvelopeBytes > decodeU64(c) {
				return false
			}
		}
	}
	return true
}

func decodeU32(c Caveat) uint64 {
	return uint64(c.Value[0])<<24 | uint64(c.Value[1])<<16 | uint64(c.Value[2])<<8 | uint64(c.Value[3])
}

func oracle(blocks [][]Caveat, q narrowRequest) bool {
	if q.op == OperationDeposit && q.usage.StoredEnvelopes >= MaxContactLaneEnvelopes {
		return false
	}
	for _, b := range blocks {
		if !oracleBlock(b, q) {
			return false
		}
	}
	return true
}

// merged is the widening a relay must not implement: the last value of each
// caveat type wins. The property test must observe it disagreeing.
func merged(blocks [][]Caveat, q narrowRequest) bool {
	last := map[CaveatType]Caveat{}
	for _, b := range blocks {
		for _, c := range b {
			last[c.Type] = c
		}
	}
	var flat []Caveat
	for _, c := range last {
		flat = append(flat, c)
	}
	return oracle([][]Caveat{flat}, q)
}

func accepts(c *Credential, q narrowRequest) bool {
	if c.CheckScope(q.now, q.relay, q.op) != nil {
		return false
	}
	return q.op != OperationDeposit || c.CheckDeposit(q.usage) == nil
}

type narrowStats struct{ accepted, refused, mergeWidened, appendNarrowed int }

// checkNarrowing builds one random chain through the public builders and
// checks every prefix against the oracle and against each other.
func checkNarrowing(t testing.TB, k *credentialKit, r *rand.Rand, stats *narrowStats) {
	var lane [16]byte
	count := 1 + r.IntN(MaxCredentialBlocks)
	var blocks [][]Caveat
	var prefixes []*Credential
	var wire []byte
	var err error
	signers := append([]ed25519.PrivateKey{k.transport}, k.holders...)
	for i := range count {
		caveats := randomCaveats(r, i == 0, &lane)
		if i == 0 {
			wire, err = IssueCredential(k.delegation, signers[0], pub(k.holders[0]), caveats)
		} else {
			wire, err = AppendCredentialBlock(wire, signers[i], pub(k.holders[i]), caveats)
		}
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		blocks = append(blocks, caveats)
		prefixes = append(prefixes, decode(t, wire))
	}
	for range 24 {
		q := randomRequest(r)
		previous := true
		for i, c := range prefixes {
			got := accepts(c, q)
			if want := oracle(blocks[:i+1], q); got != want {
				t.Fatalf("prefix %d of %v at %+v: accepted %v, oracle %v", i, blocks, q, got, want)
			}
			if got && !previous {
				t.Fatalf("block %d widened %v at %+v", i, blocks, q)
			}
			if previous && !got && i > 0 {
				stats.appendNarrowed++
			}
			previous = got
		}
		if previous {
			stats.accepted++
		} else {
			stats.refused++
		}
		if merged(blocks, q) && !previous {
			stats.mergeWidened++
		}
	}
}

func narrowingSeedFromEnv(t *testing.T) uint64 {
	seed := uint64(narrowingSeed)
	if v := os.Getenv("AGENTTRANSPORT_NARROWING_SEED"); v != "" {
		parsed, err := strconv.ParseUint(v, 0, 64)
		if err != nil {
			t.Fatal(err)
		}
		seed = parsed
	}
	t.Logf("narrowing generator seed %#x (set AGENTTRANSPORT_NARROWING_SEED to replay)", seed)
	return seed
}

func TestNarrowingProperty(t *testing.T) {
	seed := narrowingSeedFromEnv(t)
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	k := newCredentialKit(t)
	var stats narrowStats
	for range 1500 {
		checkNarrowing(t, k, r, &stats)
	}
	t.Logf("%+v", stats)
	// The generator must reach both verdicts, chains that narrow, and the
	// widening a block merge would introduce; otherwise it proves nothing.
	if stats.accepted < 100 || stats.refused < 100 || stats.appendNarrowed < 100 || stats.mergeWidened < 10 {
		t.Fatalf("generator coverage too thin: %+v", stats)
	}
}

// TestNarrowingSpliceReorderDrop: random chains of three or four blocks never
// verify after their blocks are reordered, dropped from the middle or spliced
// from another chain made with the same keys.
func TestNarrowingSpliceReorderDrop(t *testing.T) {
	seed := narrowingSeedFromEnv(t)
	r := rand.New(rand.NewPCG(seed, 1))
	k := newCredentialKit(t)
	build := func() *Credential {
		var lane [16]byte
		wire, err := IssueCredential(k.delegation, k.transport, pub(k.holders[0]), randomCaveats(r, true, &lane))
		if err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			if wire, err = AppendCredentialBlock(wire, k.holders[i], pub(k.holders[i+1]), randomCaveats(r, false, &lane)); err != nil {
				t.Fatal(err)
			}
		}
		return decode(t, wire)
	}
	for range 200 {
		a, b := build(), build()
		variants := [][]Block{
			{a.blocks[0], a.blocks[2], a.blocks[1], a.blocks[3]},
			{a.blocks[0], a.blocks[2], a.blocks[3]},
			{a.blocks[0], a.blocks[1], a.blocks[3]},
			{a.blocks[0], b.blocks[1], a.blocks[2], a.blocks[3]},
			{a.blocks[0], a.blocks[1], b.blocks[2]},
		}
		for i, blocks := range variants {
			moved, err := NewCredential(a.delegationBytes, blocks)
			if err != nil {
				t.Fatal(err)
			}
			if moved.VerifyChain() == nil {
				t.Fatalf("variant %d verified", i)
			}
		}
	}
}

// FuzzNarrowing drives the same property from fuzzer-chosen seeds.
func FuzzNarrowing(f *testing.F) {
	f.Add(uint64(narrowingSeed))
	f.Add(uint64(1))
	k := newCredentialKit(f)
	f.Fuzz(func(t *testing.T, seed uint64) {
		r := rand.New(rand.NewPCG(seed, seed>>1))
		var stats narrowStats
		checkNarrowing(t, k, r, &stats)
	})
}

// FuzzDecodeCredential: decoding is total, and anything it accepts
// re-encodes to the same bytes (one spelling per credential).
func FuzzDecodeCredential(f *testing.F) {
	k := newCredentialKit(f)
	f.Add(k.chain(f, firstCaveats(OperationList)))
	f.Add(k.chain(f, append(firstCaveats(OperationDeposit), LaneCaveat([16]byte{1}), MaxEnvelopesCaveat(3)), []Caveat{RelayCaveat(testRelay)}))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeCredential(b)
		if err != nil {
			return
		}
		encoded, err := c.Encode()
		if err != nil || string(encoded) != string(b) {
			t.Fatalf("accepted bytes do not re-encode: %v", err)
		}
		_ = c.VerifyChain()
		_ = c.CheckScope(testNow, testRelay, OperationDeposit)
		_ = c.CheckDeposit(LaneUsage{EnvelopeBytes: 1})
	})
}
