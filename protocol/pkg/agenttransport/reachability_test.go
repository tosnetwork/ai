package agenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func hintSample(t testing.TB) (*fixture, Hint, ed25519.PrivateKey) {
	t.Helper()
	f := newFixture(t)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	return f, Hint{Delegation: f.d, IssuedAt: 1800000010, ExpiresAt: 1800000610, Relays: []string{"https://relay.invalid"}}, key
}
func cardJSON(t testing.TB, agent string, size int) []byte {
	t.Helper()
	v := map[string]string{"sender_agent_id": agent, "padding": ""}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if size > 0 {
		if size < len(b) {
			t.Fatal("short fixture size")
		}
		v["padding"] = strings.Repeat("p", size-len(b))
		b, err = json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
	}
	return b
}
func signRecord(t testing.TB, h Hint, objects []HintObject, key ed25519.PrivateKey) []byte {
	t.Helper()
	h.Objects = nil
	for _, object := range objects {
		digest, err := HintObjectDigest(object.Kind, object.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		h.Objects = append(h.Objects, HintObjectRef{Kind: object.Kind, Length: uint32(len(object.Bytes)), Digest: digest})
	}
	signed, err := SignHint(h, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := (HintRecord{Hint: signed, Objects: objects}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestHintLimitsAndReducedPublication(t *testing.T) {
	f, h, key := hintSample(t)
	v := f.verifier(t)
	raw, err := v.BuildHintRecord(context.Background(), h, nil, key, PublishOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.VerifyHint(context.Background(), raw, HintPolicy{})
	if err != nil || len(got.Record.Objects) != 0 || len(got.Record.Hint.Direct) != 0 {
		t.Fatalf("reduced hint: %v", err)
	}
	for _, kind := range []HintObjectKind{ChatCard, MessengerEvidence} {
		body := cardJSON(t, f.d.AgentID(), 0)
		if _, err = v.BuildHintRecord(context.Background(), h, []HintObject{{Kind: kind, Bytes: body}}, key, PublishOptions{}); err == nil {
			t.Fatal("public-contact opt-in ignored")
		}
	}
	h.Direct = []DirectEntry{{Kind: 1, Port: 30001, InboundClass: 1, IPv4: [4]byte{8, 8, 8, 8}}}
	if _, err = v.BuildHintRecord(context.Background(), h, nil, key, PublishOptions{}); err == nil {
		t.Fatal("direct opt-in ignored")
	}
	if _, err = v.BuildHintRecord(context.Background(), h, nil, key, PublishOptions{DirectEnabled: true}); err != nil {
		t.Fatal(err)
	}
	h.Direct = append(h.Direct, DirectEntry{Kind: 1, Port: 30002, InboundClass: 2, IPv4: [4]byte{9, 9, 9, 9}})
	h.Relays = nil
	h.Relays = make([]string, 4)
	for i := range h.Relays {
		h.Relays[i] = "https://" + string(rune('d'-i)) + strings.Repeat("x", 256-len("https://d.invalid")) + ".invalid"
	}
	h.ExpiresAt = h.IssuedAt + MaxHintLifetimeSeconds
	objects := []HintObject{{RailCard, cardJSON(t, f.d.AgentID(), MaxHintCardBytes)}, {ChatCard, cardJSON(t, f.d.AgentID(), MaxHintCardBytes)}, {MessengerEvidence, bytes.Repeat([]byte{1}, MaxHintEvidenceBytes)}}
	raw, err = v.BuildHintRecord(context.Background(), h, objects, key, PublishOptions{PublicContact: true, DirectEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeHintRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := decoded.Hint.Encode()
	if err != nil || len(wire) != 1512 || len(raw) != 38419 || len(raw) > MaxHintRecordSize {
		t.Fatalf("max hint/record: %d %d %v", len(wire), len(raw), err)
	}
	if decoded.Hint.Relays[0] != h.Relays[0] {
		t.Fatal("priority order changed")
	}
	for _, kind := range []HintObjectKind{RailCard, ChatCard, MessengerEvidence} {
		if _, err = HintObjectDigest(kind, bytes.Repeat([]byte{1}, int(objectLimit(kind))+1)); err == nil {
			t.Fatal("object bound ignored")
		}
	}
}
func TestHintStructuralRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Hint)
	}{
		{"ttl-equal", func(h *Hint) { h.ExpiresAt = h.IssuedAt }},
		{"ttl-reversed", func(h *Hint) { h.ExpiresAt = h.IssuedAt - 1 }},
		{"ttl-long", func(h *Hint) { h.ExpiresAt = h.IssuedAt + 86401 }},
		{"no-relays", func(h *Hint) { h.Relays = nil }},
		{"many-relays", func(h *Hint) {
			h.Relays = []string{"https://a.invalid", "https://b.invalid", "https://c.invalid", "https://d.invalid", "https://e.invalid"}
		}},
		{"duplicate-relay", func(h *Hint) { h.Relays = append(h.Relays, h.Relays[0]) }},
		{"empty-url", func(h *Hint) { h.Relays[0] = "" }},
		{"bad-url", func(h *Hint) { h.Relays[0] = "https://relay.invalid/" }},
		{"long-url", func(h *Hint) { h.Relays[0] = "https://" + strings.Repeat("x", 257) }},
		{"many-direct", func(h *Hint) {
			h.Direct = []DirectEntry{{Kind: 1, Port: 1, InboundClass: 1}, {Kind: 1, Port: 1, InboundClass: 1}, {Kind: 1, Port: 1, InboundClass: 1}}
		}},
		{"direct-kind-zero", func(h *Hint) { h.Direct = []DirectEntry{{Kind: 0, Port: 1, InboundClass: 1}} }},
		{"direct-kind", func(h *Hint) { h.Direct = []DirectEntry{{Kind: 2, Port: 1, InboundClass: 1}} }},
		{"direct-port", func(h *Hint) { h.Direct = []DirectEntry{{Kind: 1, InboundClass: 1}} }},
		{"direct-class-zero", func(h *Hint) { h.Direct = []DirectEntry{{Kind: 1, Port: 1, InboundClass: 0}} }},
		{"direct-class", func(h *Hint) { h.Direct = []DirectEntry{{Kind: 1, Port: 1, InboundClass: 3}} }},
		{"many-objects", func(h *Hint) { h.Objects = make([]HintObjectRef, 4) }},
		{"object-kind-zero", func(h *Hint) { h.Objects = []HintObjectRef{{Kind: 0, Length: 1}} }},
		{"object-kind", func(h *Hint) { h.Objects = []HintObjectRef{{Kind: 4, Length: 1}} }},
		{"object-zero", func(h *Hint) { h.Objects = []HintObjectRef{{Kind: RailCard}} }},
		{"object-long", func(h *Hint) { h.Objects = []HintObjectRef{{Kind: RailCard, Length: 9217}} }},
		{"object-order", func(h *Hint) { h.Objects = []HintObjectRef{{Kind: ChatCard, Length: 1}, {Kind: RailCard, Length: 1}} }},
		{"object-duplicate", func(h *Hint) { h.Objects = []HintObjectRef{{Kind: RailCard, Length: 1}, {Kind: RailCard, Length: 1}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, h, key := hintSample(t)
			if _, err := SignHint(h, key); err != nil {
				t.Fatal(err)
			}
			tc.change(&h)
			if _, err := h.Encode(); !errors.Is(err, ErrHint) {
				t.Fatalf("invalid hint accepted: %v", err)
			}
		})
	}
}
func TestHintWireRefusals(t *testing.T) {
	_, h, key := hintSample(t)
	raw := signRecord(t, h, nil, key)
	decoded, err := DecodeHintRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	hw, err := decoded.Hint.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, hw[:len(hw)-1], append(bytes.Clone(hw), 0), bytes.Repeat([]byte{0}, MaxHintSize+1)} {
		if _, err = DecodeHint(bad); err == nil {
			t.Fatal("bad hint wire accepted")
		}
	}
	bad := bytes.Clone(hw)
	bad[0] ^= 1
	if _, err = DecodeHint(bad); err == nil {
		t.Fatal("hint domain ignored")
	}
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), bytes.Repeat([]byte{0}, MaxHintRecordSize+1)} {
		if _, err = DecodeHintRecord(bad); err == nil {
			t.Fatal("bad record accepted")
		}
	}
	bad = bytes.Clone(raw)
	bad[0] ^= 1
	if _, err = DecodeHintRecord(bad); err == nil {
		t.Fatal("record domain ignored")
	}
	bad = bytes.Clone(raw)
	binary.BigEndian.PutUint16(bad[len(hintRecordDomain):], MaxHintSize+1)
	if _, err = DecodeHintRecord(bad); err == nil {
		t.Fatal("hint length ignored")
	}
	for n := 0; n < len(raw); n++ {
		if _, err = DecodeHintRecord(raw[:n:n]); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
}
func TestHintObjectsArePresentAndBound(t *testing.T) {
	f, h, key := hintSample(t)
	objects := []HintObject{{RailCard, cardJSON(t, f.d.AgentID(), 0)}}
	raw := signRecord(t, h, objects, key)
	if _, err := f.verifier(t).VerifyHint(context.Background(), raw, HintPolicy{}); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(raw)
	bad[len(bad)-2] ^= 1
	if _, err := DecodeHintRecord(bad); err == nil {
		t.Fatal("object digest ignored")
	}
	if _, err := DecodeHintRecord(raw[:len(raw)-1]); err == nil {
		t.Fatal("object length ignored")
	}
	record, err := DecodeHintRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	record.Objects = nil
	if _, err = record.Encode(); err == nil {
		t.Fatal("missing object accepted")
	}
	record, err = DecodeHintRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	record.Objects[0].Kind = ChatCard
	if _, err = record.Encode(); err == nil {
		t.Fatal("object kind binding ignored")
	}
	record, err = DecodeHintRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	record.Objects[0].Bytes = append(record.Objects[0].Bytes, 0)
	if _, err = record.Encode(); err == nil {
		t.Fatal("object encoding size ignored")
	}
	for _, body := range [][]byte{[]byte(`{}`), []byte(`{"sender_agent_id":"other"}`), []byte(`{"sender_agent_id":"` + f.d.AgentID() + `","sender_agent_id":"` + f.d.AgentID() + `"}`), []byte(`{"sender_agent_id":"` + f.d.AgentID() + `"} {}`)} {
		bad = signRecord(t, h, []HintObject{{RailCard, body}}, key)
		if _, err = f.verifier(t).VerifyHint(context.Background(), bad, HintPolicy{}); err == nil {
			t.Fatal("card sender or strict JSON ignored")
		}
	}
}
func TestHintChecksSignatureAndFinalizedDelegation(t *testing.T) {
	f, h, key := hintSample(t)
	raw := signRecord(t, h, nil, key)
	v := f.verifier(t)
	if _, err := v.VerifyHint(context.Background(), raw, HintPolicy{}); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	if _, err := v.VerifyHint(context.Background(), bad, HintPolicy{}); err == nil {
		t.Fatal("hint signature ignored")
	}
	f.clock.advance(RefreshAfter)
	f.r.snapshot.State.GetAgent().Tombstoned = true
	if _, err := v.VerifyHint(context.Background(), raw, HintPolicy{}); err == nil {
		t.Fatal("revoked hint accepted")
	}
}
func TestHintTimestamps(t *testing.T) {
	for _, tc := range []struct {
		name            string
		issued, expires uint64
		ok              bool
	}{
		{"future-edge", 1800000310, 1800000610, true}, {"future-over", 1800000311, 1800000610, false},
		{"expiry-edge", 1800000000, 1800000010, false}, {"expiry-before", 1800000000, 1800000011, true},
		{"max-time", ^uint64(0) - 300, ^uint64(0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, h, key := hintSample(t)
			h.IssuedAt = tc.issued
			h.ExpiresAt = tc.expires
			raw := signRecord(t, h, nil, key)
			_, err := f.verifier(t).VerifyHint(context.Background(), raw, HintPolicy{})
			if (err == nil) != tc.ok {
				t.Fatalf("want %v got %v", tc.ok, err)
			}
		})
	}
	t.Run("during-read", func(t *testing.T) {
		f, h, key := hintSample(t)
		raw := signRecord(t, h, nil, key)
		h.ExpiresAt = h.IssuedAt + 1
		raw = signRecord(t, h, nil, key)
		f.r.after = func() { f.clock.advance(2 * time.Second) }
		if _, err := f.verifier(t).VerifyHint(context.Background(), raw, HintPolicy{}); err == nil {
			t.Fatal("expired during read accepted")
		}
	})
}
func TestDirectAddressPolicy(t *testing.T) {
	for _, raw := range [][4]byte{{0, 0, 0, 0}, {10, 1, 2, 3}, {172, 16, 1, 1}, {192, 168, 1, 1}, {127, 0, 0, 1}, {169, 254, 1, 1}, {100, 64, 1, 1}, {192, 0, 0, 1}, {192, 0, 2, 1}, {192, 88, 99, 1}, {198, 18, 1, 1}, {198, 51, 100, 1}, {203, 0, 113, 1}, {224, 1, 1, 1}, {240, 0, 0, 1}, {255, 255, 255, 255}} {
		f, h, key := hintSample(t)
		h.Direct = []DirectEntry{{Kind: 1, Port: 1, InboundClass: 1, IPv4: raw}}
		wire := signRecord(t, h, nil, key)
		if _, err := f.verifier(t).VerifyHint(context.Background(), wire, HintPolicy{}); err == nil {
			t.Fatalf("reserved address accepted %v", raw)
		}
	}
	f, h, key := hintSample(t)
	h.Direct = []DirectEntry{{Kind: 1, Port: 1, InboundClass: 2, IPv4: [4]byte{10, 1, 2, 3}}}
	raw := signRecord(t, h, nil, key)
	got, err := f.verifier(t).VerifyHint(context.Background(), raw, HintPolicy{AllowPrivateIPv4: true})
	if err != nil || !got.PrivateIPv4Allowed {
		t.Fatalf("test private mode %v", err)
	}
	if validDirectIPv4([4]byte{127, 0, 0, 1}, true) {
		t.Fatal("private mode widened to loopback")
	}
}
func TestConsumerMustAuthenticateObjects(t *testing.T) {
	f, h, key := hintSample(t)
	raw := signRecord(t, h, []HintObject{{RailCard, cardJSON(t, f.d.AgentID(), 0)}, {MessengerEvidence, []byte{1}}}, key)
	v := f.verifier(t)
	if _, err := v.VerifyConsumerHint(context.Background(), raw, HintPolicy{}, nil); err == nil {
		t.Fatal("consumer verification optional")
	}
	calls := 0
	check := func(_ context.Context, _ HintObjectKind, _ []byte) (string, error) {
		calls++
		return f.d.AgentID(), nil
	}
	if _, err := v.VerifyConsumerHint(context.Background(), raw, HintPolicy{}, check); err != nil || calls != 2 {
		t.Fatalf("verification callbacks %d %v", calls, err)
	}
	for _, check := range []ObjectVerifier{func(context.Context, HintObjectKind, []byte) (string, error) { return "other", nil }, func(context.Context, HintObjectKind, []byte) (string, error) {
		return f.d.AgentID(), errors.New("invalid card")
	}} {
		if _, err := v.VerifyConsumerHint(context.Background(), raw, HintPolicy{}, check); err == nil {
			t.Fatal("unverified/wrong Agent object accepted")
		}
	}
	if _, err := v.VerifyConsumerHint(context.Background(), raw, HintPolicy{}, func(context.Context, HintObjectKind, []byte) (string, error) {
		f.clock.advance(601 * time.Second)
		return f.d.AgentID(), nil
	}); err == nil {
		t.Fatal("stale result after object verification")
	}
}
func TestHintNewestIsPerDelegation(t *testing.T) {
	_, h, key := hintSample(t)
	a, err := SignHint(h, key)
	if err != nil {
		t.Fatal(err)
	}
	h.Relays = []string{"https://other.invalid"}
	b, err := SignHint(h, key)
	if err != nil {
		t.Fatal(err)
	}
	aw, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	bw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ah, bh := sha256.Sum256(aw), sha256.Sum256(bw)
	got, err := CompareHints(a, b)
	if err != nil || got != bytes.Compare(ah[:], bh[:]) {
		t.Fatal("tie digest ignored")
	}
	b.IssuedAt++
	got, err = CompareHints(a, b)
	if err != nil || got != -1 {
		t.Fatal("issued-at order ignored")
	}
	a.Delegation.AgentDigest[0]++
	if _, err = CompareHints(a, b); err == nil {
		t.Fatal("independent delegations compared")
	}
}

func TestHintRequiresHintsPurpose(t *testing.T) {
	f, h, key := hintSample(t)
	f.d.Purposes = Relay
	f.reencode(t)
	h.Delegation = f.d
	if _, err := f.verifier(t).VerifyHint(context.Background(), signRecord(t, h, nil, key), HintPolicy{}); err == nil {
		t.Fatal("hint purpose ignored")
	}
}
func TestSignedObjectsRespectCancellationAndClockRollback(t *testing.T) {
	f, h, key := hintSample(t)
	raw := signRecord(t, h, nil, key)
	v := f.verifier(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.VerifyHint(ctx, raw, HintPolicy{}); err == nil {
		t.Fatal("cancelled hint accepted")
	}
	if _, err := v.VerifyHint(context.Background(), raw, HintPolicy{}); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(-time.Second)
	if _, err := v.VerifyHint(context.Background(), raw, HintPolicy{}); err == nil {
		t.Fatal("clock rollback ignored")
	}
	_, hello, expect, _ := directSample(t, HelloResponder)
	if _, err := v.VerifyHello(ctx, helloWire(t, hello, key), expect); err == nil {
		t.Fatal("cancelled hello accepted")
	}
	r := Receipt{RecipientAgent: f.d.AgentDigest, Outcome: ReceiptStored}
	if _, err := v.VerifyReceipt(ctx, receiptWire(t, r, f.d, key), f.wire, r.RecipientAgent, r.EnvelopeID); err == nil {
		t.Fatal("cancelled receipt accepted")
	}
}

func TestHintNewestTimestampBeatsDigest(t *testing.T) {
	_, base, key := hintSample(t)
	found := false
	for i := range 128 {
		older := base // Keep URLs printable and canonical while varying the signed digest.
		older.Relays = []string{"https://relay.invalid/p" + strings.Repeat("x", i)}
		a, err := SignHint(older, key)
		if err != nil {
			t.Fatal(err)
		}
		newer := older
		newer.IssuedAt++
		b, err := SignHint(newer, key)
		if err != nil {
			t.Fatal(err)
		}
		aw, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		bw, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		ah, bh := sha256.Sum256(aw), sha256.Sum256(bw)
		if bytes.Compare(ah[:], bh[:]) <= 0 {
			continue
		}
		found = true
		if got, err := CompareHints(a, b); err != nil || got != -1 {
			t.Fatal("time lost to digest")
		}
		if got, err := CompareHints(b, a); err != nil || got != 1 {
			t.Fatal("newer time lost to digest")
		}
		break
	}
	if !found {
		t.Fatal("timestamp-vs-digest control was vacuous")
	}
}

func TestConsumerSnapshotCannotChangeDuringVerification(t *testing.T) {
	f, h, key := hintSample(t)
	original := cardJSON(t, f.d.AgentID(), 150)
	changed := bytes.Clone(original)
	for i, value := range changed {
		if value == 'p' {
			changed[i] = 'q'
			break
		}
	}
	wire := signRecord(t, h, []HintObject{{RailCard, original}}, key)
	replacement := signRecord(t, h, []HintObject{{RailCard, changed}}, key)
	if len(wire) != len(replacement) {
		t.Fatal("mutation length changed")
	}
	verified := 0
	got, err := f.verifier(t).VerifyConsumerHint(context.Background(), wire, HintPolicy{}, func(_ context.Context, _ HintObjectKind, body []byte) (string, error) {
		if !bytes.Equal(body, original) {
			t.Fatal("callback did not see original object")
		}
		copy(wire, replacement)
		verified++
		return f.d.AgentID(), nil
	})
	if err != nil || verified != 1 || !bytes.Equal(got.Record.Objects[0].Bytes, original) {
		t.Fatalf("consumer mixed snapshots: %v", err)
	}
}
func TestConsumerOversizedInputRefusesBeforeAllocation(t *testing.T) {
	f, _, _ := hintSample(t)
	v := f.verifier(t)
	raw := make([]byte, MaxHintRecordSize+1)
	allocations := testing.AllocsPerRun(10, func() {
		if _, err := v.VerifyConsumerHint(context.Background(), raw, HintPolicy{}, nil); err == nil {
			t.Fatal("oversized input accepted")
		}
	})
	if allocations != 0 {
		t.Fatalf("oversized input allocated %v", allocations)
	}
}
