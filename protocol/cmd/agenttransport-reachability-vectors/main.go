// agenttransport-reachability-vectors deliberately emits public fixture material.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	at "github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

type object struct {
	Kind at.HintObjectKind `json:"kind"`
	Hex  string            `json:"hex"`
}
type positive struct {
	Name       string        `json:"name"`
	Kind       string        `json:"kind"`
	Seed       string        `json:"test_seed"`
	Hint       *at.Hint      `json:"hint,omitempty"`
	Hello      *at.Hello     `json:"hello,omitempty"`
	Receipt    *at.Receipt   `json:"receipt,omitempty"`
	Delegation at.Delegation `json:"delegation"`
	Objects    []object      `json:"objects,omitempty"`
	Private    bool          `json:"allow_private_ipv4,omitempty"`
	Wire       string        `json:"wire"`
	SHA256     string        `json:"sha256"`
}
type negative struct {
	Name  string `json:"name"`
	Base  string `json:"base"`
	Wire  string `json:"wire"`
	Stage string `json:"stage"`
	Class string `json:"class"`
}
type corpus struct {
	Schema   string     `json:"schema"`
	Now      uint64     `json:"now"`
	Positive []positive `json:"positive"`
	Negative []negative `json:"negative"`
}

func policyHash() ([32]byte, error) {
	public := make([]byte, mldsa44.PublicKeySize)
	public[0] = 1
	id, err := mldsa44.KeyID(public)
	if err != nil {
		return [32]byte{}, err
	}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{KeyId: mldsa44.KeyIDText(id), Mldsa44PublicKey: public, Weight: 1, PurposeMask: 15, Recovery: true}}}
	cell, err := nativecore.PolicyCell(policy)
	if err != nil {
		return [32]byte{}, err
	}
	var digest [32]byte
	copy(digest[:], cell.Hash())
	return digest, nil
}
func card(agent string, size int) ([]byte, error) {
	value := map[string]string{"sender_agent_id": agent, "padding": ""}
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if size > 0 {
		if len(b) > size {
			return nil, fmt.Errorf("short card fixture")
		}
		value["padding"] = strings.Repeat("x", size-len(b))
	}
	return json.Marshal(value)
}
func run() error {
	out := corpus{Schema: "tos.agent-transport-reachability-v1.vectors", Now: 1800000010}
	seed := sha256.Sum256([]byte("reachability-vector-public-test-seed"))
	key := ed25519.NewKeyFromSeed(seed[:])
	policy, err := policyHash()
	if err != nil {
		return err
	}
	d := at.Delegation{AgentDigest: sha256.Sum256([]byte("reachability-vector-agent")), AuthorizationEpoch: 2, PolicyHash: policy, Purposes: 7, NotBefore: 1800000000, NotAfter: 1800000000 + at.MaxDelegationSeconds, MaxCredentialSeconds: 600}
	copy(d.TransportKey[:], key[32:])
	emit := func(v positive, wire []byte) {
		hash := sha256.Sum256(wire)
		v.Wire = hex.EncodeToString(wire)
		v.SHA256 = hex.EncodeToString(hash[:])
		v.Seed = hex.EncodeToString(seed[:])
		v.Delegation = d
		out.Positive = append(out.Positive, v)
	}
	for _, name := range []string{"reduced", "rail-public", "public-contact", "maximal", "addresses-public", "private-test", "future-edge", "expiry-before"} {
		h := at.Hint{Delegation: d, IssuedAt: out.Now, ExpiresAt: out.Now + at.RecommendedHintLifetimeSeconds, Relays: []string{"https://relay.invalid"}}
		var objects []at.HintObject
		if name == "rail-public" || name == "public-contact" || name == "maximal" || name == "addresses-public" {
			body, err := card(d.AgentID(), 0)
			if err != nil {
				return err
			}
			objects = append(objects, at.HintObject{Kind: at.RailCard, Bytes: body})
		}
		if name == "public-contact" || name == "maximal" || name == "addresses-public" {
			body, err := card(d.AgentID(), 0)
			if err != nil {
				return err
			}
			objects = append(objects, at.HintObject{Kind: at.ChatCard, Bytes: body}, at.HintObject{Kind: at.MessengerEvidence, Bytes: []byte("public evidence structural fixture")})
		}
		if name == "rail-public" {
			h.Relays = append(h.Relays, "https://second.invalid")
		}
		if name == "maximal" {
			h.ExpiresAt = h.IssuedAt + at.MaxHintLifetimeSeconds
			h.Relays = nil
			for i := range 4 {
				h.Relays = append(h.Relays, "https://"+string(rune('d'-i))+strings.Repeat("x", 256-len("https://d.invalid"))+".invalid")
			}
			h.Direct = []at.DirectEntry{{Kind: 1, ADNLID: sha256.Sum256([]byte("direct-one")), IPv4: [4]byte{8, 8, 8, 8}, Port: 30001, InboundClass: 1}, {Kind: 1, ADNLID: sha256.Sum256([]byte("direct-two")), IPv4: [4]byte{9, 9, 9, 9}, Port: 30002, InboundClass: 2}}
			for i := range objects {
				if objects[i].Kind == at.MessengerEvidence {
					objects[i].Bytes = bytes.Repeat([]byte{0x41}, at.MaxHintEvidenceBytes)
				} else {
					objects[i].Bytes, err = card(d.AgentID(), at.MaxHintCardBytes)
					if err != nil {
						return err
					}
				}
			}
		}
		if name == "addresses-public" {
			h.Relays = []string{"https://d.invalid", "https://c.invalid", "https://b.invalid", "https://a.invalid"}
			h.Direct = []at.DirectEntry{{Kind: 1, ADNLID: sha256.Sum256([]byte("direct-one")), IPv4: [4]byte{8, 8, 8, 8}, Port: 30001, InboundClass: 1}, {Kind: 1, ADNLID: sha256.Sum256([]byte("direct-two")), IPv4: [4]byte{9, 9, 9, 9}, Port: 30002, InboundClass: 2}}
		}
		if name == "private-test" {
			h.Direct = []at.DirectEntry{{Kind: 1, IPv4: [4]byte{10, 1, 2, 3}, ADNLID: sha256.Sum256([]byte("private-direct")), Port: 30001, InboundClass: 1}}
		}
		if name == "future-edge" {
			h.IssuedAt = out.Now + 300
			h.ExpiresAt = h.IssuedAt + 1
		}
		if name == "expiry-before" {
			h.ExpiresAt = out.Now + 1
		}
		var entries []object
		for _, ob := range objects {
			digest, err := at.HintObjectDigest(ob.Kind, ob.Bytes)
			if err != nil {
				return err
			}
			h.Objects = append(h.Objects, at.HintObjectRef{Kind: ob.Kind, Length: uint32(len(ob.Bytes)), Digest: digest})
			entries = append(entries, object{Kind: ob.Kind, Hex: hex.EncodeToString(ob.Bytes)})
		}
		signed, err := at.SignHint(h, key)
		if err != nil {
			return err
		}
		wire, err := (at.HintRecord{Hint: signed, Objects: objects}).Encode()
		if err != nil {
			return err
		}
		emit(positive{Name: name, Kind: "hint-record", Hint: &h, Objects: entries, Private: name == "private-test"}, wire)
	}
	for _, role := range []byte{at.HelloInitiator, at.HelloResponder} {
		h := at.Hello{Role: role, Delegation: d, LocalADNL: sha256.Sum256([]byte("hello-local")), PeerADNL: sha256.Sum256([]byte("hello-peer")), InitiatorNonce: sha256.Sum256([]byte("hello-init-nonce")), IssuedAt: out.Now}
		if role == at.HelloResponder {
			h.ResponderNonce = sha256.Sum256([]byte("hello-response-nonce"))
		}
		signed, err := at.SignHello(h, key)
		if err != nil {
			return err
		}
		wire, err := signed.Encode()
		if err != nil {
			return err
		}
		emit(positive{Name: fmt.Sprintf("hello-%d", role), Kind: "hello", Hello: &h}, wire)
	}
	for _, outcome := range []at.ReceiptOutcome{at.ReceiptStored, at.ReceiptDuplicate, at.ReceiptRefused} {
		r := at.Receipt{RecipientAgent: d.AgentDigest, EnvelopeID: sha256.Sum256([]byte("receipt-envelope")), Outcome: outcome, ReceivedAt: out.Now}
		signed, err := at.SignReceipt(r, d, key)
		if err != nil {
			return err
		}
		wire, err := signed.Encode()
		if err != nil {
			return err
		}
		emit(positive{Name: fmt.Sprintf("receipt-%d", outcome), Kind: "receipt", Receipt: &r}, wire)
	}
	bases := map[string]positive{}
	for _, v := range out.Positive {
		bases[v.Name] = v
	}
	add := func(name, base, stage string, edit func([]byte) []byte) error {
		v := bases[base]
		raw, err := hex.DecodeString(v.Wire)
		if err != nil {
			return err
		}
		raw = edit(raw)
		class := map[string]string{"hint-record": "hint_invalid", "hello": "hello_invalid", "receipt": "receipt_invalid"}[v.Kind]
		if stage == "decode" {
			var e error
			switch v.Kind {
			case "hint-record":
				_, e = at.DecodeHintRecord(raw)
			case "hello":
				_, e = at.DecodeHello(raw)
			case "receipt":
				_, e = at.DecodeReceipt(raw)
			}
			if e == nil {
				return fmt.Errorf("decode negative accepted: %s", name)
			}
		}
		out.Negative = append(out.Negative, negative{Name: name, Base: base, Wire: hex.EncodeToString(raw), Stage: stage, Class: class})
		return nil
	}
	// Offsets are derived from the domains and the frozen fixed-layout widths.
	recordHeader := len("tos.service.agent-reachability-record.v1\x00") + 2
	hintHead := len("tos.service.agent-reachability-hint.v1\x00")
	type mutation struct {
		name, base, stage string
		edit              func([]byte) []byte
	}
	changes := []mutation{}
	for _, base := range []string{"reduced", "hello-1", "receipt-1"} {
		changes = append(changes, mutation{base + "-domain", base, "decode", func(b []byte) []byte { b[0] ^= 1; return b }}, mutation{base + "-trailing", base, "decode", func(b []byte) []byte { return append(b, 0) }}, mutation{base + "-truncated", base, "decode", func(b []byte) []byte { return b[:len(b)-1] }}, mutation{base + "-signature", base, "verify", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }})
	}
	for _, base := range []string{"reduced", "hello-1", "receipt-1"} {
		domain := map[string]string{"reduced": "tos.service.agent-reachability-record.v1\x00", "hello-1": "tos.service.agent-direct-hello.v1\x00", "receipt-1": "tos.service.agent-direct-receipt.v1\x00"}[base]
		changes = append(changes,
			mutation{base + "-unknown-version", base, "decode", func(b []byte) []byte { b[len(domain)-2] = '2'; return b }},
			mutation{base + "-noncanonical-scalar", base, "verify", func(b []byte) []byte {
				for i := len(b) - 32; i < len(b); i++ {
					b[i] = 255
				}
				return b
			}},
		)
	}
	changes = append(changes,
		mutation{"hint-domain", "reduced", "decode", func(b []byte) []byte { b[recordHeader] ^= 1; return b }},
		mutation{"hint-length", "reduced", "decode", func(b []byte) []byte { binary.BigEndian.PutUint16(b[recordHeader-2:], 1537); return b }},
		mutation{"hint-ttl-equal", "reduced", "decode", func(b []byte) []byte {
			copy(b[recordHeader+hintHead+167+8:], b[recordHeader+hintHead+167:recordHeader+hintHead+167+8])
			return b
		}},
		mutation{"hint-ttl-long", "reduced", "decode", func(b []byte) []byte {
			binary.BigEndian.PutUint64(b[recordHeader+hintHead+167+8:], out.Now+86401)
			return b
		}},
		mutation{"no-relays", "reduced", "decode", func(b []byte) []byte { b[recordHeader+hintHead+167+16] = 0; return b }},
		mutation{"five-relays", "reduced", "decode", func(b []byte) []byte { b[recordHeader+hintHead+167+16] = 5; return b }},
		mutation{"object-digest", "rail-public", "decode", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		mutation{"hello-role", "hello-1", "decode", func(b []byte) []byte { b[len("tos.service.agent-direct-hello.v1\x00")] = 3; return b }},
		mutation{"hello-init-response", "hello-1", "decode", func(b []byte) []byte { b[len(b)-64-8-32] = 1; return b }},
		mutation{"receipt-outcome", "receipt-1", "decode", func(b []byte) []byte { b[len("tos.service.agent-direct-receipt.v1\x00")+64] = 4; return b }},
	)
	// Signature-preserving contexts are checked by the live verifier tests; here
	// re-sign time/address mutations so each frozen refusal reaches that check.
	resignHint := func(b []byte) []byte {
		n := int(binary.BigEndian.Uint16(b[recordHeader-2:]))
		copy(b[recordHeader+n-64:], ed25519.Sign(key, b[recordHeader:recordHeader+n-64]))
		return b
	}
	changes = append(changes,
		mutation{"future-over", "reduced", "verify", func(b []byte) []byte {
			binary.BigEndian.PutUint64(b[recordHeader+hintHead+167:], out.Now+301)
			return resignHint(b)
		}},
		mutation{"expired", "reduced", "verify", func(b []byte) []byte {
			binary.BigEndian.PutUint64(b[recordHeader+hintHead+167:], out.Now-1)
			binary.BigEndian.PutUint64(b[recordHeader+hintHead+167+8:], out.Now)
			return resignHint(b)
		}},
	)

	maximum, err := hex.DecodeString(bases["addresses-public"].Wire)
	if err != nil {
		return err
	}
	relayCount := recordHeader + hintHead + at.DelegationSize + 16
	atOffset := relayCount + 1
	var relayStarts []int
	for range 4 {
		n := int(binary.BigEndian.Uint16(maximum[atOffset:]))
		relayStarts = append(relayStarts, atOffset)
		atOffset += 2 + n
	}
	directCount := atOffset
	directStart := directCount + 1
	objectCount := directStart + 2*40
	objectStart := objectCount + 1
	changes = append(changes,
		mutation{"duplicate-relay", "addresses-public", "decode", func(b []byte) []byte {
			copy(b[relayStarts[1]+2:relayStarts[1]+2+len("https://d.invalid")], b[relayStarts[0]+2:relayStarts[0]+2+len("https://d.invalid")])
			return b
		}},
		mutation{"long-url", "addresses-public", "decode", func(b []byte) []byte { binary.BigEndian.PutUint16(b[relayStarts[0]:], 257); return b }},
		mutation{"noncanonical-url", "addresses-public", "decode", func(b []byte) []byte { b[relayStarts[0]+2+len("https://d.invalid")-1] = '/'; return b }},
		mutation{"three-direct", "addresses-public", "decode", func(b []byte) []byte { b[directCount] = 3; return b }},
		mutation{"direct-kind", "addresses-public", "decode", func(b []byte) []byte { b[directStart] = 2; return b }},
		mutation{"direct-port", "addresses-public", "decode", func(b []byte) []byte { clear(b[directStart+37 : directStart+39]); return b }},
		mutation{"direct-class", "addresses-public", "decode", func(b []byte) []byte { b[directStart+39] = 3; return b }},
		mutation{"four-objects", "addresses-public", "decode", func(b []byte) []byte { b[objectCount] = 4; return b }},
		mutation{"object-kind", "addresses-public", "decode", func(b []byte) []byte { b[objectStart] = 4; return b }},
		mutation{"object-zero", "addresses-public", "decode", func(b []byte) []byte { clear(b[objectStart+1 : objectStart+5]); return b }},
		mutation{"object-too-long", "addresses-public", "decode", func(b []byte) []byte { binary.BigEndian.PutUint32(b[objectStart+1:], 9217); return b }},
		mutation{"object-unordered", "addresses-public", "decode", func(b []byte) []byte { b[objectStart] = 2; b[objectStart+37] = 1; return b }},
		mutation{"object-duplicate", "addresses-public", "decode", func(b []byte) []byte { b[objectStart+37] = 1; return b }},
		mutation{"private-without-test-option", "addresses-public", "verify", func(b []byte) []byte {
			copy(b[directStart+33:directStart+37], []byte{10, 1, 2, 3})
			return resignHint(b)
		}},
		mutation{"loopback-direct", "addresses-public", "verify", func(b []byte) []byte {
			copy(b[directStart+33:directStart+37], []byte{127, 0, 0, 1})
			return resignHint(b)
		}},
	)
	for _, base := range []string{"hello-1", "hello-2"} {
		changes = append(changes,
			mutation{base + "-future", base, "verify", func(b []byte) []byte {
				binary.BigEndian.PutUint64(b[len(b)-72:], out.Now+121)
				copy(b[len(b)-64:], ed25519.Sign(key, b[:len(b)-64]))
				return b
			}},
			mutation{base + "-past", base, "verify", func(b []byte) []byte {
				binary.BigEndian.PutUint64(b[len(b)-72:], out.Now-121)
				copy(b[len(b)-64:], ed25519.Sign(key, b[:len(b)-64]))
				return b
			}},
			mutation{base + "-channel", base, "verify", func(b []byte) []byte {
				b[len("tos.service.agent-direct-hello.v1\x00")+1+167] ^= 1
				copy(b[len(b)-64:], ed25519.Sign(key, b[:len(b)-64]))
				return b
			}},
		)
	}
	changes = append(changes,
		mutation{"hello-challenge", "hello-2", "verify", func(b []byte) []byte {
			b[len("tos.service.agent-direct-hello.v1\x00")+1+167+64] ^= 1
			copy(b[len(b)-64:], ed25519.Sign(key, b[:len(b)-64]))
			return b
		}},
		mutation{"receipt-envelope", "receipt-1", "verify", func(b []byte) []byte {
			b[len("tos.service.agent-direct-receipt.v1\x00")+32] ^= 1
			copy(b[len(b)-64:], ed25519.Sign(key, b[:len(b)-64]))
			return b
		}},
		mutation{"receipt-agent", "receipt-1", "verify", func(b []byte) []byte {
			b[len("tos.service.agent-direct-receipt.v1\x00")] ^= 1
			copy(b[len(b)-64:], ed25519.Sign(key, b[:len(b)-64]))
			return b
		}},
	)
	for _, mode := range []string{"wrong-agent", "duplicate-json", "trailing-json"} {
		raw, err := hex.DecodeString(bases["rail-public"].Wire)
		if err != nil {
			return err
		}
		record, err := at.DecodeHintRecord(raw)
		if err != nil {
			return err
		}
		agent := d.AgentID()
		if mode == "wrong-agent" {
			agent = "agent_" + strings.Repeat("f", 64)
		}
		payload := []byte(`{"sender_agent_id":"` + agent + `"}`)
		if mode == "duplicate-json" {
			payload = []byte(`{"sender_agent_id":"` + agent + `","sender_agent_id":"` + agent + `"}`)
		}
		if mode == "trailing-json" {
			payload = append(payload, []byte(" {}")...)
		}
		record.Objects[0].Bytes = payload
		record.Hint.Objects[0].Length = uint32(len(payload))
		record.Hint.Objects[0].Digest, err = at.HintObjectDigest(at.RailCard, payload)
		if err != nil {
			return err
		}
		record.Hint, err = at.SignHint(record.Hint, key)
		if err != nil {
			return err
		}
		wire, err := record.Encode()
		if err != nil {
			return err
		}
		out.Negative = append(out.Negative, negative{Name: "card-" + mode, Base: "rail-public", Wire: hex.EncodeToString(wire), Stage: "verify", Class: "hint_invalid"})
	}
	for _, m := range changes {
		if err := add(m.name, m.base, m.stage, m.edit); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
