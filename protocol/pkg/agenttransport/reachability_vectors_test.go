package agenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

type reachabilityVector struct {
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Seed       string     `json:"test_seed"`
	Delegation Delegation `json:"delegation"`
	Hint       *Hint      `json:"hint"`
	Hello      *Hello     `json:"hello"`
	Receipt    *Receipt   `json:"receipt"`
	Objects    []struct {
		Kind HintObjectKind `json:"kind"`
		Hex  string         `json:"hex"`
	} `json:"objects"`
	Private bool   `json:"allow_private_ipv4"`
	Wire    string `json:"wire"`
	SHA256  string `json:"sha256"`
}

func vectorVerifier(t *testing.T, d Delegation, now uint64) *Verifier {
	t.Helper()
	f := newFixture(t)
	f.d = d
	f.r.snapshot.State.GetAgent().AgentId = d.AgentID()
	epoch := d.AuthorizationEpoch
	f.r.snapshot.CurrentEpoch = &epoch
	f.clock.at = time.Unix(int64(now), 0)
	f.reencode(t)
	return f.verifier(t)
}
func verifyReachabilityVector(t *testing.T, v reachabilityVector, wire []byte, now uint64, decodeOnly bool) error {
	t.Helper()
	verifier := vectorVerifier(t, v.Delegation, now)
	switch v.Kind {
	case "hint-record":
		if decodeOnly {
			_, err := DecodeHintRecord(wire)
			return err
		}
		_, err := verifier.VerifyHint(context.Background(), wire, HintPolicy{AllowPrivateIPv4: v.Private})
		return err
	case "hello":
		if decodeOnly {
			_, err := DecodeHello(wire)
			return err
		}
		expected := HelloExpectation{Role: v.Hello.Role, LocalADNL: v.Hello.PeerADNL, PeerADNL: v.Hello.LocalADNL, ExpectedAgent: v.Delegation.AgentID(), InitiatorNonce: v.Hello.InitiatorNonce, AdmittedContact: func(agent string) bool { return agent == v.Delegation.AgentID() }}
		_, err := verifier.VerifyHello(context.Background(), wire, expected)
		return err
	case "receipt":
		if decodeOnly {
			_, err := DecodeReceipt(wire)
			return err
		}
		delegation, err := v.Delegation.Encode()
		if err != nil {
			t.Fatal(err)
		}
		_, err = verifier.VerifyReceipt(context.Background(), wire, delegation, v.Receipt.RecipientAgent, v.Receipt.EnvelopeID)
		return err
	default:
		t.Fatal("unknown vector kind")
		return errors.New("unknown kind")
	}
}
func TestFrozenReachabilityVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/test-vectors/agent-transport-reachability-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Schema   string               `json:"schema"`
		Now      uint64               `json:"now"`
		Positive []reachabilityVector `json:"positive"`
		Negative []struct {
			Name  string `json:"name"`
			Base  string `json:"base"`
			Wire  string `json:"wire"`
			Stage string `json:"stage"`
			Class string `json:"class"`
		} `json:"negative"`
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "tos.agent-transport-reachability-v1.vectors" || len(corpus.Positive) != 13 || len(corpus.Negative) != 57 {
		t.Fatal("incomplete reachability corpus")
	}
	bases := map[string]reachabilityVector{}
	for _, v := range corpus.Positive {
		t.Run(v.Name, func(t *testing.T) {
			bases[v.Name] = v
			seed, err := hex.DecodeString(v.Seed)
			if err != nil || len(seed) != 32 {
				t.Fatal("fixture seed")
			}
			key := ed25519.NewKeyFromSeed(seed)
			var rebuilt []byte
			switch v.Kind {
			case "hint-record":
				if v.Hint == nil || v.Hint.Signature != ([64]byte{}) {
					t.Fatal("unexpected input signature")
				}
				var objects []HintObject
				for _, ob := range v.Objects {
					b, err := hex.DecodeString(ob.Hex)
					if err != nil {
						t.Fatal(err)
					}
					objects = append(objects, HintObject{Kind: ob.Kind, Bytes: b})
				}
				signed, err := SignHint(*v.Hint, key)
				if err != nil {
					t.Fatal(err)
				}
				rebuilt, err = (HintRecord{Hint: signed, Objects: objects}).Encode()
				if err != nil {
					t.Fatal(err)
				}
			case "hello":
				if v.Hello == nil || v.Hello.Signature != ([64]byte{}) {
					t.Fatal("hello input")
				}
				signed, err := SignHello(*v.Hello, key)
				if err != nil {
					t.Fatal(err)
				}
				rebuilt, err = signed.Encode()
				if err != nil {
					t.Fatal(err)
				}
			case "receipt":
				if v.Receipt == nil || v.Receipt.Signature != ([64]byte{}) {
					t.Fatal("receipt input")
				}
				signed, err := SignReceipt(*v.Receipt, v.Delegation, key)
				if err != nil {
					t.Fatal(err)
				}
				rebuilt, err = signed.Encode()
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatal("unknown kind")
			}
			wire, err := hex.DecodeString(v.Wire)
			if err != nil || !bytes.Equal(wire, rebuilt) {
				t.Fatal("frozen wire changed")
			}
			digest := sha256.Sum256(wire)
			if hex.EncodeToString(digest[:]) != v.SHA256 {
				t.Fatal("frozen digest changed")
			}
			if err = verifyReachabilityVector(t, v, wire, corpus.Now, false); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, n := range corpus.Negative {
		t.Run(n.Name, func(t *testing.T) {
			v, found := bases[n.Base]
			if !found {
				t.Fatal("unknown negative base")
			}
			wire, err := hex.DecodeString(n.Wire)
			if err != nil {
				t.Fatal(err)
			}
			if n.Stage != "decode" && n.Stage != "verify" {
				t.Fatal("unknown negative stage")
			}
			err = verifyReachabilityVector(t, v, wire, corpus.Now, n.Stage == "decode")
			class := map[string]error{"hint_invalid": ErrHint, "hello_invalid": ErrHello, "receipt_invalid": ErrReceipt}[n.Class]
			if class == nil || !errors.Is(err, class) {
				t.Fatalf("negative accepted or wrong class: %v", err)
			}
		})
	}
}
