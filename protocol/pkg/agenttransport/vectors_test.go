package agenttransport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestFrozenVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/test-vectors/agent-transport-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Schema   string `json:"schema"`
		Positive []struct {
			Name   string `json:"name"`
			Wire   string `json:"wire"`
			Digest string `json:"digest"`
		}
		Negative []struct {
			Name string `json:"name"`
			Wire string `json:"wire"`
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "tos.agent-transport-delegation-v1.vectors" || len(corpus.Positive) != 4 || len(corpus.Negative) != 15 {
		t.Fatal("incomplete vector corpus")
	}
	for _, v := range corpus.Positive {
		t.Run(v.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Wire)
			if err != nil {
				t.Fatal(err)
			}
			d, err := DecodeDelegation(wire)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := d.Encode()
			if err != nil || hex.EncodeToString(encoded) != v.Wire {
				t.Fatalf("encoding: %v", err)
			}
			hash, err := DelegationDigest(wire)
			if err != nil || hex.EncodeToString(hash[:]) != v.Digest || hash != sha256.Sum256(wire) {
				t.Fatalf("digest: %v", err)
			}
		})
	}
	for _, v := range corpus.Negative {
		t.Run(v.Name, func(t *testing.T) {
			wire, err := hex.DecodeString(v.Wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeDelegation(wire); err == nil {
				t.Fatal("negative accepted")
			}
			if _, err = DelegationDigest(wire); err == nil {
				t.Fatal("negative digest accepted")
			}
		})
	}
}
