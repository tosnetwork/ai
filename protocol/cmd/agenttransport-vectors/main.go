// agenttransport-vectors deliberately emits the frozen delegation corpus.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type vector struct {
	Name       string `json:"name"`
	Seed       string `json:"seed"`
	Agent      string `json:"agent_digest"`
	Key        string `json:"transport_key"`
	Epoch      uint64 `json:"epoch"`
	Policy     string `json:"policy_hash"`
	Purposes   byte   `json:"purposes"`
	Before     uint64 `json:"not_before"`
	After      uint64 `json:"not_after"`
	Credential uint32 `json:"max_credential_seconds"`
	Wire       string `json:"wire"`
	Digest     string `json:"digest"`
}
type negative struct {
	Name string `json:"name"`
	Wire string `json:"wire"`
}

func run() error {
	output := struct {
		Schema   string     `json:"schema"`
		Positive []vector   `json:"positive"`
		Negative []negative `json:"negative"`
	}{Schema: "tos.agent-transport-delegation-v1.vectors"}
	for i := range 4 {
		seed := sha256.Sum256([]byte(fmt.Sprintf("transport-vector-test-seed-%d", i)))
		key := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		d := agenttransport.Delegation{AgentDigest: sha256.Sum256([]byte(fmt.Sprintf("transport-vector-agent-%d", i))), AuthorizationEpoch: uint64(i), PolicyHash: sha256.Sum256([]byte(fmt.Sprintf("transport-vector-policy-%d", i))), Purposes: agenttransport.Purpose(i + 1), NotBefore: 1800000000, NotAfter: 1800003600, MaxCredentialSeconds: 600}
		copy(d.TransportKey[:], key)
		if i == 3 {
			d.AuthorizationEpoch = ^uint64(0)
			d.Purposes = 7
			d.NotAfter = d.NotBefore + agenttransport.MaxDelegationSeconds
			d.MaxCredentialSeconds = agenttransport.MaxCredentialSeconds
		}
		b, err := d.Encode()
		if err != nil {
			return err
		}
		hash := sha256.Sum256(b)
		output.Positive = append(output.Positive, vector{Name: fmt.Sprintf("delegation-%d", i), Seed: hex.EncodeToString(seed[:]), Agent: hex.EncodeToString(d.AgentDigest[:]), Key: hex.EncodeToString(key), Epoch: d.AuthorizationEpoch, Policy: hex.EncodeToString(d.PolicyHash[:]), Purposes: byte(d.Purposes), Before: d.NotBefore, After: d.NotAfter, Credential: d.MaxCredentialSeconds, Wire: hex.EncodeToString(b), Digest: hex.EncodeToString(hash[:])})
	}
	base, err := hex.DecodeString(output.Positive[0].Wire)
	if err != nil {
		return err
	}
	add := func(name string, change func([]byte) []byte) error {
		b := change(append([]byte{}, base...))
		if _, err := agenttransport.DecodeDelegation(b); err == nil {
			return fmt.Errorf("negative %s accepted", name)
		}
		output.Negative = append(output.Negative, negative{Name: name, Wire: hex.EncodeToString(b)})
		return nil
	}
	cases := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:166] }},
		{"trailing", func(b []byte) []byte { return append(b, 0) }},
		{"wrong-domain", func(b []byte) []byte { b[0] ^= 1; return b }},
		{"zero-key", func(b []byte) []byte { clear(b[74:106]); return b }},
		{"identity-key", func(b []byte) []byte { clear(b[74:106]); b[74] = 1; return b }},
		{"order-two-key", func(b []byte) []byte {
			for j := 74; j < 106; j++ {
				b[j] = 255
			}
			b[74] = 236
			b[105] = 127
			return b
		}},
		{"noncanonical-key", func(b []byte) []byte {
			for j := 74; j < 106; j++ {
				b[j] = 255
			}
			b[74] = 240
			b[105] = 127
			return b
		}},
		{"no-purpose", func(b []byte) []byte { b[146] = 0; return b }},
		{"unknown-purpose", func(b []byte) []byte { b[146] = 8; return b }},
		{"zero-not-before", func(b []byte) []byte { clear(b[147:155]); return b }},
		{"equal-times", func(b []byte) []byte { copy(b[155:163], b[147:155]); return b }},
		{"reversed-times", func(b []byte) []byte { binary.BigEndian.PutUint64(b[155:163], 1799999999); return b }},
		{"excessive-lifetime", func(b []byte) []byte { binary.BigEndian.PutUint64(b[155:163], 1800000000+31536001); return b }},
		{"zero-credential", func(b []byte) []byte { clear(b[163:167]); return b }},
		{"excessive-credential", func(b []byte) []byte { binary.BigEndian.PutUint32(b[163:167], 604801); return b }},
	}
	for _, tc := range cases {
		if err := add(tc.name, tc.change); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
