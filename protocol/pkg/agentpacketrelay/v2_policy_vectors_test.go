package agentpacketrelay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestV2FrozenPolicyVectors(t *testing.T) {
	type vector struct {
		Name   string `json:"name"`
		Issued uint64 `json:"issued"`
		Count  uint16 `json:"count"`
		Bytes  uint32 `json:"bytes"`
		Hex    string `json:"hex"`
	}
	var corpus struct {
		Schema       string   `json:"schema"`
		Vectors      []vector `json:"vectors"`
		Negative     []vector `json:"negative"`
		Now          uint64   `json:"now"`
		MaximumCount uint16   `json:"maximum_count"`
		MaximumBytes uint32   `json:"maximum_bytes"`
	}
	raw, err := os.ReadFile("../../../spec/test-vectors/relay-mailbox-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "tos.service.relay-mailbox-policy.vectors.v1" || len(corpus.Vectors) != 3 || len(corpus.Negative) != 7 {
		t.Fatal("incomplete frozen corpus")
	}
	limits := DefaultV2Limits(1024, 64<<20)
	limits.StrangerMaxEnvelopes = int(corpus.MaximumCount)
	limits.StrangerMaxBytes = int64(corpus.MaximumBytes)
	for _, v := range corpus.Vectors {
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		p := MailboxPolicy{v.Issued, v.Count, v.Bytes}
		if !bytes.Equal(raw, p.Encode()) {
			t.Fatal("vector differs", v.Name)
		}
		decoded, err := DecodeMailboxPolicy(raw)
		if err != nil || decoded != p || !decoded.valid(limits, corpus.Now) {
			t.Fatal(v.Name, err)
		}
	}
	for _, v := range corpus.Negative {
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeMailboxPolicy(raw)
		if err == nil && decoded.valid(limits, corpus.Now) {
			t.Fatal("negative accepted", v.Name)
		}
	}
}
