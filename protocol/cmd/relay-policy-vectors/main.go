// Command relay-policy-vectors deliberately emits the frozen policy corpus.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

func main() {
	type vector struct {
		Name   string `json:"name"`
		Issued uint64 `json:"issued"`
		Count  uint16 `json:"count"`
		Bytes  uint32 `json:"bytes"`
		Hex    string `json:"hex"`
	}
	out := struct {
		Schema       string   `json:"schema"`
		Vectors      []vector `json:"vectors"`
		Negative     []vector `json:"negative"`
		Now          uint64   `json:"now"`
		MaximumCount uint16   `json:"maximum_count"`
		MaximumBytes uint32   `json:"maximum_bytes"`
	}{Schema: "tos.service.relay-mailbox-policy.vectors.v1", Now: 1800000000, MaximumCount: 64, MaximumBytes: 4 << 20}
	for _, v := range []vector{{Name: "closed", Issued: 1800000000}, {Name: "default", Issued: 1800000000, Count: 32, Bytes: 2 << 20}, {Name: "maximum", Issued: 1800000300, Count: 64, Bytes: 4 << 20}} {
		v.Hex = hex.EncodeToString((agentpacketrelay.MailboxPolicy{IssuedAt: v.Issued, StrangerCount: v.Count, StrangerBytes: v.Bytes}).Encode())
		out.Vectors = append(out.Vectors, v)
	}
	for _, v := range []vector{{Name: "trailing", Issued: 1800000000, Count: 32, Bytes: 2 << 20}, {Name: "truncated", Issued: 1800000000, Count: 32, Bytes: 2 << 20}, {Name: "domain", Issued: 1800000000, Count: 32, Bytes: 2 << 20}, {Name: "future", Issued: 1800000301}, {Name: "overflow-time", Issued: ^uint64(0)}, {Name: "count", Issued: 1800000000, Count: 65}, {Name: "bytes", Issued: 1800000000, Bytes: (4 << 20) + 1}} {
		raw := (agentpacketrelay.MailboxPolicy{IssuedAt: v.Issued, StrangerCount: v.Count, StrangerBytes: v.Bytes}).Encode()
		switch v.Name {
		case "trailing":
			raw = append(raw, 0)
		case "truncated":
			raw = raw[:len(raw)-1]
		case "domain":
			raw[0] ^= 1
		}
		v.Hex = hex.EncodeToString(raw)
		out.Negative = append(out.Negative, v)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "policy vector encoding failed")
		os.Exit(1)
	}
}
