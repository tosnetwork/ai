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
		Schema  string   `json:"schema"`
		Vectors []vector `json:"vectors"`
	}{Schema: "tos.service.relay-mailbox-policy.vectors.v1"}
	for _, v := range []vector{{Name: "closed", Issued: 1800000000}, {Name: "default", Issued: 1800000000, Count: 32, Bytes: 2 << 20}, {Name: "maximum", Issued: 1800000300, Count: 64, Bytes: 4 << 20}} {
		v.Hex = hex.EncodeToString((agentpacketrelay.MailboxPolicy{IssuedAt: v.Issued, StrangerCount: v.Count, StrangerBytes: v.Bytes}).Encode())
		out.Vectors = append(out.Vectors, v)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "policy vector encoding failed")
		os.Exit(1)
	}
}
