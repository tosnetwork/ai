// Command relay-directory-vectors deliberately emits the frozen wire corpus.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type vector struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
	Hex   string `json:"hex"`
}
type negative struct {
	Name     string `json:"name"`
	Base     string `json:"base"`
	Mutation string `json:"mutation"`
	Hex      string `json:"hex"`
}

func build() ([]byte, error) {
	out := struct {
		Schema   string     `json:"schema"`
		Now      uint64     `json:"now"`
		Positive []vector   `json:"positive"`
		Negative []negative `json:"negative"`
	}{Schema: "tos.service.relay-directory.vectors.v2", Now: 1800000000}
	rawByName := map[string][]byte{}
	for _, v := range []vector{{Name: "revocation-single", Kind: "revocation", Count: 1}, {Name: "revocation-maximum", Kind: "revocation", Count: 32}, {Name: "index-empty", Kind: "index", Count: 0}, {Name: "index-maximum", Kind: "index", Count: 4}} {
		var raw []byte
		var err error
		if v.Kind == "revocation" {
			entries := make([]agentpacketrelay.Revocation, v.Count)
			for i := range entries {
				entries[i] = agentpacketrelay.Revocation{Chain: sha256.Sum256([]byte(fmt.Sprint("revocation:", i))), Until: out.Now + uint64(i) + 1}
			}
			raw, err = agentpacketrelay.EncodeRevocations(entries)
		} else {
			entries := make([]agentpacketrelay.HintIndexEntry, v.Count)
			for i := range entries {
				entries[i] = agentpacketrelay.HintIndexEntry{Digest: sha256.Sum256([]byte(fmt.Sprint("hint-index:", i))), IssuedAt: out.Now + uint64(i), Length: agenttransport.MaxHintRecordSize}
			}
			sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].Digest[:], entries[j].Digest[:]) < 0 })
			raw, err = agentpacketrelay.EncodeHintIndex(entries)
		}
		if err != nil {
			return nil, err
		}
		v.Hex = hex.EncodeToString(raw)
		rawByName[v.Name] = raw
		out.Positive = append(out.Positive, v)
	}
	for _, base := range []string{"revocation-maximum", "index-maximum"} {
		for _, mutation := range []string{"trailing", "truncated", "domain", "count"} {
			raw := bytes.Clone(rawByName[base])
			switch mutation {
			case "trailing":
				raw = append(raw, 0)
			case "truncated":
				raw = raw[:len(raw)-1]
			case "domain":
				raw[0] ^= 1
			case "count":
				if base == "revocation-maximum" {
					raw[len(raw)-32*40-1] = 33
				} else {
					raw[len(raw)-4*44-1] = 5
				}
			}
			out.Negative = append(out.Negative, negative{base + "-" + mutation, base, mutation, hex.EncodeToString(raw)})
		}
	}
	raw := bytes.Clone(rawByName["index-maximum"])
	at := len(raw) - 4*44
	copy(raw[at+44:at+44+32], raw[at:at+32])
	out.Negative = append(out.Negative, negative{"index-duplicate", "index-maximum", "duplicate", hex.EncodeToString(raw)})
	raw = bytes.Clone(rawByName["index-maximum"])
	at = len(raw) - 4*44
	left := bytes.Clone(raw[at : at+44])
	copy(raw[at:at+44], raw[at+44:at+88])
	copy(raw[at+44:at+88], left)
	out.Negative = append(out.Negative, negative{"index-order", "index-maximum", "order", hex.EncodeToString(raw)})
	raw = bytes.Clone(rawByName["index-maximum"])
	at = len(raw) - 4*44 + 40
	for i := range 4 {
		raw[at+i] = 0
	}
	out.Negative = append(out.Negative, negative{"index-zero-length", "index-maximum", "zero-length", hex.EncodeToString(raw)})
	return json.MarshalIndent(out, "", "  ")
}
func main() {
	raw, err := build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "directory vectors refused")
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(append(raw, '\n')); err != nil {
		os.Exit(1)
	}
}
