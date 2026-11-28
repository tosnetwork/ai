package agentpacketrelay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestV2FrozenDirectoryVectors(t *testing.T) {
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
	var corpus struct {
		Schema   string     `json:"schema"`
		Now      uint64     `json:"now"`
		Positive []vector   `json:"positive"`
		Negative []negative `json:"negative"`
	}
	raw, err := os.ReadFile("../../../spec/test-vectors/relay-directory-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "tos.service.relay-directory.vectors.v2" || len(corpus.Positive) != 4 || len(corpus.Negative) != 11 {
		t.Fatal("incomplete corpus")
	}
	kinds := map[string]string{}
	for _, v := range corpus.Positive {
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		var encoded []byte
		if v.Kind == "revocation" {
			entries, e := DecodeRevocations(raw)
			err = e
			if e == nil {
				encoded, err = EncodeRevocations(entries)
			}
		} else {
			entries, e := DecodeHintIndex(raw)
			err = e
			if e == nil {
				encoded, err = EncodeHintIndex(entries)
			}
		}
		if err != nil || !bytes.Equal(raw, encoded) {
			t.Fatal(v.Name, err)
		}
		kinds[v.Name] = v.Kind
	}
	for _, v := range corpus.Negative {
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			t.Fatal(err)
		}
		if kinds[v.Base] == "revocation" {
			_, err = DecodeRevocations(raw)
		} else {
			_, err = DecodeHintIndex(raw)
		}
		if err == nil {
			t.Fatal("negative accepted", v.Name)
		}
	}
}
func FuzzV2DirectoryDecoders(f *testing.F) {
	f.Add([]byte(hintIndexDomain + "\x00"))
	raw, err := EncodeRevocations([]Revocation{{Until: 1800000000}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxRevocationRequestBytes {
			return
		}
		if entries, err := DecodeRevocations(raw); err == nil {
			encoded, err := EncodeRevocations(entries)
			if err != nil || !bytes.Equal(raw, encoded) {
				t.Fatal("revocation noncanonical")
			}
		}
		if entries, err := DecodeHintIndex(raw); err == nil {
			encoded, err := EncodeHintIndex(entries)
			if err != nil || !bytes.Equal(raw, encoded) {
				t.Fatal("index noncanonical")
			}
		}
	})
}
