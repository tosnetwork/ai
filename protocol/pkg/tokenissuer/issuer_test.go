package tokenissuer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	policy                                                         Policy
	blacklisted, paused, deprecated                                bool
	rate, maximum                                                  uint64
	stale, wrongChain, wrongHash, wrongCode, failed, malformedBool bool
	ambiguousRPC                                                   bool
	calls                                                          int
	after                                                          func()
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	code := []byte{0x60, 0x00}
	hash := sha256.Sum256(code)
	f := &fixture{policy: Policy{ChainID: 1, Token: "0x" + strings.Repeat("12", 20), Bridge: "0x" + strings.Repeat("34", 20), CodeSHA256: hex.EncodeToString(hash[:]), Profile: Legacy}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		f.calls++
		var value any
		switch request.Method {
		case "eth_chainId":
			value = "0x1"
			if f.wrongChain {
				value = "0x2"
			}
		case "eth_getBlockByNumber":
			stamp := uint64(1800000000)
			if f.stale {
				stamp -= MaxAgeSeconds + 1
			}
			h := "0x" + strings.Repeat("ab", 32)
			if f.wrongHash && string(request.Params[0]) != "\"finalized\"" {
				h = "0x" + strings.Repeat("cd", 32)
			}
			value = map[string]any{"number": "0x7", "hash": h, "timestamp": fmt.Sprintf("0x%x", stamp)}
		case "eth_getCode":
			f.checkPoint(t, request.Params[1])
			value = "0x6000"
			if f.wrongCode {
				value = "0x6001"
			}
		case "eth_call":
			f.checkPoint(t, request.Params[1])
			var call map[string]string
			if err := json.Unmarshal(request.Params[0], &call); err != nil {
				t.Error(err)
				return
			}
			if call["to"] != f.policy.Token {
				t.Error("wrong token")
			}
			selector := call["data"][:10]
			n := uint64(0)
			switch selector {
			case "0xe47d6060", "0xfe575a87":
				if f.blacklisted {
					n = 1
				}
				if f.malformedBool {
					n = 2
				}
			case "0x5c975abb":
				if f.paused {
					n = 1
				}
			case "0x0e136b19":
				if f.deprecated {
					n = 1
				}
			case "0xdd644f72":
				n = f.rate
			case "0x35390714":
				n = f.maximum
			default:
				t.Errorf("unrecognized selector %s", selector)
			}
			value = fmt.Sprintf("0x%064x", n)
		default:
			t.Errorf("unapproved method %s", request.Method)
		}
		if f.after != nil {
			f.after()
		}
		answer := map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": value}
		if f.failed || f.ambiguousRPC {
			answer["error"] = map[string]any{"code": -32000, "message": "fixture refused"}
			if f.failed {
				delete(answer, "result")
			}
		}
		if err := json.NewEncoder(w).Encode(answer); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	f.policy.RPCURL = server.URL
	return f
}
func (f *fixture) checkPoint(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var point struct {
		BlockHash string `json:"blockHash"`
		Canonical bool   `json:"requireCanonical"`
	}
	if err := json.Unmarshal(raw, &point); err != nil || point.BlockHash != "0x"+strings.Repeat("ab", 32) || !point.Canonical {
		t.Errorf("un-pinned read: %s", raw)
	}
}
func (f *fixture) read(t *testing.T) (Snapshot, error) {
	t.Helper()
	reader, err := NewReader(f.policy, func() time.Time { return time.Unix(1800000000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	return reader.Read(context.Background(), f.policy.Bridge)
}
func TestFinalizedIssuerReadAndReceivedAmount(t *testing.T) {
	for _, profile := range []string{Legacy, Standard} {
		t.Run(profile, func(t *testing.T) {
			f := newFixture(t)
			f.policy.Profile = profile
			s, err := f.read(t)
			if err != nil {
				t.Fatal(err)
			}
			if s.BlockNumber != "0x7" || s.BlockTime != 1800000000 || s.Token != f.policy.Token {
				t.Fatal("wrong observation")
			}
			amount := big.NewInt(100000000)
			received, fee, err := s.Received(amount)
			if err != nil || received.Cmp(amount) != 0 || fee.Sign() != 0 {
				t.Fatalf("zero fee: %v", err)
			}
			if profile == Legacy {
				f.rate = 19
				f.maximum = 1000000
				s, err = f.read(t)
				if err != nil {
					t.Fatal(err)
				}
				received, fee, err = s.Received(amount)
				if err != nil || received.String() != "99810000" || fee.String() != "190000" {
					t.Fatalf("received: %v %v %v", received, fee, err)
				}
				received, fee, err = s.Received(big.NewInt(3000000000))
				if err != nil || received.String() != "2999000000" || fee.String() != "1000000" {
					t.Fatal("fee cap")
				}
			}
		})
	}
}
func TestIssuerRefusals(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*fixture)
		message string
	}{
		{"blacklisted", func(f *fixture) { f.blacklisted = true }, "blacklisted"},
		{"paused", func(f *fixture) { f.paused = true }, "paused"},
		{"deprecated", func(f *fixture) { f.deprecated = true }, "deprecated"},
		{"stale", func(f *fixture) { f.stale = true }, "stale"},
		{"chain", func(f *fixture) { f.wrongChain = true }, "chain differs"},
		{"reorg", func(f *fixture) { f.wrongHash = true }, "checkpoint changed"},
		{"code", func(f *fixture) { f.wrongCode = true }, "code differs"},
		{"failed", func(f *fixture) { f.failed = true }, "failed issuer RPC"},
		{"error-and-result", func(f *fixture) { f.ambiguousRPC = true }, "failed issuer RPC"},
		{"boolean", func(f *fixture) { f.malformedBool = true }, "noncanonical"},
		{"fee-rate", func(f *fixture) { f.rate = 10000 }, "fee rate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.read(t); err != nil {
				t.Fatal(err)
			}
			tc.change(f)
			if _, err := f.read(t); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("refusal missing: %v", err)
			}
		})
	}
}
func TestIssuerReadRechecksTimeAfterRPC(t *testing.T) {
	f := newFixture(t)
	clock := time.Unix(1800000000, 0)
	r, err := NewReader(f.policy, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	f.after = func() {
		if f.calls == 9 {
			clock = clock.Add((MaxAgeSeconds + 1) * time.Second)
		}
	}
	if _, err = r.Read(context.Background(), f.policy.Bridge); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("late read accepted: %v", err)
	}
}
func TestIssuerPolicyRefusesUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:1", "http://example.invalid", "https://u:p@example.invalid", "https://example.invalid?credential=x", "file:///issuer", "ws://127.0.0.1:1"} {
		f := newFixture(t)
		f.policy.RPCURL = endpoint
		if _, err := NewReader(f.policy, nil); err == nil {
			t.Fatalf("endpoint accepted %s", endpoint)
		}
	}
}
