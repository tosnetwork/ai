package toschain

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestEndpointOutageIsNotIntegrityFailure(t *testing.T) {
	for _, kind := range []string{"network", "integrity", "mixed", "split"} {
		t.Run(kind, func(t *testing.T) {
			nodes := []*rpcNode{{}, {}, {}}
			var n atomic.Int32
			_, _, err := quorumRead(context.Background(), nodes, 2, func(context.Context, *rpcNode) (int, error) {
				number := n.Add(1)
				switch kind {
				case "network":
					return 0, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}
				case "integrity":
					return 0, errors.New("malformed response")
				case "mixed":
					if number == 1 {
						return 0, errors.New("corrupt proof")
					}
					return 0, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}
				default:
					return int(number), nil
				}
			})
			if err == nil || errors.Is(err, ErrEndpointsUnavailable) != (kind == "network") {
				t.Fatal(kind, err)
			}
		})
	}
}
func TestCheckNetworkGenesisUsesEndpointQuorum(t *testing.T) {
	root := make([]byte, 32)
	root[0] = 1
	file := make([]byte, 32)
	file[0] = 2
	for _, kind := range []string{"same", "root", "file", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			urls := make([]string, 3)
			for i := range urls {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var call struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
					}
					if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
						t.Error(err)
						return
					}
					if call.Method != "getMasterchainInfo" {
						t.Error(call.Method)
					}
					rh, fh := base64.StdEncoding.EncodeToString(root), base64.StdEncoding.EncodeToString(file)
					if kind == "root" {
						rh = base64.StdEncoding.EncodeToString(file)
					}
					if kind == "file" {
						fh = base64.StdEncoding.EncodeToString(root)
					}
					if kind == "malformed" {
						rh = "bad"
					}
					if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": map[string]any{"@type": "blocks.masterchainInfo", "init": map[string]any{"root_hash": rh, "file_hash": fh}}}); err != nil {
						t.Error(err)
					}
				}))
				t.Cleanup(server.Close)
				urls[i] = server.URL
			}
			a, err := New(Config{Network: "tos:global-id:3", Endpoints: urls, Quorum: 2})
			if err != nil {
				t.Fatal(err)
			}
			err = a.CheckNetworkGenesis(context.Background(), "sha256:"+hex.EncodeToString(root), "sha256:"+hex.EncodeToString(file))
			if (err == nil) != (kind == "same") {
				t.Fatal(kind, err)
			}
			if kind != "same" && errors.Is(err, ErrEndpointsUnavailable) {
				t.Fatal("integrity became unavailability", err)
			}
		})
	}
}
