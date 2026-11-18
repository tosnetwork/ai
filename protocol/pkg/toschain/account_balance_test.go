package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// accountServer answers getAddressInformation for account at checkpoint 42
// with the given state and balance; block overrides the reported block.
func accountServer(t *testing.T, account, state, balance string, block map[string]any) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Address string `json:"address"`
				Seqno   uint64 `json:"seqno"`
			} `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil || call.Method != "getAddressInformation" ||
			call.Params.Address != account || call.Params.Seqno != 42 {
			http.Error(response, "unexpected call", http.StatusBadRequest)
			return
		}
		id := map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": "8000000000000000", "seqno": 42,
			"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 32)),
			"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xf1}, 32))}
		for key, value := range block {
			id[key] = value
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
			"result": map[string]any{"@type": "raw.fullAccountState", "block_id": id, "state": state, "balance": balance}})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestAccountIsTheQuorumStateAndBalanceAtTheCheckpoint(t *testing.T) {
	account := "0:" + strings.Repeat("21", 32)
	serve := func(state, balance string, block map[string]any) *ServiceActorSession {
		return testSession(t, accountServer(t, account, state, balance, block),
			accountServer(t, account, state, balance, block), accountServer(t, account, state, balance, block))
	}
	ctx := context.Background()
	value, err := serve("uninitialized", "2500000000", nil).Account(ctx, account)
	if err != nil || value.State != "uninitialized" || value.BalanceNano != 2_500_000_000 || value.Active() {
		t.Fatalf("a funded undeployed wallet: %+v %v", value, err)
	}
	value, err = serve("active", "7", nil).Account(ctx, account)
	if err != nil || !value.Active() || value.BalanceNano != 7 {
		t.Fatalf("an active wallet: %+v %v", value, err)
	}
	session := serve("active", "7", nil)
	if _, err := session.Account(ctx, account); err != nil {
		t.Fatal(err)
	}
	if root, file := session.BlockHashes(); root == "" || file == "" {
		t.Fatal("the read did not pin the session's block")
	}
	for name, server := range map[string]*ServiceActorSession{
		"another checkpoint":   serve("active", "7", map[string]any{"seqno": 43}),
		"a shard block":        serve("active", "7", map[string]any{"workchain": 0}),
		"another block type":   serve("active", "7", map[string]any{"@type": "ton.blockIdExt"}),
		"an unknown state":     serve("nonexist", "7", nil),
		"a signed balance":     serve("active", "+7", nil),
		"a padded balance":     serve("active", "07", nil),
		"a negative balance":   serve("active", "-1", nil),
		"a bad block hash":     serve("active", "7", map[string]any{"root_hash": "AA=="}),
		"an overflown balance": serve("active", "18446744073709551616", nil),
	} {
		if _, err := server.Account(ctx, account); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Endpoints that answer for a masterchain account are never asked.
	master := "-1:" + strings.Repeat("21", 32)
	masterSession := testSession(t, accountServer(t, master, "active", "7", nil),
		accountServer(t, master, "active", "7", nil), accountServer(t, master, "active", "7", nil))
	if _, err := masterSession.Account(ctx, master); err == nil {
		t.Error("a masterchain account was read")
	}
	if _, err := serve("active", "7", nil).Account(ctx, "not an address"); err == nil {
		t.Error("an invalid address was read")
	}
}
