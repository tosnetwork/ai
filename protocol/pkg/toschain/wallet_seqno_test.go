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

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// seqnoServer answers the wallet seqno getter with stack at checkpoint 42.
func seqnoServer(t *testing.T, wallet string, stack []any) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Address string `json:"address"`
				Method  string `json:"method"`
				Seqno   uint64 `json:"seqno"`
			} `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil || call.Method != "runGetMethod" ||
			call.Params.Method != "seqno" || call.Params.Address != wallet || call.Params.Seqno != 42 {
			http.Error(response, "unexpected call", http.StatusBadRequest)
			return
		}
		block := map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": "8000000000000000", "seqno": 42,
			"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa1}, 32)),
			"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xf1}, 32))}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
			"result": map[string]any{"@type": "smc.runResult", "exit_code": 0, "block_id": block, "stack": stack}})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestWalletSeqnoIsTheGetterNumberAtTheCheckpoint(t *testing.T) {
	wallet := "0:" + strings.Repeat("21", 32)
	serve := func(stack []any) *ServiceActorSession {
		return testSession(t, seqnoServer(t, wallet, stack), seqnoServer(t, wallet, stack), seqnoServer(t, wallet, stack))
	}
	seqno, err := serve([]any{[]any{"num", "7"}}).WalletSeqno(context.Background(), wallet)
	if err != nil || seqno != 7 {
		t.Fatalf("seqno %d %v", seqno, err)
	}
	if seqno, err := serve([]any{[]any{"num", "4294967295"}}).WalletSeqno(context.Background(), wallet); err != nil || seqno != 1<<32-1 {
		t.Fatalf("the largest seqno: %d %v", seqno, err)
	}
	for name, stack := range map[string][]any{
		"over 32 bits": {[]any{"num", "4294967296"}},
		"two entries":  {[]any{"num", "1"}, []any{"num", "2"}},
		"not a number": {[]any{"null"}},
		"empty":        {},
	} {
		if _, err := serve(stack).WalletSeqno(context.Background(), wallet); err == nil {
			t.Errorf("%s was accepted as a seqno", name)
		}
	}
	if _, err := serve([]any{[]any{"num", "7"}}).WalletSeqno(context.Background(), "not an address"); err == nil {
		t.Error("an invalid wallet address was read")
	}
}

func TestInboundQueryIDOfEveryTransactionKind(t *testing.T) {
	body := func(c *cell.Cell) string { return base64.StdEncoding.EncodeToString(c.ToBOC()) }
	lifecycle := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorClaimRefundOpcode, 32).MustStoreUInt(41, 64).EndCell()
	cases := map[string]struct {
		transaction ActorTransaction
		query       uint64
		known       bool
	}{
		"successful lifecycle": {ActorTransaction{Kind: ActorTxExpire, QueryID: 9}, 9, true},
		"successful call":      {ActorTransaction{Kind: ActorTxCall, QueryID: 3, Call: &ActorCallBody{QueryID: 3}}, 3, true},
		"failed call":          {ActorTransaction{Kind: ActorTxFailed, Call: &ActorCallBody{QueryID: 5}}, 5, true},
		"failed lifecycle":     {ActorTransaction{Kind: ActorTxFailed, BodyBOC: body(lifecycle)}, 41, true},
		"failed, opcode only": {ActorTransaction{Kind: ActorTxFailed,
			BodyBOC: body(cell.BeginCell().MustStoreUInt(nativecore.ServiceActorExpireOpcode, 32).EndCell())}, 0, false},
		"failed, short body": {ActorTransaction{Kind: ActorTxFailed, BodyBOC: body(cell.BeginCell().MustStoreUInt(7, 3).EndCell())}, 0, false},
		"failed, no body":    {ActorTransaction{Kind: ActorTxFailed, BodyBOC: "!"}, 0, false},
		"transfer":           {ActorTransaction{Kind: ActorTxTransfer}, 0, true},
		"bounce":             {ActorTransaction{Kind: ActorTxBounced}, 0, true},
	}
	for name, want := range cases {
		query, known := want.transaction.InboundQueryID()
		if query != want.query || known != want.known {
			t.Errorf("%s: query %d known %v, want %d %v", name, query, known, want.query, want.known)
		}
	}
}
