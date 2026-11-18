package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
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

func externalIn(t *testing.T, body *cell.Cell) *tlb.Message {
	return &tlb.Message{MsgType: tlb.MsgTypeExternalIn, Msg: &tlb.ExternalMessage{SrcAddr: address.NewAddressNone(),
		DstAddr: rawAddress(t, testActor), ImportFee: tlb.ZeroCoins, Body: body}}
}

func lifecycleOut(t *testing.T, destination string, query uint64) *tlb.Message {
	return &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{IHRDisabled: true, Bounce: true,
		SrcAddr: rawAddress(t, testActor), DstAddr: rawAddress(t, destination), Amount: tlb.FromNanoTONU(200_000_000),
		IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins,
		Body: cell.BeginCell().MustStoreUInt(nativecore.ServiceActorExpireOpcode, 32).MustStoreUInt(query, 64).EndCell()}}
}

// The wallet history since an anchor names each transaction's external
// message hash and its internal out-messages with their query IDs, and a
// walk that does not meet its anchor is refused.
func TestWalletHistoryNamesExternalMessagesAndTheirOutMessages(t *testing.T) {
	ours := cell.BeginCell().MustStoreUInt(5, 32).EndCell()
	other := cell.BeginCell().MustStoreUInt(6, 32).EndCell()
	anchor := buildTransaction(t, 10, 1000, nil, internalIn(t, testBuyer, cell.BeginCell().EndCell()), true, 0)
	first := buildTransaction(t, 11, 1001, &anchor, externalIn(t, ours), true, 0, lifecycleOut(t, testBuyer, 42),
		payout(t, testOwner, 1))
	second := buildTransaction(t, 12, 1002, &first, externalIn(t, other), true, 0)
	history := []tlb.Transaction{second, first, anchor}
	root := bytes.Repeat([]byte{0xa1}, 32)
	session := testSession(t, sessionServer(t, history, 42, root, root), sessionServer(t, history, 42, root, root),
		sessionServer(t, history, 42, root, root))
	ctx := context.Background()
	last, err := session.WalletLastTransaction(ctx, testActor)
	if err != nil || last.LT != 12 || last.Hash != hex.EncodeToString(second.Hash) {
		t.Fatalf("last transaction %+v %v", last, err)
	}
	walk, err := session.WalletHistory(ctx, testActor, ActorTxID{LT: anchor.LT, Hash: hex.EncodeToString(anchor.Hash)})
	if err != nil || len(walk.Transactions) != 2 {
		t.Fatalf("wallet history %+v %v", walk, err)
	}
	oursMessage, _ := externalIn(t, ours).ToCell()
	if got := walk.Transactions[1]; got.LT != 11 || got.ExternalMessageHash != hex.EncodeToString(oursMessage.Hash()) ||
		len(got.Out) != 2 || got.Out[0] != (WalletOutMessage{Destination: testBuyer, QueryID: 42, Known: true}) ||
		got.Out[1] != (WalletOutMessage{Destination: testOwner}) {
		t.Fatalf("reduced transaction %+v", got)
	}
	if walk.Transactions[0].ExternalMessageHash == walk.Transactions[1].ExternalMessageHash {
		t.Fatal("two different external messages share a hash")
	}
	if _, err := session.WalletHistory(ctx, testActor, ActorTxID{LT: 9, Hash: strings.Repeat("ab", 32)}); !errors.Is(err, ErrHistoryAnchorMissing) {
		t.Fatalf("a walk without its anchor: %v", err)
	}
	if _, err := session.WalletHistory(ctx, testActor, ActorTxID{}); err == nil {
		t.Fatal("a walk without an anchor was accepted")
	}
	// An internal inbound message has no external hash.
	anchorCell, err := anchor.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	if reduced, err := reduceWalletTransaction(anchor, anchorCell); err != nil || reduced.ExternalMessageHash != "" {
		t.Fatalf("an internal inbound message got an external hash: %+v %v", reduced, err)
	}
}
