package toschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenFrozenLog(t *testing.T, name string) *cell.Cell {
	t.Helper()
	bytes, err := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SAT1     []string            `json:"sat1"`
		Funding  []string            `json:"saf1_refused_amount"`
		Outcomes map[string][]string `json:"sao1"`
	}
	if err = json.Unmarshal(bytes, &fixture); err != nil {
		t.Fatal(err)
	}
	var values []string
	switch name {
	case "sat1":
		values = fixture.SAT1
	case "saf1":
		values = fixture.Funding
	default:
		values = fixture.Outcomes[name]
	}
	if len(values) != 1 {
		t.Fatalf("missing frozen log %s", name)
	}
	root, err := decodeCellBOC(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func decodeTokenTestTX(t *testing.T, tx tlb.Transaction) TokenActorTransaction {
	t.Helper()
	root, err := tx.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	result, err := DecodeTokenActorTransaction(testActor, root.ToBOC())
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func TestTokenBouncedOutcomeIsReadFromSuccessfulHandler(t *testing.T) {
	log := tokenFrozenLog(t, "kind_1_bounced_at_s")
	decoded, err := nativecore.DecodeServiceActorTokenOutcomeLog(log)
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreUInt(0xffffffff, 32).MustStoreUInt(0x52545231, 32).MustStoreUInt(decoded.PayoutID, 64).MustStoreBigCoins(decoded.Amount).EndCell()
	in := internalIn(t, testBuyer, body)
	in.AsInternal().Bounced = true
	tx := buildTransaction(t, 10, 1000, nil, in, true, 0, externalOut(t, testActor, nil, log))
	result := decodeTokenTestTX(t, tx)
	if !result.Bounced || !result.TookEffect || result.Kind != ActorTxBounced || len(result.Logs) != 1 || result.Logs[0].Outcome == nil || result.Logs[0].Outcome.Outcome != 2 || len(result.LogBodyBOCs) != 1 {
		t.Fatalf("bounced outcome hidden: %+v", result)
	}
	if result.QueryID != decoded.PayoutID || result.Opcode != 0x52545231 {
		t.Fatal("bounced reported-transfer identity missing")
	}
	failed := tx
	failed.Description = tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: false, GasFees: tlb.ZeroCoins, Details: tlb.ComputePhaseVMDetails{GasUsed: zeroBig(), GasLimit: zeroBig(), ExitCode: 9, VMInitStateHash: zeroHash32, VMFinalStateHash: zeroHash32}}}, Aborted: true}
	result = decodeTokenTestTX(t, failed)
	if result.TookEffect || len(result.Logs) != 0 {
		t.Fatal("failed handler claimed an outcome")
	}
}

func TestTokenMalformedFundingStillCarriesItsRefusalEvidence(t *testing.T) {
	log := tokenFrozenLog(t, "saf1")
	funding, err := nativecore.DecodeServiceActorTokenFundingLog(log)
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreUInt(0x7362d09c, 32).MustStoreUInt(funding.QueryID, 64).MustStoreBigCoins(funding.Amount).MustStoreAddr(rawAddress(t, funding.From.Text())).MustStoreBoolBit(false).MustStoreUInt(0, 8).EndCell()
	tx := buildTransaction(t, 10, 1000, nil, internalIn(t, testBuyer, body), true, 0, externalOut(t, testActor, nil, log))
	result := decodeTokenTestTX(t, tx)
	if result.Kind != "funding_refused" || result.Notification == nil || result.Notification.Payload != nil || len(result.Logs) != 1 || result.Logs[0].Funding == nil || result.Logs[0].Funding.QueryID != funding.QueryID {
		t.Fatalf("refused funding hidden: %+v", result)
	}
	snapshot := tokenFrozenLog(t, "sat1")
	tx = buildTransaction(t, 11, 1000, &tx, internalIn(t, testBuyer, body), true, 0, externalOut(t, testActor, nil, snapshot))
	root, err := tx.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeTokenActorTransaction(testActor, root.ToBOC()); err == nil {
		t.Fatal("malformed payload was admitted from SAT1")
	}
}
func TestTokenStoredMessageHashesAreNotReencoded(t *testing.T) {
	body := cell.BeginCell().MustStoreUInt(0, 32).EndCell()
	in := internalIn(t, testBuyer, body)
	tx := buildTransaction(t, 10, 1000, nil, in, true, 0, payout(t, testBuyer, 1))
	root, err := tx.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	result, err := reduceTokenWalletTransaction(tx, root)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := storedInboundMessage(root)
	if err != nil {
		t.Fatal(err)
	}
	if result.InboundMessageHash != hex.EncodeToString(stored.Hash()) || len(result.Outputs) != 1 {
		t.Fatal("missing exact stored message hashes")
	}
	io := root.MustPeekRef(0).MustBeginParse()
	io.MustLoadBoolBit()
	io.MustLoadRef()
	dict := io.MustLoadDict(15)
	entries, err := dict.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	message := entries[0].Value.MustLoadRef()
	encoded, err := message.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	if result.Outputs[0].Hash != hex.EncodeToString(encoded.Hash()) {
		t.Fatal("outbound message was reencoded")
	}
}

func TestTokenHistoricalViewPinsHeaderWithoutAdvancingLiveFences(t *testing.T) {
	history := linearHistory(t, 3)
	root := bytes.Repeat([]byte{8}, 32)
	serve := func() string { server := tokenHeaderServer(t, history, root); return server }
	current := testSession(t, serve(), serve(), serve())
	current.chainTime = time.Unix(2000, 0)
	current.reader.highWater = 42
	older, err := current.TokenHistoricalView(context.Background(), 40)
	if err != nil {
		t.Fatal(err)
	}
	if older.Checkpoint() != 40 || older.ChainTime().Unix() != 1000 || current.reader.highWater != 42 {
		t.Fatal("archive view changed the live checkpoint")
	}
	if _, err = current.TokenHistoricalView(context.Background(), 43); err == nil {
		t.Fatal("unfinalized archive view accepted")
	}
	if _, err = older.History(context.Background(), testActor, nil); err != nil {
		t.Fatal(err)
	}
}

func zeroBig() *big.Int { return new(big.Int) }
func tokenHeaderServer(t *testing.T, history []tlb.Transaction, root []byte) string {
	t.Helper()
	node := historyServer(t, history, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			ID     uint64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			t.Error(err)
			return
		}
		var params struct {
			Seqno    uint64 `json:"seqno"`
			Address  string `json:"address"`
			Limit    int    `json:"limit"`
			LT, Hash string
		}
		if err := json.Unmarshal(call.Params, &params); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch call.Method {
		case "getBlockHeader":
			result = map[string]any{"@type": "blocks.header", "id": tokenTestBlock(root, params.Seqno), "gen_utime": 1000, "global_id": 3, "version": 0, "after_merge": false, "before_split": false, "after_split": false, "want_merge": false, "want_split": false, "validator_list_hash_short": 1, "catchain_seqno": 1, "min_ref_mc_seqno": 1, "is_key_block": false, "prev_key_block_seqno": 0, "start_lt": "1", "end_lt": "2", "prev_blocks": []any{}}
		case "getAddressInformation":
			result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "block_id": tokenTestBlock(root, params.Seqno), "last_transaction_id": headID(history[0])}
		case "getTransactions":
			var page []rawTransaction
			if err := node.client.Call(r.Context(), call.Method, params, &page); err != nil {
				t.Error(err)
				return
			}
			result = page
		default:
			t.Error("unexpected historical method", call.Method)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestForeignAssetNotificationStaysANotificationWithoutAdmission(t *testing.T) {
	walletCode := cell.BeginCell().MustStoreUInt(2, 8).EndCell()
	var walletHash [32]byte
	copy(walletHash[:], walletCode.Hash())
	master, err := nativecore.StandardAddress("0:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCode: walletCode, WalletCodeHash: walletHash, BridgeConfigParam: 81}
	own, err := nativecore.DeriveServiceActorTokenWallet(testActor, route)
	if err != nil {
		t.Fatal(err)
	}
	route.Master, err = nativecore.StandardAddress("0:" + strings.Repeat("ac", 32))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := nativecore.DeriveServiceActorTokenWallet(testActor, route)
	if err != nil {
		t.Fatal(err)
	}
	if own == foreign {
		t.Fatal("two masters derive the same actor wallet")
	}
	payload, err := nativecore.BuildServiceActorTokenCallPayload([32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreUInt(0x7362d09c, 32).MustStoreUInt(3, 64).MustStoreCoins(1000000).MustStoreAddr(rawAddress(t, testBuyer)).MustStoreBoolBit(true).MustStoreRef(payload).EndCell()
	// The foreign-notification path finishes normally but emits no SAT1 or SAF1.
	tx := buildTransaction(t, 10, 1000, nil, internalIn(t, foreign, body), true, 0)
	decoded := decodeTokenTestTX(t, tx)
	if !decoded.TookEffect || decoded.Kind != "notification" || decoded.Sender != foreign || decoded.Sender == own || decoded.Notification == nil || decoded.Notification.Payload == nil || len(decoded.Logs) != 0 {
		t.Fatalf("foreign notification relabelled as admission: %+v", decoded)
	}
}
