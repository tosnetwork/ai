package servicebridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// prunedAnchorWithdrawChain serves one finalized checkpoint at which the
// actor's last transaction is the executed withdrawal, while the node has
// pruned the withdrawal's anchor: every read of it fails with "lt not in db".
func prunedAnchorWithdrawChain(t *testing.T, actor string, withdrawal tlb.Transaction, root, file []byte) []string {
	t.Helper()
	block := map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": "8000000000000000", "seqno": 1000,
		"root_hash": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("r", 32))),
		"file_hash": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("f", 32)))}
	encoded, err := withdrawal.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	id := map[string]string{"@type": "internal.transactionId", "lt": strconv.FormatUint(withdrawal.LT, 10),
		"hash": base64.StdEncoding.EncodeToString(encoded.Hash())}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
			Params struct {
				Address string `json:"address"`
				Seqno   uint64 `json:"seqno"`
				LT      string `json:"lt"`
			} `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		now := time.Now().Unix()
		var result any
		switch call.Method {
		case "getConsensusBlock":
			result = map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": 1000, "timestamp": now, "last_block_utime": now}
		case "getMasterchainInfo":
			result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{
				"root_hash": base64.StdEncoding.EncodeToString(root), "file_hash": base64.StdEncoding.EncodeToString(file)}}
		case "getAddressInformation":
			if call.Params.Address != actor || call.Params.Seqno != 1000 {
				t.Error("withdrawal read escaped its actor or checkpoint")
			}
			result = map[string]any{"@type": "raw.fullAccountState", "block_id": block, "state": "active", "last_transaction_id": id}
		case "getTransactions":
			if call.Params.LT != id["lt"] {
				_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
					"error": map[string]any{"code": -32603, "message": "cannot load transaction: lt not in db"}})
				return
			}
			result = []any{map[string]any{"@type": "raw.transaction", "data": base64.StdEncoding.EncodeToString(encoded.ToBOC()),
				"account": strings.TrimPrefix(actor, "0:"), "transaction_id": id}}
		default:
			http.Error(response, "unknown method", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	})
	urls := make([]string, 0, 3)
	for range 3 {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		urls = append(urls, server.URL)
	}
	return urls
}

func prunedAnchorAddress(t *testing.T, raw string) *address.Address {
	t.Helper()
	parsed, err := address.ParseRawAddr(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// The owner withdraws from an idle actor whose last transaction, the
// withdrawal's anchor, has been pruned. The executed withdrawal commits to
// the anchor through its verified predecessor link, so the withdrawal still
// resolves as finalized instead of staying unknown.
func TestWithdrawalResolvesAfterItsAnchorIsPruned(t *testing.T) {
	actor := "0:" + strings.Repeat("4b", 32)
	owner := "0:" + strings.Repeat("22", 32)
	const queryID, amount = 77, 300_000_000
	anchor := toschain.ActorTxID{LT: 10, Hash: strings.Repeat("07", 32)}
	anchorHash, err := hex.DecodeString(anchor.Hash)
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreUInt(nativecore.ServiceActorWithdrawOpcode, 32).MustStoreUInt(queryID, 64).
		MustStoreCoins(amount).EndCell()
	in := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{IHRDisabled: true, Bounce: true,
		SrcAddr: prunedAnchorAddress(t, owner), DstAddr: prunedAnchorAddress(t, actor), Amount: tlb.FromNanoTONU(50_000_000),
		IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins, Body: body}}
	out := &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{IHRDisabled: true,
		SrcAddr: prunedAnchorAddress(t, actor), DstAddr: prunedAnchorAddress(t, owner), Amount: tlb.FromNanoTONU(amount),
		IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins, Body: cell.BeginCell().EndCell()}}
	encodedOut, err := out.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	list := cell.NewDict(15)
	if err := list.SetIntKey(big.NewInt(0), cell.BeginCell().MustStoreRef(encodedOut).EndCell()); err != nil {
		t.Fatal(err)
	}
	account, err := hex.DecodeString(strings.TrimPrefix(actor, "0:"))
	if err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 32)
	withdrawal := tlb.Transaction{AccountAddr: account, LT: 20, PrevTxLT: anchor.LT, PrevTxHash: anchorHash, Now: 2000,
		OutMsgCount: 1, OrigStatus: tlb.AccountStatusActive, EndStatus: tlb.AccountStatusActive,
		TotalFees: tlb.CurrencyCollection{Coins: tlb.ZeroCoins}, StateUpdate: tlb.HashUpdate{OldHash: zero, NewHash: zero},
		Description: tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: true,
			GasFees: tlb.ZeroCoins, Details: tlb.ComputePhaseVMDetails{GasUsed: big.NewInt(0), GasLimit: big.NewInt(0),
				VMInitStateHash: zero, VMFinalStateHash: zero}}}}}
	withdrawal.IO.In = in
	withdrawal.IO.Out = &tlb.MessagesList{List: list}

	root, file := []byte(strings.Repeat("g", 32)), []byte(strings.Repeat("h", 32))
	config := sharedStateConfig(t, &checkpointChain{urls: prunedAnchorWithdrawChain(t, actor, withdrawal, root, file)}, root, file)
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	reader, err := openServiceActorReader(config, networkOf(config), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	session, err := reader.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record := WithdrawalRecord{QueryID: queryID, Actor: actor, Destination: owner, AmountNano: strconv.Itoa(amount),
		Anchor: anchor, State: WithdrawalSubmitted, StartedUnix: time.Now().Unix()}
	resolved, err := resolveWithdrawal(context.Background(), session, record)
	if err != nil {
		t.Fatalf("withdrawal after a pruned anchor stayed unresolved: %v", err)
	}
	if resolved.State != WithdrawalFinalized || resolved.PayoutNano != record.AmountNano || resolved.Checkpoint != 1000 {
		t.Fatalf("withdrawal resolved as %s (%s), not finalized", resolved.State, resolved.Detail)
	}
}
