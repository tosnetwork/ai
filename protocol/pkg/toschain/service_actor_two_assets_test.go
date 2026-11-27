package toschain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// Both test entries use the same slot-81 bridge and releases. Their source
// tokens and derived masters differ. These are fixtures, not deployment pins.
func twoAssetSession(t *testing.T, suspended bool) (*ServiceActorSession, []TokenAssetPin) {
	t.Helper()
	base, basePin, bridgeCode, _, bridgeParam, _ := tokenBridgeFixture(t)
	minterCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	walletCode := cell.BeginCell().MustStoreUInt(2, 8).EndCell()
	bridgeData := cell.BeginCell().MustStoreUInt(9, 64).MustStoreUInt(56, 32).MustStoreUInt(7, 160).MustStoreUInt(1, 32).MustStoreUInt(0, 64).MustStoreUInt(1, 2).MustStoreUInt(0, 2).MustStoreRef(minterCode).MustStoreRef(walletCode).MustStoreRef(cell.BeginCell().MustStoreUInt(0, 64).MustStoreDict(nil).MustStoreDict(nil).MustStoreUInt(0, 32).EndCell()).EndCell()
	records := make([]SettlementAssetV1, 2)
	pins := make([]TokenAssetPin, 2)
	accounts := map[string]*cell.Cell{base.Bridge: bridgeData}
	for i, label := range []string{"local-test-usdc", "local-test-usdt"} {
		record, pin := base, basePin
		record.SourceChainID = 56
		digest := sha256.Sum256([]byte(label))
		copy(record.SourceToken[:], digest[:20])
		var err error
		record.Master, err = DeriveTokenMinterAddress(record, minterCode, walletCode)
		if err != nil {
			t.Fatal(err)
		}
		record.MaxLiabilityPerActor = big.NewInt(int64(1000000 * (i + 1)))
		if suspended && i == 1 {
			record.Status = 2
		}
		pin.Master, pin.SourceChainID, pin.SourceToken, pin.BridgeConfigParam = record.Master, 56, record.SourceToken, 81
		records[i], pins[i] = record, pin
		accounts[record.Master] = tokenMinterFixtureData(t, record, walletCode)
	}
	if pins[0].Master == pins[1].Master {
		t.Fatal("test assets share a master")
	}
	configs := map[int]*cell.Cell{81: bridgeParam, 84: tokenAssetsCell(t, records...)}
	transactions := map[string]map[string]any{}
	for account := range accounts {
		tx := buildTransaction(t, 10, 1000, nil, internalIn(t, testBuyer, cell.BeginCell().EndCell()), true, 0)
		id, err := hex.DecodeString(strings.SplitN(account, ":", 2)[1])
		if err != nil {
			t.Fatal(err)
		}
		tx.AccountAddr = id
		encoded, err := tx.ToCell()
		if err != nil {
			t.Fatal(err)
		}
		tx.Hash = encoded.Hash()
		raw := rawTransactionOf(t, tx)
		raw["data"] = base64.StdEncoding.EncodeToString(encoded.ToBOC())
		raw["account"] = strings.SplitN(account, ":", 2)[1]
		raw["transaction_id"] = map[string]any{"@type": "internal.transactionId", "lt": "10", "hash": base64.StdEncoding.EncodeToString(encoded.Hash())}
		transactions[account] = raw
	}
	root := bytes.Repeat([]byte{8}, 32)
	serve := func() string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
				Params struct {
					Address   string `json:"address"`
					Seqno     uint64 `json:"seqno"`
					Param     int    `json:"param"`
					WithProof bool   `json:"with_proof"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			block := tokenTestBlock(root, 42)
			var result any
			switch call.Method {
			case "getMasterchainInfo":
				result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "state_root_hash": base64.StdEncoding.EncodeToString(root), "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))}}
			case "getConfigParam":
				if call.Params.Seqno != 42 || !call.Params.WithProof {
					t.Error("configuration escaped the checkpoint")
				}
				value, ok := configs[call.Params.Param]
				if !ok {
					t.Errorf("unexpected parameter %d", call.Params.Param)
					return
				}
				result = map[string]any{"@type": "configInfo", "config": map[string]string{"@type": "tvm.cell", "bytes": bocText(value)}, "block_id": block}
			case "getAddressInformation":
				if call.Params.Seqno != 42 {
					t.Error("account escaped checkpoint")
				}
				code := minterCode
				if call.Params.Address == base.Bridge {
					code = bridgeCode
				}
				data, ok := accounts[call.Params.Address]
				if !ok {
					t.Error("read unpinned account")
					return
				}
				result = map[string]any{"@type": "raw.fullAccountState", "balance": "1000", "code": bocText(code), "data": bocText(data), "last_transaction_id": transactions[call.Params.Address]["transaction_id"], "block_id": block, "state": "active"}
			case "getTransactions":
				result = []any{transactions[call.Params.Address]}
			case "runGetMethod":
				if call.Params.Seqno != 42 {
					t.Error("getter escaped checkpoint")
				}
				var found *SettlementAssetV1
				for i := range records {
					if records[i].Master == call.Params.Address {
						found = &records[i]
					}
				}
				if found == nil {
					t.Error("unrecognized getter")
					return
				}
				result = map[string]any{"@type": "smc.runResult", "exit_code": 0, "block_id": block, "stack": []any{[]any{"num", "6"}, []any{"num", new(big.Int).SetBytes(found.SourceToken[:]).String()}, []any{"num", "56"}}}
			default:
				t.Errorf("unexpected read %s", call.Method)
				return
			}
			// A canceled minority request may close its response pipe once
			// the client has a quorum; the selected result is checked below.
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	network := &nativev1.NetworkDomain{NetworkId: "tos:two-test-assets", GenesisRootHash: "sha256:" + strings.Repeat("31", 32), GenesisFileHash: "sha256:" + strings.Repeat("32", 32)}
	adapter, err := New(Config{Network: network.NetworkId, Endpoints: []string{serve(), serve(), serve()}, Quorum: 2, Now: func() time.Time { return time.Unix(1000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return &ServiceActorSession{reader: &ServiceActorReader{chain: adapter, network: network}, nodes: adapter.nodes, seqno: 42}, pins
}

func TestTwoPinnedAssetsVerifyIndependently(t *testing.T) {
	s, pins := twoAssetSession(t, false)
	for i, pin := range pins {
		result, err := s.ReadTokenAsset(context.Background(), pin.Master, pins)
		if err != nil {
			t.Fatalf("asset %d: %v", i, err)
		}
		if result.Checkpoint != 42 || result.Record.Master != pin.Master || result.Record.SourceToken != pin.SourceToken || result.Record.Decimals != 6 || result.EntryCount != 2 || result.Record.MaxLiabilityPerActor.Int64() != int64(1000000*(i+1)) {
			t.Fatalf("wrong asset %d: %+v", i, result)
		}
	}
	// A syntactically valid but incorrect second release cannot affect the first.
	wrong := append([]TokenAssetPin(nil), pins...)
	wrong[1].WalletCodeHash = "tvm-cell-sha256:" + strings.Repeat("ef", 32)
	if _, err := s.ReadTokenAsset(context.Background(), pins[1].Master, wrong); err == nil {
		t.Fatal("wrong second release accepted")
	}
	if _, err := s.ReadTokenAsset(context.Background(), pins[0].Master, wrong); err != nil {
		t.Fatalf("other asset affected: %v", err)
	}
}

func TestSuspendedSecondAssetLeavesFirstActive(t *testing.T) {
	s, pins := twoAssetSession(t, true)
	if _, err := s.ReadTokenAsset(context.Background(), pins[0].Master, pins); err != nil {
		t.Fatalf("active first asset affected by second status: %v", err)
	}
	if _, err := s.ReadTokenAsset(context.Background(), pins[1].Master, pins); err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("suspended asset: %v", err)
	}
	if _, err := s.ReadTokenAsset(context.Background(), pins[0].Master, pins); err != nil {
		t.Fatalf("suspension contaminated other asset: %v", err)
	}
}
