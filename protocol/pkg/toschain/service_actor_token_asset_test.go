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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenRecordCell(t *testing.T, record SettlementAssetV1) *cell.Cell {
	t.Helper()
	bridge, err := hex.DecodeString(strings.TrimPrefix(record.Bridge, "-1:"))
	if err != nil {
		t.Fatal(err)
	}
	origin := cell.BeginCell().MustStoreUInt(uint64(record.OriginKind), 8).MustStoreSlice(bridge, 256).MustStoreUInt(uint64(record.SourceChainID), 32).MustStoreSlice(record.SourceToken[:], 160).EndCell()
	return cell.BeginCell().MustStoreUInt(1, 8).MustStoreUInt(uint64(record.Status), 8).MustStoreUInt(uint64(record.Decimals), 8).MustStoreSlice(record.MinterCodeHash[:], 256).MustStoreSlice(record.WalletCodeHash[:], 256).MustStoreBigCoins(record.MaxLiabilityPerActor).MustStoreRef(origin).EndCell()
}
func tokenAssetsCell(t *testing.T, records ...SettlementAssetV1) *cell.Cell {
	t.Helper()
	dictionary := cell.NewDict(256)
	for _, record := range records {
		key, err := hex.DecodeString(strings.TrimPrefix(record.Master, "0:"))
		if err != nil {
			t.Fatal(err)
		}
		if err = dictionary.Set(cell.BeginCell().MustStoreSlice(key, 256).EndCell(), tokenRecordCell(t, record)); err != nil {
			t.Fatal(err)
		}
	}
	return cell.BeginCell().MustStoreUInt(1, 8).MustStoreDict(dictionary).EndCell()
}
func tokenSyntheticRecord() SettlementAssetV1 {
	return SettlementAssetV1{Master: "0:" + strings.Repeat("11", 32), Status: 1, Decimals: 6, MinterCodeHash: [32]byte{1}, WalletCodeHash: [32]byte{2}, MaxLiabilityPerActor: big.NewInt(1000000), OriginKind: 1, Bridge: "-1:" + strings.Repeat("33", 32), SourceChainID: 1, SourceToken: [20]byte{4}}
}
func TestTokenAssetDictionaryStrictAndUnpinnedEntriesIndependent(t *testing.T) {
	record := tokenSyntheticRecord()
	root := tokenAssetsCell(t, record)
	decoded, err := DecodeSettlementAssets(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Entries) != 1 || decoded.Entries[record.Master].Decimals != 6 {
		t.Fatal("valid recognition not decoded")
	}
	records := []SettlementAssetV1{record}
	for i := 2; i < 20; i++ {
		other := record
		other.Master = "0:" + hex.EncodeToString(bytes.Repeat([]byte{byte(i + 64)}, 32))
		records = append(records, other)
	}
	decoded, err = DecodeSettlementAssets(tokenAssetsCell(t, records...))
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.OverEntryLimit || len(decoded.Entries) != 19 {
		t.Fatal("over-16 list was rejected or count hidden")
	}
	for _, mutate := range []func(*cell.Cell) *cell.Cell{
		func(c *cell.Cell) *cell.Cell {
			return cell.BeginCell().MustStoreUInt(2, 8).MustStoreBoolBit(false).EndCell()
		},
		func(c *cell.Cell) *cell.Cell { return c.ToBuilder().MustStoreUInt(0, 1).EndCell() },
		func(c *cell.Cell) *cell.Cell { return c.ToBuilder().MustStoreRef(cell.BeginCell().EndCell()).EndCell() },
	} {
		if _, err := DecodeSettlementAssets(mutate(root)); err == nil {
			t.Fatal("malformed recognition accepted")
		}
	}
	for _, value := range []struct {
		status uint8
		kind   uint8
		cap    int64
	}{{0, 1, 1}, {4, 1, 1}, {1, 0, 1}, {1, 3, 1}, {1, 1, 0}} {
		bad := record
		bad.Status = value.status
		bad.OriginKind = value.kind
		bad.MaxLiabilityPerActor = big.NewInt(value.cap)
		if _, err = DecodeSettlementAssets(tokenAssetsCell(t, bad)); err == nil {
			t.Fatalf("invalid record accepted: %+v", value)
		}
	}
}

func TestTokenDictionaryRejectsTrailingForkData(t *testing.T) {
	dictionary := cell.NewDict(8)
	for _, key := range []uint64{0, 255} {
		if err := dictionary.SetIntKey(new(big.Int).SetUint64(key), cell.BeginCell().MustStoreUInt(7, 8).EndCell()); err != nil {
			t.Fatal(err)
		}
	}
	valid := dictionary.AsCell()
	if _, err := tokenDictionaryEntries(dictionary, 8); err != nil {
		t.Fatal(err)
	}
	bad := valid.ToBuilder().MustStoreBoolBit(false).EndCell()
	if _, err := tokenDictionaryEntries(bad.AsDict(8), 8); err == nil {
		t.Fatal("trailing fork bit accepted")
	}
}

func tokenBridgeFixture(t *testing.T) (SettlementAssetV1, TokenAssetPin, *cell.Cell, *cell.Cell, *cell.Cell, *cell.Cell) {
	t.Helper()
	minterCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	walletCode := cell.BeginCell().MustStoreUInt(2, 8).EndCell()
	bridgeCode := cell.BeginCell().MustStoreUInt(3, 8).EndCell()
	record := tokenSyntheticRecord()
	copy(record.MinterCodeHash[:], minterCode.Hash())
	copy(record.WalletCodeHash[:], walletCode.Hash())
	master, err := deriveTokenMinter(record, minterCode, walletCode)
	if err != nil {
		t.Fatal(err)
	}
	record.Master = master
	pin := TokenAssetPin{Master: master, Bridge: record.Bridge, BridgeConfigParam: 79, Decimals: 6, SourceChainID: 1, SourceToken: record.SourceToken, BridgeCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(bridgeCode.Hash()), MinterCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(minterCode.Hash()), WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletCode.Hash())}
	bridgeData := cell.BeginCell().MustStoreUInt(9, 64).MustStoreUInt(1, 32).MustStoreUInt(7, 160).MustStoreUInt(1, 32).MustStoreUInt(0, 64).MustStoreUInt(1, 2).MustStoreUInt(0, 2).MustStoreRef(minterCode).MustStoreRef(walletCode).MustStoreRef(cell.BeginCell().MustStoreUInt(0, 64).MustStoreDict(nil).MustStoreDict(nil).MustStoreUInt(0, 32).EndCell()).EndCell()
	bridgeID, _ := hex.DecodeString(strings.TrimPrefix(record.Bridge, "-1:"))
	prices := cell.BeginCell()
	for i := 0; i < 6; i++ {
		prices.MustStoreCoins(1)
	}
	bridgeParam := cell.BeginCell().MustStoreUInt(1, 8).MustStoreSlice(bridgeID, 256).MustStoreUInt(0, 256).MustStoreDict(nil).MustStoreUInt(0, 8).MustStoreRef(prices.EndCell()).MustStoreUInt(7, 256).EndCell()
	minterData := tokenMinterFixtureData(t, record, walletCode)
	return record, pin, bridgeCode, bridgeData, bridgeParam, minterData
}
func tokenMinterFixtureData(t *testing.T, record SettlementAssetV1, walletCode *cell.Cell) *cell.Cell {
	t.Helper()
	bridge := rawAddress(t, record.Bridge)
	content := cell.BeginCell().MustStoreUInt(uint64(record.SourceChainID), 32).MustStoreSlice(record.SourceToken[:], 160).MustStoreUInt(uint64(record.Decimals), 8).EndCell()
	settlement := cell.BeginCell().MustStoreAddr(bridge).MustStoreUInt(0, 129).MustStoreUInt(0, 256).MustStoreUInt(0, 32).MustStoreDict(nil).MustStoreDict(nil).MustStoreDict(nil).EndCell()
	return cell.BeginCell().MustStoreInt(0, 128).MustStoreCoins(0).MustStoreCoins(0).MustStoreCoins(0).MustStoreCoins(0).MustStoreRef(content).MustStoreRef(walletCode).MustStoreRef(settlement).EndCell()
}
func tokenTestBlock(root []byte, seqno uint64) map[string]any {
	return map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": masterchainShard, "seqno": seqno, "root_hash": base64.StdEncoding.EncodeToString(root), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}
}

func TestTokenRecognitionReadsOneCheckpointAndChecksEveryBinding(t *testing.T) {
	record, pin, bridgeCode, bridgeData, bridgeParam, minterData := tokenBridgeFixture(t)
	minterCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	root := bytes.Repeat([]byte{8}, 32)
	network := &nativev1.NetworkDomain{NetworkId: "tos:token-read", GenesisRootHash: "sha256:" + strings.Repeat("31", 32), GenesisFileHash: "sha256:" + strings.Repeat("32", 32)}
	// The last transaction may have been pruned while finalized account state remains.
	txs := map[string]map[string]any{}
	accounts := map[string]*cell.Cell{pin.Bridge: bridgeData, pin.Master: minterData}
	// The transaction account must match too, not just the RPC account summary.
	for account := range accounts {
		tx := buildTransaction(t, 10, 1000, nil, internalIn(t, testBuyer, cell.BeginCell().EndCell()), true, 0)
		id, _ := hex.DecodeString(strings.SplitN(account, ":", 2)[1])
		tx.AccountAddr = id
		c, err := tx.ToCell()
		if err != nil {
			t.Fatal(err)
		}
		tx.Hash = c.Hash()
		raw := rawTransactionOf(t, tx)
		raw["data"] = base64.StdEncoding.EncodeToString(c.ToBOC())
		raw["account"] = strings.SplitN(account, ":", 2)[1]
		raw["transaction_id"] = map[string]any{"@type": "internal.transactionId", "lt": "10", "hash": base64.StdEncoding.EncodeToString(c.Hash())}
		txs[account] = raw
	}
	run := func(t *testing.T, change func(*SettlementAssetV1, *TokenAssetPin), fork bool, unknownCount int) error {
		current, policy := record, pin
		if change != nil {
			change(&current, &policy)
		}
		records := []SettlementAssetV1{current}
		for i := 0; i < unknownCount; i++ {
			other := record
			other.Master = "0:" + hex.EncodeToString(bytes.Repeat([]byte{byte(i + 64)}, 32))
			other.Status = 3
			other.Decimals = 99
			records = append(records, other)
		}
		configs := map[int]*cell.Cell{84: tokenAssetsCell(t, records...), 79: bridgeParam}
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
						Method    string `json:"method"`
					} `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
					t.Error(err)
					return
				}
				var result any
				block := tokenTestBlock(root, 42)
				switch call.Method {
				case "getMasterchainInfo":
					result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "state_root_hash": base64.StdEncoding.EncodeToString(root), "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))}}
				case "getConfigParam":
					if call.Params.Seqno != 42 || !call.Params.WithProof {
						t.Error("config read unpinned")
					}
					if fork && call.Params.Param == 79 {
						block = tokenTestBlock(bytes.Repeat([]byte{7}, 32), 42)
					}
					result = map[string]any{"@type": "configInfo", "config": map[string]string{"@type": "tvm.cell", "bytes": bocText(configs[call.Params.Param])}, "block_id": block, "state_proof": "", "config_proof": ""}
				case "getAddressInformation":
					if call.Params.Seqno != 42 {
						t.Error("account read unpinned")
					}
					code := bridgeCode
					if call.Params.Address == record.Master {
						code = minterCode
					}
					result = map[string]any{"@type": "raw.fullAccountState", "balance": "1000", "code": bocText(code), "data": bocText(accounts[call.Params.Address]), "last_transaction_id": txs[call.Params.Address]["transaction_id"], "block_id": block, "state": "active"}
				case "getTransactions":
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": -32603, "message": "last transaction pruned: lt not in db"}})
					return
				case "runGetMethod":
					if call.Params.Seqno != 42 {
						t.Error("getter read unpinned")
					}
					result = map[string]any{"@type": "smc.runResult", "exit_code": 0, "block_id": block, "stack": []any{[]any{"num", "6"}, []any{"num", new(big.Int).SetBytes(record.SourceToken[:]).String()}, []any{"num", "1"}}}
				default:
					t.Errorf("unexpected method %s", call.Method)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
			}))
			t.Cleanup(server.Close)
			return server.URL
		}
		urls := []string{serve(), serve(), serve()}
		adapter, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2, Now: func() time.Time { return time.Unix(1000, 0) }})
		if err != nil {
			t.Fatal(err)
		}
		session := &ServiceActorSession{reader: &ServiceActorReader{chain: adapter, network: network}, nodes: adapter.nodes, seqno: 42}
		value, err := session.ReadTokenAsset(context.Background(), record.Master, []TokenAssetPin{policy})
		if err == nil && (value.Checkpoint != 42 || value.Record.Master != record.Master || value.OverEntryLimit != (unknownCount >= 16)) {
			t.Fatal("incomplete recognition result")
		}
		return err
	}
	if err := run(t, nil, false, 0); err != nil {
		t.Fatal(err)
	}
	if err := run(t, nil, false, 20); err != nil {
		t.Fatalf("unpinned entries caused rejection: %v", err)
	}
	for name, change := range map[string]func(*SettlementAssetV1, *TokenAssetPin){"status": func(r *SettlementAssetV1, p *TokenAssetPin) { r.Status = 2 }, "decimals": func(r *SettlementAssetV1, p *TokenAssetPin) { r.Decimals = 18 }, "wallet code": func(r *SettlementAssetV1, p *TokenAssetPin) { r.WalletCodeHash[0] ^= 1 }, "minter code": func(r *SettlementAssetV1, p *TokenAssetPin) { r.MinterCodeHash[0] ^= 1 }, "origin token": func(r *SettlementAssetV1, p *TokenAssetPin) { r.SourceToken[0] ^= 1 }, "master": func(r *SettlementAssetV1, p *TokenAssetPin) { p.Master = "0:" + strings.Repeat("ef", 32) }} {
		t.Run(name, func(t *testing.T) {
			if err := run(t, change, false, 0); err == nil {
				t.Fatal("identity mismatch accepted")
			}
		})
	}
	if err := run(t, nil, true, 0); err == nil {
		t.Fatal("mixed checkpoint roots accepted")
	}
}

func rawTransactionOf(t *testing.T, tx tlb.Transaction) map[string]any {
	t.Helper()
	root, err := tx.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"@type": "raw.transaction", "data": base64.StdEncoding.EncodeToString(root.ToBOC()), "account": hex.EncodeToString(tx.AccountAddr), "transaction_id": map[string]any{"@type": "internal.transactionId", "lt": strconv.FormatUint(tx.LT, 10), "hash": base64.StdEncoding.EncodeToString(root.Hash())}}
}

func TestTokenActorInspectionDoesNotReadCurrentRecognition(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Actor    string `json:"actor"`
		Wallet   string `json:"actor_wallet"`
		Code     string `json:"contract_code_boc_base64"`
		Data     string `json:"deploy_data_boc_base64"`
		CodeHash string `json:"contract_code_hash"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	domain := &nativev1.NetworkDomain{NetworkId: "tos:token-inspection", GenesisRootHash: "sha256:" + strings.Repeat("31", 32), GenesisFileHash: "sha256:" + strings.Repeat("32", 32)}
	tx := buildTransaction(t, 10, 1000, nil, internalIn(t, testBuyer, cell.BeginCell().EndCell()), true, 0)
	account, _ := hex.DecodeString(strings.TrimPrefix(fixture.Actor, "0:"))
	tx.AccountAddr = account
	encoded, err := tx.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	tx.Hash = encoded.Hash()
	transaction := rawTransactionOf(t, tx)
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	serve := func() string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
				Params struct {
					Address string `json:"address"`
					Seqno   uint64 `json:"seqno"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			var result any
			switch call.Method {
			case "getMasterchainInfo":
				result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))}}
			case "getAddressInformation":
				if call.Params.Address != fixture.Actor || call.Params.Seqno != 42 {
					t.Error("unbound actor read")
				}
				result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "1000", "code": fixture.Code, "data": fixture.Data, "last_transaction_id": transaction["transaction_id"], "block_id": block}
			case "getTransactions":
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": -32603, "message": "last transaction pruned"}})
				return
			default:
				t.Errorf("account inspection consulted %s", call.Method)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	adapter, err := New(Config{Network: domain.NetworkId, Endpoints: []string{serve(), serve(), serve()}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	session := &ServiceActorSession{reader: &ServiceActorReader{chain: adapter, network: domain, codeHash: fixture.CodeHash}, seqno: 42, nodes: adapter.nodes}
	actor, found, err := session.ReadTokenActor(context.Background(), fixture.Actor)
	if err != nil || !found {
		t.Fatalf("inspection failed: %v", err)
	}
	if actor.OwnWallet != fixture.Wallet {
		t.Fatal("actor wallet differs from frozen vector")
	}
	resolved, err := session.ResolveTokenActor(context.Background(), fixture.Actor, nil, false)
	if err != nil || resolved.Recognition != nil || resolved.Account.OwnWallet != fixture.Wallet {
		t.Fatalf("inspection consulted admission: %v", err)
	}
}

func TestTokenConfigReadRequiresAWholeValueMajority(t *testing.T) {
	record := tokenSyntheticRecord()
	good := tokenAssetsCell(t, record)
	other := record
	other.Decimals = 7
	second := tokenAssetsCell(t, other)
	other.Decimals = 8
	third := tokenAssetsCell(t, other)
	serve := func(value *cell.Cell) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
				Params struct {
					Param int    `json:"param"`
					Seqno uint64 `json:"seqno"`
					Proof bool   `json:"with_proof"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			if call.Method != "getConfigParam" || call.Params.Param != 84 || call.Params.Seqno != 42 || !call.Params.Proof {
				t.Error("unbound config request")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": map[string]any{"@type": "configInfo", "config": map[string]string{"@type": "tvm.cell", "bytes": bocText(value)}, "block_id": tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)}})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	for _, test := range []struct {
		values []*cell.Cell
		want   bool
	}{{[]*cell.Cell{good, good, second}, true}, {[]*cell.Cell{good, second, third}, false}} {
		adapter, err := New(Config{Network: "tos:token-config-majority", Endpoints: []string{serve(test.values[0]), serve(test.values[1]), serve(test.values[2])}, Quorum: 2})
		if err != nil {
			t.Fatal(err)
		}
		session := &ServiceActorSession{reader: &ServiceActorReader{chain: adapter}, nodes: adapter.nodes, seqno: 42}
		value, err := session.tokenConfigAt(context.Background(), 84)
		if test.want {
			if err != nil || !bytes.Equal(value.Hash(), good.Hash()) {
				t.Fatalf("strict majority rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("one honest response became authority without majority")
		}
	}
}

func TestTokenWalletStateSurvivesPrunedLastTransaction(t *testing.T) {
	code := cell.BeginCell().MustStoreUInt(2, 8).EndCell()
	owner := testBuyer
	master, err := nativecore.StandardAddress(testActor)
	if err != nil {
		t.Fatal(err)
	}
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, BridgeConfigParam: 79, WalletCode: code}
	copy(route.WalletCodeHash[:], code.Hash())
	wallet, err := nativecore.DeriveServiceActorTokenWallet(owner, route)
	if err != nil {
		t.Fatal(err)
	}
	settlement := cell.BeginCell().MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreBoolBit(false).MustStoreUInt(0, 32).MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreDict(nil).MustStoreUInt(0, 64).MustStoreUInt(0, 64).MustStoreDict(nil).EndCell()
	data := cell.BeginCell().MustStoreCoins(123).MustStoreAddr(rawAddress(t, owner)).MustStoreAddr(rawAddress(t, testActor)).MustStoreRef(code).MustStoreRef(settlement).MustStoreUInt(0, 16).MustStoreDict(nil).EndCell()
	network := &nativev1.NetworkDomain{NetworkId: "tos:pruned-wallet", GenesisRootHash: "sha256:" + strings.Repeat("31", 32), GenesisFileHash: "sha256:" + strings.Repeat("32", 32)}
	serve := func() string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var q struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
				Params struct {
					Address string `json:"address"`
					Seqno   uint64 `json:"seqno"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
				t.Error(err)
				return
			}
			block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
			var result any
			switch q.Method {
			case "getMasterchainInfo":
				result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))}}
			case "getAddressInformation":
				if q.Params.Address != wallet || q.Params.Seqno != 42 {
					t.Error("wallet read escaped its identity or checkpoint")
				}
				result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "1000", "code": bocText(code), "data": bocText(data), "block_id": block, "last_transaction_id": map[string]any{"@type": "internal.transactionId", "lt": "10", "hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}}
			case "getTransactions":
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32603, "message": "last transaction pruned"}})
				return
			default:
				t.Error("unexpected wallet RPC", q.Method)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	chain, err := New(Config{Network: network.NetworkId, Endpoints: []string{serve(), serve(), serve()}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	session := &ServiceActorSession{reader: &ServiceActorReader{chain: chain, network: network}, nodes: chain.nodes, seqno: 42}
	state, found, err := session.ReadTokenWallet(context.Background(), owner, route)
	if err != nil || !found {
		t.Fatalf("pruned wallet state refused: %v", err)
	}
	if state.BalanceAtomic.Cmp(big.NewInt(123)) != 0 || state.LastTransaction.LT != 10 {
		t.Fatal("wallet balance or finalized anchor missing")
	}
	// Execution evidence remains unavailable: state does not manufacture a BOC.
	_, err = readNativeAccountAt(context.Background(), chain.nodes[0], wallet, 42, network, "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()))
	if err == nil || !strings.Contains(err.Error(), "pruned") {
		t.Fatalf("execution read ignored missing history: %v", err)
	}
}

func TestOfferRegistryStateSurvivesPrunedLastTransaction(t *testing.T) {
	locator := guarantorTestLocator(t)
	fixture := newGuarantorFixture(t, locator)
	subject := registryCapability
	identity, err := locator.Locate(subject)
	if err != nil {
		t.Fatal(err)
	}
	init, err := decodeCellBOC(identity.StateInitBOC)
	if err != nil {
		t.Fatal(err)
	}
	initSlice := init.MustBeginParse()
	initSlice.MustLoadUInt(3)
	initSlice.MustLoadRef()
	initSlice.MustLoadUInt(1)
	initialData := initSlice.MustLoadRef()
	config := initialData.MustLoadRef().MustToCell()
	version := "1.0.0"
	key := sha256.Sum256([]byte(version))
	versions := cell.NewDict(256)
	err = versions.Set(cell.BeginCell().MustStoreSlice(key[:], 256).EndCell(), cell.BeginCell().MustStoreSlice(bytes.Repeat([]byte{0x55}, 32), 256).MustStoreBoolBit(false).MustStoreRef(cell.BeginCell().MustStoreBinarySnake([]byte(version)).EndCell()).EndCell())
	if err != nil {
		t.Fatal(err)
	}
	typed := cell.BeginCell().MustStoreUInt(0x4e565331, 32).MustStoreUInt(1, 16).MustStoreUInt(2, 8).MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(1, 64).MustStoreSlice(bytes.Repeat([]byte{0x44}, 32), 256).MustStoreSlice(bytes.Repeat([]byte{0x66}, 32), 256).MustStoreRef(cell.BeginCell().MustStoreUInt(1, 16).MustStoreDict(versions).EndCell()).EndCell()
	rawID, err := hex.DecodeString(strings.TrimPrefix(subject, "cap_"))
	if err != nil {
		t.Fatal(err)
	}
	data := cell.BeginCell().MustStoreUInt(0x4e564431, 32).MustStoreUInt(1, 16).MustStoreUInt(2, 8).MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(typed).EndCell()
	fixture.account = identity.Address
	fixture.data = bocText(data)
	fixture.history = []tlb.Transaction{accountTransaction(t, identity.Address, 400, 1000, nil)}
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	serve := func() string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var q struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
				Params struct {
					Address string `json:"address"`
					Seqno   uint64 `json:"seqno"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
				t.Error(err)
				return
			}
			var result any
			switch q.Method {
			case "getMasterchainInfo":
				result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xaa}, 32)), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xbb}, 32))}}
			case "getAddressInformation":
				if q.Params.Address != fixture.account || q.Params.Seqno != 42 {
					t.Error("registry read escaped its identity or checkpoint")
				}
				result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "1000", "code": fixture.code, "data": fixture.data, "block_id": block, "last_transaction_id": headID(fixture.history[0])}
			case "getTransactions":
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32603, "message": "last registry transaction pruned"}})
				return
			default:
				t.Error("unexpected registry RPC", q.Method)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	chain, err := New(Config{Network: locator.Network.NetworkId, Endpoints: []string{serve(), serve(), serve()}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewSimplifiedNativeResolver(chain, locator, fenceDirectory(t)+"/registry.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	session := &ServiceActorSession{reader: &ServiceActorReader{chain: chain, network: locator.Network, registry: resolver}, nodes: chain.nodes, seqno: 42}
	state, found, err := session.ResolveRegistry(context.Background(), subject)
	if err != nil || !found || state == nil || state.GetCapability().GetCapabilityId() != subject || state.GetReference().GetLogicalTime() != 400 || state.GetReference().GetFinalizedCheckpoint() != 42 {
		t.Fatalf("finalized registry state unavailable after pruning: found=%v err=%v", found, err)
	}
}
