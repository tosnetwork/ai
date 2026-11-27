package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentgift"
	"github.com/tosnetwork/ai/protocol/pkg/agentrelay"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// prunedHistoryError is the error a node returns once it has pruned the
// block that holds a requested transaction.
const prunedHistoryError = "cannot load transaction: lt not in db"

type prunedCall struct {
	ID     uint64 `json:"id"`
	Method string `json:"method"`
	Params struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
		Param   int    `json:"param"`
		Method  string `json:"method"`
	} `json:"params"`
}

// prunedHistoryServers serves finalized state at checkpoint 42 from three
// endpoints that have all pruned every transaction: getTransactions always
// fails with the node's pruned-history error. answer returns the result for
// every other method, or false for a method the read must not consult.
func prunedHistoryServers(t *testing.T, answer func(call prunedCall) (any, bool)) []string {
	t.Helper()
	urls := make([]string, 3)
	for index := range urls {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call prunedCall
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			if call.Method == "getTransactions" {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
					"error": map[string]any{"code": -32603, "message": prunedHistoryError}})
				return
			}
			result, ok := answer(call)
			if !ok {
				t.Errorf("pruned-history read consulted %s", call.Method)
				http.Error(w, "unexpected method", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
		}))
		t.Cleanup(server.Close)
		urls[index] = server.URL
	}
	return urls
}

func prunedMasterchainInfo(block map[string]any) map[string]any {
	return map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{
		"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)),
		"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))}}
}

func prunedNetwork(id string) *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: id, GenesisRootHash: "sha256:" + strings.Repeat("31", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("32", 32)}
}

// prunedAnchor is a well-formed last-transaction identifier whose
// transaction the node no longer holds.
func prunedAnchor() map[string]any {
	return map[string]any{"@type": "internal.transactionId", "lt": "10",
		"hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
}

// storedAttestorKey finds the stored ML-DSA-44 public key cell inside the
// actor data, which get_attestor_key returns as is.
func storedAttestorKey(t *testing.T, root *cell.Cell) *cell.Cell {
	t.Helper()
	var found *cell.Cell
	var walk func(*cell.Cell)
	walk = func(c *cell.Cell) {
		if found != nil {
			return
		}
		if c.BitsSize() == 32 && c.RefsNum() == 1 {
			if slice, err := c.BeginParse(); err == nil {
				if length, err := slice.LoadUInt(32); err == nil && length == mldsa44.PublicKeySize {
					found = c
					return
				}
			}
		}
		for index := 0; index < int(c.RefsNum()); index++ {
			next, err := c.PeekRef(index)
			if err == nil {
				walk(next)
			}
		}
	}
	walk(root)
	if found == nil {
		t.Fatal("actor vector carries no stored attestor key")
	}
	return found
}

// An idle native-rail actor whose last transaction was pruned still quotes:
// ReadActor needs only its finalized state and the state's anchor.
func TestServiceActorStateSurvivesPrunedLastTransaction(t *testing.T) {
	raw, err := os.ReadFile("../nativecore/testdata/service-actor-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Code     string `json:"contract_code_boc_base64"`
		CodeHash string `json:"contract_code_hash"`
		Data     string `json:"deploy_data_boc_base64"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	dataCell, err := decodeCellBOC(vector.Data)
	if err != nil {
		t.Fatal(err)
	}
	key := storedAttestorKey(t, dataCell)
	actor := "0:" + strings.Repeat("4b", 32)
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	urls := prunedHistoryServers(t, func(call prunedCall) (any, bool) {
		switch call.Method {
		case "getMasterchainInfo":
			return prunedMasterchainInfo(block), true
		case "getAddressInformation":
			if call.Params.Address != actor || call.Params.Seqno != 42 {
				t.Error("actor read escaped its identity or checkpoint")
			}
			return map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "1000",
				"code": vector.Code, "data": vector.Data, "block_id": block, "last_transaction_id": prunedAnchor()}, true
		case "runGetMethod":
			if call.Params.Seqno != 42 || call.Params.Method != "get_attestor_key" {
				t.Error("attestor getter escaped its checkpoint")
			}
			return map[string]any{"@type": "smc.runResult", "exit_code": 0, "block_id": block,
				"stack": []any{[]any{"cell", map[string]any{"bytes": bocText(key)}}}}, true
		}
		return nil, false
	})
	network := prunedNetwork("tos:pruned-actor")
	chain, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	session := &ServiceActorSession{reader: &ServiceActorReader{chain: chain, network: network, codeHash: vector.CodeHash},
		nodes: chain.nodes, seqno: 42}
	account, found, err := session.ReadActor(context.Background(), actor)
	if err != nil || !found {
		t.Fatalf("pruned actor state refused: found=%v err=%v", found, err)
	}
	if account.Data == nil || !account.Data.Active || !account.Data.Policy.HasAttestor ||
		account.LastTransaction != (ActorTxID{LT: 10, Hash: strings.Repeat("07", 32)}) {
		t.Fatalf("actor state or finalized anchor missing: %+v", account)
	}
	// Executed requests still need the exact history: the anchor is not a
	// transaction, so a complete history read refuses rather than guessing.
	session.reader.maxHistory = 1000
	if _, err := session.History(context.Background(), actor, nil); err == nil || !strings.Contains(err.Error(), "lt not in db") {
		t.Fatalf("actor history ignored the pruned transaction: %v", err)
	}
}

// Agent Account state is read at one finalized checkpoint without the last
// transaction; Gift execution proof stays a separate exact-history read.
func TestAgentAccountStateSurvivesPrunedLastTransaction(t *testing.T) {
	owner, err := address.ParseRawAddr("-1:" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	policy := cell.BeginCell().MustStoreCoins(5_000_000_000).MustStoreCoins(6_000_000_000).
		MustStoreUInt(3600, 64).MustStoreBoolBit(false).MustStoreBoolBit(false).EndCell()
	data := cell.BeginCell().MustStoreAddr(owner).MustStoreSlice([]byte(strings.Repeat("c", 32)), 256).
		MustStoreSlice([]byte(strings.Repeat("d", 32)), 256).
		MustStoreUInt(9, 64).MustStoreUInt(7, 32).MustStoreUInt(1, 32).MustStoreCoins(2_000_000_000).MustStoreRef(policy).EndCell()
	code := cell.BeginCell().MustStoreUInt(0xa6, 8).EndCell()
	account := "-1:" + strings.Repeat("2", 64)
	now := time.Unix(1_900_000_000, 0).UTC()
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	globalID := cell.BeginCell().MustStoreInt(42, 32).EndCell()
	urls := prunedHistoryServers(t, func(call prunedCall) (any, bool) {
		switch call.Method {
		case "getConsensusBlock":
			return map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": uint64(42),
				"timestamp": now.Unix(), "last_block_utime": now.Unix()}, true
		case "getMasterchainInfo":
			return prunedMasterchainInfo(block), true
		case "getAddressInformation":
			if call.Params.Address != account || call.Params.Seqno != 42 {
				t.Error("Agent Account read escaped its identity or checkpoint")
			}
			return map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "9000000000",
				"code": bocText(code), "data": bocText(data), "block_id": block, "last_transaction_id": prunedAnchor()}, true
		case "getConfigParam":
			if call.Params.Param != 19 || call.Params.Seqno != 42 {
				t.Error("global id read escaped its checkpoint")
			}
			return map[string]any{"@type": "configInfo", "config": map[string]string{"@type": "tvm.cell", "bytes": bocText(globalID)}}, true
		}
		return nil, false
	})
	network := prunedNetwork("tos:pruned-agent")
	chain, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewAgentGiftReader(chain, network)
	if err != nil {
		t.Fatal(err)
	}
	// The real Agent Account code is pinned; a synthetic code cell stands in.
	reader.accountCode = "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
	state, at, err := reader.FinalizedAgentAccount(context.Background(), account)
	if err != nil {
		t.Fatalf("pruned Agent Account state refused: %v", err)
	}
	if !state.Active || state.Address != account || state.OwnerAddress != owner.StringRaw() || state.ControllerEpoch != 9 ||
		state.Seqno != 7 || state.GlobalID != 42 || state.BalanceAtomic != 9_000_000_000 || at != uint32(now.Unix()) {
		t.Fatalf("wrong Agent Account state: %+v at=%d", state, at)
	}
	// Gift execution evidence is still exact: the pruned transaction is an
	// unknown, never an inferred execution or a known absence.
	if _, err := finalizedTransactionHistory(context.Background(), chain.nodes[0], account,
		transactionID{Type: "internal.transactionId", LT: "10", Hash: prunedAnchor()["hash"].(string)}); err == nil {
		t.Fatal("Gift history accepted a pruned transaction")
	}
	if errors.Is(err, ErrHistoryAnchorMissing) {
		t.Fatal("pruned history reported as a known absence")
	}
}

// The relay is an execution-time consumer: its last-transaction time anchors
// the invalidation window, so it keeps the exact transaction read. A retained
// transaction yields its authenticated time; a pruned one refuses the vote.
func TestRelayObservationKeepsExactLastTransactionTime(t *testing.T) {
	fixture, boc, key := loadRelayRustFixture(t)
	parsed, err := agentgift.ParseAgentNativeSendBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := address.ParseRawAddr(fixture.Target)
	if err != nil {
		t.Fatal(err)
	}
	policy := cell.BeginCell().MustStoreCoins(5_000_000_000).MustStoreCoins(6_000_000_000).
		MustStoreUInt(3600, 64).MustStoreBoolBit(false).MustStoreBoolBit(false).EndCell()
	data := cell.BeginCell().MustStoreAddr(owner).MustStoreSlice(key, 256).
		MustStoreSlice([]byte(strings.Repeat("d", 32)), 256).MustStoreUInt(fixture.ControllerEpoch, 64).
		MustStoreUInt(uint64(fixture.Seqno), 32).MustStoreUInt(1, 32).MustStoreCoins(0).MustStoreRef(policy).EndCell()
	code := cell.BeginCell().MustStoreUInt(0xa7, 8).EndCell()
	const lastTime = 1_899_999_000
	last := buildTransaction(t, 10, lastTime, nil, internalIn(t, fixture.Target, cell.BeginCell().EndCell()), true, 0)
	sender, err := hex.DecodeString(strings.SplitN(parsed.SenderAgentAccount, ":", 2)[1])
	if err != nil {
		t.Fatal(err)
	}
	last.AccountAddr = sender
	served := rawTransactionOf(t, last)
	network := relayTestNetwork()
	block := map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": masterchainShard, "seqno": 42,
		"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)),
		"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}
	observe := func(t *testing.T, pruned bool) (relayNodeVote, error) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call prunedCall
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			var result any
			switch call.Method {
			case "getMasterchainInfo":
				result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{
					"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
					"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))}}
			case "getAddressInformation":
				if call.Params.Address != parsed.SenderAgentAccount || call.Params.Seqno != 42 {
					t.Error("relay read escaped its identity or checkpoint")
				}
				result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "9000000000",
					"code": bocText(code), "data": bocText(data), "block_id": block, "last_transaction_id": served["transaction_id"]}
			case "getTransactions":
				if pruned {
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
						"error": map[string]any{"code": -32603, "message": prunedHistoryError}})
					return
				}
				result = []any{served}
			default:
				t.Errorf("relay observation consulted %s", call.Method)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
		})
		endpoints := make([]string, 3)
		for index := range endpoints {
			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)
			endpoints[index] = server.URL
		}
		chain, err := New(Config{Network: network.NetworkID, Endpoints: endpoints, Quorum: 2})
		if err != nil {
			t.Fatal(err)
		}
		gifts, err := NewAgentGiftReader(chain, &nativev1.NetworkDomain{NetworkId: network.NetworkID,
			GenesisRootHash: network.ZeroStateRootHash, GenesisFileHash: network.ZeroStateFileHash})
		if err != nil {
			t.Fatal(err)
		}
		gifts.accountCode = "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
		reader := &agentGiftExactRelayCheckpointReader{reader: gifts, network: network}
		checkpoint := consensusObservation{seqno: 42, observedAt: time.Unix(1_900_000_000, 0).UTC()}
		return reader.observeNodeAt(context.Background(), chain.nodes[0], checkpoint,
			AgentAccountAgentBinding{SourceAccount: parsed.SenderAgentAccount, OwnerAddress: fixture.Target,
				AuthorizedAgentID: "agent:buyer"}, parsed,
			agentrelay.RelayExecutionRequest{SignedTransactionBytes: boc, CreatedAtUnix: lastTime - 100})
	}
	vote, err := observe(t, false)
	if err != nil {
		t.Fatalf("retained relay history refused: %v", err)
	}
	if !vote.Candidate.AccountFound || vote.Candidate.CurrentLastTransactionTime != lastTime || vote.Candidate.ExactExternalFound {
		t.Fatalf("relay vote lost the authenticated last-transaction time: %+v", vote.Candidate)
	}
	if _, err := observe(t, true); err == nil || !strings.Contains(err.Error(), "lt not in db") {
		t.Fatalf("relay observation accepted pruned history: %v", err)
	}
}
