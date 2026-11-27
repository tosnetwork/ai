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
	"strconv"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentgift"
	"github.com/tosnetwork/ai/protocol/pkg/agentrelay"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
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
		// WithProof is getConfigParam's flag: the node reports the block it
		// read a parameter at only when it is set.
		WithProof bool `json:"with_proof"`
	} `json:"params"`
}

// prunedHistoryServers serves finalized state at checkpoint 42 from three
// endpoints that have all pruned every transaction: getTransactions always
// fails with the node's pruned-history error. answer returns the result for
// every other method, or false for a method the read must not consult.
func prunedHistoryServers(t *testing.T, answer func(call prunedCall) (any, bool)) []string {
	t.Helper()
	return prunedHistoryServersByIndex(t, func(_ int, call prunedCall) (any, bool) { return answer(call) })
}

// prunedHistoryServersByIndex is prunedHistoryServers with each answer told
// which of the three endpoints it serves.
func prunedHistoryServersByIndex(t *testing.T, answer func(index int, call prunedCall) (any, bool)) []string {
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
			result, ok := answer(index, call)
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
	// forked endpoints serve the account at the same seqno from another block.
	actorServers := func(forked map[int]bool) []string {
		return prunedHistoryServersByIndex(t, func(index int, call prunedCall) (any, bool) {
			switch call.Method {
			case "getMasterchainInfo":
				return prunedMasterchainInfo(block), true
			case "getAddressInformation":
				if call.Params.Address != actor || call.Params.Seqno != 42 {
					t.Error("actor read escaped its identity or checkpoint")
				}
				accountBlock := block
				if forked[index] {
					accountBlock = tokenTestBlock(bytes.Repeat([]byte{6}, 32), 42)
				}
				return map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "1000",
					"code": vector.Code, "data": vector.Data, "block_id": accountBlock, "last_transaction_id": prunedAnchor()}, true
			case "runGetMethod":
				if call.Params.Seqno != 42 || call.Params.Method != "get_attestor_key" {
					t.Error("attestor getter escaped its checkpoint")
				}
				return map[string]any{"@type": "smc.runResult", "exit_code": 0, "block_id": block,
					"stack": []any{[]any{"cell", map[string]any{"bytes": bocText(key)}}}}, true
			}
			return nil, false
		})
	}
	network := prunedNetwork("tos:pruned-actor")
	newSession := func(urls []string) *ServiceActorSession {
		chain, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2})
		if err != nil {
			t.Fatal(err)
		}
		return &ServiceActorSession{reader: &ServiceActorReader{chain: chain, network: network, codeHash: vector.CodeHash},
			nodes: chain.nodes, seqno: 42}
	}
	// Two of three endpoints agree on the account at seqno 42 but from another
	// block than the getter's: the state read is pinned to the session's one
	// block, so the mixed read is refused.
	forked := newSession(actorServers(map[int]bool{0: true, 1: true}))
	if _, _, err := forked.ReadActor(context.Background(), actor); err == nil || !strings.Contains(err.Error(), "different checkpoint blocks") {
		t.Fatalf("actor state from another block at the same seqno was accepted: %v", err)
	}
	session := newSession(actorServers(nil))
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
			return configAnswer(call, globalID, block), true
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
		state.Seqno != 7 || state.GlobalID != 42 || state.BalanceAtomic != 9_000_000_000 || at != uint32(now.Unix()) ||
		state.CodeHash != reader.accountCode {
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

// configAnswer is a node's getConfigParam answer: like the node, it names the
// block it read the parameter at only when with_proof is set.
func configAnswer(call prunedCall, value *cell.Cell, block map[string]any) map[string]any {
	answer := map[string]any{"@type": "configInfo", "config": map[string]string{"@type": "tvm.cell", "bytes": bocText(value)}}
	if call.Params.WithProof {
		answer["block_id"] = block
		answer["state_proof"], answer["config_proof"] = "c3RhdGU=", "Y29uZmln"
	}
	return answer
}

// Two endpoints can serve one seqno from different blocks. Every read of an
// Agent Account resolution is bound to the block the account state was read
// at, by root and file hash, not only by seqno.
func TestAgentAccountReadsBindToOneBlockOfTheSeqno(t *testing.T) {
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
	globalID := cell.BeginCell().MustStoreInt(42, 32).EndCell()
	blockA := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	blockB := tokenTestBlock(bytes.Repeat([]byte{0x5b}, 32), 42)
	blockC := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42) // A's root, another file hash
	blockC["file_hash"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5c}, 32))
	type blocks [3]map[string]any
	reader := func(t *testing.T, state, config blocks) (*AgentGiftReader, *Adapter) {
		t.Helper()
		urls := prunedHistoryServersByIndex(t, func(index int, call prunedCall) (any, bool) {
			switch call.Method {
			case "getConsensusBlock":
				return map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": uint64(42),
					"timestamp": now.Unix(), "last_block_utime": now.Unix()}, true
			case "getMasterchainInfo":
				return prunedMasterchainInfo(state[index]), true
			case "getAddressInformation":
				return map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "9000000000",
					"code": bocText(code), "data": bocText(data), "block_id": state[index], "last_transaction_id": prunedAnchor()}, true
			case "getConfigParam":
				return configAnswer(call, globalID, config[index]), true
			}
			return nil, false
		})
		network := prunedNetwork("tos:agent-one-block")
		chain, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		gifts, err := NewAgentGiftReader(chain, network)
		if err != nil {
			t.Fatal(err)
		}
		gifts.accountCode = "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
		return gifts, chain
	}
	for name, test := range map[string]struct {
		state, config blocks
		refused       bool
	}{
		"every read at one block":                     {state: blocks{blockA, blockA, blockA}, config: blocks{blockA, blockA, blockA}},
		"one endpoint's global id at another block":   {state: blocks{blockA, blockA, blockA}, config: blocks{blockA, blockA, blockB}},
		"the global id at another block of the seqno": {state: blocks{blockA, blockA, blockA}, config: blocks{blockB, blockB, blockB}, refused: true},
		"a majority's global id at another block":     {state: blocks{blockA, blockA, blockA}, config: blocks{blockA, blockB, blockB}, refused: true},
		"the global id at another file hash":          {state: blocks{blockA, blockA, blockA}, config: blocks{blockC, blockC, blockC}, refused: true},
		"the state at the majority's other block":     {state: blocks{blockB, blockB, blockA}, config: blocks{blockA, blockA, blockA}, refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			gifts, _ := reader(t, test.state, test.config)
			state, _, err := gifts.FinalizedAgentAccount(context.Background(), account)
			if test.refused {
				if !errors.Is(err, errAgentGiftBlockMismatch) {
					t.Fatalf("reads at different blocks of one seqno were combined: %+v %v", state, err)
				}
				return
			}
			if err != nil || !state.Active || state.GlobalID != 42 {
				t.Fatalf("reads at one block refused: %+v %v", state, err)
			}
		})
	}
	// A Gift's execution and credit walks start at a last transaction read at
	// the account state's block, and refuse one read at another block.
	_, chain := reader(t, blocks{blockA, blockB, blockC}, blocks{blockA, blockA, blockA})
	rootA, fileA, err := blockHashes(blockID{RootHash: blockA["root_hash"].(string), FileHash: blockA["file_hash"].(string)})
	if err != nil {
		t.Fatal(err)
	}
	pinned := agentGiftBlock{root: rootA, file: fileA}
	if last, err := finalizedAccountLastTransaction(context.Background(), chain.nodes[0], account, 42, pinned); err != nil || last.LT != "10" {
		t.Fatalf("last transaction at the pinned block refused: %+v %v", last, err)
	}
	for index, what := range map[int]string{1: "another root", 2: "another file hash"} {
		if _, err := finalizedAccountLastTransaction(context.Background(), chain.nodes[index], account, 42, pinned); !errors.Is(err, errAgentGiftBlockMismatch) {
			t.Fatalf("last transaction at %s of the seqno was accepted: %v", what, err)
		}
	}
	if _, err := finalizedAccountLastTransaction(context.Background(), chain.nodes[0], account, 42, agentGiftBlock{}); !errors.Is(err, errAgentGiftBlockMismatch) {
		t.Fatalf("last transaction accepted without a pinned block: %v", err)
	}
}

// A Gift resolution follows the exact external message into the sender's
// finalized history and its one output into the destination's. The
// destination's last transaction is read at the block of the sender's state
// read; an endpoint that serves the same seqno from another block is refused.
func TestResolveGiftReadsTheDestinationAtTheStateBlock(t *testing.T) {
	fixture, boc, key := loadRelayRustFixture(t)
	parsed, err := agentgift.ParseAgentNativeSendBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := address.ParseRawAddr(fixture.Target)
	if err != nil {
		t.Fatal(err)
	}
	policy := cell.BeginCell().MustStoreCoins(parsed.AmountAtomic).MustStoreCoins(parsed.AmountAtomic).
		MustStoreUInt(3600, 64).MustStoreBoolBit(false).MustStoreBoolBit(false).EndCell()
	data := cell.BeginCell().MustStoreAddr(owner).MustStoreSlice(key, 256).
		MustStoreSlice([]byte(strings.Repeat("d", 32)), 256).MustStoreUInt(parsed.ControllerEpoch, 64).
		MustStoreUInt(uint64(parsed.Seqno), 32).MustStoreUInt(1, 32).MustStoreCoins(0).MustStoreRef(policy).EndCell()
	code := cell.BeginCell().MustStoreUInt(0xa8, 8).EndCell()
	globalID := cell.BeginCell().MustStoreInt(int64(parsed.GlobalID), 32).EndCell()
	now := time.Unix(1_900_000_000, 0).UTC()
	const executedAt = 1_899_999_000

	root, err := cell.FromBOC(boc)
	if err != nil {
		t.Fatal(err)
	}
	var external tlb.Message
	if err := tlb.LoadFromCell(&external, root.MustBeginParse()); err != nil {
		t.Fatal(err)
	}
	output := testGiftMessage(t, tlb.MsgTypeInternal, parsed.SenderAgentAccount, parsed.DestinationAddress, parsed.AmountAtomic)
	sent := buildTransaction(t, 20, executedAt, nil, &external, true, 0, output)
	received := buildTransaction(t, 30, executedAt+5, nil, output, true, 0)
	description := received.Description.(tlb.TransactionDescriptionOrdinary)
	description.CreditPhase = &tlb.CreditPhase{Credit: tlb.CurrencyCollection{Coins: tlb.FromNanoTONU(parsed.AmountAtomic)}}
	received.Description = description
	sentRaw, receivedRaw := rawTransactionOf(t, sent), rawTransactionOf(t, received)

	blockA := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	blockB := tokenTestBlock(bytes.Repeat([]byte{0x5b}, 32), 42)
	resolve := func(t *testing.T, destination [3]map[string]any) (agentgift.FinalizedGiftObservation, error) {
		t.Helper()
		urls := prunedHistoryServersWithIndex(t, func(index int, call prunedCall, _ json.RawMessage) (any, bool) {
			switch call.Method {
			case "getConsensusBlock":
				return map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": uint64(42),
					"timestamp": now.Unix(), "last_block_utime": now.Unix()}, true
			case "getMasterchainInfo":
				return prunedMasterchainInfo(blockA), true
			case "getConfigParam":
				return configAnswer(call, globalID, blockA), true
			case "getAddressInformation":
				switch call.Params.Address {
				case parsed.SenderAgentAccount:
					return map[string]any{"@type": "raw.fullAccountState", "state": "active", "balance": "9000000000",
						"code": bocText(code), "data": bocText(data), "block_id": blockA,
						"last_transaction_id": sentRaw["transaction_id"]}, true
				case parsed.DestinationAddress:
					return map[string]any{"@type": "raw.fullAccountState", "state": "active", "block_id": destination[index],
						"last_transaction_id": receivedRaw["transaction_id"]}, true
				}
			case "getTransactions":
				switch call.Params.Address {
				case parsed.SenderAgentAccount:
					return []any{sentRaw}, true
				case parsed.DestinationAddress:
					return []any{receivedRaw}, true
				}
			}
			return nil, false
		})
		network := prunedNetwork("tos:gift-destination-block")
		chain, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		gifts, err := NewAgentGiftReader(chain, network)
		if err != nil {
			t.Fatal(err)
		}
		gifts.accountCode = "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
		return gifts.ResolveGift(context.Background(), parsed.SenderAgentAccount, parsed.DestinationAddress, boc,
			parsed.Seqno, parsed.ValidUntil, "sha256:"+strings.Repeat("ab", 32), 0, executedAt-100)
	}
	for name, test := range map[string]struct {
		destination [3]map[string]any
		refused     bool
	}{
		"every read at the state block":               {destination: [3]map[string]any{blockA, blockA, blockA}},
		"one endpoint's destination at another block": {destination: [3]map[string]any{blockA, blockA, blockB}},
		"a majority's destination at another block":   {destination: [3]map[string]any{blockA, blockB, blockB}, refused: true},
		"every destination at another block":          {destination: [3]map[string]any{blockB, blockB, blockB}, refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			observation, err := resolve(t, test.destination)
			if test.refused {
				if err == nil || !strings.Contains(err.Error(), "quorum not reached") ||
					!strings.Contains(err.Error(), errAgentGiftBlockMismatch.Error()) || observation.ExactDestinationCredit {
					t.Fatalf("a destination read at another block of the seqno was used: %+v %v", observation, err)
				}
				return
			}
			if err != nil || !observation.ExactExternalBOCExecuted || !observation.ExactDestinationCredit ||
				!observation.DestinationCreditFinalityKnown {
				t.Fatalf("the exact Gift was not traced at one block: %+v %v", observation, err)
			}
		})
	}
}

// The relay is an execution-time consumer: its last-transaction time anchors
// the invalidation window, so it reads the exact last transaction before any
// state-derived step. A pruned transaction or one without a time refuses the
// vote at that read; a valid one passes it and reaches the relay authority
// projection, whose production code pin refuses the synthetic code reported
// by the state read.
func TestRelayObservationReadsTheExactLastTransactionFirst(t *testing.T) {
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
	timeless := buildTransaction(t, 10, 0, nil, internalIn(t, fixture.Target, cell.BeginCell().EndCell()), true, 0)
	timeless.AccountAddr = sender
	network := relayTestNetwork()
	block := map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": masterchainShard, "seqno": 42,
		"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)),
		"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}
	observe := func(t *testing.T, transaction tlb.Transaction, pruned bool) (relayNodeVote, error) {
		served := rawTransactionOf(t, transaction)
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
	if _, err := observe(t, last, true); err == nil || !strings.Contains(err.Error(), "lt not in db") {
		t.Fatalf("relay observation did not refuse at the exact read of a pruned transaction: %v", err)
	}
	if _, err := observe(t, timeless, false); err == nil || !strings.Contains(err.Error(), "Native transaction time is missing") {
		t.Fatalf("relay observation did not authenticate the last-transaction time: %v", err)
	}
	if _, err := observe(t, last, false); err == nil || !strings.Contains(err.Error(), "authority projection is invalid") {
		t.Fatalf("relay authority accepted the code hash the state read did not check: %v", err)
	}
}

// prunedAnchorSession serves a newest-first history at checkpoint 42 whose
// newest retained transactions are still archived and whose older ones,
// including the oldest retained transaction's predecessor, are pruned.
func prunedAnchorSession(t *testing.T, history []tlb.Transaction, retained int) *ServiceActorSession {
	t.Helper()
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	kept := history[:retained]
	urls := prunedHistoryServersWith(t, func(call prunedCall, raw json.RawMessage) (any, bool) {
		switch call.Method {
		case "getMasterchainInfo":
			return prunedMasterchainInfo(block), true
		case "getAddressInformation":
			return map[string]any{"@type": "raw.fullAccountState", "state": "active", "block_id": block,
				"last_transaction_id": headID(history[0])}, true
		case "getTransactions":
			var params struct {
				Limit int    `json:"limit"`
				LT    string `json:"lt"`
				Hash  string `json:"hash"`
			}
			if err := json.Unmarshal(raw, &params); err != nil {
				t.Error(err)
				return nil, false
			}
			for index, transaction := range kept {
				if strconv.FormatUint(transaction.LT, 10) != params.LT {
					continue
				}
				page := []map[string]any{}
				for _, item := range kept[index:] {
					if len(page) == params.Limit {
						break
					}
					encoded, err := item.ToCell()
					if err != nil {
						t.Error(err)
						return nil, false
					}
					page = append(page, map[string]any{"@type": "raw.transaction", "data": base64.StdEncoding.EncodeToString(encoded.ToBOC()),
						"account": strings.TrimPrefix(testActor, "0:"), "transaction_id": map[string]string{"@type": "internal.transactionId",
							"lt": strconv.FormatUint(item.LT, 10), "hash": base64.StdEncoding.EncodeToString(item.Hash)}})
				}
				return page, true
			}
			return prunedRPCError, true
		}
		return nil, false
	})
	network := prunedNetwork("tos:pruned-anchor")
	chain, err := New(Config{Network: network.NetworkId, Endpoints: urls, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	return &ServiceActorSession{reader: &ServiceActorReader{chain: chain, network: network, maxHistory: 1000},
		nodes: chain.nodes, seqno: 42}
}

// prunedRPCError makes prunedHistoryServersWith answer with the node's
// pruned-history error.
var prunedRPCError = &struct{ pruned bool }{true}

func prunedHistoryServersWith(t *testing.T, answer func(call prunedCall, params json.RawMessage) (any, bool)) []string {
	t.Helper()
	return prunedHistoryServersWithIndex(t, func(_ int, call prunedCall, params json.RawMessage) (any, bool) {
		return answer(call, params)
	})
}

// prunedHistoryServersWithIndex is prunedHistoryServersWith with each answer
// told which of the three endpoints it serves.
func prunedHistoryServersWithIndex(t *testing.T, answer func(index int, call prunedCall, params json.RawMessage) (any, bool)) []string {
	t.Helper()
	urls := make([]string, 3)
	for index := range urls {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call struct {
				prunedCall
				Raw json.RawMessage `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			call.prunedCall.ID = call.ID
			if err := json.Unmarshal(call.Raw, &call.prunedCall.Params); err != nil {
				t.Error(err)
				return
			}
			result, ok := answer(index, call.prunedCall, call.Raw)
			switch {
			case !ok:
				t.Errorf("pruned-anchor read consulted %s", call.Method)
				http.Error(w, "unexpected method", http.StatusBadRequest)
			case result == prunedRPCError:
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID,
					"error": map[string]any{"code": -32603, "message": prunedHistoryError}})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
			}
		}))
		t.Cleanup(server.Close)
		urls[index] = server.URL
	}
	return urls
}

// A sender records the account's last transaction as the anchor before it
// sends: withdraw and the actor index walk History from it, a token action
// walks TokenHistory, and wallet senders walk TokenWalletHistory and
// WalletHistory. Once the node prunes that anchor, each walk still reaches it
// through the verified predecessor link of the newer transactions.
func TestAnchoredWalksReachAPrunedAnchorByItsVerifiedLink(t *testing.T) {
	history := linearHistory(t, 600)
	ctx := context.Background()
	walks := map[string]func(*ServiceActorSession, ActorTxID) (ActorTxID, int, error){
		"withdraw and index History": func(s *ServiceActorSession, anchor ActorTxID) (ActorTxID, int, error) {
			h, err := s.History(ctx, testActor, &anchor)
			if err != nil {
				return ActorTxID{}, 0, err
			}
			if h.Result != HistoryAnchorReached {
				return ActorTxID{}, 0, errors.New("History did not reach its anchor")
			}
			return h.Head, len(h.Transactions), nil
		},
		"token action TokenHistory": func(s *ServiceActorSession, anchor ActorTxID) (ActorTxID, int, error) {
			h, err := s.TokenHistory(ctx, testActor, &anchor)
			if err != nil {
				return ActorTxID{}, 0, err
			}
			if h.Result != HistoryAnchorReached {
				return ActorTxID{}, 0, errors.New("TokenHistory did not reach its anchor")
			}
			return h.Head, len(h.Transactions), nil
		},
		"token wallet TokenWalletHistory": func(s *ServiceActorSession, anchor ActorTxID) (ActorTxID, int, error) {
			h, err := s.TokenWalletHistory(ctx, testActor, &anchor)
			if err != nil {
				return ActorTxID{}, 0, err
			}
			if h.Result != HistoryAnchorReached {
				return ActorTxID{}, 0, errors.New("TokenWalletHistory did not reach its anchor")
			}
			return h.Head, len(h.Transactions), nil
		},
		"buyer wallet WalletHistory": func(s *ServiceActorSession, anchor ActorTxID) (ActorTxID, int, error) {
			h, err := s.WalletHistory(ctx, testActor, anchor)
			if err != nil {
				return ActorTxID{}, 0, err
			}
			return h.Head, len(h.Transactions), nil
		},
	}
	head := tokenAnchorID(history[0])
	for name, walk := range walks {
		// One sent transaction, a full page, and more than a page above the anchor.
		for _, retained := range []int{1, actorHistoryPage, actorHistoryPage + 44} {
			t.Run(name+"/"+strconv.Itoa(retained)+" newer", func(t *testing.T) {
				session := prunedAnchorSession(t, history, retained)
				anchor := tokenAnchorID(history[retained])
				got, count, err := walk(session, anchor)
				if err != nil || got != head || count != retained {
					t.Fatalf("pruned anchor not reached: head=%+v count=%d err=%v", got, count, err)
				}
			})
		}
		t.Run(name+"/link names another hash", func(t *testing.T) {
			session := prunedAnchorSession(t, history, 3)
			anchor := tokenAnchorID(history[3])
			anchor.Hash = strings.Repeat("ab", 32)
			if _, _, err := walk(session, anchor); err == nil {
				t.Fatal("an anchor the verified link does not name was accepted")
			}
		})
		t.Run(name+"/anchor older than the retained link", func(t *testing.T) {
			session := prunedAnchorSession(t, history, 3)
			if _, _, err := walk(session, tokenAnchorID(history[5])); err == nil || !strings.Contains(err.Error(), "lt not in db") {
				t.Fatalf("an anchor behind pruned history was inferred: %v", err)
			}
		})
		t.Run(name+"/link names the hash at another logical time", func(t *testing.T) {
			// The first page ends at history[255], whose link names
			// history[256]. The anchor carries that hash but the logical time
			// of history[255], so the link stop must not take it; the walk
			// reads on and finds the anchor absent.
			session := prunedAnchorSession(t, history, len(history))
			anchor := tokenAnchorID(history[actorHistoryPage])
			anchor.LT = history[actorHistoryPage-1].LT
			if _, _, err := walk(session, anchor); !errors.Is(err, ErrHistoryAnchorMissing) {
				t.Fatalf("an anchor matching the link by hash only was not refused as missing: %v", err)
			}
		})
	}
}

// Execution evidence needs the named transaction's own cell. A target that
// is pruned but linked from a retained newer transaction is an unknown, not
// a reached anchor and not a known absence.
func TestTokenWalletTransactionNeedsThePrunedTargetCell(t *testing.T) {
	history := linearHistory(t, 10)
	session := prunedAnchorSession(t, history, 3)
	tx, err := session.TokenWalletTransaction(context.Background(), testActor, tokenAnchorID(history[3]))
	if err == nil || tx != nil || !strings.Contains(err.Error(), "lt not in db") || errors.Is(err, ErrHistoryAnchorMissing) {
		t.Fatalf("a pruned execution target was not left unknown: tx=%+v err=%v", tx, err)
	}
}

// Production readers pin the real Agent Account code; nothing else sets it.
func TestAgentGiftReaderPinsTheAgentAccountCode(t *testing.T) {
	network := prunedNetwork("tos:agent-code-pin")
	chain, err := New(Config{Network: network.NetworkId, Endpoints: []string{"http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewAgentGiftReader(chain, network)
	if err != nil {
		t.Fatal(err)
	}
	if reader.accountCode != agentgift.AgentAccountCodeHash {
		t.Fatalf("Agent Gift reader pins %q, not the Agent Account code", reader.accountCode)
	}
}
