package toschain

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestRegistryEpochAdapterReadsOneFinalizedObject(t *testing.T) {
	raw, err := os.ReadFile("../nativecore/testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var release struct {
		Code string `json:"contract_code_boc_base64"`
	}
	if err := json.Unmarshal(raw, &release); err != nil {
		t.Fatal(err)
	}
	network := &nativev1.NetworkDomain{NetworkId: "registry-epoch-test", GenesisRootHash: "sha256:" + strings.Repeat("aa", 32), GenesisFileHash: "sha256:" + strings.Repeat("bb", 32)}
	locator, err := nativecore.NewLocator(network, 0, release.Code, nativecore.RegistryV2CodeHash)
	if err != nil {
		t.Fatal(err)
	}
	public := make([]byte, mldsa44.PublicKeySize)
	public[0] = 1
	keyID, err := mldsa44.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 600,
		Controllers: []*nativev1.ControllerV1{{KeyId: mldsa44.KeyIDText(keyID), Mldsa44PublicKey: public, Weight: 1, PurposeMask: 15, Recovery: true}}}
	policyCell, err := nativecore.PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	id, err := nativecore.DeriveAgentID(network, bytes.Repeat([]byte{1}, 32), policy)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := locator.Locate(id)
	if err != nil {
		t.Fatal(err)
	}
	init, err := decodeCellBOC(identity.StateInitBOC)
	if err != nil {
		t.Fatal(err)
	}
	initSlice := init.MustBeginParse()
	initSlice.MustLoadRef()
	config := initSlice.MustLoadRef().MustLoadRef().MustToCell()

	live, withdrawn := sha256.Sum256([]byte("live delegation")), sha256.Sum256([]byte("withdrawn delegation"))
	admissions := cell.NewDict(256)
	for _, entry := range []struct {
		key       [32]byte
		withdrawn bool
	}{{live, false}, {withdrawn, true}} {
		value := cell.BeginCell().MustStoreUInt(7, 64).MustStoreBoolBit(entry.withdrawn)
		if err := admissions.SetBuilderByBytesKey(entry.key[:], value); err != nil {
			t.Fatal(err)
		}
	}
	wrapper := cell.BeginCell().MustStoreUInt(1, 16).MustStoreUInt(2, 16).MustStoreDict(admissions).EndCell()
	typedState := func(sequence, epoch uint64, delegations *cell.Cell) *cell.Cell {
		return cell.BeginCell().MustStoreUInt(0x4e565331, 32).MustStoreUInt(2, 16).MustStoreUInt(1, 8).
			MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(sequence, 64).MustStoreSlice(bytes.Repeat([]byte{2}, 32), 256).MustStoreUInt(epoch, 64).
			MustStoreRef(policyCell).MustStoreRef(delegations).MustStoreRef(cell.BeginCell().MustStoreBoolBit(false).EndCell()).EndCell()
	}
	rawID, err := hex.DecodeString(strings.TrimPrefix(id, "agent_"))
	if err != nil {
		t.Fatal(err)
	}
	accountData := func(state *cell.Cell) string {
		return bocText(cell.BeginCell().MustStoreUInt(0x4e564431, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
			MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell())
	}
	priorState := typedState(9, 7, wrapper)
	priorData := accountData(priorState)
	afterBump := accountData(typedState(10, 8, cell.BeginCell().MustStoreUInt(0, 16).MustStoreUInt(0, 16).MustStoreDict(nil).EndCell()))
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	priorBlock := tokenTestBlock(bytes.Repeat([]byte{7}, 32), 41)
	var bumped atomic.Bool
	consensusTime := time.Now().Unix()
	var status atomic.Value
	status.Store("active")
	var accountReads atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		case "getConsensusBlock":
			result = map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": 42, "timestamp": consensusTime, "last_block_utime": consensusTime}
		case "getMasterchainInfo":
			result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{
				"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xaa}, 32)),
				"file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xbb}, 32)),
			}}
		case "getAddressInformation":
			accountReads.Add(1)
			if q.Params.Address != identity.Address || (q.Params.Seqno != 42 && q.Params.Seqno != 41) {
				t.Error("Registry account read escaped its finalized identity")
			}
			stateData, stateBlock := priorData, block
			if q.Params.Seqno == 41 {
				stateBlock = priorBlock
			} else if bumped.Load() {
				stateData = afterBump
			}
			result = map[string]any{"@type": "raw.fullAccountState", "state": status.Load(), "balance": "1000", "code": release.Code, "data": stateData,
				"block_id": stateBlock, "last_transaction_id": map[string]any{"@type": "internal.transactionId", "lt": "400", "hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))}}
		default:
			t.Errorf("unexpected Registry read: %s", q.Method)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	})
	var endpoints []string
	for range 3 {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		endpoints = append(endpoints, server.URL)
	}
	chain, err := New(Config{Network: network.NetworkId, Endpoints: endpoints, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewSimplifiedNativeResolver(chain, locator, fenceDirectory(t)+"/registry.checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	wireNetwork := &nativev1.NetworkDomain{NetworkId: network.NetworkId,
		GenesisRootHash: strings.TrimPrefix(network.GenesisRootHash, "sha256:"), GenesisFileHash: strings.TrimPrefix(network.GenesisFileHash, "sha256:")}
	adapter, err := agenttransport.NewRegistryResolver(wireNetwork, reader)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := adapter.ResolveFinalizedAgent(t.Context(), id)
	if err != nil || snapshot.CurrentEpoch == nil || *snapshot.CurrentEpoch != 7 || snapshot.EpochCheckpoint != 42 ||
		len(snapshot.AdmissionEpochs) != 1 || snapshot.AdmissionEpochs[live] != 7 || accountReads.Load() != 3 {
		t.Fatalf("finalized epoch and live entries were not read together: %+v, %v, %d reads", snapshot, err, accountReads.Load())
	}
	status.Store("frozen")
	if state, err := adapter.ResolveFinalizedAgent(t.Context(), id); err == nil || errors.Is(err, agenttransport.ErrUnavailable) || state.State != nil {
		t.Fatalf("frozen account treated as authority or availability failure: %v, %v", state.State, err)
	}
	status.Store("uninitialized")
	if state, err := adapter.ResolveFinalizedAgent(t.Context(), id); err != nil || state.State != nil {
		t.Fatalf("uninitialized account returned authority: %v, %v", state.State, err)
	}
	status.Store("active")
	bumped.Store(true)
	priorRoot, err := base64.StdEncoding.DecodeString(priorBlock["root_hash"].(string))
	if err != nil {
		t.Fatal(err)
	}
	priorFile, err := base64.StdEncoding.DecodeString(priorBlock["file_hash"].(string))
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: network, TargetObjectId: id, TargetContractCodeHash: locator.CodeHash,
		Generation: 1, Sequence: 10, PredecessorTvmStateHash: "tvm-cell-sha256:" + hex.EncodeToString(priorState.Hash()), Nonce: bytes.Repeat([]byte{5}, 32),
		Payload: &nativev1.NativeActionV1_WithdrawAgentDelegation{WithdrawAgentDelegation: &nativev1.WithdrawAgentDelegationV1{
			DelegationDigest: "sha256:" + hex.EncodeToString(live[:]), AuthorizationEpoch: 7,
		}}}
	proof, err := reader.ConfirmDelegationWithdrawal(t.Context(), action, &nativev1.DNSCheckpointV1{
		Workchain: -1, Sequence: 41, RootHash: priorRoot, FileHash: priorFile,
	})
	if err != nil || proof.Result != "cleared_by_epoch_bump" || proof.FinalizedEpoch != 8 || proof.FinalizedCheckpoint != 42 {
		t.Fatalf("finalized goal was not proven: %+v, %v", proof, err)
	}
}
