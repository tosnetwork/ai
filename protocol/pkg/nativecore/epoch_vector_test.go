package nativecore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestFrozenRegistryEpochLifecycle(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/test-vectors/tos-service-v1-registry-epochs.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema   string        `json:"schema"`
		CodeHash string        `json:"contract_code_hash"`
		Network  frozenNetwork `json:"network"`
		AgentID  string        `json:"agent_id"`
		States   map[string]struct {
			BOC   string `json:"boc"`
			Epoch uint64 `json:"epoch"`
			Live  int    `json:"live"`
			Total int    `json:"total"`
		} `json:"states"`
		Steps []struct {
			Name  string `json:"name"`
			Input struct {
				Kind       Kind   `json:"kind"`
				Digest     string `json:"digest"`
				Epoch      uint64 `json:"expected_epoch"`
				Generation uint64 `json:"generation"`
				Sequence   uint64 `json:"sequence"`
				Nonce      byte   `json:"nonce"`
			} `json:"input"`
			ActionBOC   string    `json:"action_boc"`
			ActionHash  string    `json:"action_hash"`
			Before      string    `json:"before"`
			After       string    `json:"after"`
			Exit        ErrorCode `json:"exit"`
			OutMessages int       `json:"out_messages"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "tos.service.registry.v2.epoch.vectors" || vectors.CodeHash != RegistryV2CodeHash ||
		len(vectors.Steps) != 8 || len(vectors.States) != 5 {
		t.Fatal("incomplete Registry epoch lifecycle vectors")
	}
	network := vectorNetwork(vectors.Network)
	states := make(map[string]*nativev1.AgentStateV1, len(vectors.States))
	for digest, expected := range vectors.States {
		raw, err := base64.StdEncoding.DecodeString(expected.BOC)
		if err != nil {
			t.Fatal(err)
		}
		state, err := cell.FromBOC(raw)
		if err != nil || hex.EncodeToString(state.Hash()) != digest {
			t.Fatalf("incorrect typed state BOC hash %s: %v", digest, err)
		}
		decoded, err := decodeState(state, vectors.AgentID, 1)
		if err != nil {
			t.Fatal(err)
		}
		agent := decoded.GetAgent()
		live := 0
		for _, entry := range agent.DelegationAdmissions {
			if !entry.Withdrawn {
				live++
			}
		}
		if agent.AuthorizationEpoch != expected.Epoch || live != expected.Live || len(agent.DelegationAdmissions) != expected.Total {
			t.Fatalf("typed state has an incorrect epoch or counts: %v", agent)
		}
		states[digest] = agent
	}

	predecessors := make(map[string]string)
	for _, step := range vectors.Steps {
		t.Run(step.Name, func(t *testing.T) {
			before, after := states[step.Before], states[step.After]
			if before == nil || after == nil {
				t.Fatal("missing typed state")
			}
			predecessor, replay := predecessors[step.ActionHash]
			if !replay {
				predecessor = step.Before
				predecessors[step.ActionHash] = predecessor
			}
			action := &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: vectors.AgentID,
				TargetContractCodeHash: vectors.CodeHash, PredecessorTvmStateHash: "tvm-cell-sha256:" + predecessor,
				Generation: step.Input.Generation, Sequence: step.Input.Sequence, Nonce: bytes32(step.Input.Nonce)}
			digest := "sha256:" + step.Input.Digest
			switch step.Input.Kind {
			case KindDelegateAgent:
				action.Payload = &nativev1.NativeActionV1_DelegateAgent{DelegateAgent: &nativev1.DelegateAgentV1{
					DelegationDigest: digest, AuthorizationEpoch: step.Input.Epoch}}
			case KindWithdrawAgentDelegation:
				action.Payload = &nativev1.NativeActionV1_WithdrawAgentDelegation{WithdrawAgentDelegation: &nativev1.WithdrawAgentDelegationV1{
					DelegationDigest: digest, AuthorizationEpoch: step.Input.Epoch}}
			case KindUpdateAgentPolicy:
				action.Payload = &nativev1.NativeActionV1_UpdateAgentPolicy{UpdateAgentPolicy: &nativev1.UpdateAgentPolicyV1{NewPolicy: before.Policy}}
			default:
				t.Fatal("unsupported vector action kind")
			}
			built, err := BuildAction(action)
			if err != nil || built.HashString != "sha256:"+step.ActionHash ||
				base64.StdEncoding.EncodeToString(built.Cell.ToBOC()) != step.ActionBOC {
				t.Fatalf("Go action does not match the sandbox BOC: %v", err)
			}
			if replay {
				if step.Before != step.After || step.Exit != 0 || before.LastActionHash != built.HashString {
					t.Fatal("exact withdrawal replay changed typed state")
				}
				return
			}
			if step.Input.Kind == KindUpdateAgentPolicy {
				if after.AuthorizationEpoch != before.AuthorizationEpoch+1 || len(after.DelegationAdmissions) != 0 {
					t.Fatal("same-bytes policy update did not bump the epoch and clear admissions")
				}
				return
			}
			withdraw := step.Input.Kind == KindWithdrawAgentDelegation
			preflight := CheckDelegationMutation(before, digest, step.Input.Epoch, withdraw)
			if got, _ := ErrorCodeOf(preflight); got != step.Exit || step.Exit == 0 && preflight != nil {
				t.Fatalf("preflight differs from contract exit %d: %v", step.Exit, preflight)
			}
			if step.Exit != 0 {
				if step.Before != step.After {
					t.Fatal("refused action changed state")
				}
				return
			}
			found := false
			for _, entry := range after.DelegationAdmissions {
				if entry.Digest == digest && entry.AdmissionEpoch == step.Input.Epoch && entry.Withdrawn == withdraw {
					found = true
				}
			}
			if !found || step.OutMessages != 0 || after.AuthorizationEpoch != before.AuthorizationEpoch {
				t.Fatal("admission/withdrawal state or out-actions differ")
			}
		})
	}
}
