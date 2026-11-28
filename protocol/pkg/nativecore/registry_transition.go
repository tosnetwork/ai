package nativecore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// opAuthorizedCapability is the opcode an owner Agent account uses to forward
// an authorized Capability action to the Capability account.
const opAuthorizedCapability = 0x4e560003

// RegistryTransitionKind names a terminal Registry liveness transition.
type RegistryTransitionKind uint8

const (
	// RegistryAgentTombstone is a revoke_agent action on an Agent account.
	RegistryAgentTombstone RegistryTransitionKind = iota + 1
	// RegistryCapabilityTombstone is a revoke_capability action without a
	// version on a Capability account.
	RegistryCapabilityTombstone
	// RegistryVersionRevocation is a revoke_capability action naming one
	// version on a Capability account.
	RegistryVersionRevocation
)

// RegistryTransitionV1 is a Registry inbound body that tombstones an object
// or revokes one Capability version.
type RegistryTransitionV1 struct {
	Kind RegistryTransitionKind
	// ObjectID is the target object, agent_<hex> or cap_<hex>.
	ObjectID string
	// ActionHash is the action cell hash, sha256:<hex>, the value a Registry
	// state records as last_action_hash once the action is applied.
	ActionHash string
	// Version is the revoked version name, for a version revocation only.
	Version string
}

// DecodeRegistryTransition decodes a Registry inbound body exactly as the
// contract reads it, opcode:uint32 query_id:uint64 ^action ^authority
// ^counterparty, and accepts only the three liveness transitions: a
// revoke_agent action submitted to an Agent account, and a revoke_capability
// action forwarded by the owner Agent to a Capability account, with or without
// a version. Any other body, including any other action, is an error.
func DecodeRegistryTransition(body *cell.Cell) (RegistryTransitionV1, error) {
	if body == nil || body.IsSpecial() {
		return RegistryTransitionV1{}, errors.New("Registry body is not an ordinary cell")
	}
	s, err := body.BeginParse()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("invalid Registry body")
	}
	opcode, err := s.LoadUInt(32)
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry body has no opcode")
	}
	if _, err := s.LoadUInt(64); err != nil {
		return RegistryTransitionV1{}, errors.New("Registry body has no query ID")
	}
	action, err := s.LoadRefCell()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry body has no action")
	}
	for _, name := range []string{"authority", "counterparty"} {
		if _, err := s.LoadRefCell(); err != nil {
			return RegistryTransitionV1{}, errors.New("Registry body has no " + name + " set")
		}
	}
	if err := endSlice(s); err != nil {
		return RegistryTransitionV1{}, err
	}
	if action.IsSpecial() {
		return RegistryTransitionV1{}, errors.New("Registry action is not an ordinary cell")
	}
	a, err := action.BeginParse()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("invalid Registry action")
	}
	magic, err := a.LoadUInt(32)
	if err != nil || magic != actionMagic {
		return RegistryTransitionV1{}, errors.New("Registry action magic is not NVA1")
	}
	version, err := a.LoadUInt(16)
	if err != nil || version != 1 {
		return RegistryTransitionV1{}, errors.New("unknown Registry action version")
	}
	kind, err := a.LoadUInt(8)
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no kind")
	}
	targetKind, err := a.LoadUInt(8)
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no target kind")
	}
	generation, err := a.LoadUInt(64)
	if err != nil || generation == 0 {
		return RegistryTransitionV1{}, errors.New("invalid Registry action generation")
	}
	sequence, err := a.LoadUInt(64)
	if err != nil || sequence == 0 {
		return RegistryTransitionV1{}, errors.New("invalid Registry action sequence")
	}
	target, err := a.LoadSlice(256)
	if err != nil || equalBytes(target, make([]byte, 32)) {
		return RegistryTransitionV1{}, errors.New("invalid Registry action target")
	}
	predecessor, err := a.LoadSlice(256)
	if err != nil || equalBytes(predecessor, make([]byte, 32)) {
		return RegistryTransitionV1{}, errors.New("a Registry revocation has no predecessor")
	}
	nonce, err := a.LoadSlice(256)
	if err != nil || equalBytes(nonce, make([]byte, 32)) {
		return RegistryTransitionV1{}, errors.New("invalid Registry action nonce")
	}
	if _, err := a.LoadRefCell(); err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no domain")
	}
	payload, err := a.LoadRefCell()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("Registry action has no payload")
	}
	if err := endSlice(a); err != nil {
		return RegistryTransitionV1{}, err
	}
	if payload.IsSpecial() {
		return RegistryTransitionV1{}, errors.New("Registry payload is not an ordinary cell")
	}
	p, err := payload.BeginParse()
	if err != nil {
		return RegistryTransitionV1{}, errors.New("invalid Registry payload")
	}
	result := RegistryTransitionV1{ActionHash: "sha256:" + hex.EncodeToString(action.Hash())}
	switch {
	case Kind(kind) == KindRevokeAgent && targetKind == 1 && opcode == opSubmit:
		if err := endSlice(p); err != nil {
			return RegistryTransitionV1{}, err
		}
		result.Kind, result.ObjectID = RegistryAgentTombstone, "agent_"+hex.EncodeToString(target)
		return result, nil
	case Kind(kind) == KindRevokeCapability && targetKind == 2 && opcode == opAuthorizedCapability:
		owner, err := p.LoadSlice(256)
		if err != nil || equalBytes(owner, make([]byte, 32)) {
			return RegistryTransitionV1{}, errors.New("invalid Capability revocation owner")
		}
		hasVersion, err := p.LoadBoolBit()
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation has no version flag")
		}
		result.ObjectID = "cap_" + hex.EncodeToString(target)
		if !hasVersion {
			if err := endSlice(p); err != nil {
				return RegistryTransitionV1{}, err
			}
			result.Kind = RegistryCapabilityTombstone
			return result, nil
		}
		versionHash, err := p.LoadSlice(256)
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation has no version hash")
		}
		nameCell, err := p.LoadRefCell()
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation has no version name")
		}
		if err := endSlice(p); err != nil {
			return RegistryTransitionV1{}, err
		}
		name, err := decodeProtocolText(nameCell, 128)
		if err != nil {
			return RegistryTransitionV1{}, errors.New("Capability revocation version name is not protocol text")
		}
		digest := sha256.Sum256([]byte(name))
		if !equalBytes(digest[:], versionHash) {
			return RegistryTransitionV1{}, errors.New("Capability revocation version hash does not match its name")
		}
		result.Kind, result.Version = RegistryVersionRevocation, name
		return result, nil
	}
	return RegistryTransitionV1{}, errors.New("Registry body is not a tombstone or version revocation")
}

// WithdrawalConfirmation describes a verified finalized goal. The original
// action may have been superseded, so this proof does not replace action
// reconciliation when the operation's exact outcome is needed.
type WithdrawalConfirmation struct {
	AgentID             string `json:"agent_id"`
	Digest              string `json:"delegation_digest"`
	ActionHash          string `json:"action_hash"`
	PriorEpoch          uint64 `json:"prior_epoch"`
	FinalizedEpoch      uint64 `json:"finalized_epoch"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	Result              string `json:"result"`
}

// ConfirmDelegationWithdrawal checks the goal against two authenticated
// finalized observations. A missing account or an exit code alone cannot
// prove that a previously live digest was revoked.
func ConfirmDelegationWithdrawal(action *nativev1.NativeActionV1, before, after *nativev1.NativeStateV1) (*WithdrawalConfirmation, error) {
	built, err := BuildAction(action)
	if err != nil {
		return nil, err
	}
	payload := action.GetWithdrawAgentDelegation()
	if payload == nil || action.TargetContractCodeHash != RegistryV2CodeHash {
		return nil, errors.New("Registry v2 withdrawal action required")
	}
	prior, current := before.GetAgent(), after.GetAgent()
	first, last := before.GetReference(), after.GetReference()
	if prior == nil || current == nil || first == nil || last == nil ||
		first.Account == "" || first.Account != last.Account ||
		first.ContractCodeHash != action.TargetContractCodeHash || last.ContractCodeHash != action.TargetContractCodeHash ||
		!proto.Equal(before.Network, action.Network) || !proto.Equal(after.Network, action.Network) ||
		prior.AgentId != action.TargetObjectId || current.AgentId != action.TargetObjectId ||
		first.FinalizedCheckpoint == 0 || first.FinalizedCheckpoint >= last.FinalizedCheckpoint {
		return nil, errors.New("withdrawal requires ordered finalized observations of the same Registry v2 Agent")
	}
	if prior.Tombstoned || before.TvmStateHash != action.PredecessorTvmStateHash ||
		prior.Generation != action.Generation || prior.Sequence == math.MaxUint64 || prior.Sequence+1 != action.Sequence {
		return nil, errors.New("withdrawal prior state does not match the signed predecessor")
	}
	if err := CheckDelegationMutation(prior, payload.DelegationDigest, payload.AuthorizationEpoch, true); err != nil {
		return nil, err
	}
	if current.EncodingVersion != StateEncodingVersion || current.AuthorizationEpoch < prior.AuthorizationEpoch ||
		current.Tombstoned && current.AuthorizationEpoch == prior.AuthorizationEpoch {
		return nil, errors.New("withdrawal finalized epoch is missing or regressed")
	}
	result := "cleared_by_epoch_bump"
	for _, entry := range current.DelegationAdmissions {
		if entry.GetDigest() != payload.DelegationDigest {
			continue
		}
		if current.AuthorizationEpoch != prior.AuthorizationEpoch || entry.AdmissionEpoch != current.AuthorizationEpoch || !entry.Withdrawn {
			return nil, errors.New("withdrawal digest is still present without proof of same-epoch withdrawal")
		}
		result = "withdrawn"
		break
	}
	if current.AuthorizationEpoch == prior.AuthorizationEpoch && result != "withdrawn" {
		return nil, errors.New("same-epoch absence cannot prove withdrawal")
	}
	return &WithdrawalConfirmation{AgentID: prior.AgentId, Digest: payload.DelegationDigest,
		ActionHash: built.HashString, PriorEpoch: prior.AuthorizationEpoch, FinalizedEpoch: current.AuthorizationEpoch,
		FinalizedCheckpoint: last.FinalizedCheckpoint, Result: result}, nil
}
