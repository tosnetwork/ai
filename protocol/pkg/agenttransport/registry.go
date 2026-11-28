package agenttransport

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

// FinalizedStateReader is the typed, authenticated finalized read exposed by
// the protocol's chain resolver. The transport spec selects its strict-majority
// reader; a single unchecked RPC response does not implement this promise.
type FinalizedStateReader interface {
	ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error)
}

type RegistryResolver struct {
	source  FinalizedStateReader
	network *nativev1.NetworkDomain
}

// NewRegistryResolver adapts one authenticated finalized Registry read.
func NewRegistryResolver(network *nativev1.NetworkDomain, source FinalizedStateReader) (*RegistryResolver, error) {
	if err := validateNetwork(network); err != nil {
		return nil, err
	}
	if source == nil {
		return nil, errors.New("finalized Registry reader is required")
	}
	return &RegistryResolver{source: source, network: proto.Clone(network).(*nativev1.NetworkDomain)}, nil
}

func (r *RegistryResolver) ResolveFinalizedAgent(ctx context.Context, id string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !agentPattern.MatchString(id) {
		return Snapshot{}, errors.New("invalid Agent identifier")
	}
	state, found, err := r.source.ResolveState(ctx, id, "")
	if err != nil {
		return Snapshot{}, err
	}
	if err = ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !found {
		return Snapshot{}, nil
	}
	if state == nil || state.GetReference().GetContractCodeHash() != nativecore.RegistryV2CodeHash {
		return Snapshot{}, errors.New("finalized reader did not return Registry v2 state")
	}
	n := state.Network
	// The native reader uses sha256-prefixed genesis hashes. Check the original
	// tuple before changing its textual representation; never relabel a read
	// from another network with the configured transport network.
	if n == nil || n.NetworkId != r.network.NetworkId ||
		(n.GenesisRootHash != r.network.GenesisRootHash && n.GenesisRootHash != "sha256:"+r.network.GenesisRootHash) ||
		(n.GenesisFileHash != r.network.GenesisFileHash && n.GenesisFileHash != "sha256:"+r.network.GenesisFileHash) {
		return Snapshot{}, errors.New("finalized reader returned another network")
	}
	cloned := proto.Clone(state).(*nativev1.NativeStateV1)
	cloned.Network = proto.Clone(r.network).(*nativev1.NetworkDomain)
	agent := cloned.GetAgent()
	if agent.GetEncodingVersion() != nativecore.StateEncodingVersion || agent.GetAuthorizationEpoch() == 0 ||
		cloned.GetReference().GetFinalizedCheckpoint() == 0 {
		return Snapshot{}, errors.New("finalized Agent requires Registry schema 2 and a positive epoch")
	}
	live := make(map[[32]byte]uint64)
	for _, entry := range agent.DelegationAdmissions {
		if entry == nil || entry.AdmissionEpoch != agent.AuthorizationEpoch {
			return Snapshot{}, errors.New("invalid finalized delegation admission epoch")
		}
		if entry.Withdrawn {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(entry.Digest, "sha256:"))
		if err != nil || len(raw) != 32 {
			return Snapshot{}, errors.New("invalid finalized delegation digest")
		}
		live[[32]byte(raw)] = entry.AdmissionEpoch
	}
	epoch := agent.AuthorizationEpoch
	return Snapshot{State: cloned, CurrentEpoch: &epoch, AdmissionEpochs: live,
		EpochCheckpoint: cloned.Reference.FinalizedCheckpoint}, nil
}
