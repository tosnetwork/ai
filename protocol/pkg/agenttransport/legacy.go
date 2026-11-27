package agenttransport

import (
	"context"
	"errors"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

// FinalizedStateReader is the typed, proof-authenticated read exposed by the
// protocol's chain resolver. No direct RPC read implements this promise.
type FinalizedStateReader interface {
	ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error)
}

type LegacyTestNetworkResolver struct {
	source  FinalizedStateReader
	network *nativev1.NetworkDomain
}

// NewLegacyTestNetworkResolver adapts the deployed epoch-less finalized reader
// only in an explicit test-network mode. It never fabricates epoch metadata.
// network uses the transport's bare genesis hash representation.
func NewLegacyTestNetworkResolver(mode NetworkMode, network *nativev1.NetworkDomain, source FinalizedStateReader) (*LegacyTestNetworkResolver, error) {
	if err := validateApprovedTestNetwork(network); err != nil {
		return nil, err
	}
	if mode != TestNetworkLegacyEpochZero || source == nil {
		return nil, errors.New("epoch-less resolver requires explicit test-network-legacy-epoch-zero mode")
	}
	return &LegacyTestNetworkResolver{source: source, network: proto.Clone(network).(*nativev1.NetworkDomain)}, nil
}

func (r *LegacyTestNetworkResolver) ResolveFinalizedAgent(ctx context.Context, id string) (Snapshot, error) {
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
	if !found || state == nil {
		return Snapshot{}, nil
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
	return Snapshot{State: cloned}, nil
}
