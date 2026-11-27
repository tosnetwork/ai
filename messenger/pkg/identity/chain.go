package identity

import (
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

// MaxRegistryCodeHashes bounds a predeclared registry code set.
const MaxRegistryCodeHashes = agenttransport.MaxRegistryCodeHashes

// AgentResolver reads the outer finalized Agent state.
type AgentResolver interface {
	ResolveAgent(string) (*nativev1.NativeStateV1, bool, error)
}

// AccountLocator recomputes the account address for an object.
type AccountLocator = agenttransport.AccountLocator

// ChainPolicy declares the finalized registry state the caller accepts.
type ChainPolicy = agenttransport.ChainPolicy

// CheckState shares the finalized-state boundary with transport delegation verification.
func CheckState(policy ChainPolicy, network *nativev1.NetworkDomain, agentID string, state *nativev1.NativeStateV1) (*nativev1.AgentStateV1, error) {
	return agenttransport.CheckState(policy, network, agentID, state)
}
