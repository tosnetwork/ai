package agenttransport

// NetworkIdentity returns the verifier's immutable network tuple, in the order
// network ID, zero-state root hash, zero-state file hash. State stores use this
// value to refuse cross-network key/journal reuse. It grants no authority; all
// objects still need their normal finalized verification. A zero verifier has
// no identity and is not a configured verifier.
func (v *Verifier) NetworkIdentity() [3]string {
	if v == nil || v.config.Network == nil {
		return [3]string{}
	}
	n := v.config.Network
	return [3]string{n.NetworkId, n.GenesisRootHash, n.GenesisFileHash}
}
