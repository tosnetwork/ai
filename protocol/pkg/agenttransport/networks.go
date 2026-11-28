package agenttransport

import (
	"errors"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// ErrUnapprovedNetwork refuses wallet use outside a reviewed
// genesis. A runtime mode string cannot enroll a network.
var ErrUnapprovedNetwork = errors.New("transport delegation network identity is not on the code-pinned approved test-network allowlist")

// These are complete, reviewed test-network identities. A reset needs a new
// source change and review; global id alone never authorizes the exception.
// NetworkId uses the canonical global-id spelling of the native network tuple.
const (
	localTestNetworkID  = "tos:global-id:3"
	localTestRoot       = "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366"
	localTestFile       = "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"
	publicTestNetworkID = "tos:global-id:2"
	publicTestRoot      = "7095f2295d9c0a2310e7530f3d4f7ac03970133a19d96167ac6aa87d03ff908c"
	publicTestFile      = "bfc773cfbb122917353c93f72494035d4986b7e4ae0dc8b7be39347f7a546186"
)

// ValidateApprovedTestNetwork validates the wallet command’s approved network tuple.
func ValidateApprovedTestNetwork(network *nativev1.NetworkDomain) error {
	if err := validateNetwork(network); err != nil {
		return err
	}
	approvedLocal := network.NetworkId == localTestNetworkID && network.GenesisRootHash == localTestRoot && network.GenesisFileHash == localTestFile
	approvedPublic := network.NetworkId == publicTestNetworkID && network.GenesisRootHash == publicTestRoot && network.GenesisFileHash == publicTestFile
	if !approvedLocal && !approvedPublic {
		return ErrUnapprovedNetwork
	}
	return nil
}
