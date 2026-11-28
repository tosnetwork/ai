package agenttransport

import (
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

// These independent expectations pin the reviewed enrollment, rather than
// silently following a changed production constant.
func approvedNetworkFixtures() []*nativev1.NetworkDomain {
	return []*nativev1.NetworkDomain{
		{NetworkId: "tos:global-id:3", GenesisRootHash: "65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366", GenesisFileHash: "c3860fe196a2a1b5e4e74a9cf9448624a353ce68a8c4c5f6413347586d688769"},
		{NetworkId: "tos:global-id:2", GenesisRootHash: "7095f2295d9c0a2310e7530f3d4f7ac03970133a19d96167ac6aa87d03ff908c", GenesisFileHash: "bfc773cfbb122917353c93f72494035d4986b7e4ae0dc8b7be39347f7a546186"},
	}
}

type badNetwork struct {
	name    string
	network *nativev1.NetworkDomain
}

func unapprovedNetworkFixtures() []badNetwork {
	pins := approvedNetworkFixtures()
	change := func(n *nativev1.NetworkDomain, field, value string) *nativev1.NetworkDomain {
		n = proto.Clone(n).(*nativev1.NetworkDomain)
		switch field {
		case "id":
			n.NetworkId = value
		case "root":
			n.GenesisRootHash = value
		case "file":
			n.GenesisFileHash = value
		}
		return n
	}
	return []badNetwork{
		{"production-identity", change(pins[0], "id", "tos:global-id:1")},
		{"unknown-identity", change(pins[0], "id", "tos:global-id:99")},
		{"local-root", change(pins[0], "root", strings.Repeat("a", 64))},
		{"local-file", change(pins[0], "file", strings.Repeat("b", 64))},
		{"public-global-id", change(pins[1], "id", "tos:global-id:1")},
		{"public-root", change(pins[1], "root", strings.Repeat("a", 64))},
		{"public-file", change(pins[1], "file", strings.Repeat("b", 64))},
		{"global-id-alias", change(pins[0], "id", "tos:global-id:03")},
		{"mixed-identities", change(pins[0], "file", pins[1].GenesisFileHash)},
	}
}

func TestWalletNetworkRequiresApprovedGenesis(t *testing.T) {
	for _, tc := range unapprovedNetworkFixtures() {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateApprovedTestNetwork(tc.network); err == nil {
				t.Fatal("unapproved network accepted")
			}
		})
	}
	for _, network := range approvedNetworkFixtures() {
		if err := ValidateApprovedTestNetwork(network); err != nil {
			t.Fatal(err)
		}
	}
}
