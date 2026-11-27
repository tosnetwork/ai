package agenttransport

import (
	"errors"
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

func TestVerifierRejectsUnapprovedNetworks(t *testing.T) {
	for _, bad := range unapprovedNetworkFixtures() {
		t.Run(bad.name, func(t *testing.T) {
			for _, mode := range []NetworkMode{TestNetworkLegacyEpochZero, TestNetworkEpochAware, Production, ""} {
				t.Run(string(mode), func(t *testing.T) {
					f := newFixture(t)
					f.c.Network = bad.network
					f.c.Mode = mode
					v, err := NewVerifier(f.c, f.r)
					if v != nil || !errors.Is(err, ErrUnapprovedNetwork) {
						t.Fatalf("unapproved network must be refused by identity before mode selection: %v", err)
					}
					if f.r.calls != 0 {
						t.Fatal("unapproved identity reached the resolver")
					}
				})
			}
		})
	}
}

func TestLegacyResolverRejectsUnapprovedNetworks(t *testing.T) {
	for _, bad := range unapprovedNetworkFixtures() {
		t.Run(bad.name, func(t *testing.T) {
			for _, mode := range []NetworkMode{TestNetworkLegacyEpochZero, TestNetworkEpochAware, Production, ""} {
				t.Run(string(mode), func(t *testing.T) {
					f := newFixture(t)
					source := legacySource{state: f.r.snapshot.State, found: true}
					resolver, err := NewLegacyTestNetworkResolver(mode, bad.network, source)
					if resolver != nil || !errors.Is(err, ErrUnapprovedNetwork) {
						t.Fatalf("unapproved network must be refused by identity before mode selection: %v", err)
					}
				})
			}
		})
	}
}

func TestApprovedNetworksAcceptOnlyExplicitTestModes(t *testing.T) {
	for _, network := range approvedNetworkFixtures() {
		t.Run(network.NetworkId, func(t *testing.T) {
			for _, mode := range []NetworkMode{TestNetworkLegacyEpochZero, TestNetworkEpochAware} {
				t.Run(string(mode), func(t *testing.T) {
					f := newFixture(t)
					f.c.Network = network
					f.c.Mode = mode
					f.r.snapshot.State.Network = proto.Clone(network).(*nativev1.NetworkDomain)
					if mode == TestNetworkLegacyEpochZero {
						f.d.AuthorizationEpoch = 0
						f.reencode(t)
						f.r.snapshot.CurrentEpoch = nil
						f.r.snapshot.AdmissionEpochs = nil
						f.r.snapshot.EpochCheckpoint = 0
						source := legacySource{state: f.r.snapshot.State, found: true}
						adapter, err := NewLegacyTestNetworkResolver(mode, network, source)
						if err != nil {
							t.Fatal(err)
						}
						v, err := NewVerifier(f.c, adapter)
						if err != nil {
							t.Fatal(err)
						}
						verify(t, v, f.wire, Relay, true)
					} else {
						verify(t, f.verifier(t), f.wire, Relay, true)
					}
				})
			}
			f := newFixture(t)
			f.c.Network = network
			f.c.Mode = Production
			if _, err := NewVerifier(f.c, f.r); err == nil {
				t.Fatal("allowlisting did not authorize production mode")
			}
		})
	}
}
