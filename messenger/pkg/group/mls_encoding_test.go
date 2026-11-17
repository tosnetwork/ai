package group

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

func TestMLSGroupIDBindsNetwork(t *testing.T) {
	network := mlsNetwork()
	groupID, err := MLSGroupID(network, "room_"+strings.Repeat("e", 64))
	if err != nil || len(groupID) != MLSGroupIDBytes {
		t.Fatalf("group id: %x %v", groupID, err)
	}
	otherNetwork := nativev1.NetworkDomain{NetworkId: network.NetworkId,
		GenesisRootHash: network.GenesisRootHash, GenesisFileHash: strings.Repeat("c", 64)}
	otherGroup, err := MLSGroupID(&otherNetwork, "room_"+strings.Repeat("e", 64))
	if err != nil || bytes.Equal(groupID, otherGroup) {
		t.Fatal("another network retained the MLS group identifier")
	}
	prefixed := nativev1.NetworkDomain{NetworkId: network.NetworkId,
		GenesisRootHash: "sha256:" + network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}
	if _, err := MLSGroupID(&prefixed, "room_"+strings.Repeat("e", 64)); err == nil {
		t.Fatal("display-prefixed genesis hash entered MLS canonical bytes")
	}
}

func TestMLSGroupIDVector(t *testing.T) {
	groupID, err := MLSGroupID(mlsNetwork(), "room_"+strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	// A candidate cross-library input: a profile change must update it
	// loudly rather than silently changing bytes under the same version.
	const expectedGroupIDHex = "5e020daea300c2231274ca1ecddea1119c262a329b6d888680884bd9fcf129ef"
	if hex.EncodeToString(groupID) != expectedGroupIDHex {
		t.Fatalf("group-id vector changed: %s", hex.EncodeToString(groupID))
	}
}
