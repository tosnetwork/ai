package group

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

const (
	// MLSGroupIDSchema fixes the derivation of the opaque MLS group_id vector.
	MLSGroupIDSchema = "tos.messaging.mls-group-id.v1"
	// MLSGroupIDBytes is a SHA-256 output, short enough for every MLS codec and
	// collision-resistant without exposing the textual room identifier.
	MLSGroupIDBytes = sha256.Size
)

// MLSGroupID derives the exact opaque group_id from the TOS network and room.
// The genesis hashes enter as raw bytes, so their JSON/display encoding cannot
// create a second identity for the same network.
func MLSGroupID(network *nativev1.NetworkDomain, roomID string) ([]byte, error) {
	b, err := MLSGroupIDCanonicalBytes(network, roomID)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return append([]byte(nil), sum[:]...), nil
}

// MLSGroupIDCanonicalBytes returns the preimage consumed by MLSGroupID for
// cross-implementation vectors.
func MLSGroupIDCanonicalBytes(network *nativev1.NetworkDomain, roomID string) ([]byte, error) {
	if !ids.Room.MatchString(roomID) {
		return nil, errors.New("invalid MLS room identifier")
	}
	b := bytes.NewBufferString(canon.DomainMLSGroupID)
	canon.Text(b, MLSGroupIDSchema)
	if err := appendMLSNetwork(b, network); err != nil {
		return nil, err
	}
	canon.Text(b, roomID)
	return b.Bytes(), nil
}

func appendMLSNetwork(b *bytes.Buffer, network *nativev1.NetworkDomain) error {
	if b == nil || network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(network.GenesisFileHash) {
		return errors.New("invalid MLS network")
	}
	root, rootErr := hex.DecodeString(network.GenesisRootHash)
	file, fileErr := hex.DecodeString(network.GenesisFileHash)
	if rootErr != nil || fileErr != nil || len(root) != sha256.Size || len(file) != sha256.Size {
		return errors.New("invalid MLS genesis hashes")
	}
	canon.Text(b, network.NetworkId)
	canon.Bytes(b, root)
	canon.Bytes(b, file)
	return nil
}
