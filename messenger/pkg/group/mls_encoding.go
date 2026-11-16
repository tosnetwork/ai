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
	// MLSBasicCredentialSchema fixes the application-defined opaque identity
	// bytes carried inside the interoperable RFC 9420 BasicCredential.
	MLSBasicCredentialSchema = "tos.messaging.mls-basic-credential.v1"
	// MLSGroupIDSchema fixes the derivation of the opaque MLS group_id vector.
	MLSGroupIDSchema = "tos.messaging.mls-group-id.v1"
	// MLSGroupIDBytes is a SHA-256 output, short enough for every MLS codec and
	// collision-resistant without exposing the textual room identifier.
	MLSGroupIDBytes = sha256.Size
)

// BasicCredentialIdentity returns the exact bytes placed in the MLS
// BasicCredential identity field. This is an application identity binding,
// not authority: callers must still verify DeviceCredential against finalized
// Endpoint and current device-set state before admitting its KeyPackage.
func BasicCredentialIdentity(c DeviceCredential) ([]byte, error) {
	if err := validateCredential(c, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainMLSBasicCredential)
	canon.Text(b, MLSBasicCredentialSchema)
	if err := appendMLSNetwork(b, c.Network); err != nil {
		return nil, err
	}
	canon.Text(b, c.AgentID)
	canon.Text(b, c.EndpointID)
	canon.Text(b, c.DeviceID)
	canon.Text(b, c.DeviceSetDigest)
	canon.Bytes(b, c.LeafSignaturePublicKey)
	canon.Uint32(b, uint32(MLSCipherSuite))
	return b.Bytes(), nil
}

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

// BasicCredential is the TOS identity a member's MLS leaf carries, as the
// driver reports it for the sender of a message or Commit. It names the
// Agent, Endpoint and device the leaf's DeviceCredential bound; it is no
// authority by itself, only what a receiver pins further checks to.
type BasicCredential struct {
	Network                *nativev1.NetworkDomain
	AgentID                string
	EndpointID             string
	DeviceID               string
	DeviceSetDigest        string
	LeafSignaturePublicKey []byte
}

// DecodeBasicCredentialIdentity parses BasicCredentialIdentity bytes and
// refuses any other encoding of the same values: the identity is re-encoded
// and must reproduce the input exactly.
func DecodeBasicCredentialIdentity(raw []byte) (BasicCredential, error) {
	invalid := errors.New("invalid MLS BasicCredential identity")
	reader := canon.NewReader(canon.DomainMLSBasicCredential, raw)
	if reader.Text(64) != MLSBasicCredentialSchema {
		return BasicCredential{}, invalid
	}
	networkID := reader.Text(128)
	root := reader.Bytes(sha256.Size)
	file := reader.Bytes(sha256.Size)
	value := BasicCredential{AgentID: reader.Text(128), EndpointID: reader.Text(128), DeviceID: reader.Text(128),
		DeviceSetDigest: reader.Text(128), LeafSignaturePublicKey: reader.Bytes(32)}
	suite := reader.Uint32()
	if err := reader.Done(); err != nil || suite != uint32(MLSCipherSuite) || len(root) != sha256.Size || len(file) != sha256.Size {
		return BasicCredential{}, invalid
	}
	value.Network = &nativev1.NetworkDomain{NetworkId: networkID, GenesisRootHash: hex.EncodeToString(root), GenesisFileHash: hex.EncodeToString(file)}
	if !ids.Agent.MatchString(value.AgentID) || !ids.Endpoint.MatchString(value.EndpointID) || !ids.Device.MatchString(value.DeviceID) ||
		!canon.ValidDigest(value.DeviceSetDigest) || len(value.LeafSignaturePublicKey) != 32 || canon.IsZero(value.LeafSignaturePublicKey) {
		return BasicCredential{}, invalid
	}
	again := bytes.NewBufferString(canon.DomainMLSBasicCredential)
	canon.Text(again, MLSBasicCredentialSchema)
	if err := appendMLSNetwork(again, value.Network); err != nil {
		return BasicCredential{}, invalid
	}
	canon.Text(again, value.AgentID)
	canon.Text(again, value.EndpointID)
	canon.Text(again, value.DeviceID)
	canon.Text(again, value.DeviceSetDigest)
	canon.Bytes(again, value.LeafSignaturePublicKey)
	canon.Uint32(again, uint32(MLSCipherSuite))
	if !bytes.Equal(again.Bytes(), raw) {
		return BasicCredential{}, invalid
	}
	return value, nil
}
