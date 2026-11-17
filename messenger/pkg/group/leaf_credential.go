package group

// The compact leaf identity and the leaf credential of a relay room leaf
// (section 11.2).
//
// The identity in a leaf's MLS BasicCredential is copied into the ratchet
// tree and into every retained epoch, so it is a fixed 128-byte binding:
//
//	leaf_identity =
//	  agent                   32   raw digest of the agent_ ID
//	  endpoint                32   raw digest of the mep_ ID
//	  device                  32   raw digest of the dev_ ID
//	  leaf_credential_digest  32   SHA-256(leaf_credential)
//
// The leaf credential is the Endpoint-signed statement the identity names by
// digest. It does not name the KeyPackage: the KeyPackage carries the
// identity, which names the credential, so a reference back would be
// circular. It is bound to the leaf by the leaf signature key.
//
//	leaf_credential =
//	  D("tos.messaging.mls-leaf-credential.v1")   37 bytes
//	  network_id          u16-prefixed, 1 .. 128 bytes
//	  genesis_root        32
//	  genesis_file        32
//	  agent               32
//	  endpoint            32
//	  device              32
//	  device_set_digest   32
//	  leaf_signature_key  32
//	  cipher_suite        u16  0x0001
//	  issued_at           u64
//	  expires_at          u64
//	  signature           64   the Endpoint's Ed25519 signature over every
//	                           byte before it

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

const (
	// LeafIdentityBytes is the exact length of a relay room leaf identity.
	LeafIdentityBytes = 4 * sha256.Size
	// MaxLeafCredentialBytes is the largest valid leaf credential: a
	// 128-byte network ID.
	MaxLeafCredentialBytes = len(canon.DomainMLSLeafCredential) + 2 + maxLeafNetworkBytes + 2*sha256.Size +
		5*sha256.Size + 2 + 8 + 8 + ed25519.SignatureSize
	// MaxLeafCredentialCodecBytes is the bound a codec carrying a leaf
	// credential applies (a roster entry, a room.invite, room.key-package).
	MaxLeafCredentialCodecBytes = 512

	maxLeafNetworkBytes = 128
)

// The arithmetic of section 11.2: the largest credential is 473 bytes and
// fits the 512-byte codec bound.
var (
	_ [MaxLeafCredentialBytes - 473]struct{}
	_ [473 - MaxLeafCredentialBytes]struct{}
	_ [MaxLeafCredentialCodecBytes - MaxLeafCredentialBytes]struct{}
)

// Leaf credential errors. Every refusal is one of these, so callers map them
// to fault codes without reading messages.
var (
	// ErrLeafCredentialMalformed: the bytes are not a canonical credential.
	ErrLeafCredentialMalformed = errors.New("leaf credential is malformed")
	// ErrLeafIdentityMalformed: the identity is not the 128-byte binding.
	ErrLeafIdentityMalformed = errors.New("MLS leaf identity is not the 128-byte compact binding")
	// ErrLeafCredentialNotAuthentic: the credential is not the delegation's,
	// not of this network, or its signature does not verify.
	ErrLeafCredentialNotAuthentic = errors.New("leaf credential is not authentic")
	// ErrLeafCredentialOutsideWindow: now is outside the credential's
	// window, or the window does not last as long as it must.
	ErrLeafCredentialOutsideWindow = errors.New("leaf credential is outside its validity window")
	// ErrLeafMismatch: a leaf, identity or DeviceCredential does not match
	// the credential.
	ErrLeafMismatch = errors.New("MLS leaf does not match its leaf credential")
)

// LeafCredential is a member's Endpoint-signed binding of an MLS leaf
// signature key to its Agent, Endpoint and device.
type LeafCredential struct {
	Network                *nativev1.NetworkDomain
	AgentID                string
	EndpointID             string
	DeviceID               string
	DeviceSetDigest        string
	LeafSignaturePublicKey ed25519.PublicKey
	IssuedAtUnix           uint64
	ExpiresAtUnix          uint64
	EndpointSignature      []byte
}

// LeafIdentity is a decoded 128-byte compact leaf identity.
type LeafIdentity struct {
	AgentID          string
	EndpointID       string
	DeviceID         string
	CredentialDigest [sha256.Size]byte
}

// LeafCredentialSigningBytes returns every byte of the credential before its
// signature: what the Endpoint signs.
func LeafCredentialSigningBytes(c LeafCredential) ([]byte, error) {
	if err := validateLeafCredential(c, false); err != nil {
		return nil, err
	}
	out := bytes.NewBuffer(make([]byte, 0, MaxLeafCredentialBytes))
	out.WriteString(canon.DomainMLSLeafCredential)
	var number [8]byte
	binary.BigEndian.PutUint16(number[:2], uint16(len(c.Network.NetworkId)))
	out.Write(number[:2])
	out.WriteString(c.Network.NetworkId)
	for _, value := range []string{c.Network.GenesisRootHash, c.Network.GenesisFileHash} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != sha256.Size {
			return nil, ErrLeafCredentialMalformed
		}
		out.Write(raw)
	}
	for _, id := range []string{c.AgentID, c.EndpointID, c.DeviceID} {
		raw, err := rawID(id)
		if err != nil {
			return nil, err
		}
		out.Write(raw)
	}
	setDigest, err := hex.DecodeString(c.DeviceSetDigest[len("sha256:"):])
	if err != nil || len(setDigest) != sha256.Size {
		return nil, ErrLeafCredentialMalformed
	}
	out.Write(setDigest)
	out.Write(c.LeafSignaturePublicKey)
	binary.BigEndian.PutUint16(number[:2], MLSCipherSuite)
	out.Write(number[:2])
	binary.BigEndian.PutUint64(number[:], c.IssuedAtUnix)
	out.Write(number[:])
	binary.BigEndian.PutUint64(number[:], c.ExpiresAtUnix)
	out.Write(number[:])
	return out.Bytes(), nil
}

// SignLeafCredential signs a credential with the delegated Endpoint key.
func SignLeafCredential(c LeafCredential, endpointKey ed25519.PrivateKey) (LeafCredential, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return LeafCredential{}, errors.New("invalid endpoint signing key")
	}
	c.EndpointSignature = nil
	preimage, err := LeafCredentialSigningBytes(c)
	if err != nil {
		return LeafCredential{}, err
	}
	c.EndpointSignature = ed25519.Sign(endpointKey, preimage)
	return c, nil
}

// EncodeLeafCredential returns the canonical bytes of a signed credential.
func EncodeLeafCredential(c LeafCredential) ([]byte, error) {
	if err := validateLeafCredential(c, true); err != nil {
		return nil, err
	}
	preimage, err := LeafCredentialSigningBytes(c)
	if err != nil {
		return nil, err
	}
	return append(preimage, c.EndpointSignature...), nil
}

// DecodeLeafCredential strictly parses a credential: trailing bytes, any
// other encoding of the same values, another suite and a credential over
// MaxLeafCredentialBytes are refused. It checks shape only; whose the
// credential is, and whether it is current, is VerifyLeafCredential's.
func DecodeLeafCredential(raw []byte) (LeafCredential, error) {
	minimum := len(canon.DomainMLSLeafCredential) + 2 + 1 + 7*sha256.Size + 2 + 8 + 8 + ed25519.SignatureSize
	if len(raw) < minimum || len(raw) > MaxLeafCredentialBytes ||
		!bytes.HasPrefix(raw, []byte(canon.DomainMLSLeafCredential)) {
		return LeafCredential{}, ErrLeafCredentialMalformed
	}
	offset := len(canon.DomainMLSLeafCredential)
	take := func(n int) []byte {
		if n < 0 || offset > len(raw)-n {
			offset = len(raw) + 1
			return nil
		}
		value := raw[offset : offset+n]
		offset += n
		return value
	}
	networkLength := take(2)
	if networkLength == nil {
		return LeafCredential{}, ErrLeafCredentialMalformed
	}
	networkID := take(int(binary.BigEndian.Uint16(networkLength)))
	root, file := take(sha256.Size), take(sha256.Size)
	agent, endpoint, device := take(sha256.Size), take(sha256.Size), take(sha256.Size)
	setDigest, leafKey := take(sha256.Size), take(ed25519.PublicKeySize)
	suite, issued, expires := take(2), take(8), take(8)
	signature := take(ed25519.SignatureSize)
	if signature == nil || offset != len(raw) {
		return LeafCredential{}, ErrLeafCredentialMalformed
	}
	if binary.BigEndian.Uint16(suite) != MLSCipherSuite {
		return LeafCredential{}, ErrLeafCredentialMalformed
	}
	c := LeafCredential{
		Network: &nativev1.NetworkDomain{NetworkId: string(networkID), GenesisRootHash: hex.EncodeToString(root),
			GenesisFileHash: hex.EncodeToString(file)},
		AgentID:                "agent_" + hex.EncodeToString(agent),
		EndpointID:             "mep_" + hex.EncodeToString(endpoint),
		DeviceID:               "dev_" + hex.EncodeToString(device),
		DeviceSetDigest:        "sha256:" + hex.EncodeToString(setDigest),
		LeafSignaturePublicKey: append(ed25519.PublicKey(nil), leafKey...),
		IssuedAtUnix:           binary.BigEndian.Uint64(issued),
		ExpiresAtUnix:          binary.BigEndian.Uint64(expires),
		EndpointSignature:      append([]byte(nil), signature...),
	}
	again, err := EncodeLeafCredential(c)
	if err != nil || !bytes.Equal(again, raw) {
		return LeafCredential{}, ErrLeafCredentialMalformed
	}
	return c, nil
}

// LeafCredentialDigest is SHA-256 of the canonical credential bytes: what the
// leaf identity names.
func LeafCredentialDigest(c LeafCredential) ([sha256.Size]byte, error) {
	encoded, err := EncodeLeafCredential(c)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// EncodeLeafIdentity returns the 128-byte compact identity naming c.
func EncodeLeafIdentity(c LeafCredential) ([]byte, error) {
	digest, err := LeafCredentialDigest(c)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, LeafIdentityBytes)
	for _, id := range []string{c.AgentID, c.EndpointID, c.DeviceID} {
		raw, err := rawID(id)
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)
	}
	return append(out, digest[:]...), nil
}

// DecodeLeafIdentity parses a compact identity. Any length other than 128
// bytes is refused: the relay room path carries no other identity.
func DecodeLeafIdentity(raw []byte) (LeafIdentity, error) {
	if len(raw) != LeafIdentityBytes {
		return LeafIdentity{}, ErrLeafIdentityMalformed
	}
	identity := LeafIdentity{
		AgentID:    "agent_" + hex.EncodeToString(raw[0:32]),
		EndpointID: "mep_" + hex.EncodeToString(raw[32:64]),
		DeviceID:   "dev_" + hex.EncodeToString(raw[64:96]),
	}
	copy(identity.CredentialDigest[:], raw[96:128])
	return identity, nil
}

// VerifyLeafCredential checks a credential against its Agent's delegation as
// finalized now: the delegation's Agent, Endpoint and network, a leaf key
// distinct from the Endpoint key, a window no longer than 30 days that does
// not outlast the delegation and holds now, and the Endpoint's signature.
func VerifyLeafCredential(delegation identity.Delegation, c LeafCredential, now time.Time) error {
	if err := validateLeafCredential(c, true); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid leaf credential verification time")
	}
	if err := identity.CheckWindow(delegation, now); err != nil {
		return ErrLeafCredentialNotAuthentic
	}
	if c.AgentID != delegation.AgentID || c.EndpointID != delegation.EndpointID || !sameLeafNetwork(c.Network, delegation.Network) {
		return ErrLeafCredentialNotAuthentic
	}
	if len(delegation.IdentityPublicKey) != ed25519.PublicKeySize || bytes.Equal(c.LeafSignaturePublicKey, delegation.IdentityPublicKey) {
		return ErrLeafCredentialNotAuthentic
	}
	if c.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return ErrLeafCredentialNotAuthentic
	}
	preimage, err := LeafCredentialSigningBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, c.EndpointSignature) {
		return ErrLeafCredentialNotAuthentic
	}
	return CheckLeafCredentialWindow(c, now, 0)
}

// CheckLeafCredentialWindow requires now to be inside the credential's
// window and, when lastsUntilUnix is not zero, the window to last at least
// until then (a room's end, D18).
func CheckLeafCredentialWindow(c LeafCredential, now time.Time, lastsUntilUnix uint64) error {
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid leaf credential verification time")
	}
	seconds := uint64(now.Unix())
	if seconds < c.IssuedAtUnix || seconds >= c.ExpiresAtUnix {
		return ErrLeafCredentialOutsideWindow
	}
	if lastsUntilUnix != 0 && c.ExpiresAtUnix < lastsUntilUnix {
		return ErrLeafCredentialOutsideWindow
	}
	return nil
}

// CheckLeafCredentialDevice requires the credential's device to be current in
// the Endpoint's device set, the set the credential names.
func CheckLeafCredentialDevice(c LeafCredential, currentSet e2ee.SetSummary) error {
	if currentSet.EndpointID != c.EndpointID || currentSet.Digest != c.DeviceSetDigest || !contains(currentSet.DeviceIDs, c.DeviceID) {
		return ErrLeafCredentialNotAuthentic
	}
	return nil
}

// MatchLeafToDeviceCredential requires a joiner's leaf credential and the
// DeviceCredential of its KeyPackage to name the same Agent, Endpoint,
// device, device set, leaf signature key, network and window.
func MatchLeafToDeviceCredential(leaf LeafCredential, device DeviceCredential) error {
	if err := validateLeafCredential(leaf, true); err != nil {
		return err
	}
	if err := validateCredential(device, true); err != nil {
		return err
	}
	if leaf.AgentID != device.AgentID || leaf.EndpointID != device.EndpointID || leaf.DeviceID != device.DeviceID ||
		leaf.DeviceSetDigest != device.DeviceSetDigest || !bytes.Equal(leaf.LeafSignaturePublicKey, device.LeafSignaturePublicKey) ||
		!sameLeafNetwork(leaf.Network, device.Network) || leaf.IssuedAtUnix != device.IssuedAtUnix || leaf.ExpiresAtUnix != device.ExpiresAtUnix {
		return ErrLeafMismatch
	}
	return nil
}

// CheckLeaf requires an MLS leaf (its BasicCredential identity and signature
// key, as the driver reports them) to be exactly the compact binding of c:
// the identity's Agent, Endpoint, device and digest are c's, and the leaf's
// key is c's leaf signature key.
func CheckLeaf(c LeafCredential, leafIdentity []byte, leafSignatureKey ed25519.PublicKey) error {
	decoded, err := DecodeLeafIdentity(leafIdentity)
	if err != nil {
		return err
	}
	digest, err := LeafCredentialDigest(c)
	if err != nil {
		return err
	}
	if decoded.AgentID != c.AgentID || decoded.EndpointID != c.EndpointID || decoded.DeviceID != c.DeviceID ||
		decoded.CredentialDigest != digest || !bytes.Equal(leafSignatureKey, c.LeafSignaturePublicKey) {
		return ErrLeafMismatch
	}
	return nil
}

// LeafFromCredentials builds the relay room leaf a joiner's KeyPackage must
// carry: the leaf credential and the DeviceCredential must match, and the
// leaf's identity is the compact binding naming the leaf credential. The
// result is what a Driver validates the KeyPackage against before an Add.
func LeafFromCredentials(device DeviceCredential, leaf LeafCredential) (Leaf, error) {
	if err := MatchLeafToDeviceCredential(leaf, device); err != nil {
		return Leaf{}, err
	}
	ref, err := KeyPackageRef(device)
	if err != nil {
		return Leaf{}, err
	}
	identity, err := EncodeLeafIdentity(leaf)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{AgentID: device.AgentID, EndpointID: device.EndpointID, DeviceID: device.DeviceID,
		DeviceSetDigest: device.DeviceSetDigest, KeyPackageRef: ref, CredentialIdentity: identity,
		LeafSignaturePublicKey: append(ed25519.PublicKey(nil), device.LeafSignaturePublicKey...),
		KeyPackage:             append([]byte(nil), device.KeyPackage...)}, nil
}

// LeafBinding is the MLS leaf a verified leaf credential expects: its
// compact identity and its leaf signature key. A receiver passes it to the
// room controller, which refuses a Commit or message whose MLS sender is any
// other leaf.
type LeafBinding struct {
	Identity     []byte
	SignatureKey ed25519.PublicKey
}

// LeafBindingOf returns the leaf a credential expects.
func LeafBindingOf(c LeafCredential) (LeafBinding, error) {
	identity, err := EncodeLeafIdentity(c)
	if err != nil {
		return LeafBinding{}, err
	}
	return LeafBinding{Identity: identity, SignatureKey: append(ed25519.PublicKey(nil), c.LeafSignaturePublicKey...)}, nil
}

// Validate checks a binding's shape: a 128-byte compact identity and an
// Ed25519 key.
func (b LeafBinding) Validate() error {
	if _, err := DecodeLeafIdentity(b.Identity); err != nil {
		return err
	}
	if len(b.SignatureKey) != ed25519.PublicKeySize || canon.IsZero(b.SignatureKey) {
		return ErrLeafMismatch
	}
	return nil
}

// Matches reports whether a driver-reported leaf is exactly this binding.
func (b LeafBinding) Matches(member MLSMember) bool {
	return bytes.Equal(b.Identity, member.Identity) && bytes.Equal(b.SignatureKey, member.SignatureKey)
}

func validateLeafCredential(c LeafCredential, signed bool) error {
	if c.Network == nil || c.Network.NetworkId == "" || len(c.Network.NetworkId) > maxLeafNetworkBytes ||
		!canon.HashPattern.MatchString(c.Network.GenesisRootHash) || !canon.HashPattern.MatchString(c.Network.GenesisFileHash) {
		return ErrLeafCredentialMalformed
	}
	if !ids.Agent.MatchString(c.AgentID) || !ids.Endpoint.MatchString(c.EndpointID) || !ids.Device.MatchString(c.DeviceID) ||
		!canon.ValidDigest(c.DeviceSetDigest) {
		return ErrLeafCredentialMalformed
	}
	if len(c.LeafSignaturePublicKey) != ed25519.PublicKeySize || canon.IsZero(c.LeafSignaturePublicKey) {
		return ErrLeafCredentialMalformed
	}
	if c.IssuedAtUnix == 0 || c.ExpiresAtUnix <= c.IssuedAtUnix || c.ExpiresAtUnix-c.IssuedAtUnix > MaxCredentialLifetimeSeconds {
		return ErrLeafCredentialMalformed
	}
	if signed && len(c.EndpointSignature) != ed25519.SignatureSize {
		return ErrLeafCredentialMalformed
	}
	return nil
}

func sameLeafNetwork(a, b *nativev1.NetworkDomain) bool {
	return a != nil && b != nil && a.NetworkId == b.NetworkId && a.GenesisRootHash == b.GenesisRootHash &&
		a.GenesisFileHash == b.GenesisFileHash
}

// rawID returns the 32 raw bytes of an agent_, mep_ or dev_ identifier.
func rawID(id string) ([]byte, error) {
	var prefix string
	switch {
	case ids.Agent.MatchString(id):
		prefix = "agent_"
	case ids.Endpoint.MatchString(id):
		prefix = "mep_"
	case ids.Device.MatchString(id):
		prefix = "dev_"
	default:
		return nil, ErrLeafCredentialMalformed
	}
	raw, err := hex.DecodeString(id[len(prefix):])
	if err != nil || len(raw) != sha256.Size {
		return nil, ErrLeafCredentialMalformed
	}
	return raw, nil
}
