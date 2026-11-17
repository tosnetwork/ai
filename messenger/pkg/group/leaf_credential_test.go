package group

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// mlsLeafCredentials are a device's DeviceCredential and the matching leaf
// credential, both signed by the delegated Endpoint.
func mlsLeafCredentials(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey, device, setDigest string) DeviceLeafCredentials {
	t.Helper()
	dc := mlsCredential(t, delegation, key, device, setDigest)
	leaf, err := SignLeafCredential(LeafCredential{Network: dc.Network, AgentID: dc.AgentID, EndpointID: dc.EndpointID,
		DeviceID: dc.DeviceID, DeviceSetDigest: dc.DeviceSetDigest, LeafSignaturePublicKey: dc.LeafSignaturePublicKey,
		IssuedAtUnix: dc.IssuedAtUnix, ExpiresAtUnix: dc.ExpiresAtUnix}, key)
	if err != nil {
		t.Fatal(err)
	}
	return DeviceLeafCredentials{Device: dc, Leaf: leaf}
}

func testLeafCredential(t *testing.T) (identity.Delegation, ed25519.PrivateKey, LeafCredential) {
	t.Helper()
	delegation, key := mlsAuthority(t)
	return delegation, key, mlsLeafCredentials(t, delegation, key, mlsDevice("1"), canon.Digest([]byte("set"))).Leaf
}

func resignLeaf(t *testing.T, c LeafCredential, key ed25519.PrivateKey) LeafCredential {
	t.Helper()
	signed, err := SignLeafCredential(c, key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestLeafCredentialCodecIsStrictAndBounded(t *testing.T) {
	_, key, c := testLeafCredential(t)
	raw, err := EncodeLeafCredential(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeLeafCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeLeafCredential(decoded)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("a leaf credential does not round-trip")
	}
	// The largest credential, a 128-byte network ID, is 473 bytes.
	maximal := c
	maximal.Network = &nativev1.NetworkDomain{NetworkId: strings.Repeat("n", 128), GenesisRootHash: c.Network.GenesisRootHash,
		GenesisFileHash: c.Network.GenesisFileHash}
	maximalRaw, err := EncodeLeafCredential(resignLeaf(t, maximal, key))
	if err != nil || len(maximalRaw) != 473 || MaxLeafCredentialBytes != 473 {
		t.Fatalf("maximal credential %d bytes: %v", len(maximalRaw), err)
	}
	if _, err := DecodeLeafCredential(maximalRaw); err != nil {
		t.Fatalf("maximal credential refused: %v", err)
	}
	domain := len(canon.DomainMLSLeafCredential)
	suiteAt := len(raw) - ed25519.SignatureSize - 8 - 8 - 2
	mutations := map[string]func([]byte) []byte{
		"trailing byte": func(b []byte) []byte { return append(b, 0) },
		"truncated":     func(b []byte) []byte { return b[:len(b)-1] },
		"other domain":  func(b []byte) []byte { b[0] ^= 1; return b },
		"other suite":   func(b []byte) []byte { b[suiteAt+1] = 2; return b },
		"network length past the end": func(b []byte) []byte {
			b[domain], b[domain+1] = 0xff, 0xff
			return b
		},
		"empty network": func(b []byte) []byte {
			out := append([]byte(nil), b[:domain]...)
			out = append(out, 0, 0)
			return append(out, b[domain+2+len(c.Network.NetworkId):]...)
		},
		"zero leaf key": func(b []byte) []byte {
			keyAt := suiteAt - ed25519.PublicKeySize
			copy(b[keyAt:keyAt+ed25519.PublicKeySize], make([]byte, ed25519.PublicKeySize))
			return b
		},
		"over the bound": func(b []byte) []byte { return make([]byte, MaxLeafCredentialBytes+1) },
		"empty":          func(b []byte) []byte { return nil },
	}
	for name, mutate := range mutations {
		if _, err := DecodeLeafCredential(mutate(append([]byte(nil), raw...))); !errors.Is(err, ErrLeafCredentialMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	unsigned := c
	unsigned.EndpointSignature = nil
	if _, err := EncodeLeafCredential(unsigned); err == nil {
		t.Fatal("an unsigned credential encoded")
	}
	tooLong := c
	tooLong.ExpiresAtUnix = tooLong.IssuedAtUnix + MaxCredentialLifetimeSeconds + 1
	if _, err := SignLeafCredential(tooLong, key); err == nil {
		t.Fatal("a window over 30 days was signed")
	}
}

func TestLeafIdentityIsTheFixedCompactBinding(t *testing.T) {
	_, _, c := testLeafCredential(t)
	identityBytes, err := EncodeLeafIdentity(c)
	if err != nil || len(identityBytes) != LeafIdentityBytes || LeafIdentityBytes != 128 {
		t.Fatalf("identity %d bytes: %v", len(identityBytes), err)
	}
	decoded, err := DecodeLeafIdentity(identityBytes)
	if err != nil || decoded.AgentID != c.AgentID || decoded.EndpointID != c.EndpointID || decoded.DeviceID != c.DeviceID {
		t.Fatalf("identity: %+v %v", decoded, err)
	}
	raw, err := EncodeLeafCredential(c)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CredentialDigest != sha256.Sum256(raw) {
		t.Fatal("the identity does not name SHA-256 of the credential")
	}
	for _, length := range []int{0, 9, 127, 129, 4096} {
		if _, err := DecodeLeafIdentity(make([]byte, length)); !errors.Is(err, ErrLeafIdentityMalformed) {
			t.Fatalf("a %d-byte identity: %v", length, err)
		}
	}
}

func TestVerifyLeafCredentialAgainstTheDelegation(t *testing.T) {
	delegation, key, c := testLeafCredential(t)
	now := time.Unix(500, 0)
	if err := VerifyLeafCredential(delegation, c, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	forged := c
	forged.EndpointSignature = append([]byte(nil), c.EndpointSignature...)
	forged.EndpointSignature[0] ^= 1
	endpointKeyLeaf := c
	endpointKeyLeaf.LeafSignaturePublicKey = delegation.IdentityPublicKey
	otherNetwork := c
	otherNetwork.Network = &nativev1.NetworkDomain{NetworkId: "other", GenesisRootHash: c.Network.GenesisRootHash, GenesisFileHash: c.Network.GenesisFileHash}
	otherAgent := c
	otherAgent.AgentID = "agent_" + strings.Repeat("d", 64)
	otherEndpoint := c
	otherEndpoint.EndpointID = "mep_" + strings.Repeat("d", 64)
	outlives := c
	outlives.ExpiresAtUnix = delegation.ExpiresAtUnix + 1
	outlives.IssuedAtUnix = delegation.ExpiresAtUnix - 100
	cases := []struct {
		name       string
		credential LeafCredential
		at         time.Time
		want       error
	}{
		{"forged signature", forged, now, ErrLeafCredentialNotAuthentic},
		{"signed by another key", resignLeaf(t, c, other), now, ErrLeafCredentialNotAuthentic},
		{"leaf key is the Endpoint key", resignLeaf(t, endpointKeyLeaf, key), now, ErrLeafCredentialNotAuthentic},
		{"another network", resignLeaf(t, otherNetwork, key), now, ErrLeafCredentialNotAuthentic},
		{"another Agent", resignLeaf(t, otherAgent, key), now, ErrLeafCredentialNotAuthentic},
		{"another Endpoint", resignLeaf(t, otherEndpoint, key), now, ErrLeafCredentialNotAuthentic},
		{"outlives the delegation", resignLeaf(t, outlives, key), time.Unix(int64(delegation.ExpiresAtUnix)-50, 0), ErrLeafCredentialNotAuthentic},
		{"before its window", c, time.Unix(int64(c.IssuedAtUnix)-1, 0), ErrLeafCredentialNotAuthentic},
		{"at its expiry", c, time.Unix(int64(c.ExpiresAtUnix), 0), ErrLeafCredentialOutsideWindow},
		{"after the delegation", c, time.Unix(int64(delegation.ExpiresAtUnix), 0), ErrLeafCredentialNotAuthentic},
	}
	for _, test := range cases {
		if err := VerifyLeafCredential(delegation, test.credential, test.at); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v", test.name, err)
		}
	}
	if err := VerifyLeafCredential(delegation, c, time.Time{}); err == nil {
		t.Fatal("a zero time verified")
	}
}

// Before the delegation's window opens the delegation itself refuses; a
// credential issued later than now is outside its own window.
func TestLeafCredentialWindowAndRoomEnd(t *testing.T) {
	_, _, c := testLeafCredential(t)
	if err := checkLeafCredentialWindow(c, time.Unix(int64(c.IssuedAtUnix), 0), c.ExpiresAtUnix); err != nil {
		t.Fatalf("a credential lasting exactly until the end: %v", err)
	}
	if err := checkLeafCredentialWindow(c, time.Unix(int64(c.IssuedAtUnix), 0), c.ExpiresAtUnix+1); !errors.Is(err, ErrLeafCredentialOutsideWindow) {
		t.Fatalf("a credential ending before the room: %v", err)
	}
	if err := checkLeafCredentialWindow(c, time.Unix(int64(c.IssuedAtUnix)-1, 0), 0); !errors.Is(err, ErrLeafCredentialOutsideWindow) {
		t.Fatalf("before its window: %v", err)
	}
	if err := checkLeafCredentialWindow(c, time.Unix(int64(c.ExpiresAtUnix)-1, 0), 0); err != nil {
		t.Fatalf("last second: %v", err)
	}
}

func TestLeafCredentialDeviceIsCurrent(t *testing.T) {
	_, _, c := testLeafCredential(t)
	set := e2ee.SetSummary{EndpointID: c.EndpointID, Digest: c.DeviceSetDigest, DeviceIDs: []string{c.DeviceID}}
	if err := checkLeafCredentialDevice(c, set); err != nil {
		t.Fatal(err)
	}
	for name, stale := range map[string]e2ee.SetSummary{
		"a newer set":      {EndpointID: c.EndpointID, Digest: canon.Digest([]byte("newer")), DeviceIDs: []string{c.DeviceID}},
		"device removed":   {EndpointID: c.EndpointID, Digest: c.DeviceSetDigest, DeviceIDs: []string{mlsDevice("2")}},
		"another Endpoint": {EndpointID: "mep_" + strings.Repeat("d", 64), Digest: c.DeviceSetDigest, DeviceIDs: []string{c.DeviceID}},
	} {
		if err := checkLeafCredentialDevice(c, stale); !errors.Is(err, ErrLeafCredentialNotAuthentic) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The authority requires the joiner's two credentials to agree on every
// shared field before it builds the leaf it adds.
func TestLeafCredentialMustMatchTheDeviceCredential(t *testing.T) {
	delegation, key := mlsAuthority(t)
	pair := mlsLeafCredentials(t, delegation, key, mlsDevice("1"), canon.Digest([]byte("set")))
	leaf, err := LeafFromCredentials(pair.Device, pair.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLeaf(pair.Leaf, leaf.CredentialIdentity, leaf.LeafSignaturePublicKey); err != nil {
		t.Fatalf("built leaf: %v", err)
	}
	if ref, _ := KeyPackageRef(pair.Device); leaf.KeyPackageRef != ref || !bytes.Equal(leaf.KeyPackage, pair.Device.KeyPackage) {
		t.Fatal("the leaf lost its KeyPackage")
	}
	otherLeafKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	changes := map[string]func(*LeafCredential){
		"device":     func(c *LeafCredential) { c.DeviceID = mlsDevice("2") },
		"device set": func(c *LeafCredential) { c.DeviceSetDigest = canon.Digest([]byte("other set")) },
		"leaf key":   func(c *LeafCredential) { c.LeafSignaturePublicKey = otherLeafKey },
		"issued":     func(c *LeafCredential) { c.IssuedAtUnix++ },
		"expires":    func(c *LeafCredential) { c.ExpiresAtUnix-- },
		"network": func(c *LeafCredential) {
			c.Network = &nativev1.NetworkDomain{NetworkId: "other", GenesisRootHash: c.Network.GenesisRootHash, GenesisFileHash: c.Network.GenesisFileHash}
		},
		"Agent": func(c *LeafCredential) { c.AgentID = "agent_" + strings.Repeat("d", 64) },
	}
	for name, change := range changes {
		changed := pair.Leaf
		change(&changed)
		if _, err := LeafFromCredentials(pair.Device, resignLeaf(t, changed, key)); !errors.Is(err, ErrLeafMismatch) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// A leaf is the binding of a credential only if its identity names exactly
// that credential and its key is the credential's.
func TestCheckLeafBindsIdentityAndKey(t *testing.T) {
	delegation, key, c := testLeafCredential(t)
	set := e2ee.SetSummary{EndpointID: c.EndpointID, Digest: c.DeviceSetDigest, DeviceIDs: []string{c.DeviceID}}
	binding, err := VerifyRoomLeafCredential(delegation, c, set, c.ExpiresAtUnix, time.Unix(500, 0))
	if err != nil || binding.Validate() != nil {
		t.Fatalf("binding: %v", err)
	}
	if err := CheckLeaf(c, binding.Identity(), binding.SignatureKey()); err != nil {
		t.Fatal(err)
	}
	if !binding.Matches(MLSMember{Identity: binding.Identity(), SignatureKey: binding.SignatureKey()}) {
		t.Fatal("a binding does not match its own leaf")
	}
	if binding.Credential().AgentID != c.AgentID {
		t.Fatal("the binding lost its credential")
	}
	other := mlsLeafCredentials(t, delegation, key, mlsDevice("2"), canon.Digest([]byte("set"))).Leaf
	otherIdentity, err := EncodeLeafIdentity(other)
	if err != nil {
		t.Fatal(err)
	}
	// Same Agent, Endpoint and device, another credential (another window).
	renewed := c
	renewed.ExpiresAtUnix--
	renewedIdentity, err := EncodeLeafIdentity(resignLeaf(t, renewed, key))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		identity []byte
		key      ed25519.PublicKey
		want     error
	}{
		"another device's identity":   {otherIdentity, c.LeafSignaturePublicKey, ErrLeafMismatch},
		"another credential's digest": {renewedIdentity, c.LeafSignaturePublicKey, ErrLeafMismatch},
		"another leaf key":            {binding.Identity(), other.LeafSignaturePublicKey, ErrLeafMismatch},
		"a short identity":            {binding.Identity()[:127], c.LeafSignaturePublicKey, ErrLeafIdentityMalformed},
	}
	for name, test := range cases {
		if err := CheckLeaf(c, test.identity, test.key); !errors.Is(err, test.want) {
			t.Fatalf("%s: %v", name, err)
		}
		if binding.Matches(MLSMember{Identity: test.identity, SignatureKey: test.key}) {
			t.Fatalf("%s: the binding matched", name)
		}
	}
	if (LeafBinding{}).Validate() == nil {
		t.Fatal("the zero binding validated")
	}
	if (LeafBinding{identity: make([]byte, 9), signatureKey: c.LeafSignaturePublicKey}).Validate() == nil {
		t.Fatal("a 9-byte identity validated")
	}
	if (LeafBinding{identity: binding.Identity(), signatureKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}).Validate() == nil {
		t.Fatal("a zero key validated")
	}
	// The accessors hand out copies: changing one does not change the binding.
	identityCopy := binding.Identity()
	identityCopy[0] ^= 1
	if !binding.Matches(MLSMember{Identity: binding.Identity(), SignatureKey: binding.SignatureKey()}) {
		t.Fatal("an accessor exposed the binding's bytes")
	}
}

// VerifyRoomLeafCredential is the room path's one verification: everything
// VerifyLeafCredential checks, the current device set and the room's end.
func TestVerifyRoomLeafCredential(t *testing.T) {
	delegation, _, c := testLeafCredential(t)
	now := time.Unix(500, 0)
	set := e2ee.SetSummary{EndpointID: c.EndpointID, Digest: c.DeviceSetDigest, DeviceIDs: []string{c.DeviceID}}
	if _, err := VerifyRoomLeafCredential(delegation, c, set, c.ExpiresAtUnix, now); err != nil {
		t.Fatalf("a credential lasting until the end: %v", err)
	}
	forged := resignLeaf(t, c, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize)))
	stale := e2ee.SetSummary{EndpointID: c.EndpointID, Digest: canon.Digest([]byte("newer")), DeviceIDs: []string{c.DeviceID}}
	cases := []struct {
		name       string
		credential LeafCredential
		set        e2ee.SetSummary
		end        uint64
		want       error
	}{
		{"not signed by the Endpoint", forged, set, c.ExpiresAtUnix, ErrLeafCredentialNotAuthentic},
		{"device no longer current", c, stale, c.ExpiresAtUnix, ErrLeafCredentialNotAuthentic},
		{"ends before the room", c, set, c.ExpiresAtUnix + 1, ErrLeafCredentialOutsideWindow},
	}
	for _, test := range cases {
		binding, err := VerifyRoomLeafCredential(delegation, test.credential, test.set, test.end, now)
		if !errors.Is(err, test.want) || binding.Validate() == nil {
			t.Fatalf("%s: %v", test.name, err)
		}
	}
	if _, err := VerifyRoomLeafCredential(delegation, c, set, 0, now); err == nil {
		t.Fatal("a room leaf was verified without the room's end")
	}
}
