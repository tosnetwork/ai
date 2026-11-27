package agenttransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"filippo.io/edwards25519"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// Relay credential limits of section 5.2, 5.3 and 15.
const (
	MaxCredentialSize       = 2048
	MaxCredentialBlocks     = 4
	MaxCaveatsPerBlock      = 8
	MaxRelayURLBytes        = 256
	MaxEnvelopeBytes        = 262144
	MaxContactLaneEnvelopes = 64
	// ClockSkewSeconds is the not_before tolerance of credentials and delegations.
	ClockSkewSeconds = 300

	credentialDomain      = "tos.service.relay-credential.v1\x00"
	credentialChainDomain = "tos.service.relay-credential.chain.v1\x00"
	credentialBlockDomain = "tos.service.relay-credential.block.v1\x00"
	// domain, delegation and block_count precede the blocks.
	credentialHeaderSize = len(credentialDomain) + DelegationSize + 1
)

// Refusal classes of section 6.6. Every refusal wraps exactly one of them.
var (
	// ErrCredentialInvalid is a decode, chain, signature, proof or nonce failure.
	ErrCredentialInvalid = errors.New("credential_invalid")
	// ErrCredentialScope is a caveat failure or a path naming another Agent.
	ErrCredentialScope = errors.New("credential_scope")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCredentialInvalid}, args...)...)
}

func scope(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCredentialScope}, args...)...)
}

// CaveatType is the closed caveat set of section 5.3.
type CaveatType byte

const (
	CaveatNotBefore        CaveatType = 1
	CaveatNotAfter         CaveatType = 2
	CaveatRelay            CaveatType = 3
	CaveatOperations       CaveatType = 4
	CaveatLane             CaveatType = 5
	CaveatMaxEnvelopes     CaveatType = 6
	CaveatMaxEnvelopeBytes CaveatType = 7
	CaveatMaxLaneBytes     CaveatType = 8
)

// Operation is one bit of the operations caveat.
type Operation uint16

const (
	OperationDeposit Operation = 1 << 0
	OperationList    Operation = 1 << 1
	OperationFetch   Operation = 1 << 2
	OperationPublish Operation = 1 << 3
	OperationRevoke  Operation = 1 << 4
	allOperations    Operation = 0x1f
)

// Caveat is one type-length-value entry. Value holds the exact wire bytes.
type Caveat struct {
	Type  CaveatType
	Value []byte
}

func u64Caveat(t CaveatType, v uint64) Caveat {
	return Caveat{Type: t, Value: binary.BigEndian.AppendUint64(nil, v)}
}

func u32Caveat(t CaveatType, v uint32) Caveat {
	return Caveat{Type: t, Value: binary.BigEndian.AppendUint32(nil, v)}
}

func NotBeforeCaveat(unix uint64) Caveat { return u64Caveat(CaveatNotBefore, unix) }
func NotAfterCaveat(unix uint64) Caveat  { return u64Caveat(CaveatNotAfter, unix) }
func RelayCaveat(url string) Caveat      { return Caveat{Type: CaveatRelay, Value: []byte(url)} }
func OperationsCaveat(ops Operation) Caveat {
	return Caveat{Type: CaveatOperations, Value: binary.BigEndian.AppendUint16(nil, uint16(ops))}
}
func LaneCaveat(lane [16]byte) Caveat        { return Caveat{Type: CaveatLane, Value: lane[:]} }
func MaxEnvelopesCaveat(n uint32) Caveat     { return u32Caveat(CaveatMaxEnvelopes, n) }
func MaxEnvelopeBytesCaveat(n uint32) Caveat { return u32Caveat(CaveatMaxEnvelopeBytes, n) }
func MaxLaneBytesCaveat(n uint64) Caveat     { return u64Caveat(CaveatMaxLaneBytes, n) }

// validate enforces the value rules of the caveat table. An unknown type is
// a decode error, never ignored.
func (c Caveat) validate() error {
	switch c.Type {
	case CaveatNotBefore, CaveatNotAfter:
		if len(c.Value) != 8 {
			return invalid("time caveat length %d", len(c.Value))
		}
	case CaveatRelay:
		if len(c.Value) < 1 || len(c.Value) > MaxRelayURLBytes {
			return invalid("relay caveat length %d", len(c.Value))
		}
		if err := agentpacketseal.CheckRelayURL(string(c.Value)); err != nil {
			return invalid("relay caveat is not a canonical relay base URL")
		}
	case CaveatOperations:
		if len(c.Value) != 2 {
			return invalid("operations caveat length %d", len(c.Value))
		}
		if Operation(binary.BigEndian.Uint16(c.Value)) & ^allOperations != 0 {
			return invalid("operations caveat has unknown bits")
		}
	case CaveatLane:
		if len(c.Value) != 16 {
			return invalid("lane caveat length %d", len(c.Value))
		}
		if bytes.Equal(c.Value, make([]byte, 16)) {
			return invalid("lane caveat is all zero")
		}
	case CaveatMaxEnvelopes:
		if len(c.Value) != 4 {
			return invalid("max_envelopes caveat length %d", len(c.Value))
		}
		if binary.BigEndian.Uint32(c.Value) == 0 {
			return invalid("max_envelopes caveat is zero")
		}
	case CaveatMaxEnvelopeBytes:
		if len(c.Value) != 4 {
			return invalid("max_envelope_bytes caveat length %d", len(c.Value))
		}
		if n := binary.BigEndian.Uint32(c.Value); n == 0 || n > MaxEnvelopeBytes {
			return invalid("max_envelope_bytes caveat out of range")
		}
	case CaveatMaxLaneBytes:
		if len(c.Value) != 8 {
			return invalid("max_lane_bytes caveat length %d", len(c.Value))
		}
		if binary.BigEndian.Uint64(c.Value) == 0 {
			return invalid("max_lane_bytes caveat is zero")
		}
	default:
		return invalid("unknown caveat type %d", c.Type)
	}
	return nil
}

// Block is one link of the chain. Caveats are in strictly ascending type order.
type Block struct {
	NextPublicKey [32]byte
	Caveats       []Caveat
	Signature     [64]byte
}

func (b Block) caveatBytes() []byte {
	var out []byte
	for _, c := range b.Caveats {
		out = append(out, byte(c.Type))
		out = binary.BigEndian.AppendUint16(out, uint16(len(c.Value)))
		out = append(out, c.Value...)
	}
	return out
}

// Credential is a decoded relay credential. Decoding checks structure only;
// VerifyChain checks the signatures.
type Credential struct {
	Delegation      Delegation
	DelegationBytes []byte
	Blocks          []Block
	chain           [][32]byte
}

func checkEd25519Key(key [32]byte) error {
	point, err := new(edwards25519.Point).SetBytes(key[:])
	if err != nil || !bytes.Equal(point.Bytes(), key[:]) {
		return invalid("noncanonical Ed25519 public key")
	}
	if new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return invalid("small-order Ed25519 public key")
	}
	return nil
}

func chainStep(previous []byte, extra []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(credentialChainDomain))
	h.Write(previous)
	h.Write(extra)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func blockPreimage(chain [32]byte, index int, b Block) []byte {
	out := append([]byte(credentialBlockDomain), chain[:]...)
	out = append(out, byte(index))
	out = append(out, b.NextPublicKey[:]...)
	out = append(out, byte(len(b.Caveats)))
	return append(out, b.caveatBytes()...)
}

// BlockSigningPreimage is preimage_i of the block that follows prior, for a
// signer outside this package. It performs no validation of the caveats;
// a credential built from it is accepted only if DecodeCredential and
// VerifyChain accept the result.
func BlockSigningPreimage(delegation []byte, prior []Block, b Block) ([]byte, error) {
	if len(delegation) != DelegationSize || len(prior) >= MaxCredentialBlocks || len(b.Caveats) > 0xff {
		return nil, invalid("block preimage inputs out of range")
	}
	chain := computeChain(delegation, prior)
	return blockPreimage(chain[len(prior)], len(prior), b), nil
}

// computeChain derives chain_0 .. chain_n from the delegation and signatures.
func computeChain(delegation []byte, blocks []Block) [][32]byte {
	digest := sha256.Sum256(delegation)
	chain := make([][32]byte, 0, len(blocks)+1)
	chain = append(chain, chainStep(digest[:], nil))
	for _, b := range blocks {
		last := chain[len(chain)-1]
		chain = append(chain, chainStep(last[:], b.Signature[:]))
	}
	return chain
}

func decodeU64(c Caveat) uint64 { return binary.BigEndian.Uint64(c.Value) }

func findCaveat(b Block, t CaveatType) (Caveat, bool) {
	for _, c := range b.Caveats {
		if c.Type == t {
			return c, true
		}
	}
	return Caveat{}, false
}

// checkFirstBlock enforces the block 0 rule: it carries not_before,
// not_after and operations, within the delegation's credential lifetime.
func checkFirstBlock(d Delegation, b Block) error {
	nb, okBefore := findCaveat(b, CaveatNotBefore)
	na, okAfter := findCaveat(b, CaveatNotAfter)
	_, okOps := findCaveat(b, CaveatOperations)
	if !okBefore || !okAfter || !okOps {
		return invalid("block 0 lacks not_before, not_after or operations")
	}
	before, after := decodeU64(nb), decodeU64(na)
	if after <= before || after-before > uint64(d.MaxCredentialSeconds) {
		return invalid("block 0 lifetime exceeds the delegation's max_credential_seconds")
	}
	return nil
}

func encodeBlock(b Block) ([]byte, error) {
	rest := 32 + 1 + len(b.caveatBytes()) + 64
	if rest > 0xffff {
		return nil, invalid("block too long")
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(rest))
	out = append(out, b.NextPublicKey[:]...)
	out = append(out, byte(len(b.Caveats)))
	out = append(out, b.caveatBytes()...)
	return append(out, b.Signature[:]...), nil
}

// Encode serializes a credential. It re-validates every rule DecodeCredential
// checks, so encoding and decoding agree.
func (c *Credential) Encode() ([]byte, error) {
	out := append([]byte(credentialDomain), c.DelegationBytes...)
	out = append(out, byte(len(c.Blocks)))
	for _, b := range c.Blocks {
		encoded, err := encodeBlock(b)
		if err != nil {
			return nil, err
		}
		out = append(out, encoded...)
	}
	if _, err := DecodeCredential(out); err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeCredential strictly decodes a credential: canonical lengths, the
// closed caveat set in strictly ascending type order, canonical keys, the
// block 0 rule and no trailing bytes. It does not verify signatures.
func DecodeCredential(b []byte) (*Credential, error) {
	if len(b) > MaxCredentialSize {
		return nil, invalid("credential exceeds %d bytes", MaxCredentialSize)
	}
	if len(b) < credentialHeaderSize || !bytes.Equal(b[:len(credentialDomain)], []byte(credentialDomain)) {
		return nil, invalid("credential size or domain")
	}
	raw := b[len(credentialDomain) : len(credentialDomain)+DelegationSize]
	d, err := DecodeDelegation(raw)
	if err != nil {
		return nil, invalid("embedded delegation: %v", err)
	}
	count := int(b[credentialHeaderSize-1])
	if count < 1 || count > MaxCredentialBlocks {
		return nil, invalid("block_count %d", count)
	}
	c := &Credential{Delegation: d, DelegationBytes: append([]byte(nil), raw...)}
	rest := b[credentialHeaderSize:]
	for index := range count {
		if len(rest) < 2 {
			return nil, invalid("block %d truncated", index)
		}
		length := int(binary.BigEndian.Uint16(rest))
		if len(rest)-2 < length {
			return nil, invalid("block %d length exceeds the credential", index)
		}
		block, err := decodeBlock(rest[2 : 2+length])
		if err != nil {
			return nil, fmt.Errorf("block %d: %w", index, err)
		}
		c.Blocks = append(c.Blocks, block)
		rest = rest[2+length:]
	}
	if len(rest) != 0 {
		return nil, invalid("trailing bytes after the last block")
	}
	if err := checkFirstBlock(d, c.Blocks[0]); err != nil {
		return nil, err
	}
	c.chain = computeChain(c.DelegationBytes, c.Blocks)
	return c, nil
}

func decodeBlock(body []byte) (Block, error) {
	var b Block
	if len(body) < 32+1+64 {
		return b, invalid("block too short")
	}
	copy(b.NextPublicKey[:], body[:32])
	if err := checkEd25519Key(b.NextPublicKey); err != nil {
		return b, err
	}
	count := int(body[32])
	if count < 1 || count > MaxCaveatsPerBlock {
		return b, invalid("caveat_count %d", count)
	}
	rest := body[33 : len(body)-64]
	for index := range count {
		if len(rest) < 3 {
			return b, invalid("caveat %d truncated", index)
		}
		t := CaveatType(rest[0])
		length := int(binary.BigEndian.Uint16(rest[1:3]))
		if len(rest)-3 < length {
			return b, invalid("caveat %d value truncated", index)
		}
		if index > 0 && t <= b.Caveats[index-1].Type {
			return b, invalid("caveat types not strictly ascending")
		}
		c := Caveat{Type: t, Value: append([]byte(nil), rest[3:3+length]...)}
		if err := c.validate(); err != nil {
			return b, err
		}
		b.Caveats = append(b.Caveats, c)
		rest = rest[3+length:]
	}
	if len(rest) != 0 {
		return b, invalid("block length disagrees with its caveats")
	}
	copy(b.Signature[:], body[len(body)-64:])
	return b, nil
}

// VerifyChain verifies every block signature: block 0 by the delegation's
// transport key, block i by the key block i-1 names. Each preimage covers the
// chain value of every earlier signature, so reorder, drop and splice fail.
func (c *Credential) VerifyChain() error {
	signer := c.Delegation.TransportKey
	for index, b := range c.Blocks {
		if !ed25519.Verify(signer[:], blockPreimage(c.chain[index], index, b), b.Signature[:]) {
			return invalid("block %d signature", index)
		}
		signer = b.NextPublicKey
	}
	return nil
}

// ChainValues returns chain_0 .. chain_n; any of them may be revoked (6.3).
func (c *Credential) ChainValues() [][32]byte { return slices.Clone(c.chain) }

// CredentialID is chain_n, the replay and default lane key.
func (c *Credential) CredentialID() [32]byte { return c.chain[len(c.chain)-1] }

// HolderKey is next_public_key of the last block; it signs request proofs.
func (c *Credential) HolderKey() [32]byte { return c.Blocks[len(c.Blocks)-1].NextPublicKey }

// Lane returns the single lane value of the chain, if any. Two different
// values make the credential unusable.
func (c *Credential) Lane() (lane [16]byte, explicit bool, err error) {
	for _, b := range c.Blocks {
		if v, ok := findCaveat(b, CaveatLane); ok {
			if explicit && !bytes.Equal(lane[:], v.Value) {
				return [16]byte{}, false, scope("credential carries two different lane values")
			}
			copy(lane[:], v.Value)
			explicit = true
		}
	}
	return lane, explicit, nil
}

// NotAfter is the earliest not_after over the blocks, the credential expiry.
func (c *Credential) NotAfter() uint64 {
	expiry := ^uint64(0)
	for _, b := range c.Blocks {
		if v, ok := findCaveat(b, CaveatNotAfter); ok {
			expiry = min(expiry, decodeU64(v))
		}
	}
	return expiry
}

func checkOperation(op Operation) error {
	switch op {
	case OperationDeposit, OperationList, OperationFetch, OperationPublish, OperationRevoke:
		return nil
	default:
		return scope("request names no single known operation")
	}
}

// CheckScope evaluates the request-dependent caveats of every block. It never
// merges blocks: each caveat of each block must hold on its own (6.4). Size
// and count caveats constrain stored envelopes and are evaluated by
// CheckDeposit at the quota step.
func (c *Credential) CheckScope(now uint64, relayURL string, op Operation) error {
	if err := checkOperation(op); err != nil {
		return err
	}
	if now == 0 {
		return scope("request time is missing")
	}
	if _, _, err := c.Lane(); err != nil {
		return err
	}
	for index, b := range c.Blocks {
		for _, cv := range b.Caveats {
			switch cv.Type {
			case CaveatNotBefore:
				// Compare before subtracting so an untrusted u64 cannot overflow.
				if nb := decodeU64(cv); nb > now && nb-now > ClockSkewSeconds {
					return scope("block %d not_before is in the future", index)
				}
			case CaveatNotAfter:
				if now >= decodeU64(cv) {
					return scope("block %d not_after has passed", index)
				}
			case CaveatRelay:
				if string(cv.Value) != relayURL {
					return scope("block %d names another relay", index)
				}
			case CaveatOperations:
				if Operation(binary.BigEndian.Uint16(cv.Value))&op == 0 {
					return scope("block %d does not grant the operation", index)
				}
			case CaveatLane, CaveatMaxEnvelopes, CaveatMaxEnvelopeBytes, CaveatMaxLaneBytes:
				// Lane names the quota lane; the limits apply at the quota step.
			default:
				return invalid("unknown caveat type %d", cv.Type)
			}
		}
	}
	return nil
}

// LaneUsage is what a contact lane holds before a deposit, and the deposit.
type LaneUsage struct {
	StoredEnvelopes uint64
	StoredBytes     uint64
	EnvelopeBytes   uint64
}

// CheckDeposit evaluates the size and count caveats of every block against
// the lane and the deposited envelope. A contact lane never holds more than
// MaxContactLaneEnvelopes whatever its caveats say.
func (c *Credential) CheckDeposit(u LaneUsage) error {
	if u.EnvelopeBytes == 0 || u.EnvelopeBytes > MaxEnvelopeBytes {
		return scope("envelope size out of range")
	}
	if u.StoredEnvelopes >= MaxContactLaneEnvelopes {
		return scope("contact lane holds %d envelopes", MaxContactLaneEnvelopes)
	}
	total, overflow := addU64(u.StoredBytes, u.EnvelopeBytes)
	for index, b := range c.Blocks {
		for _, cv := range b.Caveats {
			switch cv.Type {
			case CaveatMaxEnvelopes:
				if u.StoredEnvelopes >= uint64(binary.BigEndian.Uint32(cv.Value)) {
					return scope("block %d max_envelopes reached", index)
				}
			case CaveatMaxEnvelopeBytes:
				if u.EnvelopeBytes > uint64(binary.BigEndian.Uint32(cv.Value)) {
					return scope("block %d max_envelope_bytes exceeded", index)
				}
			case CaveatMaxLaneBytes:
				if overflow || total > decodeU64(cv) {
					return scope("block %d max_lane_bytes exceeded", index)
				}
			case CaveatNotBefore, CaveatNotAfter, CaveatRelay, CaveatOperations, CaveatLane:
				// Request caveats are evaluated by CheckScope.
			default:
				return invalid("unknown caveat type %d", cv.Type)
			}
		}
	}
	return nil
}

func addU64(a, b uint64) (uint64, bool) {
	sum := a + b
	return sum, sum < a
}

// canonicalCaveats copies a caller's caveats in ascending type order. Counts,
// repeated types and values are refused by decoding the encoded result.
func canonicalCaveats(caveats []Caveat) []Caveat {
	out := make([]Caveat, len(caveats))
	for i, c := range caveats {
		out[i] = Caveat{Type: c.Type, Value: append([]byte(nil), c.Value...)}
	}
	slices.SortStableFunc(out, func(a, b Caveat) int { return int(a.Type) - int(b.Type) })
	return out
}

func publicOf(key ed25519.PrivateKey) ([32]byte, error) {
	var out [32]byte
	if len(key) != ed25519.PrivateKeySize {
		return out, invalid("signing key length")
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return out, invalid("signing key has no Ed25519 public half")
	}
	copy(out[:], public)
	return out, nil
}

// appendSigned signs one more block. The encoded result is decoded again, so
// the block count, caveat rules and size limit have a single implementation.
func (c *Credential) appendSigned(signer ed25519.PrivateKey, next [32]byte, caveats []Caveat) ([]byte, error) {
	if len(caveats) > 0xff || len(c.Blocks) > 0xff {
		return nil, invalid("block inputs out of range")
	}
	b := Block{NextPublicKey: next, Caveats: canonicalCaveats(caveats)}
	index := len(c.Blocks)
	chain := computeChain(c.DelegationBytes, c.Blocks)
	copy(b.Signature[:], ed25519.Sign(signer, blockPreimage(chain[index], index, b)))
	extended := &Credential{Delegation: c.Delegation, DelegationBytes: c.DelegationBytes, Blocks: append(slices.Clone(c.Blocks), b)}
	encoded, err := extended.Encode()
	if err != nil {
		return nil, err
	}
	decoded, err := DecodeCredential(encoded)
	if err != nil {
		return nil, err
	}
	if _, _, err = decoded.Lane(); err != nil {
		return nil, err
	}
	return encoded, nil
}

// IssueCredential signs block 0 with the delegation's transport key. Use the
// result only once VerifyDelegation accepts the delegation.
func IssueCredential(delegation []byte, transportKey ed25519.PrivateKey, next ed25519.PublicKey, caveats []Caveat) ([]byte, error) {
	d, err := DecodeDelegation(delegation)
	if err != nil {
		return nil, invalid("delegation: %v", err)
	}
	signer, err := publicOf(transportKey)
	if err != nil {
		return nil, err
	}
	if signer != d.TransportKey {
		return nil, invalid("signing key is not the delegation's transport key")
	}
	if len(next) != ed25519.PublicKeySize {
		return nil, invalid("next public key length")
	}
	c := &Credential{Delegation: d, DelegationBytes: append([]byte(nil), delegation...)}
	return c.appendSigned(transportKey, [32]byte(next), caveats)
}

// AppendCredentialBlock narrows a credential: the holder signs one more block
// naming the next holder key. Appending can only add bounds.
func AppendCredentialBlock(credential []byte, holder ed25519.PrivateKey, next ed25519.PublicKey, caveats []Caveat) ([]byte, error) {
	c, err := DecodeCredential(credential)
	if err != nil {
		return nil, err
	}
	if err = c.VerifyChain(); err != nil {
		return nil, err
	}
	signer, err := publicOf(holder)
	if err != nil {
		return nil, err
	}
	if signer != c.HolderKey() {
		return nil, invalid("signing key is not the credential's holder key")
	}
	if len(next) != ed25519.PublicKeySize {
		return nil, invalid("next public key length")
	}
	return c.appendSigned(holder, [32]byte(next), caveats)
}
