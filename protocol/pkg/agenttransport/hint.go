package agenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

type HintObjectKind byte

const (
	RailCard          HintObjectKind = 1
	ChatCard          HintObjectKind = 2
	MessengerEvidence HintObjectKind = 3
)

type HintObjectRef struct {
	Kind   HintObjectKind
	Length uint32
	Digest [32]byte
}
type DirectEntry struct {
	Kind         byte
	ADNLID       [32]byte
	IPv4         [4]byte
	Port         uint16
	InboundClass byte
}
type Hint struct {
	Delegation Delegation
	IssuedAt   uint64
	ExpiresAt  uint64
	Relays     []string
	Direct     []DirectEntry
	Objects    []HintObjectRef
	Signature  [64]byte
}
type HintObject struct {
	Kind  HintObjectKind
	Bytes []byte
}
type HintRecord struct {
	Hint    Hint
	Objects []HintObject
}

func objectLimit(kind HintObjectKind) uint32 {
	switch kind {
	case RailCard, ChatCard:
		return MaxHintCardBytes
	case MessengerEvidence:
		return MaxHintEvidenceBytes
	default:
		return 0
	}
}
func HintObjectDigest(kind HintObjectKind, raw []byte) ([32]byte, error) {
	if objectLimit(kind) == 0 || len(raw) == 0 || uint64(len(raw)) > uint64(objectLimit(kind)) {
		return [32]byte{}, ErrHint
	}
	preimage := append([]byte(hintObjectDomain), byte(kind))
	preimage = append(preimage, raw...)
	return sha256.Sum256(preimage), nil
}
func (h Hint) preimage() ([]byte, error) {
	delegation, err := h.Delegation.Encode()
	if err != nil {
		return nil, ErrHint
	}
	if h.ExpiresAt <= h.IssuedAt || h.ExpiresAt-h.IssuedAt > MaxHintLifetimeSeconds {
		return nil, ErrHint
	}
	if len(h.Relays) < 1 || len(h.Relays) > MaxHintRelays || len(h.Direct) > MaxDirectEntries || len(h.Objects) > MaxHintObjects {
		return nil, ErrHint
	}
	out := append([]byte(hintDomain), delegation...)
	out = binary.BigEndian.AppendUint64(out, h.IssuedAt)
	out = binary.BigEndian.AppendUint64(out, h.ExpiresAt)
	out = append(out, byte(len(h.Relays)))
	seen := make(map[string]bool, len(h.Relays))
	for _, relay := range h.Relays {
		if agentpacketseal.CheckRelayURL(relay) != nil || seen[relay] {
			return nil, ErrHint
		}
		seen[relay] = true
		out = binary.BigEndian.AppendUint16(out, uint16(len(relay)))
		out = append(out, relay...)
	}
	out = append(out, byte(len(h.Direct)))
	for _, entry := range h.Direct {
		if entry.Kind != 1 || entry.Port == 0 || (entry.InboundClass != 1 && entry.InboundClass != 2) {
			return nil, ErrHint
		}
		out = append(out, entry.Kind)
		out = append(out, entry.ADNLID[:]...)
		out = append(out, entry.IPv4[:]...)
		out = binary.BigEndian.AppendUint16(out, entry.Port)
		out = append(out, entry.InboundClass)
	}
	out = append(out, byte(len(h.Objects)))
	var previous HintObjectKind
	for _, object := range h.Objects {
		limit := objectLimit(object.Kind)
		if limit == 0 || object.Kind <= previous || object.Length == 0 || object.Length > limit {
			return nil, ErrHint
		}
		previous = object.Kind
		out = append(out, byte(object.Kind))
		out = binary.BigEndian.AppendUint32(out, object.Length)
		out = append(out, object.Digest[:]...)
	}
	if len(out)+ed25519.SignatureSize > MaxHintSize {
		return nil, ErrHint
	}
	return out, nil
}
func (h Hint) Encode() ([]byte, error) {
	b, err := h.preimage()
	if err != nil {
		return nil, err
	}
	return append(b, h.Signature[:]...), nil
}
func SignHint(h Hint, key ed25519.PrivateKey) (Hint, error) {
	b, err := h.preimage()
	if err != nil {
		return Hint{}, err
	}
	h.Signature, err = signTransport(key, h.Delegation, b)
	return h, err
}
func DecodeHint(raw []byte) (Hint, error) {
	var h Hint
	if len(raw) > MaxHintSize || len(raw) < len(hintDomain)+DelegationSize+16+3+64 || !bytes.HasPrefix(raw, []byte(hintDomain)) {
		return h, ErrHint
	}
	r := wireReader{raw: raw, at: len(hintDomain)}
	var err error
	h.Delegation, err = DecodeDelegation(r.take(DelegationSize))
	if err != nil {
		return Hint{}, ErrHint
	}
	h.IssuedAt = r.u64()
	h.ExpiresAt = r.u64()
	relays := int(r.u8())
	if relays < 1 || relays > MaxHintRelays {
		return Hint{}, ErrHint
	}
	for range relays {
		n := int(r.u16())
		if n < 1 || n > 256 {
			return Hint{}, ErrHint
		}
		h.Relays = append(h.Relays, string(r.take(n)))
	}
	direct := int(r.u8())
	if direct > MaxDirectEntries {
		return Hint{}, ErrHint
	}
	for range direct {
		entry := DirectEntry{Kind: r.u8()}
		copy(entry.ADNLID[:], r.take(32))
		copy(entry.IPv4[:], r.take(4))
		entry.Port = r.u16()
		entry.InboundClass = r.u8()
		h.Direct = append(h.Direct, entry)
	}
	objects := int(r.u8())
	if objects > MaxHintObjects {
		return Hint{}, ErrHint
	}
	for range objects {
		entry := HintObjectRef{Kind: HintObjectKind(r.u8()), Length: r.u32()}
		copy(entry.Digest[:], r.take(32))
		h.Objects = append(h.Objects, entry)
	}
	copy(h.Signature[:], r.take(64))
	if !r.done() {
		return Hint{}, ErrHint
	}
	if _, err = h.preimage(); err != nil {
		return Hint{}, err
	}
	return h, nil
}
func (r HintRecord) Encode() ([]byte, error) {
	h, err := r.Hint.Encode()
	if err != nil {
		return nil, err
	}
	if len(r.Objects) != len(r.Hint.Objects) {
		return nil, ErrHint
	}
	out := append([]byte(hintRecordDomain), byte(len(h)>>8), byte(len(h)))
	out = append(out, h...)
	for i, object := range r.Objects {
		ref := r.Hint.Objects[i]
		digest, err := HintObjectDigest(object.Kind, object.Bytes)
		if err != nil || object.Kind != ref.Kind || uint64(len(object.Bytes)) != uint64(ref.Length) || digest != ref.Digest {
			return nil, ErrHint
		}
		out = append(out, object.Bytes...)
	}
	if len(out) > MaxHintRecordSize {
		return nil, ErrHint
	}
	return out, nil
}
func DecodeHintRecord(raw []byte) (HintRecord, error) {
	var record HintRecord
	if len(raw) > MaxHintRecordSize || len(raw) < len(hintRecordDomain)+2 || !bytes.HasPrefix(raw, []byte(hintRecordDomain)) {
		return record, ErrHint
	}
	reader := wireReader{raw: raw, at: len(hintRecordDomain)}
	length := int(reader.u16())
	if length > MaxHintSize {
		return record, ErrHint
	}
	hint, err := DecodeHint(reader.take(length))
	if err != nil {
		return record, ErrHint
	}
	record.Hint = hint
	for _, ref := range hint.Objects {
		payload := reader.take(int(ref.Length))
		if reader.err {
			return HintRecord{}, ErrHint
		}
		digest, err := HintObjectDigest(ref.Kind, payload)
		if err != nil || digest != ref.Digest {
			return HintRecord{}, ErrHint
		}
		record.Objects = append(record.Objects, HintObject{Kind: ref.Kind, Bytes: append([]byte(nil), payload...)})
	}
	if !reader.done() {
		return HintRecord{}, ErrHint
	}
	return record, nil
}

// HintPolicy is trusted consumer configuration, never a field from a directory.
// AllowPrivateIPv4 is usable only with the verifier's pinned test networks; the
// returned observation records this exception. It admits private ranges only,
// never loopback, multicast, unspecified or other reserved destinations.
type HintPolicy struct{ AllowPrivateIPv4 bool }
type VerifiedHint struct {
	Record             HintRecord
	PrivateIPv4Allowed bool
}

var reservedIPv4 = []netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 8), netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, 0}), 10), netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8), netip.PrefixFrom(netip.AddrFrom4([4]byte{169, 254, 0, 0}), 16), netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 0, 0}), 24), netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 24), netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 88, 99, 0}), 24), netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, 0, 0}), 15), netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 24), netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 0}), 24), netip.PrefixFrom(netip.AddrFrom4([4]byte{224, 0, 0, 0}), 4), netip.PrefixFrom(netip.AddrFrom4([4]byte{240, 0, 0, 0}), 4),
}

func validDirectIPv4(raw [4]byte, allowPrivate bool) bool {
	ip := netip.AddrFrom4(raw)
	if !ip.IsGlobalUnicast() {
		return false
	}
	if ip.IsPrivate() {
		return allowPrivate
	}
	for _, prefix := range reservedIPv4 {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
func checkHintTime(h Hint, now uint64) error {
	if (h.IssuedAt > now && h.IssuedAt-now > 300) || now >= h.ExpiresAt {
		return ErrHint
	}
	return nil
}

// VerifyHint performs the relay-level checks, not card/evidence authentication.
// A consumer must call VerifyConsumerHint with its independent card/evidence
// verifier before using embedded objects. This package never holds a controller key.
func (v *Verifier) VerifyHint(ctx context.Context, raw []byte, policy HintPolicy) (VerifiedHint, error) {
	var result VerifiedHint
	record, err := DecodeHintRecord(raw)
	if err != nil {
		return result, err
	}
	delegation, err := record.Hint.Delegation.Encode()
	if err != nil {
		return result, ErrHint
	}
	if _, err = v.VerifyDelegation(ctx, delegation, Hints); err != nil {
		return result, errors.Join(ErrHint, err)
	}
	preimage, err := record.Hint.preimage()
	if err != nil || !ed25519.Verify(record.Hint.Delegation.TransportKey[:], preimage, record.Hint.Signature[:]) {
		return result, ErrHint
	}
	now, err := v.objectTime(ctx)
	if err != nil {
		return result, errors.Join(ErrHint, err)
	}
	if err = checkHintTime(record.Hint, now); err != nil {
		return result, err
	}
	for _, entry := range record.Hint.Direct {
		if !validDirectIPv4(entry.IPv4, policy.AllowPrivateIPv4) {
			return result, ErrHint
		}
	}
	for _, object := range record.Objects {
		if object.Kind == RailCard || object.Kind == ChatCard {
			var packet map[string]json.RawMessage
			if jsonstrict.Decode(object.Bytes, &packet) != nil {
				return result, ErrHint
			}
			var sender string
			if json.Unmarshal(packet["sender_agent_id"], &sender) != nil || sender != record.Hint.Delegation.AgentID() {
				return result, ErrHint
			}
		}
	}
	return VerifiedHint{Record: record, PrivateIPv4Allowed: policy.AllowPrivateIPv4}, nil
}

// ObjectVerifier must authenticate the complete card/evidence under finalized
// authority, and return its authenticated Agent ID, not just a parsed JSON field.
type ObjectVerifier func(context.Context, HintObjectKind, []byte) (string, error)

func (v *Verifier) VerifyConsumerHint(ctx context.Context, raw []byte, policy HintPolicy, verify ObjectVerifier) (VerifiedHint, error) {
	ctx, cancel := context.WithTimeout(ctx, v.config.ReadTimeout)
	defer cancel()
	result, err := v.VerifyHint(ctx, raw, policy)
	if err != nil {
		return VerifiedHint{}, err
	}
	if len(result.Record.Objects) > 0 && verify == nil {
		return VerifiedHint{}, ErrHint
	}
	for _, object := range result.Record.Objects {
		agent, err := verify(ctx, object.Kind, append([]byte(nil), object.Bytes...))
		if err != nil || agent != result.Record.Hint.Delegation.AgentID() {
			return VerifiedHint{}, ErrHint
		}
	}
	if err = ctx.Err(); err != nil {
		return VerifiedHint{}, err
	}
	return v.VerifyHint(ctx, raw, policy)
}

// PublishOptions defaults to the reduced public hint. Consent is local policy,
// not a signer-controlled wire flag. Direct enablement is separate from chat.
type PublishOptions struct {
	PublicContact bool
	DirectEnabled bool
	HintPolicy    HintPolicy
}

func (v *Verifier) BuildHintRecord(ctx context.Context, h Hint, objects []HintObject, key ed25519.PrivateKey, options PublishOptions) ([]byte, error) {
	if !options.DirectEnabled && len(h.Direct) > 0 {
		return nil, ErrHint
	}
	h.Objects = nil
	for _, object := range objects {
		if object.Kind != RailCard && !options.PublicContact {
			return nil, ErrHint
		}
		digest, err := HintObjectDigest(object.Kind, object.Bytes)
		if err != nil {
			return nil, err
		}
		h.Objects = append(h.Objects, HintObjectRef{Kind: object.Kind, Length: uint32(len(object.Bytes)), Digest: digest})
	}
	signed, err := SignHint(h, key)
	if err != nil {
		return nil, err
	}
	raw, err := (HintRecord{Hint: signed, Objects: objects}).Encode()
	if err != nil {
		return nil, err
	}
	if _, err = v.VerifyHint(ctx, raw, options.HintPolicy); err != nil {
		return nil, err
	}
	return raw, nil
}

// CompareHints compares only hints of the same delegation. Positive means a is
// newer. Independent lane delegations are never ordered against one another.
func CompareHints(a, b Hint) (int, error) {
	da, err := a.Delegation.Encode()
	if err != nil {
		return 0, ErrHint
	}
	db, err := b.Delegation.Encode()
	if err != nil || !bytes.Equal(da, db) {
		return 0, ErrHint
	}
	wa, err := a.Encode()
	if err != nil {
		return 0, err
	}
	wb, err := b.Encode()
	if err != nil {
		return 0, err
	}
	if a.IssuedAt < b.IssuedAt {
		return -1, nil
	}
	if a.IssuedAt > b.IssuedAt {
		return 1, nil
	}
	ha, hb := sha256.Sum256(wa), sha256.Sum256(wb)
	return bytes.Compare(ha[:], hb[:]), nil
}
