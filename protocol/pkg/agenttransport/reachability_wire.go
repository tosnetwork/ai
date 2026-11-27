package agenttransport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

const (
	MaxHintSize                    = 1536
	MaxHintRecordSize              = 40960
	MaxHintLifetimeSeconds         = 86400
	RecommendedHintLifetimeSeconds = 21600
	MaxHintRelays                  = 4
	MaxDirectEntries               = 2
	MaxHintObjects                 = 3
	MaxHintCardBytes               = 9216
	MaxHintEvidenceBytes           = 18432
	HelloSize                      = 402
	ReceiptSize                    = len(receiptDomain) + 32 + 32 + 1 + 8 + 64
	hintDomain                     = "tos.service.agent-reachability-hint.v1\x00"
	hintRecordDomain               = "tos.service.agent-reachability-record.v1\x00"
	hintObjectDomain               = "tos.service.agent-reachability-hint.object.v1\x00"
	helloDomain                    = "tos.service.agent-direct-hello.v1\x00"
	receiptDomain                  = "tos.service.agent-direct-receipt.v1\x00"
)

var (
	ErrHint    = errors.New("hint_invalid")
	ErrHello   = errors.New("hello_invalid")
	ErrReceipt = errors.New("receipt_invalid")
)

// wireReader never slices beyond the untrusted byte limit.
type wireReader struct {
	raw []byte
	at  int
	err bool
}

func (r *wireReader) take(n int) []byte {
	if n < 0 || n > len(r.raw)-r.at {
		r.err = true
		return nil
	}
	b := r.raw[r.at : r.at+n]
	r.at += n
	return b
}
func (r *wireReader) u8() byte {
	b := r.take(1)
	if r.err {
		return 0
	}
	return b[0]
}
func (r *wireReader) u16() uint16 {
	b := r.take(2)
	if r.err {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *wireReader) u32() uint32 {
	b := r.take(4)
	if r.err {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *wireReader) u64() uint64 {
	b := r.take(8)
	if r.err {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func (r *wireReader) done() bool { return !r.err && r.at == len(r.raw) }

func signTransport(key ed25519.PrivateKey, delegation Delegation, preimage []byte) ([64]byte, error) {
	var signature [64]byte
	if len(key) != ed25519.PrivateKeySize {
		return signature, errors.New("invalid transport signing key length")
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) || !bytes.Equal(derived[ed25519.SeedSize:], delegation.TransportKey[:]) {
		return signature, errors.New("signing key differs from delegation")
	}
	copy(signature[:], ed25519.Sign(key, preimage))
	return signature, nil
}
