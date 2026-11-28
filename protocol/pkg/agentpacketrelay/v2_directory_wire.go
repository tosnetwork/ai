package agentpacketrelay

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const (
	revocationDomain          = "tos.service.relay-revocation.v1\x00"
	hintIndexDomain           = "tos.service.relay-hint-index.v1\x00"
	MaxRevocationsPerRequest  = 32
	MaxRevocationsPerMailbox  = 1024
	MaxRevocationLifetime     = 604800 + 300
	MaxRevocationRequestBytes = len(revocationDomain) + 1 + MaxRevocationsPerRequest*40
	MaxHintIndexBytes         = len(hintIndexDomain) + 1 + 4*44
)

var ErrRevocation = errors.New("invalid revocation request")
var ErrHintIndex = errors.New("invalid hint index")
var ErrCredentialRevoked = errors.New("credential revoked at relay")

type Revocation struct {
	Chain [32]byte `json:"chain"`
	Until uint64   `json:"until"`
}

func EncodeRevocations(entries []Revocation) ([]byte, error) {
	if len(entries) < 1 || len(entries) > MaxRevocationsPerRequest {
		return nil, ErrRevocation
	}
	out := append([]byte(nil), revocationDomain...)
	out = append(out, byte(len(entries)))
	for _, entry := range entries {
		out = append(out, entry.Chain[:]...)
		out = binary.BigEndian.AppendUint64(out, entry.Until)
	}
	return out, nil
}
func DecodeRevocations(raw []byte) ([]Revocation, error) {
	if len(raw) < len(revocationDomain)+1 || len(raw) > MaxRevocationRequestBytes || !bytes.HasPrefix(raw, []byte(revocationDomain)) {
		return nil, ErrRevocation
	}
	count := int(raw[len(revocationDomain)])
	if count < 1 || count > 32 || len(raw) != len(revocationDomain)+1+count*40 {
		return nil, ErrRevocation
	}
	out := make([]Revocation, count)
	at := len(revocationDomain) + 1
	for i := range out {
		copy(out[i].Chain[:], raw[at:at+32])
		out[i].Until = binary.BigEndian.Uint64(raw[at+32 : at+40])
		at += 40
	}
	return out, nil
}
func validRevocationTime(until, now uint64) bool {
	return until <= now || until-now <= MaxRevocationLifetime
}

type HintIndexEntry struct {
	Digest   [32]byte
	IssuedAt uint64
	Length   uint32
}

func EncodeHintIndex(entries []HintIndexEntry) ([]byte, error) {
	if len(entries) > 4 {
		return nil, ErrHintIndex
	}
	out := append([]byte(nil), hintIndexDomain...)
	out = append(out, byte(len(entries)))
	for i, e := range entries {
		if e.Length == 0 || e.Length > agenttransport.MaxHintRecordSize || (i > 0 && bytes.Compare(entries[i-1].Digest[:], e.Digest[:]) >= 0) {
			return nil, ErrHintIndex
		}
		out = append(out, e.Digest[:]...)
		out = binary.BigEndian.AppendUint64(out, e.IssuedAt)
		out = binary.BigEndian.AppendUint32(out, e.Length)
	}
	return out, nil
}
func DecodeHintIndex(raw []byte) ([]HintIndexEntry, error) {
	if len(raw) < len(hintIndexDomain)+1 || len(raw) > MaxHintIndexBytes || !bytes.HasPrefix(raw, []byte(hintIndexDomain)) {
		return nil, ErrHintIndex
	}
	count := int(raw[len(hintIndexDomain)])
	if count > 4 || len(raw) != len(hintIndexDomain)+1+44*count {
		return nil, ErrHintIndex
	}
	out := make([]HintIndexEntry, count)
	at := len(hintIndexDomain) + 1
	for i := range out {
		copy(out[i].Digest[:], raw[at:at+32])
		out[i].IssuedAt = binary.BigEndian.Uint64(raw[at+32 : at+40])
		out[i].Length = binary.BigEndian.Uint32(raw[at+40 : at+44])
		at += 44
	}
	if _, err := EncodeHintIndex(out); err != nil {
		return nil, err
	}
	return out, nil
}
