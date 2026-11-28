package agenttransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

const (
	HelloInitiator byte = 1
	HelloResponder byte = 2
)

type Hello struct {
	Role           byte
	Delegation     Delegation
	LocalADNL      [32]byte
	PeerADNL       [32]byte
	InitiatorNonce [32]byte
	ResponderNonce [32]byte
	IssuedAt       uint64
	Signature      [64]byte
}

func (h Hello) preimage() ([]byte, error) {
	if h.Role != HelloInitiator && h.Role != HelloResponder {
		return nil, ErrHello
	}
	if h.Role == HelloInitiator && h.ResponderNonce != ([32]byte{}) {
		return nil, ErrHello
	}
	delegation, err := h.Delegation.Encode()
	if err != nil {
		return nil, ErrHello
	}
	out := append([]byte(helloDomain), h.Role)
	out = append(out, delegation...)
	out = append(out, h.LocalADNL[:]...)
	out = append(out, h.PeerADNL[:]...)
	out = append(out, h.InitiatorNonce[:]...)
	out = append(out, h.ResponderNonce[:]...)
	return binary.BigEndian.AppendUint64(out, h.IssuedAt), nil
}
func (h Hello) Encode() ([]byte, error) {
	b, err := h.preimage()
	if err != nil {
		return nil, err
	}
	return append(b, h.Signature[:]...), nil
}
func SignHello(h Hello, key ed25519.PrivateKey) (Hello, error) {
	b, err := h.preimage()
	if err != nil {
		return Hello{}, err
	}
	h.Signature, err = signTransport(key, h.Delegation, b)
	return h, err
}
func DecodeHello(raw []byte) (Hello, error) {
	var h Hello
	if len(raw) != HelloSize || !bytes.HasPrefix(raw, []byte(helloDomain)) {
		return h, ErrHello
	}
	reader := wireReader{raw: raw, at: len(helloDomain)}
	h.Role = reader.u8()
	var err error
	h.Delegation, err = DecodeDelegation(reader.take(DelegationSize))
	if err != nil {
		return Hello{}, ErrHello
	}
	copy(h.LocalADNL[:], reader.take(32))
	copy(h.PeerADNL[:], reader.take(32))
	copy(h.InitiatorNonce[:], reader.take(32))
	copy(h.ResponderNonce[:], reader.take(32))
	h.IssuedAt = reader.u64()
	copy(h.Signature[:], reader.take(64))
	if !reader.done() {
		return Hello{}, ErrHello
	}
	if _, err = h.preimage(); err != nil {
		return Hello{}, err
	}
	return h, nil
}

// HelloExpectation comes from the authenticated channel and the local lane,
// not fields copied from an unauthenticated hello. AdmittedContact must be a
// nonblocking local lane-policy lookup. A responder checks contact
// admission; an initiator additionally pins the intended Agent and challenge.
// ExpectedAgent may be empty only when receiving an initiator's first hello.
type HelloExpectation struct {
	Role            byte
	LocalADNL       [32]byte
	PeerADNL        [32]byte
	ExpectedAgent   string
	InitiatorNonce  [32]byte
	AdmittedContact func(string) bool
}

func (v *Verifier) VerifyHello(ctx context.Context, raw []byte, expected HelloExpectation) (Hello, error) {
	h, err := DecodeHello(raw)
	if err != nil {
		return Hello{}, err
	}
	if h.Role != expected.Role || h.LocalADNL != expected.PeerADNL || h.PeerADNL != expected.LocalADNL {
		return Hello{}, ErrHello
	}
	if expected.AdmittedContact == nil {
		return Hello{}, ErrHello
	}
	if h.Role == HelloResponder && (expected.ExpectedAgent == "" || h.InitiatorNonce != expected.InitiatorNonce) {
		return Hello{}, ErrHello
	}
	if expected.ExpectedAgent != "" && expected.ExpectedAgent != h.Delegation.AgentID() {
		return Hello{}, ErrHello
	}
	now, err := v.objectTime(ctx)
	if err != nil || !withinDirectWindow(h.IssuedAt, now) {
		return Hello{}, ErrHello
	}
	delegation, err := h.Delegation.Encode()
	if err != nil {
		return Hello{}, ErrHello
	}
	if _, err = v.VerifyDelegation(ctx, delegation, Direct); err != nil {
		return Hello{}, errors.Join(ErrHello, err)
	}
	preimage, err := h.preimage()
	if err != nil || !ed25519.Verify(h.Delegation.TransportKey[:], preimage, h.Signature[:]) {
		return Hello{}, ErrHello
	}
	if !expected.AdmittedContact(h.Delegation.AgentID()) {
		return Hello{}, ErrHello
	}
	now, err = v.objectTime(ctx)
	if err != nil || !withinDirectWindow(h.IssuedAt, now) {
		return Hello{}, ErrHello
	}
	return h, nil
}
func withinDirectWindow(issued, now uint64) bool {
	if issued > now {
		return issued-now <= 120
	}
	return now-issued <= 120
}

type ReceiptOutcome byte

const (
	ReceiptStored    ReceiptOutcome = 1
	ReceiptDuplicate ReceiptOutcome = 2
	ReceiptRefused   ReceiptOutcome = 3
)

type Receipt struct {
	RecipientAgent [32]byte
	EnvelopeID     [32]byte
	Outcome        ReceiptOutcome
	ReceivedAt     uint64
	Signature      [64]byte
}

func (r Receipt) preimage() ([]byte, error) {
	if r.Outcome < ReceiptStored || r.Outcome > ReceiptRefused {
		return nil, ErrReceipt
	}
	out := append([]byte(receiptDomain), r.RecipientAgent[:]...)
	out = append(out, r.EnvelopeID[:]...)
	out = append(out, byte(r.Outcome))
	return binary.BigEndian.AppendUint64(out, r.ReceivedAt), nil
}
func (r Receipt) Encode() ([]byte, error) {
	b, err := r.preimage()
	if err != nil {
		return nil, err
	}
	return append(b, r.Signature[:]...), nil
}
func DecodeReceipt(raw []byte) (Receipt, error) {
	var r Receipt
	if len(raw) != ReceiptSize || !bytes.HasPrefix(raw, []byte(receiptDomain)) {
		return r, ErrReceipt
	}
	reader := wireReader{raw: raw, at: len(receiptDomain)}
	copy(r.RecipientAgent[:], reader.take(32))
	copy(r.EnvelopeID[:], reader.take(32))
	r.Outcome = ReceiptOutcome(reader.u8())
	r.ReceivedAt = reader.u64()
	copy(r.Signature[:], reader.take(64))
	if !reader.done() {
		return Receipt{}, ErrReceipt
	}
	if _, err := r.preimage(); err != nil {
		return Receipt{}, err
	}
	return r, nil
}
func SignReceipt(r Receipt, delegation Delegation, key ed25519.PrivateKey) (Receipt, error) {
	if r.RecipientAgent != delegation.AgentDigest {
		return Receipt{}, ErrReceipt
	}
	b, err := r.preimage()
	if err != nil {
		return Receipt{}, err
	}
	r.Signature, err = signTransport(key, delegation, b)
	return r, err
}

// VerifyReceipt pins the expected Agent, envelope and peer delegation. The
// protocol defines no independent timestamp window for receipts: replay of a
// receipt for the same immutable envelope describes the same delivery outcome.
// Issuers must only sign stored/duplicate after the durable inbox write; this
// codec cannot attest that storage happened or authorize protocol execution.
func (v *Verifier) VerifyReceipt(ctx context.Context, raw, peerDelegation []byte, expectedAgent, expectedEnvelope [32]byte) (Receipt, error) {
	r, err := DecodeReceipt(raw)
	if err != nil {
		return Receipt{}, err
	}
	if r.RecipientAgent != expectedAgent || r.EnvelopeID != expectedEnvelope {
		return Receipt{}, ErrReceipt
	}
	d, err := v.VerifyDelegation(ctx, peerDelegation, Direct)
	if err != nil {
		return Receipt{}, errors.Join(ErrReceipt, err)
	}
	if d.AgentDigest != expectedAgent {
		return Receipt{}, ErrReceipt
	}
	preimage, err := r.preimage()
	if err != nil || !ed25519.Verify(d.TransportKey[:], preimage, r.Signature[:]) {
		return Receipt{}, ErrReceipt
	}
	if err = ctx.Err(); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

// objectTime serializes clock rollback handling with delegation verification.
func (v *Verifier) objectTime(ctx context.Context) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, v.config.ReadTimeout)
	defer cancel()
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	now, err := v.now()
	if err != nil {
		return 0, err
	}
	return uint64(now.Unix()), nil
}
