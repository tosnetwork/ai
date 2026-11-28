// Package agenttransport implements the fixed transport delegation boundary.
// Delegations have no off-chain issuer signature: finalized registry membership
// authorizes their exact digest.
package agenttransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"filippo.io/edwards25519"
)

const (
	DelegationSize       = 167
	MaxDelegationSeconds = 31536000
	MaxCredentialSeconds = 604800
	delegationDomain     = "tos.service.agent-transport-delegation.v1\x00"
)

type Purpose byte

const (
	Relay  Purpose = 1
	Hints  Purpose = 2
	Direct Purpose = 4
)

// Delegation contains every field in the canonical preimage, in wire order.
type Delegation struct {
	AgentDigest          [32]byte
	TransportKey         [32]byte
	AuthorizationEpoch   uint64
	PolicyHash           [32]byte
	Purposes             Purpose
	NotBefore            uint64
	NotAfter             uint64
	MaxCredentialSeconds uint32
}

func (d Delegation) AgentID() string { return "agent_" + hex.EncodeToString(d.AgentDigest[:]) }

func (d Delegation) validate() error {
	p, err := new(edwards25519.Point).SetBytes(d.TransportKey[:])
	if err != nil || !bytes.Equal(p.Bytes(), d.TransportKey[:]) {
		return errors.New("noncanonical transport public key")
	}
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("small-order transport public key")
	}
	if d.Purposes == 0 || d.Purposes & ^Purpose(7) != 0 {
		return errors.New("invalid delegation purposes")
	}
	if d.NotBefore == 0 || d.NotAfter <= d.NotBefore || d.NotAfter-d.NotBefore > MaxDelegationSeconds {
		return errors.New("invalid delegation lifetime")
	}
	if d.MaxCredentialSeconds == 0 || d.MaxCredentialSeconds > MaxCredentialSeconds {
		return errors.New("invalid credential lifetime")
	}
	return nil
}

// Encode serializes structural values. Use Verifier.BuildDelegation for an
// issuance checked against the current finalized epoch and policy.
func (d Delegation) Encode() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, DelegationSize)
	b = append(b, delegationDomain...)
	b = append(b, d.AgentDigest[:]...)
	b = append(b, d.TransportKey[:]...)
	b = binary.BigEndian.AppendUint64(b, d.AuthorizationEpoch)
	b = append(b, d.PolicyHash[:]...)
	b = append(b, byte(d.Purposes))
	b = binary.BigEndian.AppendUint64(b, d.NotBefore)
	b = binary.BigEndian.AppendUint64(b, d.NotAfter)
	return binary.BigEndian.AppendUint32(b, d.MaxCredentialSeconds), nil
}

func DecodeDelegation(b []byte) (Delegation, error) {
	var d Delegation
	if len(b) != DelegationSize || !bytes.Equal(b[:len(delegationDomain)], []byte(delegationDomain)) {
		return d, errors.New("invalid delegation size or domain")
	}
	n := len(delegationDomain)
	copy(d.AgentDigest[:], b[n:n+32])
	n += 32
	copy(d.TransportKey[:], b[n:n+32])
	n += 32
	d.AuthorizationEpoch = binary.BigEndian.Uint64(b[n:])
	n += 8
	copy(d.PolicyHash[:], b[n:n+32])
	n += 32
	d.Purposes = Purpose(b[n])
	n++
	d.NotBefore = binary.BigEndian.Uint64(b[n:])
	n += 8
	d.NotAfter = binary.BigEndian.Uint64(b[n:])
	n += 8
	d.MaxCredentialSeconds = binary.BigEndian.Uint32(b[n:])
	return d, d.validate()
}

func DelegationDigest(b []byte) ([32]byte, error) {
	if _, err := DecodeDelegation(b); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// BuildDelegation refuses issuance for a future/stale epoch or another policy.
// It does not require membership: committing the resulting digest is a later
// native action, authorized by the Agent's controllers.
func (v *Verifier) BuildDelegation(ctx context.Context, d Delegation) ([]byte, error) {
	b, err := d.Encode()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, v.config.ReadTimeout)
	defer cancel()
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := v.resolver.ResolveFinalizedAgent(ctx, d.AgentID())
	if expired := ctx.Err(); expired != nil {
		return nil, expired
	}
	if err != nil {
		return nil, err
	}
	if err = v.checkSnapshot(d, sha256.Sum256(b), s, false); err != nil {
		return nil, err
	}
	return b, nil
}
