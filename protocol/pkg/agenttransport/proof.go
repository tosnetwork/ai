package agenttransport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

// Request proof limits of section 5.4.
const (
	ProofWindowSeconds = 120
	// ProofHeaderSize is issued_at_unix u64 || nonce 32 || signature 64.
	ProofHeaderSize = 8 + 32 + 64

	proofDomain = "tos.service.relay-request.v1\x00"
	maxPathSize = 0xffff
	maxMethod   = 0xff
)

var rawURL = base64.RawURLEncoding.Strict()

// maxCredentialHeader is the unpadded base64url length of MaxCredentialSize.
var maxCredentialHeader = rawURL.EncodedLen(MaxCredentialSize)

// ProofRequest is what a request proof binds besides the credential.
// RelayURL is the relay's configured base URL; Path is the escaped request
// path without query or fragment.
type ProofRequest struct {
	RelayURL string
	Method   string
	Path     string
	Body     []byte
}

func (r ProofRequest) validate() error {
	if err := (Caveat{Type: CaveatRelay, Value: []byte(r.RelayURL)}).validate(); err != nil {
		return invalid("proof relay URL is not a canonical relay base URL")
	}
	if len(r.Method) < 1 || len(r.Method) > maxMethod {
		return invalid("proof method length")
	}
	for i := 0; i < len(r.Method); i++ {
		if r.Method[i] < 'A' || r.Method[i] > 'Z' {
			return invalid("proof method is not an uppercase token")
		}
	}
	if len(r.Path) < 1 || len(r.Path) > maxPathSize || r.Path[0] != '/' {
		return invalid("proof path must begin with / and fit u16")
	}
	for i := 0; i < len(r.Path); i++ {
		if c := r.Path[i]; c <= 0x20 || c >= 0x7f || c == '?' || c == '#' {
			return invalid("proof path has a byte outside an escaped path")
		}
	}
	return nil
}

// ProofPreimage is the signed request proof preimage of section 5.4.
func ProofPreimage(credentialID [32]byte, r ProofRequest, issuedAt uint64, nonce [32]byte) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	body := sha256.Sum256(r.Body)
	out := append([]byte(proofDomain), credentialID[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.RelayURL)))
	out = append(out, r.RelayURL...)
	out = append(out, byte(len(r.Method)))
	out = append(out, r.Method...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Path)))
	out = append(out, r.Path...)
	out = append(out, body[:]...)
	out = binary.BigEndian.AppendUint64(out, issuedAt)
	return append(out, nonce[:]...), nil
}

// EncodeCredentialHeader is the TOS-Relay-Credential header value.
func EncodeCredentialHeader(credential []byte) string { return rawURL.EncodeToString(credential) }

// decodeHeader accepts only the canonical unpadded base64url spelling: the
// decoder skips CR and LF, so the value must re-encode to itself.
func decodeHeader(value string, limit int) ([]byte, error) {
	if len(value) > limit {
		return nil, invalid("header too long")
	}
	raw, err := rawURL.DecodeString(value)
	if err != nil || rawURL.EncodeToString(raw) != value {
		return nil, invalid("header is not canonical unpadded base64url")
	}
	return raw, nil
}

// DecodeCredentialHeader decodes a TOS-Relay-Credential value.
func DecodeCredentialHeader(value string) ([]byte, error) {
	return decodeHeader(value, maxCredentialHeader)
}

// Proof is a decoded TOS-Relay-Proof value.
type Proof struct {
	IssuedAt  uint64
	Nonce     [32]byte
	Signature [64]byte
}

func (p Proof) Header() string {
	raw := binary.BigEndian.AppendUint64(nil, p.IssuedAt)
	raw = append(raw, p.Nonce[:]...)
	return rawURL.EncodeToString(append(raw, p.Signature[:]...))
}

// DecodeProofHeader decodes a TOS-Relay-Proof value of exactly 104 bytes.
func DecodeProofHeader(value string) (Proof, error) {
	var p Proof
	raw, err := decodeHeader(value, rawURL.EncodedLen(ProofHeaderSize))
	if err != nil {
		return p, err
	}
	if len(raw) != ProofHeaderSize {
		return p, invalid("proof is %d bytes, want %d", len(raw), ProofHeaderSize)
	}
	p.IssuedAt = binary.BigEndian.Uint64(raw)
	copy(p.Nonce[:], raw[8:40])
	copy(p.Signature[:], raw[40:])
	return p, nil
}

// SignRequest makes a request proof with the credential's holder key.
func SignRequest(c *Credential, holder ed25519.PrivateKey, r ProofRequest, issuedAt uint64, nonce [32]byte) (Proof, error) {
	public, err := publicOf(holder)
	if err != nil {
		return Proof{}, err
	}
	if public != c.HolderKey() {
		return Proof{}, invalid("signing key is not the credential's holder key")
	}
	preimage, err := ProofPreimage(c.CredentialID(), r, issuedAt, nonce)
	if err != nil {
		return Proof{}, err
	}
	p := Proof{IssuedAt: issuedAt, Nonce: nonce}
	copy(p.Signature[:], ed25519.Sign(holder, preimage))
	return p, nil
}

// CheckProofWindow requires |now - issued_at| <= 120.
func CheckProofWindow(issuedAt, now uint64) error {
	if (issuedAt > now && issuedAt-now > ProofWindowSeconds) || (now > issuedAt && now-issuedAt > ProofWindowSeconds) {
		return invalid("proof time is outside the %d-second window", ProofWindowSeconds)
	}
	return nil
}

// VerifyProof checks the proof window and the holder signature. It does not
// claim the nonce: the relay's replay table does (ReplayTable.Claim).
func (c *Credential) VerifyProof(r ProofRequest, p Proof, now uint64) error {
	if err := CheckProofWindow(p.IssuedAt, now); err != nil {
		return err
	}
	preimage, err := ProofPreimage(c.CredentialID(), r, p.IssuedAt, p.Nonce)
	if err != nil {
		return err
	}
	holder := c.HolderKey()
	if !ed25519.Verify(holder[:], preimage, p.Signature[:]) {
		return invalid("request proof signature")
	}
	return nil
}

// Request is one credentialed relay request as the relay sees it.
type Request struct {
	// AgentID is the {agent} path segment.
	AgentID         string
	Operation       Operation
	Proof           ProofRequest
	CredentialValue string
	ProofValue      string
	Now             uint64
}

// CheckedRequest is a request whose stateless checks passed. The relay then
// claims the nonce, checks the mailbox revocation set against ChainValues and
// calls VerifyDelegation with the relay-access purpose, in that order (6.1).
type CheckedRequest struct {
	Credential *Credential
	Proof      Proof
}

// CheckRequest runs the stateless credential checks of section 6.1, cheapest
// first: decode; delegation shape and Agent match; chain and signatures;
// caveats against the request; proof window and signature.
func CheckRequest(r Request) (CheckedRequest, error) {
	raw, err := DecodeCredentialHeader(r.CredentialValue)
	if err != nil {
		return CheckedRequest{}, err
	}
	c, err := DecodeCredential(raw)
	if err != nil {
		return CheckedRequest{}, err
	}
	proof, err := DecodeProofHeader(r.ProofValue)
	if err != nil {
		return CheckedRequest{}, err
	}
	if c.Delegation.AgentID() != r.AgentID {
		return CheckedRequest{}, scope("path names another Agent")
	}
	if err = c.VerifyChain(); err != nil {
		return CheckedRequest{}, err
	}
	if err = c.CheckScope(r.Now, r.Proof.RelayURL, r.Operation); err != nil {
		return CheckedRequest{}, err
	}
	if err = c.VerifyProof(r.Proof, proof, r.Now); err != nil {
		return CheckedRequest{}, err
	}
	return CheckedRequest{Credential: c, Proof: proof}, nil
}
