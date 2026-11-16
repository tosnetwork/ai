package relayframe

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// AckSchema names the kind-2 object.
const AckSchema = "tos.messaging.relay-delivery-ack.v1"

// Delivery ack outcomes.
const (
	OutcomeAccepted  = "accepted"
	OutcomeDuplicate = "duplicate"
	OutcomeHeld      = "held"
	OutcomeRejected  = "rejected"
)

const maxOutcomeBytes = 16

// ErrAckSignature reports an ack not signed by the expected Endpoint key.
var ErrAckSignature = errors.New("relay delivery ack signature is not from the recipient Endpoint")

// Ack is a recipient Endpoint's signed outcome for one device copy. Its
// fields are those of the HTTPS ack; the signing domain is not, so an ack
// verifies on one route only.
type Ack struct {
	EventID             string
	SessionID           string
	RecipientEndpointID string
	RecipientDeviceID   string
	CiphertextDigest    string
	Outcome             string
	Code                fault.Code
	AcceptedAtUnix      uint64
	Signature           []byte
}

// AckSigningBytes is the preimage the recipient Endpoint signs.
func AckSigningBytes(ack Ack) ([]byte, error) {
	if !ids.Event.MatchString(ack.EventID) || !ids.Session.MatchString(ack.SessionID) ||
		!ids.Endpoint.MatchString(ack.RecipientEndpointID) || !ids.Device.MatchString(ack.RecipientDeviceID) ||
		!canon.ValidDigest(ack.CiphertextDigest) || ack.AcceptedAtUnix == 0 || !ValidOutcome(ack.Outcome, ack.Code) {
		return nil, ErrFrameMalformed
	}
	buffer := bytes.NewBufferString(canon.DomainRelayDeliveryAck)
	for _, value := range []string{ack.EventID, ack.SessionID, ack.RecipientEndpointID,
		ack.RecipientDeviceID, ack.CiphertextDigest, ack.Outcome, string(ack.Code)} {
		canon.Text(buffer, value)
	}
	canon.Uint64(buffer, ack.AcceptedAtUnix)
	return buffer.Bytes(), nil
}

// ValidOutcome accepts an outcome with exactly the code it needs: none for
// accepted, duplicate and held, a known code for rejected.
func ValidOutcome(outcome string, code fault.Code) bool {
	switch outcome {
	case OutcomeAccepted, OutcomeDuplicate, OutcomeHeld:
		return code == ""
	case OutcomeRejected:
		return code != "" && fault.Known(code)
	default:
		return false
	}
}

// SignAck signs an ack with the Endpoint signer, which must be Ed25519.
func SignAck(ack Ack, signer crypto.Signer) (Ack, error) {
	if signer == nil {
		return Ack{}, errors.New("relay delivery ack needs an Endpoint signer")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return Ack{}, errors.New("relay delivery ack needs an Ed25519 Endpoint signer")
	}
	preimage, err := AckSigningBytes(ack)
	if err != nil {
		return Ack{}, err
	}
	signature, err := signer.Sign(rand.Reader, preimage, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Ack{}, errors.New("sign relay delivery ack")
	}
	if !ed25519.Verify(public, preimage, signature) {
		return Ack{}, ErrAckSignature
	}
	ack.Signature = append([]byte(nil), signature...)
	return ack, nil
}

// VerifyAck checks the signature under the recipient Endpoint's public key.
func VerifyAck(ack Ack, endpointKey ed25519.PublicKey) error {
	if len(endpointKey) != ed25519.PublicKeySize || len(ack.Signature) != ed25519.SignatureSize {
		return ErrAckSignature
	}
	preimage, err := AckSigningBytes(ack)
	if err != nil {
		return err
	}
	if !ed25519.Verify(endpointKey, preimage, ack.Signature) {
		return ErrAckSignature
	}
	return nil
}

// EncodeAck returns the kind-2 object: the signing preimage followed by the
// length-prefixed signature.
func EncodeAck(ack Ack) ([]byte, error) {
	preimage, err := AckSigningBytes(ack)
	if err != nil {
		return nil, err
	}
	if len(ack.Signature) != ed25519.SignatureSize {
		return nil, ErrFrameMalformed
	}
	buffer := bytes.NewBuffer(preimage)
	canon.Bytes(buffer, ack.Signature)
	return buffer.Bytes(), nil
}

// DecodeAck strictly parses a kind-2 object. It checks shape only; the caller
// verifies the signature under the finalized Endpoint key.
func DecodeAck(raw []byte) (Ack, error) {
	if !bytes.HasPrefix(raw, []byte(canon.DomainRelayDeliveryAck)) {
		return Ack{}, ErrFrameMalformed
	}
	reader := byteReader{buffer: raw, offset: len(canon.DomainRelayDeliveryAck)}
	ack := Ack{
		EventID:             string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		SessionID:           string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		RecipientEndpointID: string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		RecipientDeviceID:   string(reader.lengthPrefixed(idBytes, ErrFrameMalformed)),
		CiphertextDigest:    string(reader.lengthPrefixed(len("sha256:")+64, ErrFrameMalformed)),
		Outcome:             string(reader.lengthPrefixed(maxOutcomeBytes, ErrFrameMalformed)),
		Code:                fault.Code(reader.lengthPrefixed(64, ErrFrameMalformed)),
	}
	ack.AcceptedAtUnix = reader.u64()
	ack.Signature = reader.lengthPrefixed(ed25519.SignatureSize, ErrFrameMalformed)
	if err := reader.done(); err != nil {
		return Ack{}, err
	}
	if len(ack.Signature) != ed25519.SignatureSize {
		return Ack{}, ErrFrameMalformed
	}
	if _, err := AckSigningBytes(ack); err != nil {
		return Ack{}, err
	}
	return ack, nil
}
