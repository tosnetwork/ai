package relayframe

// The room ack is a member Endpoint's signed outcome for one room handshake
// object (Commit, Welcome or roster). It rides in a kind-2 frame beside the
// copy ack and is told apart by its object domain. It reports the member's MLS
// epoch and epoch authenticator after handling the object, so the authority
// sees a member whose state diverged.

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// RoomAckSchema names the room ack object.
const RoomAckSchema = "tos.messaging.relay-room-ack.v1"

// ErrRoomAckSignature reports a room ack not signed by the expected Endpoint.
var ErrRoomAckSignature = errors.New("relay room ack signature is not from the member Endpoint")

// RoomAck is one member's outcome for one handshake object. EpochAuthenticator
// is empty only in a rejection by a member with no MLS state (validAckEpoch).
type RoomAck struct {
	RoomID              string
	ObjectDigest        [sha256.Size]byte
	RecipientEndpointID string
	RecipientDeviceID   string
	MLSEpoch            uint64
	EpochAuthenticator  []byte
	Outcome             string
	Code                fault.Code
	AckedAtUnix         uint64
	Signature           []byte
}

// ValidRoomOutcome accepts an outcome with exactly the code it needs: none
// for accepted and duplicate, a known code for rejected. A room handshake is
// never held: its order is the authority's queue.
func ValidRoomOutcome(outcome string, code fault.Code) bool {
	switch outcome {
	case OutcomeAccepted, OutcomeDuplicate:
		return code == ""
	case OutcomeRejected:
		return code != "" && fault.Known(code)
	default:
		return false
	}
}

// validAckEpoch requires the member's MLS epoch and epoch authenticator for
// every outcome but one: a pending joiner refusing its Welcome holds no MLS
// state yet, so a rejected ack may carry no authenticator, and then MLS epoch
// 0. An authenticator, when present, is the 32 non-zero bytes of the suite.
func validAckEpoch(ack RoomAck) bool {
	if len(ack.EpochAuthenticator) == 0 {
		return ack.Outcome == OutcomeRejected && ack.MLSEpoch == 0
	}
	return len(ack.EpochAuthenticator) == RoomAADEpochAuthenticatorBytes && !canon.IsZero(ack.EpochAuthenticator)
}

// RoomAckSigningBytes is the preimage the member Endpoint signs.
func RoomAckSigningBytes(ack RoomAck) ([]byte, error) {
	if !ids.Room.MatchString(ack.RoomID) || ack.ObjectDigest == ([sha256.Size]byte{}) ||
		!ids.Endpoint.MatchString(ack.RecipientEndpointID) || !ids.Device.MatchString(ack.RecipientDeviceID) ||
		ack.AckedAtUnix == 0 || !ValidRoomOutcome(ack.Outcome, ack.Code) || !validAckEpoch(ack) {
		return nil, ErrFrameMalformed
	}
	buffer := bytes.NewBufferString(canon.DomainRelayRoomAck)
	canon.Text(buffer, ack.RoomID)
	canon.Bytes(buffer, ack.ObjectDigest[:])
	canon.Text(buffer, ack.RecipientEndpointID)
	canon.Text(buffer, ack.RecipientDeviceID)
	canon.Uint64(buffer, ack.MLSEpoch)
	canon.Bytes(buffer, ack.EpochAuthenticator)
	canon.Text(buffer, ack.Outcome)
	canon.Text(buffer, string(ack.Code))
	canon.Uint64(buffer, ack.AckedAtUnix)
	return buffer.Bytes(), nil
}

// SignRoomAck signs a room ack with the Endpoint signer, which must be Ed25519.
func SignRoomAck(ack RoomAck, signer crypto.Signer) (RoomAck, error) {
	if signer == nil {
		return RoomAck{}, errors.New("relay room ack needs an Endpoint signer")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return RoomAck{}, errors.New("relay room ack needs an Ed25519 Endpoint signer")
	}
	preimage, err := RoomAckSigningBytes(ack)
	if err != nil {
		return RoomAck{}, err
	}
	signature, err := signer.Sign(rand.Reader, preimage, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return RoomAck{}, errors.New("sign relay room ack")
	}
	if !ed25519.Verify(public, preimage, signature) {
		return RoomAck{}, ErrRoomAckSignature
	}
	ack.Signature = append([]byte(nil), signature...)
	return ack, nil
}

// VerifyRoomAck checks the signature under the member Endpoint's public key.
func VerifyRoomAck(ack RoomAck, endpointKey ed25519.PublicKey) error {
	if len(endpointKey) != ed25519.PublicKeySize || len(ack.Signature) != ed25519.SignatureSize {
		return ErrRoomAckSignature
	}
	preimage, err := RoomAckSigningBytes(ack)
	if err != nil {
		return err
	}
	if !ed25519.Verify(endpointKey, preimage, ack.Signature) {
		return ErrRoomAckSignature
	}
	return nil
}

// EncodeRoomAck returns the room ack object: the signing preimage followed by
// the length-prefixed signature.
func EncodeRoomAck(ack RoomAck) ([]byte, error) {
	preimage, err := RoomAckSigningBytes(ack)
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

// DecodeRoomAck strictly parses a room ack object. It checks shape only; the
// caller verifies the signature under the finalized Endpoint key.
func DecodeRoomAck(raw []byte) (RoomAck, error) {
	if !bytes.HasPrefix(raw, []byte(canon.DomainRelayRoomAck)) {
		return RoomAck{}, ErrFrameMalformed
	}
	reader := byteReader{buffer: raw, offset: len(canon.DomainRelayRoomAck)}
	ack := RoomAck{RoomID: string(reader.lengthPrefixed(len("room_")+64, ErrFrameMalformed))}
	digest := reader.lengthPrefixed(sha256.Size, ErrFrameMalformed)
	ack.RecipientEndpointID = string(reader.lengthPrefixed(idBytes, ErrFrameMalformed))
	ack.RecipientDeviceID = string(reader.lengthPrefixed(idBytes, ErrFrameMalformed))
	ack.MLSEpoch = reader.u64()
	ack.EpochAuthenticator = reader.lengthPrefixed(RoomAADEpochAuthenticatorBytes, ErrFrameMalformed)
	ack.Outcome = string(reader.lengthPrefixed(maxOutcomeBytes, ErrFrameMalformed))
	ack.Code = fault.Code(reader.lengthPrefixed(64, ErrFrameMalformed))
	ack.AckedAtUnix = reader.u64()
	ack.Signature = reader.lengthPrefixed(ed25519.SignatureSize, ErrFrameMalformed)
	if err := reader.done(); err != nil {
		return RoomAck{}, err
	}
	if len(digest) != sha256.Size || len(ack.Signature) != ed25519.SignatureSize {
		return RoomAck{}, ErrFrameMalformed
	}
	copy(ack.ObjectDigest[:], digest)
	if _, err := RoomAckSigningBytes(ack); err != nil {
		return RoomAck{}, err
	}
	return ack, nil
}

// IsRoomAck reports whether a kind-2 object is a room ack rather than a copy
// ack, by its domain.
func IsRoomAck(object []byte) bool {
	return bytes.HasPrefix(object, []byte(canon.DomainRelayRoomAck))
}
