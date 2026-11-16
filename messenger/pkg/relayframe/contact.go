package relayframe

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

// ContactSchema names the exported relay contact: an unsigned container of
// the node's relay identity evidence and its chat key card. Nothing in it is
// authority; the importer verifies every object.
const ContactSchema = "tos.messaging.relay-contact.v1"

// MaxContactBytes bounds one contact file.
const MaxContactBytes = 64 << 10

// Contact is one exported relay contact. It carries no locator.
type Contact struct {
	AgentID  string
	Evidence []byte
	Card     []byte
}

type wireContact struct {
	Schema         string `json:"schema"`
	AgentID        string `json:"agent_id"`
	EvidenceBase64 string `json:"relay_evidence_base64"`
	CardBase64     string `json:"chat_card_base64"`
}

// EncodeContactJSON returns the strict contact file bytes.
func EncodeContactJSON(contact Contact) ([]byte, error) {
	if err := validateContact(contact); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wireContact{Schema: ContactSchema, AgentID: contact.AgentID,
		EvidenceBase64: base64.StdEncoding.EncodeToString(contact.Evidence),
		CardBase64:     base64.StdEncoding.EncodeToString(contact.Card)})
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxContactBytes {
		return nil, ErrRelayEvidenceTooLarge
	}
	return raw, nil
}

// DecodeContactJSON strictly parses a contact file and checks the shape of
// its evidence. It verifies nothing against finalized state.
func DecodeContactJSON(raw []byte) (Contact, error) {
	if len(raw) == 0 || len(raw) > MaxContactBytes {
		return Contact{}, errors.New("relay contact file size is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire wireContact
	if err := decoder.Decode(&wire); err != nil {
		return Contact{}, errors.New("relay contact file is not strict JSON")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Contact{}, errors.New("relay contact file has trailing content")
	}
	if wire.Schema != ContactSchema {
		return Contact{}, errors.New("unsupported relay contact schema")
	}
	evidence, err := base64.StdEncoding.Strict().DecodeString(wire.EvidenceBase64)
	if err != nil {
		return Contact{}, errors.New("relay contact evidence is not base64")
	}
	card, err := base64.StdEncoding.Strict().DecodeString(wire.CardBase64)
	if err != nil {
		return Contact{}, errors.New("relay contact card is not base64")
	}
	contact := Contact{AgentID: wire.AgentID, Evidence: evidence, Card: card}
	if err := validateContact(contact); err != nil {
		return Contact{}, err
	}
	return contact, nil
}

func validateContact(contact Contact) error {
	if !ids.Agent.MatchString(contact.AgentID) {
		return errors.New("relay contact names no valid Agent")
	}
	if len(contact.Card) == 0 {
		return ErrCardRequired
	}
	if len(contact.Card) > MaxCardBytes {
		return ErrCardTooLarge
	}
	if len(contact.Evidence) == 0 {
		return ErrEvidenceRequired
	}
	_, err := DecodeEvidence(contact.Evidence)
	return err
}

// Idempotency key purposes.
const (
	purposeCopy             = "copy"
	purposeEvidenceRequest  = "evidence-request"
	purposeEvidenceResponse = "evidence-response"
)

// CopyIdempotencyKey names one deposit generation of one device copy. A
// retry of the same generation reuses the key, so the carrier reuses the
// envelope it journaled; the next generation gets a fresh one.
func CopyIdempotencyKey(deliveryID string, generation uint32) (string, error) {
	if deliveryID == "" || len(deliveryID) > 128 || generation == 0 {
		return "", errors.New("invalid relay copy generation")
	}
	return idempotencyKey(purposeCopy, deliveryID, uint64(generation))
}

// EvidenceRequestKey names one deposit generation of the single outstanding
// evidence request to a peer.
func EvidenceRequestKey(peerAgentID string, generation uint32) (string, error) {
	if !ids.Agent.MatchString(peerAgentID) || generation == 0 {
		return "", errors.New("invalid relay evidence request generation")
	}
	return idempotencyKey(purposeEvidenceRequest, peerAgentID, uint64(generation))
}

// EvidenceResponseKey names the one response a node may send a peer for one
// of its own descriptors within one hour.
func EvidenceResponseKey(peerAgentID, ownDescriptorDigest string, hour uint64) (string, error) {
	if !ids.Agent.MatchString(peerAgentID) || !canon.ValidDigest(ownDescriptorDigest) || hour == 0 {
		return "", errors.New("invalid relay evidence response window")
	}
	return idempotencyKey(purposeEvidenceResponse, peerAgentID+"\x00"+ownDescriptorDigest, hour)
}

func idempotencyKey(purpose, subject string, counter uint64) (string, error) {
	buffer := bytes.NewBufferString(canon.DomainRelayIdempotency)
	canon.Text(buffer, purpose)
	canon.Text(buffer, subject)
	canon.Uint64(buffer, counter)
	sum := sha256.Sum256(buffer.Bytes())
	return "idem_" + hex.EncodeToString(sum[:]), nil
}
