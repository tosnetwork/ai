package relayframe

import (
	"bytes"

	"github.com/tosnetwork/ai/messenger/internal/canon"
)

// EvidenceSchema names the locator-free relay identity evidence.
const EvidenceSchema = "tos.messaging.relay-evidence.v1"

// Relay bounds of the four evidence objects. They are lower than the network
// route's bounds on purpose: the real objects are several times smaller, and
// a node whose own objects exceed one of them cannot publish relay evidence.
const (
	MaxEvidenceDelegationBytes = 4_096
	MaxEvidencePolicyBytes     = 1_024
	MaxEvidenceDescriptorBytes = 4_096
	MaxEvidenceBundleSetBytes  = 8_192
)

// Evidence is the exact wire bytes of the four objects of the refresh chain
// that remain once the locator stage is removed: the Endpoint delegation, the
// descriptor policy it commits, the signed Contact Descriptor, and the prekey
// bundle set that descriptor commits. Nothing here is trusted; the directory
// verifies every object against finalized state.
type Evidence struct {
	Delegation []byte
	Policy     []byte
	Descriptor []byte
	BundleSet  []byte
}

// EncodeEvidence returns the canonical evidence encoding. An empty object is
// malformed; an object above its relay bound, or a total above the frame's
// evidence bound, fails with ErrRelayEvidenceTooLarge.
func EncodeEvidence(evidence Evidence) ([]byte, error) {
	if err := checkEvidenceObjects(evidence); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainRelayEvidence)
	canon.Bytes(buffer, evidence.Delegation)
	canon.Bytes(buffer, evidence.Policy)
	canon.Bytes(buffer, evidence.Descriptor)
	canon.Bytes(buffer, evidence.BundleSet)
	if buffer.Len() > MaxEvidenceBytes {
		return nil, ErrRelayEvidenceTooLarge
	}
	return buffer.Bytes(), nil
}

// DecodeEvidence strictly parses evidence bytes, refusing an object above its
// relay bound with ErrRelayEvidenceTooLarge before reading it.
func DecodeEvidence(raw []byte) (Evidence, error) {
	if len(raw) > MaxEvidenceBytes {
		return Evidence{}, ErrRelayEvidenceTooLarge
	}
	if !bytes.HasPrefix(raw, []byte(canon.DomainRelayEvidence)) {
		return Evidence{}, ErrFrameMalformed
	}
	reader := byteReader{buffer: raw, offset: len(canon.DomainRelayEvidence)}
	evidence := Evidence{
		Delegation: reader.lengthPrefixed(MaxEvidenceDelegationBytes, ErrRelayEvidenceTooLarge),
		Policy:     reader.lengthPrefixed(MaxEvidencePolicyBytes, ErrRelayEvidenceTooLarge),
		Descriptor: reader.lengthPrefixed(MaxEvidenceDescriptorBytes, ErrRelayEvidenceTooLarge),
		BundleSet:  reader.lengthPrefixed(MaxEvidenceBundleSetBytes, ErrRelayEvidenceTooLarge),
	}
	if err := reader.done(); err != nil {
		return Evidence{}, err
	}
	if err := checkEvidenceObjects(evidence); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

// EvidenceDigest identifies exact evidence bytes.
func EvidenceDigest(raw []byte) string { return canon.Digest(raw) }

func checkEvidenceObjects(evidence Evidence) error {
	for _, object := range []struct {
		value   []byte
		maximum int
	}{
		{evidence.Delegation, MaxEvidenceDelegationBytes},
		{evidence.Policy, MaxEvidencePolicyBytes},
		{evidence.Descriptor, MaxEvidenceDescriptorBytes},
		{evidence.BundleSet, MaxEvidenceBundleSetBytes},
	} {
		if len(object.value) == 0 {
			return ErrFrameMalformed
		}
		if len(object.value) > object.maximum {
			return ErrRelayEvidenceTooLarge
		}
	}
	return nil
}
