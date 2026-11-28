package vectors

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// RelayVector is one relay carriage object. Error is the fixed error a
// decoder must return for it, or empty for a valid object.
type RelayVector struct {
	Name   string `json:"name"`
	Wire   string `json:"wire_hex"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Error  string `json:"error,omitempty"`
}

func TestRelayCarriageVectors(t *testing.T) {
	produced := buildRelay(t)
	path := filepath.Join("testdata", "relay-vectors.json")
	encoded, err := json.MarshalIndent(produced, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded = append(encoded, '\n')
	if *update {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed relay vectors: %v (run with -update to create them)", err)
	}
	if !bytes.Equal(committed, encoded) {
		t.Fatal("the relay carriage forms changed; this is a wire-format change. Re-run with -update and review the diff.")
	}
	// Every committed vector decodes, or fails, exactly as it says.
	for _, vector := range produced {
		raw, err := hex.DecodeString(vector.Wire)
		if err != nil {
			t.Fatal(err)
		}
		var decodeErr error
		switch {
		case strings.HasPrefix(vector.Name, "relay-frame"):
			_, decodeErr = relayframe.Decode(raw)
		case strings.HasPrefix(vector.Name, "relay-evidence"):
			_, decodeErr = relayframe.DecodeEvidence(raw)
		case strings.HasPrefix(vector.Name, "relay-copy"):
			_, decodeErr = relayframe.DecodeCopy(raw)
		case strings.HasPrefix(vector.Name, "relay-delivery-ack"):
			_, decodeErr = relayframe.DecodeAck(raw)
		default:
			t.Fatalf("unclassified relay vector %s", vector.Name)
		}
		if vector.Error == "" && decodeErr != nil || vector.Error != "" && (decodeErr == nil || decodeErr.Error() != vector.Error) {
			t.Fatalf("%s: decode error %v, vector says %q", vector.Name, decodeErr, vector.Error)
		}
	}
}

func buildRelay(t *testing.T) []RelayVector {
	t.Helper()
	key := endpointKey()
	del := delegation(t)
	var vectors []RelayVector
	add := func(name string, raw []byte, expected error) {
		vector := RelayVector{Name: name, Wire: hex.EncodeToString(raw), SHA256: canon.Digest(raw), Bytes: len(raw)}
		if expected != nil {
			vector.Error = expected.Error()
		}
		vectors = append(vectors, vector)
	}

	// Locator-free evidence of one device.
	bundle, err := e2ee.SignBundle(e2ee.Bundle{Network: del.Network, AgentID: del.AgentID, EndpointID: del.EndpointID,
		DeviceID: deviceOne, AlgorithmID: algorithm, Material: []byte("published prekey material"),
		IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600}, key)
	if err != nil {
		t.Fatal(err)
	}
	set, err := e2ee.EncodeBundleSetJSON([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	setDigest, err := e2ee.SetDigest([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	delegationDigest, err := identity.Digest(del)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := directory.SignDescriptor(directory.Descriptor{Network: del.Network, AgentID: del.AgentID,
		EndpointID: del.EndpointID, DelegationDigest: delegationDigest, SupportedMessagingVersions: []uint32{1},
		ADNLID: del.ADNLID, PrekeyBundleDigest: setDigest, InboxAdmissionPolicyDigest: del.InboxAdmissionPolicyDigest,
		MaximumEnvelopeBytes: 64 << 10, IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600}, key)
	if err != nil {
		t.Fatal(err)
	}
	descriptorJSON, err := directory.EncodeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	delegationJSON, err := identity.EncodeJSON(del)
	if err != nil {
		t.Fatal(err)
	}
	policyJSON, err := directory.EncodeDescriptorPolicyJSON(descriptorPolicy())
	if err != nil {
		t.Fatal(err)
	}
	objects := relayframe.Evidence{Delegation: delegationJSON, Policy: policyJSON, Descriptor: descriptorJSON, BundleSet: set}
	evidence, err := relayframe.EncodeEvidence(objects)
	if err != nil {
		t.Fatal(err)
	}
	add("relay-evidence", evidence, nil)

	// One over-bound object of each kind, as a hostile sender would write it.
	for _, over := range []struct {
		name    string
		maximum int
		set     func(*relayframe.Evidence, []byte)
	}{
		{"delegation", relayframe.MaxEvidenceDelegationBytes, func(e *relayframe.Evidence, v []byte) { e.Delegation = v }},
		{"policy", relayframe.MaxEvidencePolicyBytes, func(e *relayframe.Evidence, v []byte) { e.Policy = v }},
		{"descriptor", relayframe.MaxEvidenceDescriptorBytes, func(e *relayframe.Evidence, v []byte) { e.Descriptor = v }},
		{"bundle-set", relayframe.MaxEvidenceBundleSetBytes, func(e *relayframe.Evidence, v []byte) { e.BundleSet = v }},
	} {
		value := objects
		over.set(&value, bytes.Repeat([]byte{' '}, over.maximum+1))
		buffer := bytes.NewBufferString(canon.DomainRelayEvidence)
		for _, object := range [][]byte{value.Delegation, value.Policy, value.Descriptor, value.BundleSet} {
			canon.Bytes(buffer, object)
		}
		if _, err := relayframe.EncodeEvidence(value); !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
			t.Fatalf("over-bound %s encoded: %v", over.name, err)
		}
		add("relay-evidence-over-bound-"+over.name, buffer.Bytes(), relayframe.ErrRelayEvidenceTooLarge)
	}

	// A device copy, its delivery ack and the four frames.
	copyObject, err := relayframe.EncodeCopy(relayframe.Copy{EventID: "evt_" + strings.Repeat("1a", 32),
		SessionID: "ses_" + strings.Repeat("2b", 32), RecipientEndpointID: "mep_" + strings.Repeat("3c", 32),
		RecipientDeviceID: deviceTwo, ConversationID: convoID, AdmissionToken: "invite.1",
		Ciphertext: bytes.Repeat([]byte{0x5e}, 96), ExpiresAtUnix: baseUnix + 3600})
	if err != nil {
		t.Fatal(err)
	}
	add("relay-copy", copyObject, nil)
	ack, err := relayframe.SignAck(relayframe.Ack{EventID: "evt_" + strings.Repeat("1a", 32),
		SessionID: "ses_" + strings.Repeat("2b", 32), RecipientEndpointID: del.EndpointID, RecipientDeviceID: deviceOne,
		CiphertextDigest: canon.Digest(bytes.Repeat([]byte{0x5e}, 96)), Outcome: relayframe.OutcomeRejected,
		Code: fault.CodeDescriptorExpired, AcceptedAtUnix: baseUnix + 20}, key)
	if err != nil {
		t.Fatal(err)
	}
	ackObject, err := relayframe.EncodeAck(ack)
	if err != nil {
		t.Fatal(err)
	}
	add("relay-delivery-ack", ackObject, nil)
	card := []byte(`{"schema":"tos.service.agent-packet.v1","note":"opaque to the frame codec"}`)
	for _, frame := range []struct {
		name  string
		value relayframe.Frame
	}{
		{"relay-frame-copy", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Card: card, Evidence: evidence, Part: copyObject}},
		{"relay-frame-delivery-ack", relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1, Evidence: evidence, Part: ackObject}},
		{"relay-frame-evidence-request", relayframe.Frame{Kind: relayframe.KindEvidence, PartCount: 1, Card: card,
			Evidence: evidence, Part: []byte{relayframe.EvidenceRequest}}},
		{"relay-frame-evidence-response", relayframe.Frame{Kind: relayframe.KindEvidence, PartCount: 1, Card: card,
			Evidence: evidence, Part: []byte{relayframe.EvidenceResponse}}},
	} {
		raw, err := relayframe.Encode(frame.value)
		if err != nil {
			t.Fatalf("%s: %v", frame.name, err)
		}
		add(frame.name, raw, nil)
	}

	// Frame v2's credential field: a copy carrying a contact credential and its
	// holder seed, the largest credential, and the refusals a decoder owes.
	credential := []byte("contact credential, opaque to the frame codec")
	seed := [relayframe.HolderSeedBytes]byte{}
	for index := range seed {
		seed[index] = byte(0xa0 + index)
	}
	withCredential := relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Card: card, Evidence: evidence,
		Credential: credential, HolderSeed: seed, Part: copyObject}
	raw, err := relayframe.Encode(withCredential)
	if err != nil {
		t.Fatal(err)
	}
	add("relay-frame-copy-credential", raw, nil)
	largest := withCredential
	largest.Credential = bytes.Repeat([]byte{0xc5}, relayframe.MaxCredentialBytes)
	largestRaw, err := relayframe.Encode(largest)
	if err != nil {
		t.Fatal(err)
	}
	add("relay-frame-copy-credential-maximal", largestRaw, nil)
	// The credential length sits after the separator, kind, index, count,
	// digest, card and evidence.
	credentialLength := len(canon.DomainRelayFrame) + 3 + 32 + 2 + len(card) + 2 + len(evidence)
	overBound := append([]byte(nil), raw...)
	binary.BigEndian.PutUint16(overBound[credentialLength:], relayframe.MaxCredentialBytes+1)
	add("relay-frame-credential-over-bound", overBound, relayframe.ErrCredentialTooLarge)
	zeroSeed := append([]byte(nil), raw...)
	copy(zeroSeed[credentialLength+2+len(credential):], make([]byte, relayframe.HolderSeedBytes))
	add("relay-frame-credential-zero-holder-seed", zeroSeed, relayframe.ErrCredentialMalformed)
	retired := append([]byte(nil), raw...)
	copy(retired, strings.Replace(canon.DomainRelayFrame, ".v2", ".v1", 1))
	add("relay-frame-retired-v1-separator", retired, relayframe.ErrFrameMalformed)
	// A later room part carries no credential. The encoder refuses one, so
	// the vector is a valid part-1 frame with a credential and seed inserted
	// after its empty evidence, re-padded to its bucket.
	add("relay-frame-credential-in-later-room-part",
		laterPartWithCredential(t, credential, seed), relayframe.ErrCredentialMalformed)
	return vectors
}

// laterPartWithCredential returns part 1 of a two-part room object whose
// credential length, credential and holder seed have been written in by hand.
func laterPartWithCredential(t *testing.T, credential []byte, seed [relayframe.HolderSeedBytes]byte) []byte {
	t.Helper()
	valid, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 2,
		ObjectDigest: [32]byte{0x3d}, Part: []byte("second part of a room object")})
	if err != nil {
		t.Fatal(err)
	}
	// Separator, kind, index, count, digest, card length 0, evidence length 0.
	at := len(canon.DomainRelayFrame) + 3 + 32 + 2 + 2
	if valid[at] != 0 || valid[at+1] != 0 {
		t.Fatal("part 1 frame already carries a credential")
	}
	partLength := int(binary.BigEndian.Uint32(valid[at+2:]))
	rest := valid[at+2 : at+2+4+partLength]
	mutated := append([]byte(nil), valid[:at]...)
	mutated = binary.BigEndian.AppendUint16(mutated, uint16(len(credential)))
	mutated = append(mutated, credential...)
	mutated = append(mutated, seed[:]...)
	mutated = append(mutated, rest...)
	bucket, err := relayframe.BucketFor(len(mutated))
	if err != nil {
		t.Fatal(err)
	}
	return append(mutated, make([]byte, bucket-len(mutated))...)
}
