package vectors

import (
	"bytes"
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
	return vectors
}
