package relayframe_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/envelope"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
)

func evidence(t testing.TB) []byte {
	t.Helper()
	raw, err := relayframe.EncodeEvidence(relayframe.Evidence{Delegation: []byte(`{"delegation":1}`),
		Policy: []byte(`{"policy":1}`), Descriptor: []byte(`{"descriptor":1}`), BundleSet: []byte(`{"set":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func copyObject(t *testing.T, ciphertext int) []byte {
	t.Helper()
	raw, err := relayframe.EncodeCopy(relayframe.Copy{EventID: "evt_" + strings.Repeat("1", 64),
		SessionID: "ses_" + strings.Repeat("2", 64), RecipientEndpointID: "mep_" + strings.Repeat("3", 64),
		RecipientDeviceID: "dev_" + strings.Repeat("4", 64), ConversationID: "conv_" + strings.Repeat("5", 64),
		AdmissionToken: "invite.token-1", Ciphertext: bytes.Repeat([]byte{0x6a}, ciphertext), ExpiresAtUnix: 1_900_000_000})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEachKindRoundTripsAndPadsToItsBucket(t *testing.T) {
	ack := []byte("an ack object is opaque to the frame codec")
	for _, frame := range []relayframe.Frame{
		{Kind: relayframe.KindCopy, PartCount: 1, Evidence: evidence(t), Part: copyObject(t, 64)},
		{Kind: relayframe.KindCopy, PartCount: 1, Card: []byte("card"), Evidence: evidence(t), Part: copyObject(t, 64)},
		{Kind: relayframe.KindDeliveryAck, PartCount: 1, Evidence: evidence(t), Part: ack},
		{Kind: relayframe.KindEvidence, PartCount: 1, Card: []byte("card"), Evidence: evidence(t), Part: []byte{relayframe.EvidenceRequest}},
		{Kind: relayframe.KindEvidence, PartCount: 1, Card: []byte("card"), Evidence: evidence(t), Part: []byte{relayframe.EvidenceResponse}},
	} {
		encoded, err := relayframe.Encode(frame)
		if err != nil {
			t.Fatalf("encode kind %d: %v", frame.Kind, err)
		}
		unpadded, err := relayframe.UnpaddedSize(len(frame.Card), len(frame.Evidence), len(frame.Credential), len(frame.Part))
		if err != nil {
			t.Fatal(err)
		}
		bucket, err := relayframe.BucketFor(unpadded)
		if err != nil || len(encoded) != bucket {
			t.Fatalf("kind %d: %d bytes, bucket %d (%v)", frame.Kind, len(encoded), bucket, err)
		}
		if !bytes.Equal(encoded[unpadded:], make([]byte, bucket-unpadded)) {
			t.Fatal("padding is not zero")
		}
		decoded, err := relayframe.Decode(encoded)
		if err != nil {
			t.Fatalf("decode kind %d: %v", frame.Kind, err)
		}
		if decoded.Kind != frame.Kind || !bytes.Equal(decoded.Card, frame.Card) ||
			!bytes.Equal(decoded.Evidence, frame.Evidence) || !bytes.Equal(decoded.Part, frame.Part) ||
			decoded.ObjectDigest != relayframe.ObjectDigest(frame.Part) {
			t.Fatalf("kind %d did not round-trip", frame.Kind)
		}
	}
}

func TestEveryBucketIsReachableAndTheLargestIsTheBound(t *testing.T) {
	buckets := relayframe.Buckets()
	want := []int{1 << 10, 2 << 10, 4 << 10, 8 << 10, 16 << 10, 32 << 10, 64 << 10, 128 << 10, 190_464}
	if len(buckets) != len(want) {
		t.Fatalf("buckets=%v", buckets)
	}
	ev := evidence(t)
	for index, bucket := range buckets {
		if bucket != want[index] {
			t.Fatalf("buckets=%v", buckets)
		}
		base, _ := relayframe.UnpaddedSize(0, len(ev), 0, 0)
		part := bucket - base
		encoded, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1,
			Evidence: ev, Part: bytes.Repeat([]byte{1}, part)})
		if err != nil || len(encoded) != bucket {
			t.Fatalf("exact bucket %d: %d %v", bucket, len(encoded), err)
		}
		if index+1 < len(buckets) {
			over, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1,
				Evidence: ev, Part: bytes.Repeat([]byte{1}, part+1)})
			if err != nil || len(over) != buckets[index+1] {
				t.Fatalf("one over bucket %d: %d %v", bucket, len(over), err)
			}
		}
	}
	base, _ := relayframe.UnpaddedSize(0, len(ev), 0, 0)
	if _, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1, Evidence: ev,
		Part: make([]byte, relayframe.MaxFrameBytes-base+1)}); !errors.Is(err, relayframe.ErrContentTooLarge) {
		t.Fatalf("over the largest bucket: %v", err)
	}
	for _, n := range []int{0, -1} {
		if _, err := relayframe.BucketFor(n); err == nil {
			t.Fatalf("bucket for %d", n)
		}
	}
}

func TestEncodeRefusesInvalidFrames(t *testing.T) {
	ev := evidence(t)
	cases := []struct {
		name  string
		frame relayframe.Frame
		want  error
	}{
		{"unknown kind", relayframe.Frame{Kind: 9, PartCount: 1, Evidence: ev, Part: []byte{1}}, relayframe.ErrFrameKind},
		{"zero kind", relayframe.Frame{Kind: 0, PartCount: 1, Evidence: ev, Part: []byte{1}}, relayframe.ErrFrameKind},
		{"room part index past count", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 2, PartCount: 2, ObjectDigest: [32]byte{1}, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"room nine parts", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 9, ObjectDigest: [32]byte{1}, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"room zero parts", relayframe.Frame{Kind: relayframe.KindRoom, PartCount: 0, Evidence: ev, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"room later part with evidence", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 2, ObjectDigest: [32]byte{1}, Evidence: ev, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"room later part with card", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 2, ObjectDigest: [32]byte{1}, Card: []byte{1}, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"room part 0 without evidence", relayframe.Frame{Kind: relayframe.KindRoom, PartCount: 2, ObjectDigest: [32]byte{1}, Part: []byte{1}}, relayframe.ErrEvidenceRequired},
		{"room split without its object digest", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 2, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"room part above the frame", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 2, ObjectDigest: [32]byte{1}, Part: make([]byte, relayframe.MaxPartBytes+1)}, relayframe.ErrContentTooLarge},
		{"two parts", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 2, Evidence: ev, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"part index", relayframe.Frame{Kind: relayframe.KindCopy, PartIndex: 1, PartCount: 1, Evidence: ev, Part: []byte{1}}, relayframe.ErrFrameMalformed},
		{"no evidence", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Part: []byte{1}}, relayframe.ErrEvidenceRequired},
		{"evidence too large", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1,
			Evidence: make([]byte, relayframe.MaxEvidenceBytes+1), Part: []byte{1}}, relayframe.ErrRelayEvidenceTooLarge},
		{"card too large", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1,
			Card: make([]byte, relayframe.MaxCardBytes+1), Evidence: ev, Part: []byte{1}}, relayframe.ErrCardTooLarge},
		{"evidence kind without card", relayframe.Frame{Kind: relayframe.KindEvidence, PartCount: 1, Evidence: ev,
			Part: []byte{relayframe.EvidenceRequest}}, relayframe.ErrCardRequired},
		{"evidence kind bad value", relayframe.Frame{Kind: relayframe.KindEvidence, PartCount: 1, Card: []byte{1},
			Evidence: ev, Part: []byte{3}}, relayframe.ErrFrameMalformed},
		{"evidence kind long part", relayframe.Frame{Kind: relayframe.KindEvidence, PartCount: 1, Card: []byte{1},
			Evidence: ev, Part: []byte{1, 2}}, relayframe.ErrFrameMalformed},
		{"empty part", relayframe.Frame{Kind: relayframe.KindDeliveryAck, PartCount: 1, Evidence: ev}, relayframe.ErrFrameMalformed},
	}
	for _, test := range cases {
		if _, err := relayframe.Encode(test.frame); !errors.Is(err, test.want) {
			t.Fatalf("%s: err=%v want %v", test.name, err, test.want)
		}
	}
	// Maximal card and evidence still encode.
	maximal, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindEvidence, PartCount: 1,
		Card: make([]byte, relayframe.MaxCardBytes), Evidence: make([]byte, relayframe.MaxEvidenceBytes),
		Part: []byte{relayframe.EvidenceResponse}})
	if err != nil || len(maximal) != 32<<10 {
		t.Fatalf("maximal card and evidence: %d %v", len(maximal), err)
	}
}

func TestDecodeRefusesEveryMalformation(t *testing.T) {
	good, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Card: []byte("card"),
		Evidence: evidence(t), Part: copyObject(t, 64)})
	if err != nil {
		t.Fatal(err)
	}
	domain := len(canon.DomainRelayFrame)
	mutate := func(apply func([]byte) []byte) []byte {
		return apply(append([]byte(nil), good...))
	}
	cardLength := domain + 3 + 32
	evidenceLength := cardLength + 2 + 4
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, relayframe.ErrFrameSize},
		{"not a bucket", good[:len(good)-1], relayframe.ErrFrameSize},
		{"trailing byte", append(append([]byte(nil), good...), 0), relayframe.ErrFrameSize},
		{"other domain", mutate(func(b []byte) []byte { b[0] ^= 1; return b }), relayframe.ErrFrameMalformed},
		{"unknown kind", mutate(func(b []byte) []byte { b[domain] = 7; return b }), relayframe.ErrFrameKind},
		{"room kind with nine parts", mutate(func(b []byte) []byte { b[domain] = relayframe.KindRoom; b[domain+1] = 1; b[domain+2] = 9; return b }), relayframe.ErrFrameMalformed},
		{"room later part with evidence", mutate(func(b []byte) []byte { b[domain] = relayframe.KindRoom; b[domain+1] = 1; b[domain+2] = 2; return b }), relayframe.ErrFrameMalformed},
		{"part count", mutate(func(b []byte) []byte { b[domain+2] = 2; return b }), relayframe.ErrFrameMalformed},
		{"part index", mutate(func(b []byte) []byte { b[domain+1] = 1; return b }), relayframe.ErrFrameMalformed},
		{"digest", mutate(func(b []byte) []byte { b[domain+3] ^= 1; return b }), relayframe.ErrFrameDigest},
		{"card over bound", mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[cardLength:], relayframe.MaxCardBytes+1)
			return b
		}), relayframe.ErrCardTooLarge},
		{"evidence over bound", mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[evidenceLength:], relayframe.MaxEvidenceBytes+1)
			return b
		}), relayframe.ErrRelayEvidenceTooLarge},
		{"no evidence", mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[evidenceLength:], 0)
			return b
		}), nil},
		{"non-zero padding", mutate(func(b []byte) []byte { b[len(b)-1] = 1; return b }), relayframe.ErrFramePadding},
		{"padded past its smallest bucket", append(append([]byte(nil), good...), make([]byte, len(good))...),
			relayframe.ErrFrameNotMinimal},
	}
	for _, test := range cases {
		_, err := relayframe.Decode(test.raw)
		if err == nil || test.want != nil && !errors.Is(err, test.want) {
			t.Fatalf("%s: err=%v want %v", test.name, err, test.want)
		}
	}
}

func TestEvidenceCodecEnforcesEachRelayBound(t *testing.T) {
	base := relayframe.Evidence{Delegation: []byte("d"), Policy: []byte("p"), Descriptor: []byte("c"), BundleSet: []byte("s")}
	bounds := []struct {
		name    string
		maximum int
		set     func(*relayframe.Evidence, []byte)
	}{
		{"delegation", relayframe.MaxEvidenceDelegationBytes, func(e *relayframe.Evidence, v []byte) { e.Delegation = v }},
		{"policy", relayframe.MaxEvidencePolicyBytes, func(e *relayframe.Evidence, v []byte) { e.Policy = v }},
		{"descriptor", relayframe.MaxEvidenceDescriptorBytes, func(e *relayframe.Evidence, v []byte) { e.Descriptor = v }},
		{"bundle set", relayframe.MaxEvidenceBundleSetBytes, func(e *relayframe.Evidence, v []byte) { e.BundleSet = v }},
	}
	for _, bound := range bounds {
		at := base
		bound.set(&at, bytes.Repeat([]byte{'x'}, bound.maximum))
		raw, err := relayframe.EncodeEvidence(at)
		if err != nil {
			t.Fatalf("%s at its bound: %v", bound.name, err)
		}
		if decoded, err := relayframe.DecodeEvidence(raw); err != nil || !bytes.Equal(raw, mustEncode(t, decoded)) {
			t.Fatalf("%s at its bound did not round-trip: %v", bound.name, err)
		}
		over := base
		bound.set(&over, bytes.Repeat([]byte{'x'}, bound.maximum+1))
		if _, err := relayframe.EncodeEvidence(over); !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) || err.Error() != "relay-evidence-too-large" {
			t.Fatalf("%s over its bound: %v", bound.name, err)
		}
		// The decoder refuses the same over-bound object before reading it.
		forged := forgeEvidence(over)
		if _, err := relayframe.DecodeEvidence(forged); !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
			t.Fatalf("%s over its bound decoded: %v", bound.name, err)
		}
		empty := base
		bound.set(&empty, nil)
		if _, err := relayframe.EncodeEvidence(empty); err == nil {
			t.Fatalf("%s empty encoded", bound.name)
		}
	}
	maximal := relayframe.Evidence{Delegation: make([]byte, relayframe.MaxEvidenceDelegationBytes),
		Policy: make([]byte, relayframe.MaxEvidencePolicyBytes), Descriptor: make([]byte, relayframe.MaxEvidenceDescriptorBytes),
		BundleSet: make([]byte, relayframe.MaxEvidenceBundleSetBytes)}
	raw, err := relayframe.EncodeEvidence(maximal)
	if err != nil || len(raw) > relayframe.MaxEvidenceBytes {
		t.Fatalf("maximal evidence %d bytes: %v", len(raw), err)
	}
	if _, err := relayframe.DecodeEvidence(append(raw, 0)); err == nil {
		t.Fatal("trailing evidence byte accepted")
	}
	if _, err := relayframe.DecodeEvidence(make([]byte, relayframe.MaxEvidenceBytes+1)); !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
		t.Fatalf("oversized evidence: %v", err)
	}
}

func mustEncode(t *testing.T, value relayframe.Evidence) []byte {
	t.Helper()
	raw, err := relayframe.EncodeEvidence(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// forgeEvidence writes evidence bytes without the encoder's bounds, as a
// hostile sender would.
func forgeEvidence(value relayframe.Evidence) []byte {
	buffer := bytes.NewBufferString(canon.DomainRelayEvidence)
	for _, object := range [][]byte{value.Delegation, value.Policy, value.Descriptor, value.BundleSet} {
		canon.Bytes(buffer, object)
	}
	return buffer.Bytes()
}

func TestCopyObjectRoundTripsAndBoundsItsFields(t *testing.T) {
	raw := copyObject(t, 64)
	value, err := relayframe.DecodeCopy(raw)
	if err != nil || value.AdmissionToken != "invite.token-1" || len(value.Ciphertext) != 64 || value.Bootstrap != nil {
		t.Fatalf("copy: %+v %v", value, err)
	}
	if again, err := relayframe.EncodeCopy(value); err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("copy re-encoding differs: %v", err)
	}
	if _, err := relayframe.DecodeCopy(append(raw, 0)); err == nil {
		t.Fatal("trailing copy byte accepted")
	}
	base := value
	for name, mutate := range map[string]func(*relayframe.Copy){
		"short ciphertext": func(c *relayframe.Copy) { c.Ciphertext = make([]byte, relayframe.MinCiphertextBytes-1) },
		"long ciphertext":  func(c *relayframe.Copy) { c.Ciphertext = make([]byte, relayframe.MaxCiphertextBytes+1) },
		"bad token":        func(c *relayframe.Copy) { c.AdmissionToken = "has space" },
		"long token":       func(c *relayframe.Copy) { c.AdmissionToken = strings.Repeat("a", relayframe.MaxAdmissionTokenBytes+1) },
		"long bootstrap":   func(c *relayframe.Copy) { c.Bootstrap = make([]byte, relayframe.MaxBootstrapBytes+1) },
		"bad event":        func(c *relayframe.Copy) { c.EventID = "evt_x" },
		"zero expiry":      func(c *relayframe.Copy) { c.ExpiresAtUnix = 0 },
	} {
		changed := base
		mutate(&changed)
		if _, err := relayframe.EncodeCopy(changed); err == nil {
			t.Fatalf("%s encoded", name)
		}
	}
}

func TestCopyBoundsRepeatTheJournalAndEnvelopeBounds(t *testing.T) {
	if relayframe.MaxCiphertextBytes != eventlog.MaxCiphertextBytes ||
		relayframe.MaxSealOverheadBytes != eventlog.MaxCiphertextBytes-eventlog.MaxPayloadBytes ||
		relayframe.MinCiphertextBytes != envelope.MinCiphertextBytes ||
		relayframe.MaxAdmissionTokenBytes != envelope.MaxAdmissionTokenBytes {
		t.Fatal("relay copy bounds drifted from the journal and envelope bounds")
	}
}

// The largest first-contact bootstrap: maximal material and initial message,
// the longest network identifier in its most-escaped JSON form, the longest
// algorithm identifier and maximal integers.
func TestMaximalBootstrapFitsItsBound(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	network := &nativev1.NetworkDomain{NetworkId: strings.Repeat("<", 128),
		GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
	algorithm := "tos.messaging.e2ee." + strings.Repeat("a", 32) + ".v999"
	bundle, err := e2ee.SignBundle(e2ee.Bundle{Network: network, AgentID: "agent_" + strings.Repeat("1", 64),
		EndpointID: "mep_" + strings.Repeat("2", 64), DeviceID: "dev_" + strings.Repeat("3", 64), AlgorithmID: algorithm,
		Material: bytes.Repeat([]byte{0xff}, e2ee.MaxMaterialBytes), IssuedAtUnix: math.MaxUint64 - e2ee.MaxBundleLifetimeSeconds,
		ExpiresAtUnix: math.MaxUint64}, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e2ee.EncodeFirstContactJSON(e2ee.FirstContact{Binding: e2ee.Binding{Network: network, AlgorithmID: algorithm,
		ConversationID: "conv_" + strings.Repeat("4", 64), SenderAgentID: bundle.AgentID, SenderEndpointID: bundle.EndpointID,
		SenderDeviceID: bundle.DeviceID, RecipientAgentID: "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64), RecipientDeviceID: "dev_" + strings.Repeat("7", 64)},
		SenderBundle: bundle, RecipientBundleDigest: "sha256:" + strings.Repeat("8", 64),
		Initial: bytes.Repeat([]byte{0xee}, e2ee.MaxInitialMessageBytes)})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > relayframe.MaxBootstrapBytes {
		t.Fatalf("maximal bootstrap is %d bytes, bound %d", len(raw), relayframe.MaxBootstrapBytes)
	}
	t.Logf("maximal bootstrap %d of %d bytes", len(raw), relayframe.MaxBootstrapBytes)
}

func TestWorstCaseCopyIsCheckedBeforeSealing(t *testing.T) {
	largest := relayframe.MaxRelayPayloadBytes()
	// v1 carried 139,547 bytes; the v2 credential field (2,048-byte credential,
	// 32-byte holder seed and a 2-byte length) takes 2,082 of them.
	if largest != 137_465 || largest >= eventlog.MaxPayloadBytes {
		t.Fatalf("largest relay payload %d", largest)
	}
	if err := relayframe.CheckCopyFits(largest); err != nil {
		t.Fatalf("largest payload refused: %v", err)
	}
	size, err := relayframe.WorstCaseCopyFrameBytes(largest)
	if err != nil || size != relayframe.MaxFrameBytes {
		t.Fatalf("worst case at the largest payload: %d %v", size, err)
	}
	for _, payload := range []int{largest + 1, eventlog.MaxPayloadBytes, eventlog.MaxPayloadBytes + 1} {
		if err := relayframe.CheckCopyFits(payload); fault.CodeOf(err) != fault.CodeContentTooLarge {
			t.Fatalf("payload %d: %v", payload, err)
		}
	}
	if err := relayframe.CheckCopyFits(0); fault.CodeOf(err) != fault.CodePayloadMalformed {
		t.Fatalf("empty payload: %v", err)
	}
	// A real worst-case copy of the largest payload fits its bucket.
	object, err := relayframe.EncodeCopy(relayframe.Copy{EventID: "evt_" + strings.Repeat("1", 64),
		SessionID: "ses_" + strings.Repeat("2", 64), RecipientEndpointID: "mep_" + strings.Repeat("3", 64),
		RecipientDeviceID: "dev_" + strings.Repeat("4", 64), ConversationID: "conv_" + strings.Repeat("5", 64),
		Bootstrap: make([]byte, relayframe.MaxBootstrapBytes), AdmissionToken: strings.Repeat("t", relayframe.MaxAdmissionTokenBytes),
		Ciphertext: make([]byte, largest+relayframe.MaxSealOverheadBytes), ExpiresAtUnix: math.MaxUint64})
	if err != nil {
		t.Fatal(err)
	}
	worst := relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1,
		Card: make([]byte, relayframe.MaxCardBytes), Evidence: make([]byte, relayframe.MaxEvidenceBytes),
		Credential: make([]byte, relayframe.MaxCredentialBytes), HolderSeed: [32]byte{1}, Part: object}
	frame, err := relayframe.Encode(worst)
	if err != nil || len(frame) != relayframe.MaxFrameBytes {
		t.Fatalf("worst-case frame %d bytes: %v", len(frame), err)
	}
	// It is exactly full: unpadded, it is the largest bucket.
	if unpadded, err := relayframe.UnpaddedSize(len(worst.Card), len(worst.Evidence), len(worst.Credential),
		len(worst.Part)); err != nil || unpadded != relayframe.MaxFrameBytes {
		t.Fatalf("worst-case frame unpadded %d: %v", unpadded, err)
	}
	decoded, err := relayframe.Decode(frame)
	if err != nil || !bytes.Equal(decoded.Credential, worst.Credential) || decoded.HolderSeed != worst.HolderSeed {
		t.Fatalf("worst-case frame decode: %v", err)
	}
	// One more payload byte does not fit.
	over, err := relayframe.EncodeCopy(relayframe.Copy{EventID: "evt_" + strings.Repeat("1", 64),
		SessionID: "ses_" + strings.Repeat("2", 64), RecipientEndpointID: "mep_" + strings.Repeat("3", 64),
		RecipientDeviceID: "dev_" + strings.Repeat("4", 64), ConversationID: "conv_" + strings.Repeat("5", 64),
		Bootstrap: make([]byte, relayframe.MaxBootstrapBytes), AdmissionToken: strings.Repeat("t", relayframe.MaxAdmissionTokenBytes),
		Ciphertext: make([]byte, largest+1+relayframe.MaxSealOverheadBytes), ExpiresAtUnix: math.MaxUint64})
	if err != nil {
		t.Fatal(err)
	}
	worst.Part = over
	if _, err := relayframe.Encode(worst); !errors.Is(err, relayframe.ErrContentTooLarge) {
		t.Fatalf("one payload byte over the worst case: %v", err)
	}
}

// The v2 credential field: a credential of 1..2,048 bytes with a non-zero
// holder seed, or neither; never in a later room part; and nothing but a v2
// frame decodes.
func TestCredentialFieldRoundTripsAndIsBounded(t *testing.T) {
	ev := evidence(t)
	credential := []byte("contact credential bytes, opaque to the frame codec")
	seed := [32]byte{7, 7, 7}
	for _, frame := range []relayframe.Frame{
		{Kind: relayframe.KindCopy, PartCount: 1, Evidence: ev, Credential: credential, HolderSeed: seed, Part: copyObject(t, 64)},
		{Kind: relayframe.KindDeliveryAck, PartCount: 1, Evidence: ev, Credential: credential, HolderSeed: seed, Part: []byte("ack")},
		{Kind: relayframe.KindEvidence, PartCount: 1, Card: []byte("card"), Evidence: ev, Credential: credential,
			HolderSeed: seed, Part: []byte{relayframe.EvidenceRequest}},
		{Kind: relayframe.KindRoom, PartCount: 2, ObjectDigest: [32]byte{9}, Evidence: ev, Credential: credential,
			HolderSeed: seed, Part: []byte("part zero")},
		{Kind: relayframe.KindCopy, PartCount: 1, Evidence: ev, Credential: make([]byte, relayframe.MaxCredentialBytes),
			HolderSeed: seed, Part: copyObject(t, 64)},
	} {
		raw, err := relayframe.Encode(frame)
		if err != nil {
			t.Fatalf("kind %d: %v", frame.Kind, err)
		}
		decoded, err := relayframe.Decode(raw)
		if err != nil || !bytes.Equal(decoded.Credential, frame.Credential) || decoded.HolderSeed != seed {
			t.Fatalf("kind %d did not round-trip: %v", frame.Kind, err)
		}
		withoutCredential := frame
		withoutCredential.Credential, withoutCredential.HolderSeed = nil, [32]byte{}
		plain, err := relayframe.Encode(withoutCredential)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := relayframe.UnpaddedSize(len(frame.Card), len(frame.Evidence), len(frame.Credential), len(frame.Part))
		b, _ := relayframe.UnpaddedSize(len(frame.Card), len(frame.Evidence), 0, len(frame.Part))
		if a-b != len(frame.Credential)+relayframe.HolderSeedBytes || len(plain) > len(raw) {
			t.Fatalf("kind %d: credential adds %d bytes", frame.Kind, a-b)
		}
	}
	for _, test := range []struct {
		name  string
		frame relayframe.Frame
		want  error
	}{
		{"credential over bound", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Evidence: ev,
			Credential: make([]byte, relayframe.MaxCredentialBytes+1), HolderSeed: seed, Part: copyObject(t, 64)},
			relayframe.ErrCredentialTooLarge},
		{"credential without a seed", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Evidence: ev,
			Credential: credential, Part: copyObject(t, 64)}, relayframe.ErrCredentialMalformed},
		{"seed without a credential", relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Evidence: ev,
			HolderSeed: seed, Part: copyObject(t, 64)}, relayframe.ErrCredentialMalformed},
		{"credential in a later room part", relayframe.Frame{Kind: relayframe.KindRoom, PartIndex: 1, PartCount: 2,
			ObjectDigest: [32]byte{9}, Credential: credential, HolderSeed: seed, Part: []byte("part one")},
			relayframe.ErrCredentialMalformed},
	} {
		if _, err := relayframe.Encode(test.frame); !errors.Is(err, test.want) {
			t.Fatalf("encode %s: %v", test.name, err)
		}
	}

	good, err := relayframe.Encode(relayframe.Frame{Kind: relayframe.KindCopy, PartCount: 1, Evidence: ev,
		Credential: credential, HolderSeed: seed, Part: copyObject(t, 64)})
	if err != nil {
		t.Fatal(err)
	}
	domain := len(canon.DomainRelayFrame)
	credentialLength := domain + 3 + 32 + 2 + 2 + len(ev)
	mutate := func(apply func([]byte) []byte) []byte { return apply(append([]byte(nil), good...)) }
	for _, test := range []struct {
		name string
		raw  []byte
		want error
	}{
		{"credential length over bound", mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[credentialLength:], relayframe.MaxCredentialBytes+1)
			return b
		}), relayframe.ErrCredentialTooLarge},
		{"zero holder seed", mutate(func(b []byte) []byte {
			copy(b[credentialLength+2+len(credential):], make([]byte, 32))
			return b
		}), relayframe.ErrCredentialMalformed},
		{"v1 frame domain", mutate(func(b []byte) []byte {
			// The retired version's separator, derived so no unregistered
			// separator appears in source.
			copy(b, strings.Replace(canon.DomainRelayFrame, ".v2", ".v1", 1))
			return b
		}), relayframe.ErrFrameMalformed},
	} {
		if _, err := relayframe.Decode(test.raw); !errors.Is(err, test.want) {
			t.Fatalf("decode %s: %v", test.name, err)
		}
	}
	if !strings.HasSuffix(canon.DomainRelayFrame, ".relay-frame.v2\x00") {
		t.Fatalf("frame domain %q", canon.DomainRelayFrame)
	}
}

func TestAckSignsUnderItsOwnDomainOnly(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	ack := relayframe.Ack{EventID: "evt_" + strings.Repeat("1", 64), SessionID: "ses_" + strings.Repeat("2", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("3", 64), RecipientDeviceID: "dev_" + strings.Repeat("4", 64),
		CiphertextDigest: "sha256:" + strings.Repeat("5", 64), Outcome: relayframe.OutcomeAccepted, AcceptedAtUnix: 1_900_000_000}
	signed, err := relayframe.SignAck(ack, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := relayframe.EncodeAck(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := relayframe.DecodeAck(raw)
	if err != nil || relayframe.VerifyAck(decoded, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("signed ack does not verify: %v", err)
	}
	if relayframe.VerifyAck(decoded, other.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("ack verified under another Endpoint key")
	}
	tampered := decoded
	tampered.Outcome = relayframe.OutcomeDuplicate
	if relayframe.VerifyAck(tampered, key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("tampered ack verified")
	}
	// A signature over the same fields under the HTTPS ack domain does not
	// verify here.
	preimage, err := relayframe.AckSigningBytes(ack)
	if err != nil {
		t.Fatal(err)
	}
	https := append([]byte(canon.DomainHTTPSDeliveryAck), preimage[len(canon.DomainRelayDeliveryAck):]...)
	crossed := ack
	crossed.Signature = ed25519.Sign(key, https)
	if relayframe.VerifyAck(crossed, key.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("an HTTPS-domain ack signature verified on the relay route")
	}
	for name, mutate := range map[string]func(*relayframe.Ack){
		"rejected without code": func(a *relayframe.Ack) { a.Outcome = relayframe.OutcomeRejected },
		"accepted with code":    func(a *relayframe.Ack) { a.Code = fault.CodeDescriptorExpired },
		"unknown code":          func(a *relayframe.Ack) { a.Outcome, a.Code = relayframe.OutcomeRejected, "made-up" },
		"unknown outcome":       func(a *relayframe.Ack) { a.Outcome = "delivered" },
		"zero time":             func(a *relayframe.Ack) { a.AcceptedAtUnix = 0 },
	} {
		changed := ack
		mutate(&changed)
		if _, err := relayframe.SignAck(changed, key); err == nil {
			t.Fatalf("%s signed", name)
		}
	}
	rejected := ack
	rejected.Outcome, rejected.Code = relayframe.OutcomeRejected, fault.CodeDescriptorExpired
	if signed, err := relayframe.SignAck(rejected, key); err != nil || relayframe.VerifyAck(signed, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("descriptor-expired ack: %v", err)
	}
	if _, err := relayframe.DecodeAck(append(raw, 0)); err == nil {
		t.Fatal("trailing ack byte accepted")
	}
}

// The stored envelope size is 1,373 + F + 4·⌈B/3⌉, checked against a real
// seal of a real carriage packet at both ends of the fixed-field range.
func TestEnvelopeSizeFormulaMatchesARealSeal(t *testing.T) {
	sender := "agent_" + strings.Repeat("a", 64)
	recipient := "agent_" + strings.Repeat("b", 64)
	private, err := agentpacketseal.NewPrivateKey(recipient, bytes.Repeat([]byte{3}, agentpacketseal.PrivateKeySize))
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	key := agentpacketseal.RecipientKey{AgentID: recipient, KeyID: private.KeyID, PublicKey: public}
	if relayframe.SealOverheadBytes != 1_373 {
		t.Fatalf("seal overhead %d", relayframe.SealOverheadBytes)
	}
	for _, bucket := range relayframe.Buckets() {
		frame := make([]byte, bucket)
		frame[0] = 1
		for _, integers := range []uint64{1, math.MaxUint64} {
			packet := agentpacket.Packet{SenderAgentID: sender, RecipientAgentID: recipient,
				CapabilityID: "cap_" + strings.Repeat("0", 64), Sequence: integers, Nonce: [32]byte{1},
				Payload: frame, CreatedAtUnix: integers, SenderKeyID: [mldsa44.KeyIDSize]byte{2},
				Signature: make([]byte, mldsa44.SignatureSize)}
			packetJSON, err := agentpacket.EncodeJSON(packet)
			if err != nil {
				t.Fatal(err)
			}
			fixed := len(packetJSON) - base64.StdEncoding.EncodedLen(bucket)
			wantFixed := relayframe.MinPacketFixedFieldBytes
			if integers == math.MaxUint64 {
				wantFixed = relayframe.MaxPacketFixedFieldBytes
			}
			if fixed != wantFixed {
				t.Fatalf("bucket %d integers %d: fixed fields %d want %d", bucket, integers, fixed, wantFixed)
			}
			sealed, err := agentpacketseal.Seal(key, [32]byte{4}, packetJSON, 1_900_000_000)
			if err != nil {
				t.Fatalf("seal bucket %d: %v", bucket, err)
			}
			size, err := relayframe.EnvelopeSize(bucket, fixed)
			if err != nil || len(sealed) != size {
				t.Fatalf("bucket %d: sealed %d formula %d (%v)", bucket, len(sealed), size, err)
			}
		}
	}
	for _, test := range []struct{ bucket, fixed int }{{8 << 10, 5432}, {16 << 10, 5432}, {32 << 10, 5432}} {
		size, _ := relayframe.EnvelopeSize(test.bucket, test.fixed)
		want := map[int]int{8 << 10: 17_729, 16 << 10: 28_653, 32 << 10: 50_497}[test.bucket]
		if size != want {
			t.Fatalf("bucket %d stored %d want %d", test.bucket, size, want)
		}
	}
	if _, err := relayframe.EnvelopeSize(1000, 5400); err == nil {
		t.Fatal("non-bucket accepted")
	}
	if _, err := relayframe.EnvelopeSize(1<<10, 5393); err == nil {
		t.Fatal("fixed fields below range accepted")
	}
}

func TestContactFileCarriesEvidenceAndCardOnly(t *testing.T) {
	contact := relayframe.Contact{AgentID: "agent_" + strings.Repeat("a", 64), Evidence: evidence(t), Card: []byte("card")}
	raw, err := relayframe.EncodeContactJSON(contact)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "locator") {
		t.Fatal("contact file mentions a locator")
	}
	decoded, err := relayframe.DecodeContactJSON(raw)
	if err != nil || decoded.AgentID != contact.AgentID || !bytes.Equal(decoded.Evidence, contact.Evidence) ||
		!bytes.Equal(decoded.Card, contact.Card) {
		t.Fatalf("contact: %+v %v", decoded, err)
	}
	over := contact
	over.Evidence = forgeEvidence(relayframe.Evidence{Delegation: make([]byte, relayframe.MaxEvidenceDelegationBytes+1),
		Policy: []byte("p"), Descriptor: []byte("d"), BundleSet: []byte("s")})
	forged := []byte(`{"schema":"` + relayframe.ContactSchema + `","agent_id":"` + contact.AgentID +
		`","relay_evidence_base64":"` + base64.StdEncoding.EncodeToString(over.Evidence) +
		`","chat_card_base64":"Y2FyZA=="}`)
	if _, err := relayframe.DecodeContactJSON(forged); !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
		t.Fatalf("over-bound contact evidence: %v", err)
	}
	if _, err := relayframe.EncodeContactJSON(over); !errors.Is(err, relayframe.ErrRelayEvidenceTooLarge) {
		t.Fatalf("over-bound contact export: %v", err)
	}
	for name, mutate := range map[string]func(*relayframe.Contact){
		"no card":    func(c *relayframe.Contact) { c.Card = nil },
		"large card": func(c *relayframe.Contact) { c.Card = make([]byte, relayframe.MaxCardBytes+1) },
		"bad Agent":  func(c *relayframe.Contact) { c.AgentID = "agent_x" },
	} {
		changed := contact
		mutate(&changed)
		if _, err := relayframe.EncodeContactJSON(changed); err == nil {
			t.Fatalf("%s exported", name)
		}
	}
	if _, err := relayframe.DecodeContactJSON(append(raw, []byte(" {}")...)); err == nil {
		t.Fatal("trailing contact JSON accepted")
	}
}

func TestIdempotencyKeysSeparateGenerationsAndPurposes(t *testing.T) {
	delivery := "cpy_" + strings.Repeat("a", 64)
	peer := "agent_" + strings.Repeat("b", 64)
	one, err := relayframe.CopyIdempotencyKey(delivery, 1)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := relayframe.CopyIdempotencyKey(delivery, 1)
	two, _ := relayframe.CopyIdempotencyKey(delivery, 2)
	request, _ := relayframe.EvidenceRequestKey(peer, 1)
	response, _ := relayframe.EvidenceResponseKey(peer, "sha256:"+strings.Repeat("c", 64), 1)
	if one != again || one == two || one == request || request == response || len(one) != len("idem_")+64 {
		t.Fatalf("keys: %s %s %s %s", one, two, request, response)
	}
	if _, err := relayframe.CopyIdempotencyKey(delivery, 0); err == nil {
		t.Fatal("generation zero accepted")
	}
	if _, err := relayframe.EvidenceRequestKey("agent_x", 1); err == nil {
		t.Fatal("invalid peer accepted")
	}
	if _, err := relayframe.EvidenceResponseKey(peer, "sha256:"+strings.Repeat("0", 64), 1); err == nil {
		t.Fatal("zero descriptor digest accepted")
	}
}
