package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The frozen software-work manifest vector for the Service Actor profile
// (keys 16, 18, 20 and 21 of SOFTWARE_WORK_MANIFEST_V1). The test compares the
// committed file with what this implementation generates and never rewrites
// it. A new vector file is written only when
// SOFTWARE_WORK_MANIFEST_VECTOR_OUT names a path that does not exist yet.
var (
	manifestVectorPath       = filepath.Join("..", "..", "..", "spec", "test-vectors", "software-work-manifest-v1-service-actor.json")
	manifestVectorSchemaRoot = filepath.Join("..", "..", "..", "spec", "schemas")
)

const (
	manifestVectorSchema = "tos.service.software-work-manifest.v1.service-actor.vector"
	manifestVectorMedia  = "application/vnd.tos.service.software-work-manifest.v1+cbor"
	// The pinned executor OCI toolchain index digest (ROADMAP Gate D); an
	// input of the vector, not a value it derives.
	manifestVectorToolchain = "sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105"
	// The typed transport binding digest of the software-work profile; an
	// input of the vector.
	manifestVectorEndpoint = "sha256:dca9babcd44775f2c19ef571964c01e2e75b15254d0d16f2349c8d446f76c44c"
)

type manifestVectorNegativeJSON struct {
	Name     string          `json:"name"`
	Rule     string          `json:"rule"`
	Manifest json.RawMessage `json:"manifest"`
}

type manifestVectorNegativeCBOR struct {
	Name       string `json:"name"`
	Rule       string `json:"rule"`
	CBORBase64 string `json:"cbor_base64"`
}

type manifestVectorDocument struct {
	Schema           string                       `json:"schema"`
	MediaType        string                       `json:"media_type"`
	Canonicalization string                       `json:"canonicalization"`
	Sources          map[string]string            `json:"sources"`
	Manifest         json.RawMessage              `json:"manifest"`
	Expected         manifestVectorExpected       `json:"expected"`
	NegativeJSON     []manifestVectorNegativeJSON `json:"negative_json"`
	NegativeCBOR     []manifestVectorNegativeCBOR `json:"negative_cbor"`
}

type manifestVectorExpected struct {
	Digest              string `json:"digest"`
	CanonicalCBORBase64 string `json:"canonical_cbor_base64"`
}

func fileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// manifestVectorManifest builds the positive manifest from its sources: the
// frozen schema files, and the release code hash and attestor key ID of the
// contract-execution vectors.
func manifestVectorManifest() (SoftwareWorkManifestV1, error) {
	input, err := fileDigest(filepath.Join(manifestVectorSchemaRoot, "software-work-job-v1.schema.json"))
	if err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	output, err := fileDigest(filepath.Join(manifestVectorSchemaRoot, "software-work-outcome-v1.schema.json"))
	if err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "service-actor-conformance-vectors.json"))
	if err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	var actor struct {
		CodeHash string `json:"contract_code_hash"`
		Init     struct {
			AttestorKeyID string `json:"attestor_key_id"`
		} `json:"init"`
	}
	if err := json.Unmarshal(raw, &actor); err != nil {
		return SoftwareWorkManifestV1{}, err
	}
	codeHash, err := hex.DecodeString(strings.TrimPrefix(actor.CodeHash, "tvm-cell-sha256:"))
	if err != nil || len(codeHash) != 32 || !strings.HasPrefix(actor.CodeHash, "tvm-cell-sha256:") {
		return SoftwareWorkManifestV1{}, errors.New("contract-execution vectors carry no release code hash")
	}
	attestor := "mldsa44:" + actor.Init.AttestorKeyID
	// An illustrative workchain-0 actor account; the manifest binds whatever
	// account the provider deployed.
	account := sha256.Sum256([]byte("software-work manifest vector actor account"))
	return SoftwareWorkManifestV1{
		Protocol: SoftwareWorkManifestProtocolV1, Version: "2.0.0", Name: "Deterministic Go test",
		Description: "Run the committed Go test suite without network access.", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive", "immutable-repository-commit"},
		InputSchemaDigest:   input, OutputSchemaDigest: output, ToolchainDigest: manifestVectorToolchain,
		Invocation: SoftwareWorkInvocationV1{Executable: "/usr/local/go/bin/go", Arguments: []string{"test", "-count=1", "./..."},
			WorkingDirectory: "/workspace/source"},
		NetworkPolicy: "none",
		Limits: SoftwareWorkLimitsV1{CPUMillis: 120000, MemoryBytes: 1073741824, ScratchBytes: 2147483648,
			OutputBytes: 16777216, WallClockMillis: 180000},
		ArtifactMediaTypes: []string{"application/vnd.tos.service.software-artifact.v1+tar"},
		ReportMediaTypes:   []string{"application/vnd.tos.service.test-report.v1+json"},
		SuccessCondition:   "exit-code-zero-and-valid-reports", RefundConditions: []string{NoAttestedResponseRefund},
		EndpointCommitment: manifestVectorEndpoint, ExecutionSignerAuthorization: SettlementAttestorAuthorization(attestor),
		RetentionSeconds: 86400, SupportedAssets: []SoftwareWorkAssetV1{{Kind: NativeTOSAsset}},
		Settlement: SoftwareWorkSettlementV1{Rail: ServiceActorRail, ActorWorkchain: 0, ActorAccountID: account[:],
			ActorCodeHash: codeHash, AttestorKey: attestor},
	}, nil
}

// jsonObject is the generic JSON projection of a manifest, for negative cases
// that a typed edit cannot express (a missing or an unknown field).
func jsonObject(manifest SoftwareWorkManifestV1) (map[string]any, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	return object, nil
}

func negativeJSONCases(base SoftwareWorkManifestV1) ([]manifestVectorNegativeJSON, error) {
	attestor := base.Settlement.AttestorKey
	keyID := strings.TrimPrefix(attestor, "mldsa44:")
	otherAttestor := "mldsa44:" + strings.Repeat("98", 32)
	typed := []struct {
		name, rule string
		edit       func(*SoftwareWorkManifestV1)
	}{
		{"key16_escrow_refund_value", "key 16 is exactly [no-attested-response-before-deadline]",
			func(m *SoftwareWorkManifestV1) { m.RefundConditions = []string{"not-started-before-deadline"} }},
		{"key16_duplicate_refund_value", "key 16 is exactly [no-attested-response-before-deadline]",
			func(m *SoftwareWorkManifestV1) {
				m.RefundConditions = []string{NoAttestedResponseRefund, NoAttestedResponseRefund}
			}},
		{"key18_unrelated_digest", "key 18 is SHA-256 of the exact ASCII of key 21 field 5",
			func(m *SoftwareWorkManifestV1) { m.ExecutionSignerAuthorization = "sha256:" + strings.Repeat("55", 32) }},
		{"key18_raw_key_id", "key 18 hashes the attestor text form, not the bare key ID",
			func(m *SoftwareWorkManifestV1) { m.ExecutionSignerAuthorization = "sha256:" + keyID }},
		{"key20_stablecoin_asset", "key 20 is exactly [{0: native-tos}]",
			func(m *SoftwareWorkManifestV1) { m.SupportedAssets = []SoftwareWorkAssetV1{{Kind: "USDT"}} }},
		{"key20_two_assets", "key 20 is exactly [{0: native-tos}]",
			func(m *SoftwareWorkManifestV1) {
				m.SupportedAssets = []SoftwareWorkAssetV1{{Kind: NativeTOSAsset}, {Kind: NativeTOSAsset}}
			}},
		{"key20_no_asset", "key 20 is exactly [{0: native-tos}]",
			func(m *SoftwareWorkManifestV1) { m.SupportedAssets = []SoftwareWorkAssetV1{} }},
		{"key21_escrow_rail", "key 21 field 1 is exactly tos.service.service-actor.v1",
			func(m *SoftwareWorkManifestV1) { m.Settlement.Rail = "tos.service.escrow.v2" }},
		{"key21_masterchain_actor", "key 21 field 2 is exactly 0",
			func(m *SoftwareWorkManifestV1) { m.Settlement.ActorWorkchain = -1 }},
		{"key21_short_actor_account", "key 21 field 3 is 32 non-zero bytes",
			func(m *SoftwareWorkManifestV1) { m.Settlement.ActorAccountID = m.Settlement.ActorAccountID[:31] }},
		{"key21_zero_actor_account", "key 21 field 3 is 32 non-zero bytes",
			func(m *SoftwareWorkManifestV1) { m.Settlement.ActorAccountID = make([]byte, 32) }},
		{"key21_long_code_hash", "key 21 field 4 is 32 non-zero bytes",
			func(m *SoftwareWorkManifestV1) {
				m.Settlement.ActorCodeHash = append(append([]byte{}, m.Settlement.ActorCodeHash...), 0)
			}},
		{"key21_zero_code_hash", "key 21 field 4 is 32 non-zero bytes",
			func(m *SoftwareWorkManifestV1) { m.Settlement.ActorCodeHash = make([]byte, 32) }},
		{"key21_bare_attestor_key_id", "key 21 field 5 is mldsa44:<64 lowercase hex>",
			func(m *SoftwareWorkManifestV1) {
				m.Settlement.AttestorKey = keyID
				m.ExecutionSignerAuthorization = SettlementAttestorAuthorization(keyID)
			}},
		{"key21_uppercase_attestor_key_id", "key 21 field 5 is mldsa44:<64 lowercase hex>",
			func(m *SoftwareWorkManifestV1) {
				m.Settlement.AttestorKey = "mldsa44:" + strings.ToUpper(keyID)
				m.ExecutionSignerAuthorization = SettlementAttestorAuthorization(m.Settlement.AttestorKey)
			}},
		{"key21_zero_attestor_key_id", "key 21 field 5 names a non-zero key ID",
			func(m *SoftwareWorkManifestV1) {
				m.Settlement.AttestorKey = "mldsa44:" + strings.Repeat("00", 32)
				m.ExecutionSignerAuthorization = SettlementAttestorAuthorization(m.Settlement.AttestorKey)
			}},
		{"key21_attestor_without_key18", "a changed key 21 attestor needs the matching key 18",
			func(m *SoftwareWorkManifestV1) { m.Settlement.AttestorKey = otherAttestor }},
	}
	cases := make([]manifestVectorNegativeJSON, 0, len(typed)+3)
	for _, item := range typed {
		manifest := base
		manifest.RefundConditions = append([]string{}, base.RefundConditions...)
		manifest.SupportedAssets = append([]SoftwareWorkAssetV1{}, base.SupportedAssets...)
		manifest.Settlement.ActorAccountID = append([]byte{}, base.Settlement.ActorAccountID...)
		manifest.Settlement.ActorCodeHash = append([]byte{}, base.Settlement.ActorCodeHash...)
		item.edit(&manifest)
		object, err := jsonObject(manifest)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		cases = append(cases, manifestVectorNegativeJSON{Name: item.name, Rule: item.rule, Manifest: raw})
	}
	generic := []struct {
		name, rule string
		edit       func(map[string]any)
	}{
		{"key21_missing", "key 21 is required", func(object map[string]any) { delete(object, "settlement") }},
		{"key21_missing_attestor", "key 21 has exactly fields 1-5",
			func(object map[string]any) { delete(object["settlement"].(map[string]any), "attestor_key") }},
		{"key21_unknown_field", "key 21 has exactly fields 1-5",
			func(object map[string]any) { object["settlement"].(map[string]any)["actor_address"] = "0:" + keyID }},
	}
	for _, item := range generic {
		object, err := jsonObject(base)
		if err != nil {
			return nil, err
		}
		item.edit(object)
		raw, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		cases = append(cases, manifestVectorNegativeJSON{Name: item.name, Rule: item.rule, Manifest: raw})
	}
	return cases, nil
}

func negativeCBORCases(canonical []byte) ([]manifestVectorNegativeCBOR, error) {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	edited := func(edit func(map[uint64]any) error) (string, error) {
		var generic map[uint64]any
		if err := cbor.Unmarshal(canonical, &generic); err != nil {
			return "", err
		}
		if err := edit(generic); err != nil {
			return "", err
		}
		encoded, err := mode.Marshal(generic)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(encoded), nil
	}
	settlement := func(generic map[uint64]any) (map[any]any, error) {
		value, ok := generic[21].(map[any]any)
		if !ok {
			return nil, fmt.Errorf("key 21 is %T", generic[21])
		}
		return value, nil
	}
	if canonical[0] != 0xb5 {
		return nil, fmt.Errorf("unexpected manifest map header %x", canonical[0])
	}
	indefinite := append(append([]byte{0xbf}, canonical[1:]...), 0xff)
	cases := []manifestVectorNegativeCBOR{{Name: "indefinite_root_map", Rule: "definite lengths only",
		CBORBase64: base64.StdEncoding.EncodeToString(indefinite)}}

	// Two encodings that decode to the same valid manifest and differ from
	// the canonical bytes only in form, so only a canonical re-encode check
	// refuses them.
	var root map[uint64]any
	if err := cbor.Unmarshal(canonical, &root); err != nil {
		return nil, err
	}
	entry := func(key uint64) ([]byte, error) {
		encodedKey, err := mode.Marshal(key)
		if err != nil {
			return nil, err
		}
		encodedValue, err := mode.Marshal(root[key])
		if err != nil {
			return nil, err
		}
		return append(encodedKey, encodedValue...), nil
	}
	first, err := entry(1)
	if err != nil {
		return nil, err
	}
	second, err := entry(2)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical[1:1+len(first)+len(second)], append(append([]byte{}, first...), second...)) {
		return nil, errors.New("the canonical manifest does not start with keys 1 and 2")
	}
	unsorted := append([]byte{canonical[0]}, second...)
	unsorted = append(append(unsorted, first...), canonical[1+len(first)+len(second):]...)
	cases = append(cases, manifestVectorNegativeCBOR{Name: "unsorted_root_keys",
		Rule: "map keys in canonical order (keys 2 and 1 swapped)", CBORBase64: base64.StdEncoding.EncodeToString(unsorted)})

	// Key 21 field 2 (the actor workchain, 0) as the two-byte 0x18 0x00
	// instead of the one-byte 0x00.
	workchain := []byte{0x02, 0x00, 0x03, 0x58, 0x20}
	at := bytes.Index(canonical, workchain)
	if at < 0 || bytes.Count(canonical, workchain) != 1 {
		return nil, errors.New("the key 21 workchain entry is not found exactly once")
	}
	longer := append(append(append([]byte{}, canonical[:at+1]...), 0x18, 0x00), canonical[at+2:]...)
	cases = append(cases, manifestVectorNegativeCBOR{Name: "key21_workchain_not_shortest",
		Rule: "integers in their shortest form (key 21 field 2 as 0x18 0x00)", CBORBase64: base64.StdEncoding.EncodeToString(longer)})
	for _, item := range []struct {
		name, rule string
		edit       func(map[uint64]any) error
	}{
		{"root_key_22", "the root map has exactly keys 1-21", func(generic map[uint64]any) error {
			generic[22] = "extra"
			return nil
		}},
		{"key20_extra_entry_key", "a key 20 entry is exactly {0: native-tos}", func(generic map[uint64]any) error {
			assets, ok := generic[20].([]any)
			if !ok || len(assets) != 1 {
				return errors.New("key 20 is not a one-element array")
			}
			entry, ok := assets[0].(map[any]any)
			if !ok {
				return errors.New("key 20 entry is not a map")
			}
			entry[uint64(1)] = "decimals"
			return nil
		}},
		{"key21_account_as_text", "key 21 field 3 is a byte string", func(generic map[uint64]any) error {
			value, err := settlement(generic)
			if err != nil {
				return err
			}
			raw, ok := value[uint64(3)].([]byte)
			if !ok {
				return errors.New("key 21 field 3 is not bytes")
			}
			value[uint64(3)] = hex.EncodeToString(raw)
			return nil
		}},
		{"key21_code_hash_as_text", "key 21 field 4 is a byte string", func(generic map[uint64]any) error {
			value, err := settlement(generic)
			if err != nil {
				return err
			}
			raw, ok := value[uint64(4)].([]byte)
			if !ok {
				return errors.New("key 21 field 4 is not bytes")
			}
			value[uint64(4)] = hex.EncodeToString(raw)
			return nil
		}},
		{"key21_field_6", "key 21 has exactly fields 1-5", func(generic map[uint64]any) error {
			value, err := settlement(generic)
			if err != nil {
				return err
			}
			value[uint64(6)] = "extra"
			return nil
		}},
		{"key21_missing_field_5", "key 21 has exactly fields 1-5", func(generic map[uint64]any) error {
			value, err := settlement(generic)
			if err != nil {
				return err
			}
			delete(value, uint64(5))
			return nil
		}},
	} {
		encoded, err := edited(item.edit)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", item.name, err)
		}
		cases = append(cases, manifestVectorNegativeCBOR{Name: item.name, Rule: item.rule, CBORBase64: encoded})
	}
	return cases, nil
}

func generateManifestVector() ([]byte, error) {
	manifest, err := manifestVectorManifest()
	if err != nil {
		return nil, err
	}
	canonical, digest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		return nil, err
	}
	projection, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	negativeJSON, err := negativeJSONCases(manifest)
	if err != nil {
		return nil, err
	}
	negativeCBOR, err := negativeCBORCases(canonical)
	if err != nil {
		return nil, err
	}
	document := manifestVectorDocument{
		Schema: manifestVectorSchema, MediaType: manifestVectorMedia,
		Canonicalization: "RFC 8949 Core Deterministic Encoding; integer field keys of docs/SOFTWARE_WORK_MANIFEST_V1.md; " +
			"byte strings project to JSON as standard Base64",
		Sources: map[string]string{
			"input_schema_digest":            "SHA-256 of schemas/software-work-job-v1.schema.json",
			"output_schema_digest":           "SHA-256 of schemas/software-work-outcome-v1.schema.json",
			"settlement.actor_code_hash":     "contract_code_hash of test-vectors/service-actor-conformance-vectors.json (the tos-service-actor-v1 release)",
			"settlement.attestor_key":        "mldsa44: and init.attestor_key_id of test-vectors/service-actor-conformance-vectors.json",
			"settlement.actor_account_id":    "illustrative: SHA-256 of the ASCII text 'software-work manifest vector actor account'",
			"execution_signer_authorization": "SHA-256 of the exact ASCII of settlement.attestor_key",
		},
		Manifest:     projection,
		Expected:     manifestVectorExpected{Digest: digest, CanonicalCBORBase64: base64.StdEncoding.EncodeToString(canonical)},
		NegativeJSON: negativeJSON, NegativeCBOR: negativeCBOR,
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func TestSoftwareWorkManifestServiceActorVector(t *testing.T) {
	generated, err := generateManifestVector()
	if err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("SOFTWARE_WORK_MANIFEST_VECTOR_OUT"); out != "" {
		file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			t.Fatalf("a new vector is written only to a path that does not exist: %v", err)
		}
		if _, err := file.Write(generated); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		t.Skipf("wrote a new vector to %s; compare it before committing", out)
	}
	committed, err := os.ReadFile(manifestVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, generated) {
		t.Fatal("the frozen manifest vector differs from what this implementation generates")
	}

	var document manifestVectorDocument
	decoder := json.NewDecoder(bytes.NewReader(committed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || document.Schema != manifestVectorSchema {
		t.Fatalf("vector file: %v", err)
	}
	manifest, err := DecodeSoftwareWorkManifestJSON(document.Manifest)
	if err != nil {
		t.Fatalf("positive manifest refused: %v", err)
	}
	canonical, digest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	want, err := base64.StdEncoding.DecodeString(document.Expected.CanonicalCBORBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, want) || digest != document.Expected.Digest {
		t.Fatalf("positive manifest encodes to %s, vector says %s", digest, document.Expected.Digest)
	}
	if decoded, err := DecodeCanonicalSoftwareWorkManifestCBOR(want); err != nil || decoded.Settlement.AttestorKey != manifest.Settlement.AttestorKey {
		t.Fatalf("canonical CBOR refused: %v", err)
	}
	if len(document.NegativeJSON) == 0 || len(document.NegativeCBOR) == 0 {
		t.Fatal("the negative corpus is empty")
	}
	seen := map[string]bool{}
	for _, item := range document.NegativeJSON {
		if seen[item.Name] {
			t.Fatalf("duplicate negative case %s", item.Name)
		}
		seen[item.Name] = true
		if _, err := DecodeSoftwareWorkManifestJSON(item.Manifest); err == nil {
			t.Errorf("negative JSON case %s was accepted", item.Name)
		} else {
			t.Logf("%s (%s): %v", item.Name, item.Rule, err)
		}
	}
	for _, item := range document.NegativeCBOR {
		if seen[item.Name] {
			t.Fatalf("duplicate negative case %s", item.Name)
		}
		seen[item.Name] = true
		raw, err := base64.StdEncoding.DecodeString(item.CBORBase64)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeCanonicalSoftwareWorkManifestCBOR(raw); err == nil {
			t.Errorf("negative CBOR case %s was accepted", item.Name)
		} else {
			t.Logf("%s (%s): %v", item.Name, item.Rule, err)
		}
	}
}
