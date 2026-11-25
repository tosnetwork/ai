package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const tokenProtocolVectorPath = "../../../spec/test-vectors/service-actor-token-protocol-v1.json"

type tokenProtocolVector struct {
	Schema   string                     `json:"schema"`
	Sources  map[string]string          `json:"sources"`
	Network  *nativev1.NetworkDomain    `json:"network"`
	Manifest SoftwareWorkManifestV1     `json:"manifest"`
	Proposal *nativev1.QuoteProposalV1  `json:"proposal"`
	Receipt  SoftwareWorkTokenReceiptV1 `json:"receipt"`
	Expected struct {
		ManifestCBOR   string `json:"manifest_cbor_base64"`
		ManifestDigest string `json:"manifest_digest"`
		QuoteBOC       string `json:"quote_boc_base64"`
		QuoteHash      string `json:"quote_hash"`
		ReceiptBOC     string `json:"receipt_boc_base64"`
		ReceiptHash    string `json:"receipt_hash"`
	} `json:"expected"`
}

func tokenVectorHex(t *testing.T, s string) []byte {
	t.Helper()
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func tokenVectorHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
func newTokenProtocolVector(t *testing.T) tokenProtocolVector {
	t.Helper()
	var source struct {
		ContractCodeHash, WalletCodeHash, Master string
		Attested                                 struct {
			Actor         string
			AttestorKeyID string
			TermsHash     string
		}
	}
	// The inputs below come from the frozen contract-execution vectors; no generated
	// output is accepted as an encoder's expectation.
	raw, err := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(object["contract_code_hash"], &source.ContractCodeHash)
	_ = json.Unmarshal(object["wallet_code_hash"], &source.WalletCodeHash)
	source.ContractCodeHash = strings.TrimPrefix(source.ContractCodeHash, "tvm-cell-sha256:")
	source.WalletCodeHash = strings.TrimPrefix(source.WalletCodeHash, "tvm-cell-sha256:")
	_ = json.Unmarshal(object["master"], &source.Master)
	var attested map[string]json.RawMessage
	_ = json.Unmarshal(object["attested"], &attested)
	_ = json.Unmarshal(attested["actor"], &source.Attested.Actor)
	_ = json.Unmarshal(attested["attestor_key_id"], &source.Attested.AttestorKeyID)
	_ = json.Unmarshal(attested["terms_hash"], &source.Attested.TermsHash)
	nativeRaw, err := os.ReadFile(manifestVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var native struct {
		Manifest SoftwareWorkManifestV1 `json:"manifest"`
	}
	if err = json.Unmarshal(nativeRaw, &native); err != nil {
		t.Fatal(err)
	}
	v := tokenProtocolVector{Schema: "tos.service.token-rail.protocol.v1.vectors", Sources: map[string]string{"contract_sha": "7a32aa402944bb944a1c778197e491605f909df4", "contract_vectors_sha256": func() string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }()}, Network: &nativev1.NetworkDomain{NetworkId: "tos:token-vector", GenesisRootHash: "sha256:" + tokenVectorHash("token-vector-genesis-root"), GenesisFileHash: "sha256:" + tokenVectorHash("token-vector-genesis-file")}, Manifest: native.Manifest}
	decimals := uint8(6)
	master := tokenVectorHex(t, strings.TrimPrefix(source.Master, "0:"))
	wallet := tokenVectorHex(t, source.WalletCodeHash)
	v.Manifest.SupportedAssets = []SoftwareWorkAssetV1{{Kind: TOSTokenAsset, MasterAccountID: master, WalletCodeHash: wallet, Decimals: &decimals}}
	v.Manifest.Settlement = SoftwareWorkSettlementV1{Rail: ServiceActorTokenRail, ActorWorkchain: 0, ActorAccountID: tokenVectorHex(t, strings.TrimPrefix(source.Attested.Actor, "0:")), ActorCodeHash: tokenVectorHex(t, source.ContractCodeHash), AttestorKey: "mldsa44:" + source.Attested.AttestorKeyID}
	v.Manifest.ExecutionSignerAuthorization = SettlementAttestorAuthorization(v.Manifest.Settlement.AttestorKey)
	_, md, err := CanonicalSoftwareWorkManifest(v.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	minterHash := "tvm-cell-sha256:" + tokenVectorHash("token-vector-pinned-minter-code")
	v.Proposal = &nativev1.QuoteProposalV1{CapabilityId: "cap_" + tokenVectorHash("token-vector-capability"), CapabilityVersion: v.Manifest.Version, ProviderAgentId: "agent_" + tokenVectorHash("token-vector-provider"), ManifestDigest: md, TransportBindingDigest: v.Manifest.EndpointCommitment, ExpiresAtUnixSeconds: 1800000000, Actor: &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: v.Manifest.Settlement.ActorAccountID}, ActorCodeHash: "tvm-cell-sha256:" + source.ContractCodeHash, PolicyVersion: 0, TermsHash: source.Attested.TermsHash, PriceAtomic: "1000", StorageFeeNanotos: "200000000", AttestorKeyId: v.Manifest.Settlement.AttestorKey, Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: master, CodeHash: minterHash}, WalletCodeHash: "tvm-cell-sha256:" + source.WalletCodeHash, Decimals: 6}}
	_, qh, err := BuildAcceptedTokenQuoteCommitment(v.Network, v.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	v.Receipt = SoftwareWorkTokenReceiptV1{SoftwareWorkReceiptV1: SoftwareWorkReceiptV1{QuoteCommitment: qh, ExecutionID: "sha256:" + tokenVectorHash("token-vector-execution"), InputDigest: "sha256:" + tokenVectorHash("token-vector-input"), ResultDigest: "sha256:" + tokenVectorHash("token-vector-result"), ArtifactDigest: "sha256:" + tokenVectorHash("token-vector-artifact"), ReportDigest: "sha256:" + tokenVectorHash("token-vector-report"), SourceDigest: "sha256:" + tokenVectorHash("token-vector-source"), ToolchainDigest: v.Manifest.ToolchainDigest, SandboxDigest: "sha256:" + tokenVectorHash("token-vector-sandbox"), ChargedAtomicAmount: "1000", ProviderAgentID: v.Proposal.ProviderAgentId, CompletedAt: 1799999000, ExitCode: 0}}
	copy(v.Receipt.AssetMaster[:], master)
	fillTokenProtocolExpected(t, &v)
	return v
}
func fillTokenProtocolExpected(t *testing.T, v *tokenProtocolVector) {
	t.Helper()
	data, d, err := CanonicalSoftwareWorkManifest(v.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	v.Expected.ManifestCBOR = base64.StdEncoding.EncodeToString(data)
	v.Expected.ManifestDigest = d
	q, h, err := BuildAcceptedTokenQuoteCommitment(v.Network, v.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	v.Expected.QuoteBOC = base64.StdEncoding.EncodeToString(q.ToBOCWithOptions(cell.BOCSerializeOptions{}))
	v.Expected.QuoteHash = h
	r, h, err := BuildSoftwareWorkTokenReceiptCellV1(v.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	v.Expected.ReceiptBOC = base64.StdEncoding.EncodeToString(r.ToBOCWithOptions(cell.BOCSerializeOptions{}))
	v.Expected.ReceiptHash = h
}
func readTokenProtocolVector(t *testing.T) tokenProtocolVector {
	t.Helper()
	raw, err := os.ReadFile(tokenProtocolVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v tokenProtocolVector
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func TestTokenProtocolFrozenVector(t *testing.T) {
	// Creation is deliberate and exclusive, never a rewrite on mismatch.
	if output := os.Getenv("TOKEN_PROTOCOL_VECTOR_OUT"); output != "" {
		v := newTokenProtocolVector(t)
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')
		f, err := os.OpenFile(filepath.Clean(output), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(tokenProtocolVectorPath); os.IsNotExist(err) {
			return
		}
	}
	expected := readTokenProtocolVector(t)
	actual := expected
	fillTokenProtocolExpected(t, &actual)
	a, _ := json.Marshal(actual.Expected)
	b, _ := json.Marshal(expected.Expected)
	if !bytes.Equal(a, b) {
		t.Fatalf("token protocol vector changed:\n%s\nwant\n%s", a, b)
	}
	q, _, _ := BuildAcceptedTokenQuoteCommitment(expected.Network, expected.Proposal)
	decoded, err := DecodeAcceptedTokenQuoteV1(q, expected.Network)
	if err != nil || !proto.Equal(decoded.Proposal, expected.Proposal) {
		t.Fatalf("token Quote decode: %v", err)
	}
	r, _, _ := BuildSoftwareWorkTokenReceiptCellV1(expected.Receipt)
	receipt, err := DecodeSoftwareWorkTokenReceiptCellV1(r)
	if err != nil {
		t.Fatal(err)
	}
	if err = TokenReceiptMatchesQuote(receipt, decoded); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeAcceptedQuoteV1(q, expected.Network); err == nil {
		t.Fatal("native decoder accepted token Quote")
	}
	if _, err = DecodeSoftwareWorkReceiptCellV1(r); err == nil {
		t.Fatal("native decoder accepted token Receipt")
	}
}
func TestTokenQuoteRefusesMixedAndMismatchedFields(t *testing.T) {
	v := newTokenProtocolVector(t)
	for name, edit := range map[string]func(*nativev1.QuoteProposalV1){"native price": func(p *nativev1.QuoteProposalV1) { p.PriceNanotos = "1000" }, "no asset": func(p *nativev1.QuoteProposalV1) { p.Asset = nil }, "no price": func(p *nativev1.QuoteProposalV1) { p.PriceAtomic = "" }, "noncanonical price": func(p *nativev1.QuoteProposalV1) { p.PriceAtomic = "01000" }, "range": func(p *nativev1.QuoteProposalV1) { p.PriceAtomic = MaxServiceActorCoins.String() }, "native code": func(p *nativev1.QuoteProposalV1) { p.ActorCodeHash = digestString(ServiceActorReleaseCodeHash[:]) }, "bad decimals": func(p *nativev1.QuoteProposalV1) { p.Asset.Decimals = 256 }, "master wc": func(p *nativev1.QuoteProposalV1) { p.Asset.Master.Workchain = -1 }, "zero master": func(p *nativev1.QuoteProposalV1) { p.Asset.Master.AccountId = make([]byte, 32) }, "zero wallet": func(p *nativev1.QuoteProposalV1) {
		p.Asset.WalletCodeHash = "tvm-cell-sha256:" + strings.Repeat("0", 64)
	}} {
		t.Run(name, func(t *testing.T) {
			p := proto.Clone(v.Proposal).(*nativev1.QuoteProposalV1)
			edit(p)
			if _, _, err := BuildAcceptedTokenQuoteCommitment(v.Network, p); err == nil {
				t.Fatal("bad token Quote accepted")
			}
		})
	}
}
func TestTokenManifestKeepsNativeEncodingAndRefusesCrossRail(t *testing.T) {
	v := newTokenProtocolVector(t)
	m := v.Manifest
	m.Settlement.Rail = ServiceActorRail
	if _, _, err := CanonicalSoftwareWorkManifest(m); err == nil {
		t.Fatal("token identity on native rail")
	}
	m = v.Manifest
	m.SupportedAssets = []SoftwareWorkAssetV1{{Kind: NativeTOSAsset}}
	if _, _, err := CanonicalSoftwareWorkManifest(m); err == nil {
		t.Fatal("native identity on token rail")
	}
	m = v.Manifest
	m.Settlement.ActorCodeHash = ServiceActorReleaseCodeHash[:]
	if _, _, err := CanonicalSoftwareWorkManifest(m); err == nil {
		t.Fatal("native code on token rail")
	}
}
func TestTokenReceiptBindsAssetAmountAndVersion(t *testing.T) {
	v := newTokenProtocolVector(t)
	q := &AcceptedQuoteTermsV1{Network: v.Network, Proposal: v.Proposal}
	for _, edit := range []func(*SoftwareWorkTokenReceiptV1){func(r *SoftwareWorkTokenReceiptV1) { r.AssetMaster[0] ^= 1 }, func(r *SoftwareWorkTokenReceiptV1) { r.ChargedAtomicAmount = "999" }, func(r *SoftwareWorkTokenReceiptV1) { r.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("ab", 32) }, func(r *SoftwareWorkTokenReceiptV1) { r.ExecutionID = "" }} {
		r := v.Receipt
		edit(&r)
		if err := TokenReceiptMatchesQuote(r, q); err == nil {
			t.Fatal("token Receipt mismatch accepted")
		}
	}
}
