package railwork

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

// worstTaskHeader is a task header with every field but the package at its
// maximum: a 128-byte version that is escaped six-fold, the largest
// request ID and logical time, and a maximal key card.
func worstTaskHeader() (TaskHeader, []byte) {
	card := make([]byte, MaxKeyCardBytes)
	return TaskHeader{
		BuyerAgentID: testBuyer, BuyerWallet: testWallet, CapabilityID: testCap,
		CapabilityVersion: strings.Repeat("<", MaxCapabilityVersionBytes),
		ExecutionID:       strings.Repeat("12", 32), ExecutionNonce: strings.Repeat("12", 32),
		RequestID: math.MaxUint64, CallLT: math.MaxUint64, CallHash: strings.Repeat("12", 32),
	}, card
}

// The package bound is exactly the largest package a maximal task header
// carries: the worst-case task at the bound encodes and decodes, one byte
// more does not fit the 64 KiB header.
func TestThePackageBoundIsTheLargestAMaximalTaskHeaderCarries(t *testing.T) {
	header, card := worstTaskHeader()
	header.Schema = TaskSchema
	header.SourceDigest = "sha256:" + strings.Repeat("ab", 32)
	header.BuyerKeyCard = base64.StdEncoding.EncodeToString(card)
	empty, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != maxTaskHeaderWithoutPackage || maxTaskHeaderWithoutPackage != 23386 {
		t.Fatalf("the header without its package is %d bytes, the constant %d", len(empty), maxTaskHeaderWithoutPackage)
	}
	if MaxPackageBytes != 31611 || MaxPackageBase64 != 42148 {
		t.Fatalf("bound %d bytes, %d characters", MaxPackageBytes, MaxPackageBase64)
	}
	header, card = worstTaskHeader()
	raw, err := EncodeTask(Task{Header: header, Package: make([]byte, MaxPackageBytes), Archive: []byte{1}, BuyerKeyCard: card})
	if err != nil {
		t.Fatalf("the worst-case task at the bound: %v", err)
	}
	if length := binary.BigEndian.Uint32(raw[:4]); length > MaxMessageHeaderBytes || length < MaxMessageHeaderBytes-3 {
		t.Fatalf("the worst-case header is %d bytes", length)
	}
	if _, err = DecodeTask(raw); err != nil {
		t.Fatalf("the worst-case task does not decode: %v", err)
	}
	if _, err = EncodeTask(Task{Header: header, Package: make([]byte, MaxPackageBytes+1), Archive: []byte{1},
		BuyerKeyCard: card}); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("one byte over the bound: %v", err)
	}
	// Even with a bound check removed, one more Base64 quantum overflows
	// the header: the bound is the real limit.
	over := header
	over.Schema, over.BuyerKeyCard = TaskSchema, base64.StdEncoding.EncodeToString(card)
	over.SourceDigest = "sha256:" + strings.Repeat("ab", 32)
	over.PackageBase64 = base64.StdEncoding.EncodeToString(make([]byte, MaxPackageBytes+1))
	encoded, err := json.Marshal(over)
	if err != nil || len(encoded) <= MaxMessageHeaderBytes {
		t.Fatalf("a package one byte over fits a %d-byte header: %v", len(encoded), err)
	}
}

func boundManifest(t *testing.T, mutate func(*nativecore.SoftwareWorkManifestV1)) ([]byte, nativecore.SoftwareWorkManifestV1) {
	t.Helper()
	manifest := servicefixture.Manifest("1.0.0", servicefixture.DefaultSettlement())
	mutate(&manifest)
	manifestCBOR, _, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return manifestCBOR, manifest
}

func agentPacketTransport(t *testing.T) nativecore.TransportBindingV1 {
	t.Helper()
	binding, err := nativecore.AgentPacketTransportBinding(testProvider, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func packageFor(t *testing.T, manifestCBOR []byte, manifest nativecore.SoftwareWorkManifestV1,
	transport nativecore.TransportBindingV1) *nativev1.QuoteProposalPackageV1 {
	t.Helper()
	settlement := servicefixture.DefaultSettlement()
	root, transportDigest, err := nativecore.BuildTransportBindingCellV1(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &nativev1.QuoteProposalPackageV1{Proposal: &nativev1.QuoteProposalV1{ProposalId: "provider-proposal-1",
		CapabilityId: testCap, CapabilityVersion: manifest.Version, ProviderAgentId: testProvider,
		ManifestDigest: manifestDigest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: uint64(time.Unix(2_000_000_000, 0).Unix()),
		Actor:                &nativev1.TOSAccountAddressV1{AccountId: settlement.ActorAccount},
		ActorCodeHash:        "tvm-cell-sha256:" + hex.EncodeToString(settlement.ActorCodeHash), PolicyVersion: 2,
		TermsHash: strings.Repeat("ab", 32), PriceNanotos: "300000000", StorageFeeNanotos: "200000000",
		AttestorKeyId: settlement.AttestorKey}, CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: root.ToBOC()}
	if _, err = quoteexchange.ValidatePortable(servicefixture.Network(), &nativev1.RequestQuoteProposalRequest{
		CapabilityId: testCap, CapabilityVersion: manifest.Version, BuyerAddress: testWallet}, pkg); err != nil {
		t.Fatalf("portable validation refuses the package: %v", err)
	}
	return pkg
}

func largeArguments(m *nativecore.SoftwareWorkManifestV1) {
	m.Description = strings.Repeat("d", 2048)
	for index := 0; index < 16; index++ {
		m.Invocation.Arguments = append(m.Invocation.Arguments, fmt.Sprintf("--flag%02d=%s", index, strings.Repeat("v", 290)))
	}
}

func maximalManifest(m *nativecore.SoftwareWorkManifestV1) {
	m.Name, m.Description = strings.Repeat("n", 128), strings.Repeat("d", 2048)
	m.Invocation.Executable = "/" + strings.Repeat("e", 255)
	m.Invocation.WorkingDirectory = "/workspace" + strings.Repeat("w", 246)
	m.Invocation.Arguments = nil
	for index := 0; index < 64; index++ {
		m.Invocation.Arguments = append(m.Invocation.Arguments, fmt.Sprintf("%02d%s", index, strings.Repeat("a", 510)))
	}
	var media []string
	for index := 0; index < 16; index++ {
		media = append(media, fmt.Sprintf("a%02d%s/%s", index, strings.Repeat("t", 61), strings.Repeat("s", 128)))
	}
	m.ArtifactMediaTypes, m.ReportMediaTypes = media, media
}

// A valid manifest with a large description and arguments makes a package
// over the old 8 KiB bound; it is carried now. A manifest at its own field
// limits makes a package no task can carry; it is refused for mode 2
// before any Quote exists, and its package is refused by every check.
func TestValidQuotesAreCarriedAndUncarriableOnesAreRefusedBeforePayment(t *testing.T) {
	transport := agentPacketTransport(t)
	for name, mutate := range map[string]func(*nativecore.SoftwareWorkManifestV1){
		"fixture":           func(*nativecore.SoftwareWorkManifestV1) {},
		"large description": largeArguments,
	} {
		manifestCBOR, manifest := boundManifest(t, mutate)
		pkg := packageFor(t, manifestCBOR, manifest, transport)
		if err := CheckCarriableManifest(manifestCBOR, transport); err != nil {
			t.Errorf("%s: manifest refused: %v", name, err)
		}
		if err := CheckCarriableQuote(pkg, transport); err != nil {
			t.Errorf("%s: package refused: %v", name, err)
		}
		raw, err := proto.Marshal(pkg)
		if err != nil {
			t.Fatal(err)
		}
		header, _ := worstTaskHeader()
		if _, err = EncodeTask(Task{Header: header, Package: raw, Archive: []byte{1}}); err != nil {
			t.Errorf("%s: a %d-byte package does not encode: %v", name, len(raw), err)
		}
		if name == "large description" && len(raw) <= 8<<10 {
			t.Errorf("the large-description package is only %d bytes", len(raw))
		}
	}
	manifestCBOR, manifest := boundManifest(t, maximalManifest)
	pkg := packageFor(t, manifestCBOR, manifest, transport)
	if size := proto.Size(pkg); size <= MaxPackageBytes {
		t.Fatalf("the maximal manifest's package is only %d bytes", size)
	}
	if err := CheckCarriableManifest(manifestCBOR, transport); !errors.Is(err, ErrQuoteNotCarriable) {
		t.Errorf("the maximal manifest was accepted for mode 2: %v", err)
	}
	if err := CheckCarriableQuote(pkg, transport); !errors.Is(err, ErrQuoteNotCarriable) {
		t.Errorf("the maximal package was accepted: %v", err)
	}
	https := nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20,
		BaseURL: "https://provider.example"}
	if err := CheckCarriableManifest(manifestCBOR, https); err != nil {
		t.Errorf("a non-rail transport was held to the rail bound: %v", err)
	}
	if err := CheckCarriablePackage(MaxPackageBytes+1, https); err != nil {
		t.Errorf("a non-rail package was held to the rail bound: %v", err)
	}
	if err := CheckCarriablePackage(MaxPackageBytes, transport); err != nil {
		t.Errorf("a package at the bound was refused: %v", err)
	}
	if err := CheckCarriablePackage(MaxPackageBytes+1, transport); !errors.Is(err, ErrQuoteNotCarriable) {
		t.Errorf("a package one byte over was accepted: %v", err)
	}
	if err := CheckCarriableQuote(nil, transport); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("no package: %v", err)
	}
}

// The Quote the manifest check sizes is never smaller than a real Quote
// for that manifest with every proposal field at its longest.
func TestTheManifestCheckSizesTheLargestProposal(t *testing.T) {
	transport := agentPacketTransport(t)
	for _, mutate := range []func(*nativecore.SoftwareWorkManifestV1){func(*nativecore.SoftwareWorkManifestV1) {}, largeArguments} {
		manifestCBOR, manifest := boundManifest(t, mutate)
		real := packageFor(t, manifestCBOR, manifest, transport)
		real.Proposal.ProposalId = strings.Repeat("x", maxProposalIDBytes)
		real.Proposal.PriceNanotos = new(big.Int).Sub(nativecore.MaxServiceActorCoins, big.NewInt(1)).String()
		real.Proposal.StorageFeeNanotos = real.Proposal.PriceNanotos
		real.Proposal.ExpiresAtUnixSeconds, real.Proposal.PolicyVersion = math.MaxUint64, math.MaxUint32
		largest, err := largestQuoteSize(manifestCBOR, transport)
		if err != nil {
			t.Fatal(err)
		}
		if size := proto.Size(real); size > largest || size < largest-8 {
			t.Fatalf("a real Quote of %d bytes against the assumed largest %d", size, largest)
		}
	}
}
