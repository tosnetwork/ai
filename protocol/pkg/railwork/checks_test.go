package railwork

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const (
	testBuyer    = "agent_" + "07a5c13bc5ca714991ded6331d8161e3b162870d726d6f47ce61439f76a1dc33"
	testProvider = "agent_" + "5555555555555555555555555555555555555555555555555555555555555555"
	testWallet   = "0:" + "1111111111111111111111111111111111111111111111111111111111111111"
	testCap      = "cap_" + "4444444444444444444444444444444444444444444444444444444444444444"
)

// taskFixture is one paid task as a buyer sends it and a provider admits it.
type taskFixture struct {
	provider Provider
	pkg      *nativev1.QuoteProposalPackageV1
	nonce    [32]byte
	archive  []byte
	header   TaskHeader
	binding  Binding
}

func quotePackage(t *testing.T, recipient string, maxRequestBytes uint32) *nativev1.QuoteProposalPackageV1 {
	t.Helper()
	settlement := servicefixture.DefaultSettlement()
	manifest := servicefixture.Manifest("1.0.0", settlement)
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	transportBinding, err := nativecore.AgentPacketTransportBinding(recipient, maxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(transportBinding)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-proposal-1", CapabilityId: testCap,
		CapabilityVersion: manifest.Version, ProviderAgentId: testProvider, ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: uint64(time.Unix(2_000_000_000, 0).Unix()),
		Actor:         &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: settlement.ActorAccount},
		ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(settlement.ActorCodeHash), PolicyVersion: 2,
		TermsHash: strings.Repeat("ab", 32), PriceNanotos: "300000000", StorageFeeNanotos: "200000000",
		AttestorKeyId: settlement.AttestorKey}
	return &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR,
		TransportBindingBoc: transport.ToBOC()}
}

func newTaskFixture(t *testing.T) *taskFixture {
	t.Helper()
	network := servicefixture.Network()
	pkg := quotePackage(t, testProvider, nativecore.MaxAgentPacketTransportRequestBytes)
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x42}, 32))
	executionID, err := ExecutionID(testBuyer, nonce)
	if err != nil {
		t.Fatal(err)
	}
	archive := bytes.Repeat([]byte("source "), 100)
	quoteHash, _, err := QuoteCommitment(network, pkg.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	requestHash, err := RequestHash(quoteHash, executionID, InputDigest(sha256.Sum256(archive)))
	if err != nil {
		t.Fatal(err)
	}
	var actor [32]byte
	copy(actor[:], servicefixture.DefaultSettlement().ActorAccount)
	return &taskFixture{
		provider: Provider{Network: network, AgentID: testProvider, CapabilityID: testCap, Version: "1.0.0"},
		pkg:      pkg, nonce: nonce, archive: archive,
		header: TaskHeader{BuyerAgentID: testBuyer, BuyerWallet: testWallet, CapabilityID: testCap,
			CapabilityVersion: "1.0.0", ExecutionID: hex.EncodeToString(executionID[:]),
			ExecutionNonce: hex.EncodeToString(nonce[:]), RequestID: 5, CallLT: 10, CallHash: strings.Repeat("cd", 32)},
		binding: Binding{ActorAccount: actor, RequestID: 5, RequestHash: requestHash},
	}
}

func (f *taskFixture) message(t *testing.T) Message {
	t.Helper()
	packageBytes, err := proto.Marshal(f.pkg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeTask(Task{Header: f.header, Package: packageBytes, Archive: f.archive})
	if err != nil {
		t.Fatal(err)
	}
	return Message{SenderAgentID: f.header.BuyerAgentID, Kind: KindTask, Binding: f.binding,
		MessageDigest: sha256.Sum256(body), Body: body}
}

func TestProviderAdmitsAPaidTaskAndDerivesItsRequest(t *testing.T) {
	fixture := newTaskFixture(t)
	admission, err := fixture.provider.CheckTask(fixture.message(t))
	if err != nil {
		t.Fatal(err)
	}
	if admission.RequestHash != fixture.binding.RequestHash || admission.Actor != fixture.binding.Actor() ||
		!admission.FrameBindingMatchesQuote() || admission.InputDigest != InputDigest(sha256.Sum256(fixture.archive)) {
		t.Fatalf("admission %+v", admission)
	}
	if slot := admission.Slot(); slot.QuoteCommitment != admission.QuoteCommitment || slot.RequestID != 5 ||
		slot.Actor != fixture.binding.Actor() {
		t.Fatalf("slot %+v", slot)
	}
	if err = admission.CheckVerifiedBinding(fixture.binding.Actor(), fixture.binding.RequestHash); err != nil {
		t.Fatal(err)
	}
}

func TestProviderAdmitsRequestIDZero(t *testing.T) {
	fixture := newTaskFixture(t)
	fixture.header.RequestID, fixture.binding.RequestID = 0, 0
	if _, err := fixture.provider.CheckTask(fixture.message(t)); err != nil {
		t.Fatal(err)
	}
}

func TestProviderRefusesTasksThatDoNotBindToItsQuote(t *testing.T) {
	cases := map[string]func(*testing.T, *taskFixture, *Message){
		"sender is not the buyer": func(_ *testing.T, _ *taskFixture, m *Message) {
			m.SenderAgentID = "agent_" + strings.Repeat("66", 32)
		},
		"frames name another request id": func(_ *testing.T, _ *taskFixture, m *Message) { m.Binding.RequestID = 6 },
		"another provider": func(_ *testing.T, f *taskFixture, _ *Message) {
			f.provider.AgentID = "agent_" + strings.Repeat("57", 32)
		},
		"another version": func(_ *testing.T, f *taskFixture, _ *Message) { f.provider.Version = "1.0.1" },
		"another capability": func(_ *testing.T, f *taskFixture, _ *Message) {
			f.provider.CapabilityID = "cap_" + strings.Repeat("45", 32)
		},
		"archive over the quoted request bound": func(t *testing.T, f *taskFixture, m *Message) {
			f.pkg = quotePackage(t, testProvider, uint32(len(f.archive)-1))
			*m = f.message(t)
		},
		"execution id of another buyer Agent": func(t *testing.T, f *taskFixture, m *Message) {
			other, err := ExecutionID("agent_"+strings.Repeat("68", 32), f.nonce)
			if err != nil {
				t.Fatal(err)
			}
			f.header.ExecutionID = hex.EncodeToString(other[:])
			*m = f.message(t)
		},
		"execution nonce that does not open the id": func(t *testing.T, f *taskFixture, m *Message) {
			f.header.ExecutionNonce = strings.Repeat("43", 32)
			*m = f.message(t)
		},
		"package that does not decode": func(t *testing.T, f *taskFixture, m *Message) {
			body, err := EncodeTask(Task{Header: f.header, Package: []byte{0xff, 0xff, 0xff}, Archive: f.archive})
			if err != nil {
				t.Fatal(err)
			}
			m.Body = body
		},
		"Quote package that does not validate": func(t *testing.T, f *taskFixture, m *Message) {
			f.pkg.CanonicalManifestCbor[0] ^= 1
			*m = f.message(t)
		},
		"capability version other than the Quote's": func(t *testing.T, f *taskFixture, m *Message) {
			f.header.CapabilityVersion = "1.0.1"
			*m = f.message(t)
		},
		"not a task": func(_ *testing.T, _ *taskFixture, m *Message) { m.Kind = KindResult },
	}
	for name, mutate := range cases {
		fixture := newTaskFixture(t)
		message := fixture.message(t)
		mutate(t, fixture, &message)
		if _, err := fixture.provider.CheckTask(message); !errors.Is(err, ErrTaskNotAdmitted) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestProviderRefusesAQuoteThatDoesNotDeliverToIt(t *testing.T) {
	fixture := newTaskFixture(t)
	https, digest, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{
		SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.pkg.TransportBindingBoc, fixture.pkg.Proposal.TransportBindingDigest = https.ToBOC(), digest
	if _, err = fixture.provider.CheckTask(fixture.message(t)); !errors.Is(err, ErrTaskNotAdmitted) {
		t.Fatalf("err=%v", err)
	}
}

func TestProviderRefusesAMalformedTaskAsMessageInvalid(t *testing.T) {
	fixture := newTaskFixture(t)
	message := fixture.message(t)
	message.Body = message.Body[:len(message.Body)-1]
	if _, err := fixture.provider.CheckTask(message); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("err=%v", err)
	}
	if _, err := (Provider{}).CheckTask(message); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unconfigured provider err=%v", err)
	}
}

func TestFrameBindingMustEqualTheVerifiedRequest(t *testing.T) {
	fixture := newTaskFixture(t)
	message := fixture.message(t)
	message.Binding.RequestHash[0] ^= 1
	admission, err := fixture.provider.CheckTask(message)
	if err != nil {
		t.Fatal(err)
	}
	if admission.FrameBindingMatchesQuote() {
		t.Fatal("a wrong frame request hash matched the Quote")
	}
	if err = admission.CheckVerifiedBinding(fixture.binding.Actor(), fixture.binding.RequestHash); !errors.Is(err, ErrTaskNotAdmitted) {
		t.Fatalf("wrong request hash err=%v", err)
	}
	fixture = newTaskFixture(t)
	message = fixture.message(t)
	message.Binding.ActorAccount[0] ^= 1
	if admission, err = fixture.provider.CheckTask(message); err != nil {
		t.Fatal(err)
	}
	if admission.FrameBindingMatchesQuote() {
		t.Fatal("a wrong frame actor matched the Quote")
	}
	if err = admission.CheckVerifiedBinding(fixture.binding.Actor(), fixture.binding.RequestHash); !errors.Is(err, ErrTaskNotAdmitted) {
		t.Fatalf("wrong actor err=%v", err)
	}
	if err = admission.CheckVerifiedBinding("", fixture.binding.RequestHash); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty verified actor err=%v", err)
	}
}

// --- buyer acceptance -------------------------------------------------------

func vectorResult(t *testing.T, document *vectorDocument) Result {
	t.Helper()
	for _, message := range document.Messages {
		if message.Name == "result" {
			result, err := DecodeResult(document.messageBytes(t, message))
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
	}
	t.Fatal("no result vector")
	return Result{}
}

func TestBuyerAcceptsTheVectorResult(t *testing.T) {
	document := loadVectors(t)
	result := vectorResult(t, document)
	finalized := mustHex32(t, document.Receipt.ResponseHashHex)
	if err := ValidateResult(result, vectorReceiptBinding(t, document), finalized); err != nil {
		t.Fatal(err)
	}
}

func TestBuyerRefusesAResultThatDoesNotBindItsPurchase(t *testing.T) {
	document := loadVectors(t)
	finalized := mustHex32(t, document.Receipt.ResponseHashHex)
	bindingCases := map[string]func(*ReceiptBinding){
		"quote commitment": func(b *ReceiptBinding) { b.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("01", 32) },
		"execution id":     func(b *ReceiptBinding) { b.ExecutionID[0] ^= 1 },
		"input digest":     func(b *ReceiptBinding) { b.InputDigest[0] ^= 1 },
		"source digest":    func(b *ReceiptBinding) { b.SourceDigest = "sha256:" + strings.Repeat("02", 32) },
		"price":            func(b *ReceiptBinding) { b.Price = new(big.Int).Add(b.Price, big.NewInt(1)) },
		"provider":         func(b *ReceiptBinding) { b.ProviderAgentID = "agent_" + strings.Repeat("03", 32) },
		"toolchain":        func(b *ReceiptBinding) { b.ToolchainDigest = "sha256:" + strings.Repeat("04", 32) },
		"sandbox":          func(b *ReceiptBinding) { b.SandboxDigest = "sha256:" + strings.Repeat("05", 32) },
	}
	for name, mutate := range bindingCases {
		binding := vectorReceiptBinding(t, document)
		mutate(&binding)
		if err := ValidateResult(vectorResult(t, document), binding, finalized); !errors.Is(err, ErrResultNotAccepted) {
			t.Errorf("binding %s: err=%v", name, err)
		}
	}
	resultCases := map[string]func(*Result, *[32]byte){
		"finalized response hash": func(_ *Result, f *[32]byte) { f[0] ^= 1 },
		"header response hash": func(r *Result, _ *[32]byte) {
			r.Header.ResponseHash = strings.Repeat("0", 63) + "1"
		},
		"artifact byte": func(r *Result, _ *[32]byte) { r.Artifact[len(r.Artifact)-1] ^= 1 },
		// Bytes after the end-of-archive blocks leave both members as they
		// were: only the artifact digest refuses them.
		"artifact trailer":   func(r *Result, _ *[32]byte) { r.Artifact = append(r.Artifact, make([]byte, 512)...) },
		"receipt byte":       func(r *Result, _ *[32]byte) { r.Receipt[len(r.Receipt)-1] ^= 1 },
		"receipt over bound": func(r *Result, _ *[32]byte) { r.Receipt = make([]byte, MaxReceiptBytes+1) },
	}
	for name, mutate := range resultCases {
		result, hash := vectorResult(t, document), finalized
		mutate(&result, &hash)
		if err := ValidateResult(result, vectorReceiptBinding(t, document), hash); !errors.Is(err, ErrResultNotAccepted) {
			t.Errorf("result %s: err=%v", name, err)
		}
	}
	if err := ValidateResult(vectorResult(t, document), vectorReceiptBinding(t, document), [32]byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("zero finalized hash err=%v", err)
	}
}

func tarOf(t *testing.T, members ...[2]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, member := range members {
		if err := writer.WriteHeader(&tar.Header{Name: member[0], Mode: 0o644, Size: int64(len(member[1])),
			Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(member[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

// Section 7.2 requires a single-root Receipt BOC: a valid Receipt followed
// by a second root is refused, not decoded from its first root.
func TestAReceiptBOCWithTwoRootsIsRefused(t *testing.T) {
	document := loadVectors(t)
	root, err := cell.FromBOC(mustBase64(t, document.Receipt.ReceiptBOCBase64))
	if err != nil {
		t.Fatal(err)
	}
	extra := cell.BeginCell().MustStoreUInt(7, 8).EndCell()
	boc := cell.ToBOCWithFlags([]*cell.Cell{root, extra}, false)
	roots, err := cell.FromBOCMultiRoot(boc)
	if err != nil || len(roots) != 2 || !bytes.Equal(roots[0].Hash(), root.Hash()) {
		t.Fatalf("the test BOC does not hold the Receipt and a second root: %d roots, err=%v", len(roots), err)
	}
	if _, _, err = DecodeReceipt(boc); !errors.Is(err, ErrResultNotAccepted) {
		t.Fatalf("DecodeReceipt err=%v", err)
	}
	result := vectorResult(t, document)
	result.Receipt = boc
	err = ValidateResult(result, vectorReceiptBinding(t, document), mustHex32(t, document.Receipt.ResponseHashHex))
	if !errors.Is(err, ErrResultNotAccepted) {
		t.Fatalf("ValidateResult err=%v", err)
	}
}

func TestArtifactMustHoldExactlyItsOutputAndReport(t *testing.T) {
	output, report := [2]string{"output.log", "ok\n"}, [2]string{"report.json", "{}\n"}
	if gotOutput, gotReport, err := ArtifactMembers(tarOf(t, report, output)); err != nil ||
		string(gotOutput) != "ok\n" || string(gotReport) != "{}\n" {
		t.Fatalf("err=%v", err)
	}
	bad := map[string][]byte{
		"missing report": tarOf(t, output),
		"missing output": tarOf(t, report),
		"extra member":   tarOf(t, output, report, [2]string{"extra", "x"}),
		"repeated":       tarOf(t, output, report, output),
		"empty":          nil,
		"not a tar":      bytes.Repeat([]byte{1}, 600),
	}
	for name, artifact := range bad {
		if _, _, err := ArtifactMembers(artifact); !errors.Is(err, ErrResultNotAccepted) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	if err := writer.WriteHeader(&tar.Header{Name: "output.log", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "report.json", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ArtifactMembers(buffer.Bytes()); !errors.Is(err, ErrResultNotAccepted) {
		t.Errorf("symlink member err=%v", err)
	}
}

func TestAttestorPolicyRequiresTheActualOutcome(t *testing.T) {
	document := loadVectors(t)
	boc := mustBase64(t, document.Receipt.ReceiptBOCBase64)
	receipt, hash, err := DecodeReceipt(boc)
	if err != nil {
		t.Fatal(err)
	}
	outcome := Outcome{ResultDigest: receipt.ResultDigest, ArtifactDigest: receipt.ArtifactDigest,
		ReportDigest: receipt.ReportDigest, CompletedAtUnix: receipt.CompletedAt}
	binding := vectorReceiptBinding(t, document)
	if got, err := CheckAttestable(boc, binding, outcome); err != nil || got != hash {
		t.Fatalf("attestable %x err=%v", got, err)
	}
	for name, mutate := range map[string]func(*Outcome){
		"exit code":    func(o *Outcome) { o.ExitCode = 1 },
		"result":       func(o *Outcome) { o.ResultDigest = "sha256:" + strings.Repeat("06", 32) },
		"artifact":     func(o *Outcome) { o.ArtifactDigest = "sha256:" + strings.Repeat("07", 32) },
		"report":       func(o *Outcome) { o.ReportDigest = "sha256:" + strings.Repeat("08", 32) },
		"completed at": func(o *Outcome) { o.CompletedAtUnix++ },
	} {
		changed := outcome
		mutate(&changed)
		if _, err := CheckAttestable(boc, binding, changed); !errors.Is(err, ErrResultNotAccepted) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if _, _, err := BuildReceipt(binding, Outcome{ResultDigest: outcome.ResultDigest, ArtifactDigest: outcome.ArtifactDigest,
		ReportDigest: outcome.ReportDigest, CompletedAtUnix: outcome.CompletedAtUnix, ExitCode: 2}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("failed execution built a Receipt: %v", err)
	}
	binding.Price = big.NewInt(0)
	if _, _, err := BuildReceipt(binding, outcome); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("zero price built a Receipt: %v", err)
	}
}

func TestResultsAcksAndResultRequestsMustComeFromTheCounterpartyForTheBinding(t *testing.T) {
	document := loadVectors(t)
	binding := Binding{ActorAccount: mustHex32(t, document.Binding.ActorAccountHex), RequestID: document.Binding.RequestID,
		RequestHash: mustHex32(t, document.Binding.RequestHashHex)}
	bodies := map[string][]byte{}
	for _, message := range document.Messages {
		bodies[message.Name] = document.messageBytes(t, message)
	}
	provider, buyer := document.Receipt.ProviderAgentID, document.Binding.BuyerAgentID
	responseHash := mustHex32(t, document.Receipt.ResponseHashHex)
	result := Message{SenderAgentID: provider, Kind: KindResult, Binding: binding, Body: bodies["result"]}
	if _, err := CheckResultFrom(result, provider, binding); err != nil {
		t.Fatal(err)
	}
	ack := Message{SenderAgentID: buyer, Kind: KindResultAck, Binding: binding, Body: bodies["ack_with_card"]}
	if got, err := CheckAck(ack, buyer, binding, responseHash); err != nil || len(got.BuyerKeyCard) == 0 {
		t.Fatalf("ack err=%v", err)
	}
	request := Message{SenderAgentID: buyer, Kind: KindResultRequest, Binding: binding, Body: bodies["result_request"]}
	if _, err := CheckResultRequest(request, buyer, binding); err != nil {
		t.Fatal(err)
	}
	other := "agent_" + strings.Repeat("69", 32)
	otherBinding := binding
	otherBinding.RequestID++
	otherHash := responseHash
	otherHash[0] ^= 1
	for name, check := range map[string]func() error{
		"result from another Agent": func() error { _, err := CheckResultFrom(result, other, binding); return err },
		"result for another request": func() error {
			_, err := CheckResultFrom(result, provider, otherBinding)
			return err
		},
		"result of another kind": func() error {
			changed := result
			changed.Kind = KindResultAck
			_, err := CheckResultFrom(changed, provider, binding)
			return err
		},
	} {
		if err := check(); !errors.Is(err, ErrResultNotAccepted) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	for name, check := range map[string]func() error{
		"ack from another Agent":      func() error { _, err := CheckAck(ack, other, binding, responseHash); return err },
		"ack for another request":     func() error { _, err := CheckAck(ack, buyer, otherBinding, responseHash); return err },
		"ack of another response":     func() error { _, err := CheckAck(ack, buyer, binding, otherHash); return err },
		"request from another Agent":  func() error { _, err := CheckResultRequest(request, other, binding); return err },
		"request for another request": func() error { _, err := CheckResultRequest(request, buyer, otherBinding); return err },
	} {
		err := check()
		if !errors.Is(err, ErrAckUnmatched) && !errors.Is(err, ErrResultRequestRefused) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

// --- strictness and bounds ----------------------------------------------------

// canonicalMessage frames a header that is canonical JSON with a body.
func canonicalMessage(t *testing.T, header any, body []byte) []byte {
	t.Helper()
	encoded, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(encoded)))
	return append(append(out, encoded...), body...)
}

// The shared package is stricter than the deployed decoder in one respect:
// Go's StdEncoding.Strict() skips CR and LF, so it accepts Base64 with line
// breaks inside; this package refuses them (section 5, Q10).
func TestBase64WithLineBreaksIsRefused(t *testing.T) {
	fixture := newTaskFixture(t)
	packageBytes, err := proto.Marshal(fixture.pkg)
	if err != nil {
		t.Fatal(err)
	}
	clean := base64.StdEncoding.EncodeToString(packageBytes)
	for _, brk := range []string{"\n", "\r\n", "\r"} {
		broken := clean[:8] + brk + clean[8:]
		if lenient, lenientErr := base64.StdEncoding.Strict().DecodeString(broken); lenientErr != nil ||
			!bytes.Equal(lenient, packageBytes) {
			t.Fatalf("Strict() no longer skips %q; this test no longer shows the difference", brk)
		}
		header := fixture.header
		header.Schema, header.PackageBase64 = TaskSchema, broken
		header.SourceDigest = sha256Text(sha256.Sum256(fixture.archive))
		if _, err = DecodeTask(canonicalMessage(t, header, fixture.archive)); !errors.Is(err, ErrMessageInvalid) {
			t.Errorf("package with %q: err=%v", brk, err)
		}
	}
	document := loadVectors(t)
	receiptText := document.Receipt.ReceiptBOCBase64
	header := ResultHeader{Schema: ResultSchema, ResponseHash: document.Receipt.ResponseHashHex,
		ReceiptBOCBase64: receiptText[:4] + "\n" + receiptText[4:]}
	if _, err = DecodeResult(canonicalMessage(t, header, []byte{1})); !errors.Is(err, ErrMessageInvalid) {
		t.Errorf("receipt with a line feed: err=%v", err)
	}
	header.ReceiptBOCBase64 = receiptText
	if _, err = DecodeResult(canonicalMessage(t, header, []byte{1})); err != nil {
		t.Errorf("clean receipt: %v", err)
	}
}

func TestKeyCardsMustBeCanonicalBase64WhenDecoded(t *testing.T) {
	overDecoded := strings.Repeat("QUJD", MaxKeyCardBase64/4) // 21848 characters, 16386 bytes
	cases := map[string]string{
		"not Base64":        "!!!!",
		"non-zero pad bits": "QR==",
		"missing padding":   "QQ",
		"line feed":         "QUJD\nQUJD",
		"decodes over 16384 bytes within the character bound": overDecoded,
	}
	for name, card := range cases {
		messages := map[string]error{}
		_, messages["ack"] = DecodeAck(canonicalMessage(t, AckHeader{Schema: AckSchema,
			ResponseHash: strings.Repeat("ab", 32), BuyerKeyCard: card}, nil))
		_, messages["result request"] = DecodeResultRequest(canonicalMessage(t,
			ResultRequestHeader{Schema: ResultRequestSchema, BuyerKeyCard: card}, nil))
		_, messages["result"] = DecodeResult(canonicalMessage(t, ResultHeader{Schema: ResultSchema,
			ResponseHash: strings.Repeat("ab", 32), ReceiptBOCBase64: "AQ==", ProviderKeyCard: card}, []byte{1}))
		fixture := newTaskFixture(t)
		header := fixture.header
		header.Schema, header.PackageBase64, header.BuyerKeyCard = TaskSchema, "AQ==", card
		header.SourceDigest = sha256Text(sha256.Sum256(fixture.archive))
		_, messages["task"] = DecodeTask(canonicalMessage(t, header, fixture.archive))
		for kind, err := range messages {
			if !errors.Is(err, ErrMessageInvalid) {
				t.Errorf("%s card in %s: err=%v", name, kind, err)
			}
		}
	}
	largest := bytes.Repeat([]byte{'k'}, MaxKeyCardBytes)
	raw, err := EncodeAck([32]byte{1}, largest)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := DecodeAck(raw); err != nil || !bytes.Equal(ack.BuyerKeyCard, largest) ||
		len(ack.Header.BuyerKeyCard) != MaxKeyCardBase64 {
		t.Fatalf("largest card err=%v", err)
	}
	if _, err = EncodeAck([32]byte{1}, append(largest, 'k')); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("oversized card err=%v", err)
	}
}

func TestEncodersRefuseWhatDecodersRefuse(t *testing.T) {
	fixture := newTaskFixture(t)
	packageBytes, err := proto.Marshal(fixture.pkg)
	if err != nil {
		t.Fatal(err)
	}
	task := func(mutate func(*Task)) error {
		value := Task{Header: fixture.header, Package: packageBytes, Archive: fixture.archive}
		mutate(&value)
		_, err := EncodeTask(value)
		return err
	}
	for name, mutate := range map[string]func(*Task){
		"empty archive":           func(v *Task) { v.Archive = nil },
		"archive over 1 MiB":      func(v *Task) { v.Archive = make([]byte, MaxInlineInputBytes+1) },
		"empty package":           func(v *Task) { v.Package = nil },
		"invalid UTF-8 version":   func(v *Task) { v.Header.CapabilityVersion = "1.0\xff" },
		"version over 128 bytes":  func(v *Task) { v.Header.CapabilityVersion = strings.Repeat("1", 129) },
		"zero call lt":            func(v *Task) { v.Header.CallLT = 0 },
		"other source digest":     func(v *Task) { v.Header.SourceDigest = "sha256:" + strings.Repeat("00", 32) },
		"other package text":      func(v *Task) { v.Header.PackageBase64 = "AQ==" },
		"card text without bytes": func(v *Task) { v.Header.BuyerKeyCard = "AQ==" },
		"wrong schema":            func(v *Task) { v.Header.Schema = ResultSchema },
	} {
		if err := task(mutate); !errors.Is(err, ErrMessageInvalid) {
			t.Errorf("task %s: err=%v", name, err)
		}
	}
	if err := task(func(v *Task) { v.Archive = make([]byte, MaxInlineInputBytes) }); err != nil {
		t.Errorf("a 1 MiB archive: %v", err)
	}
	if _, err = EncodeResult([32]byte{}, []byte{1}, []byte{1}, nil); !errors.Is(err, ErrMessageInvalid) {
		t.Errorf("zero response hash: %v", err)
	}
	if _, err = EncodeResult([32]byte{1}, nil, []byte{1}, nil); !errors.Is(err, ErrMessageInvalid) {
		t.Errorf("empty receipt: %v", err)
	}
	if _, err = EncodeResult([32]byte{1}, []byte{1}, make([]byte, MaxResultBytes+1), nil); !errors.Is(err, ErrMessageInvalid) {
		t.Errorf("oversized artifact: %v", err)
	}
	if _, err = EncodeAck([32]byte{}, nil); !errors.Is(err, ErrMessageInvalid) {
		t.Errorf("zero ack hash: %v", err)
	}
}

func TestTheLargestMessagesTakeNineteenAndTwentyFrames(t *testing.T) {
	fixture := newTaskFixture(t)
	packageBytes, err := proto.Marshal(fixture.pkg)
	if err != nil {
		t.Fatal(err)
	}
	cardBytes := bytes.Repeat([]byte{'c'}, MaxKeyCardBytes)
	// Pad the package so the task header is as large as the 64 KiB bound
	// allows; the archive is the full 1 MiB.
	archive := make([]byte, MaxInlineInputBytes)
	padded := append(bytes.Clone(packageBytes), make([]byte, 30000)...)
	raw, err := EncodeTask(Task{Header: fixture.header, Package: padded, Archive: archive, BuyerKeyCard: cardBytes})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 17*MaxChunkData || len(raw) > MaxTaskMessageBytes {
		t.Fatalf("task of %d bytes", len(raw))
	}
	frames, err := SplitMessage(KindTask, fixture.binding, raw)
	if err != nil || len(frames) > 19 {
		t.Fatalf("%d task frames err=%v", len(frames), err)
	}
	if _, err := DecodeTask(raw); err != nil {
		t.Fatal(err)
	}
	artifact := make([]byte, MaxResultBytes)
	result, err := EncodeResult([32]byte{1}, make([]byte, 3000), artifact, cardBytes)
	if err != nil {
		t.Fatal(err)
	}
	frames, err = SplitMessage(KindResult, fixture.binding, result)
	if err != nil || len(frames) != 19 {
		t.Fatalf("%d result frames err=%v", len(frames), err)
	}
	if count := (MaxResultMessageBytes + MaxChunkData - 1) / MaxChunkData; count != 20 {
		t.Fatalf("the largest result takes %d frames", count)
	}
	if count := (MaxTaskMessageBytes + MaxChunkData - 1) / MaxChunkData; count != 19 {
		t.Fatalf("the largest task takes %d frames", count)
	}
	if _, err = SplitMessage(KindTask, fixture.binding, make([]byte, MaxTaskMessageBytes+1)); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("oversized task split err=%v", err)
	}
	if _, err = SplitMessage(KindResultAck, fixture.binding, nil); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("empty split err=%v", err)
	}
	if _, err = SplitMessage(KindResultAck, Binding{RequestHash: [32]byte{1}}, []byte{1}); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("zero actor split err=%v", err)
	}
	if _, err = SplitMessage(Kind(9), fixture.binding, []byte{1}); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("unknown kind split err=%v", err)
	}
}

// The kind's bound is checked by itself: a single-frame acknowledgement
// whose data and total length agree but exceed the ack bound passes the
// chunking rule and must still be refused.
func TestFrameTotalOverTheKindBoundIsRefusedEvenWhenChunkingAgrees(t *testing.T) {
	data := make([]byte, MaxAckMessageBytes+1)
	frame := Frame{Kind: KindResultAck, Binding: Binding{ActorAccount: [32]byte{1}, RequestHash: [32]byte{1}},
		MessageDigest: sha256.Sum256(data), TotalLength: uint32(len(data)), Count: 1, Data: data}
	if _, err := EncodeFrame(frame); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("encode err=%v", err)
	}
	frame.Kind = KindResult
	raw, err := EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	raw[6] = byte(KindResultAck)
	if _, err = DecodeFrame(raw); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("decode err=%v", err)
	}
	if _, err = SplitMessage(KindResultAck, frame.Binding, data); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("split err=%v", err)
	}
}

func TestATaskArchiveOverOneMiBIsRefusedWhenDecoded(t *testing.T) {
	fixture := newTaskFixture(t)
	archive := make([]byte, MaxInlineInputBytes+1)
	header := fixture.header
	header.Schema, header.PackageBase64 = TaskSchema, "AQ=="
	header.SourceDigest = sha256Text(sha256.Sum256(archive))
	raw := canonicalMessage(t, header, archive)
	if len(raw) > MaxTaskMessageBytes {
		t.Fatalf("the message itself is over the task bound: %d", len(raw))
	}
	if _, err := DecodeTask(raw); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestAResultArtifactOverItsBoundIsRefusedWhenDecoded(t *testing.T) {
	header := ResultHeader{Schema: ResultSchema, ResponseHash: strings.Repeat("ab", 32), ReceiptBOCBase64: "AQ=="}
	if _, err := DecodeResult(canonicalMessage(t, header, make([]byte, MaxResultBytes))); err != nil {
		t.Fatalf("largest artifact: %v", err)
	}
	raw := canonicalMessage(t, header, make([]byte, MaxResultBytes+1))
	if len(raw) > MaxResultMessageBytes {
		t.Fatalf("the message itself is over the result bound: %d", len(raw))
	}
	if _, err := DecodeResult(raw); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestJoinRefusesARepeatedIndexEvenInAnOtherwiseCompleteSet(t *testing.T) {
	message := make([]byte, MaxChunkData+10)
	frames, err := SplitMessage(KindTask, Binding{ActorAccount: [32]byte{1}, RequestHash: [32]byte{1}}, message)
	if err != nil || len(frames) != 2 {
		t.Fatalf("%d frames err=%v", len(frames), err)
	}
	if _, err = JoinFrames([]Frame{frames[0], frames[0], frames[1]}); !errors.Is(err, ErrJoinInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestAResultWithAnEmptyReceiptIsRefused(t *testing.T) {
	header := ResultHeader{Schema: ResultSchema, ResponseHash: strings.Repeat("ab", 32), ReceiptBOCBase64: ""}
	if _, err := DecodeResult(canonicalMessage(t, header, []byte{1})); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("err=%v", err)
	}
}

// A canonical header one byte over the 64 KiB bound inside a message the
// task bound admits is refused by the header bound alone.
func TestAHeaderOverItsBoundIsRefusedWhenEverythingElseIsValid(t *testing.T) {
	fixture := newTaskFixture(t)
	header := fixture.header
	header.Schema = TaskSchema
	header.SourceDigest = sha256Text(sha256.Sum256(fixture.archive))
	header.PackageBase64 = "AQ=="
	base, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	// Each three package bytes add four Base64 characters.
	missing := MaxMessageHeaderBytes + 1 - len(base) + len("AQ==")
	packageBytes := make([]byte, (missing+3)/4*3)
	for len(base64.StdEncoding.EncodeToString(packageBytes))-len("AQ==")+len(base) <= MaxMessageHeaderBytes {
		packageBytes = append(packageBytes, 0)
	}
	header.PackageBase64 = base64.StdEncoding.EncodeToString(packageBytes)
	raw := canonicalMessage(t, header, fixture.archive)
	headerLength := binary.BigEndian.Uint32(raw[:4])
	if headerLength <= MaxMessageHeaderBytes || headerLength > MaxMessageHeaderBytes+4 || len(raw) > MaxTaskMessageBytes {
		t.Fatalf("header of %d bytes, message of %d", headerLength, len(raw))
	}
	if _, err = DecodeTask(raw); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("err=%v", err)
	}
}

func TestMessageHeaderBoundsAreEnforced(t *testing.T) {
	raw := binary.BigEndian.AppendUint32(nil, MaxMessageHeaderBytes+1)
	raw = append(raw, make([]byte, MaxMessageHeaderBytes+1)...)
	if _, err := DecodeTask(raw); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("oversized header err=%v", err)
	}
	ack := canonicalMessage(t, AckHeader{Schema: AckSchema, ResponseHash: strings.Repeat("ab", 32)}, nil)
	if _, err := DecodeAck(append(ack, make([]byte, MaxAckMessageBytes)...)); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("oversized ack err=%v", err)
	}
	if _, err := DecodeAck(ack[:3]); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("short ack err=%v", err)
	}
	duplicate := []byte(`{"schema":"tos.openfox.rail-result-request.v1","schema":"tos.openfox.rail-result-request.v1"}`)
	message := binary.BigEndian.AppendUint32(nil, uint32(len(duplicate)))
	if _, err := DecodeResultRequest(append(message, duplicate...)); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("duplicate field err=%v", err)
	}
	folded := []byte(`{"Schema":"tos.openfox.rail-result-request.v1"}`)
	message = binary.BigEndian.AppendUint32(nil, uint32(len(folded)))
	if _, err := DecodeResultRequest(append(message, folded...)); !errors.Is(err, ErrMessageInvalid) {
		t.Fatalf("case-folded field err=%v", err)
	}
}

func TestAssemblyRefusesAConflictingFrame(t *testing.T) {
	fixture := newTaskFixture(t)
	message := fixture.message(t)
	frames, err := SplitMessage(KindTask, fixture.binding, message.Body)
	if err != nil || len(frames) != 1 {
		t.Fatalf("%d frames err=%v", len(frames), err)
	}
	assembly, err := NewAssembly(testBuyer, frames[0])
	if err != nil {
		t.Fatal(err)
	}
	conflicting := frames[0]
	conflicting.Data = bytes.Clone(conflicting.Data)
	conflicting.Data[0] ^= 1
	if _, err = assembly.Add(conflicting); !errors.Is(err, ErrFrameConflict) {
		t.Fatalf("conflict err=%v", err)
	}
	other := frames[0]
	other.Binding.RequestID++
	if _, err = assembly.Add(other); !errors.Is(err, ErrJoinInvalid) {
		t.Fatalf("other message err=%v", err)
	}
	corrupt, err := NewAssembly(testBuyer, conflicting)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = corrupt.Message(); !errors.Is(err, ErrJoinInvalid) {
		t.Fatalf("digest mismatch err=%v", err)
	}
	if _, err = NewAssembly("not-an-agent", frames[0]); !errors.Is(err, ErrPacketInvalid) {
		t.Fatalf("bad sender err=%v", err)
	}
	if _, err = (&Assembly{}).Message(); !errors.Is(err, ErrJoinInvalid) {
		t.Fatalf("empty assembly err=%v", err)
	}
}

func TestFrameRefusalsAndPayloadPurpose(t *testing.T) {
	if err := CheckRailPayload([]byte(`{"chat":"frame"}`)); !errors.Is(err, ErrNotARailFrame) {
		t.Fatalf("err=%v", err)
	}
	if _, err := EncodeFrame(Frame{Kind: KindTask, Binding: Binding{RequestHash: [32]byte{1}}, MessageDigest: [32]byte{1},
		TotalLength: 1, Count: 1, Data: []byte{1}}); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("zero actor encoded: %v", err)
	}
	frame := Frame{Kind: KindResultAck, Binding: Binding{ActorAccount: [32]byte{1}, RequestHash: [32]byte{1}},
		MessageDigest: [32]byte{1}, TotalLength: 1, Count: 1, Data: []byte{1}}
	raw, err := EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeFrame(raw); err != nil || decoded.Binding.RequestID != 0 {
		t.Fatalf("request id 0 frame: %v", err)
	}
	if _, err = JoinFrames(nil); !errors.Is(err, ErrJoinInvalid) {
		t.Fatalf("empty join err=%v", err)
	}
	if _, err = ChunkLength(0, 0, 1); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("zero total err=%v", err)
	}
	if length, err := ChunkLength(MaxChunkData+1, 1, 2); err != nil || length != 1 {
		t.Fatalf("last chunk %d err=%v", length, err)
	}
}

func TestRefusalLabelsMatchByLabelOnly(t *testing.T) {
	err := refuse(RefusalFrameInvalid, "some reason")
	if !errors.Is(err, ErrFrameInvalid) || errors.Is(err, ErrJoinInvalid) {
		t.Fatal("label matching")
	}
	if label, ok := RefusalOf(err); !ok || label != RefusalFrameInvalid {
		t.Fatal("RefusalOf")
	}
	cause := errors.New("cause")
	wrapped := refuseWith(RefusalTaskNotAdmitted, "outer", cause)
	if !errors.Is(wrapped, cause) || !errors.Is(wrapped, ErrTaskNotAdmitted) ||
		!strings.Contains(wrapped.Error(), "task-not-admitted: outer: cause") {
		t.Fatalf("wrapped %v", wrapped)
	}
	if _, ok := RefusalOf(cause); ok {
		t.Fatal("foreign error has a label")
	}
	if errors.Is(ErrFrameInvalid, err) {
		t.Fatal("a reason-less sentinel matched a target with a reason")
	}
	if _, err := ExecutionID("agent_X", [32]byte{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad agent err=%v", err)
	}
	if _, err := RequestHash([32]byte{}, [32]byte{1}, [32]byte{1}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero quote err=%v", err)
	}
	if Kind(9).String() != "kind-9" || KindResultRequest.String() != "result-request" {
		t.Fatal("kind names")
	}
}
