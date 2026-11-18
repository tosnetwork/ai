package buyeragent

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

const (
	fxCapability = "cap_3333333333333333333333333333333333333333333333333333333333333333"
	fxProvider   = "agent_4444444444444444444444444444444444444444444444444444444444444444"
	fxBuyerAgent = "agent_5555555555555555555555555555555555555555555555555555555555555555"
)

var (
	fxBuyer = "0:" + strings.Repeat("21", 32)
	fxKey   = bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	fxKeyID = func() [32]byte { id, _ := mldsa44.KeyID(fxKey); return id }()
	fxNow   = time.Unix(2_000_000_000, 0)
)

// The admitted policy's terms the fake buyer journals, as buyersdk
// Prepare takes them from the admission.
const (
	fxResponseSLA   = 3_600
	fxRefundWindow  = 7_200
	fxCleanupBounty = "100000000"
)

// fakeBuyer stands in for buyersdk.ServiceActorBuyer over a real journal:
// it validates the Quote the way Prepare does, journals the call, and
// records every send.
type fakeBuyer struct {
	t        *testing.T
	network  *nativev1.NetworkDomain
	journal  *buyersdk.ServiceActorJournal
	limits   buyersdk.ServiceActorLimits
	now      func() time.Time
	mu       sync.Mutex
	sends    []string
	queryID  uint64
	callErr  error
	callNext buyersdk.CallPhase
	// panics makes Prepare panic, standing in for any defect a request
	// reaches.
	panics atomic.Bool
	// status is the finalized status Resolve reports for admitted calls;
	// lifecycle records every lifecycle send and lifecycleErr fails them.
	status       serviceactor.Status
	resolveErr   error
	lifecycle    []string
	lifecycleErr error
	// lifecycleUnsettled makes every send report an earlier send of the
	// operation that may still execute, as buyersdk does.
	lifecycleUnsettled bool
}

func (f *fakeBuyer) Resolve(_ context.Context, requestHash string) (*buyersdk.RequestReport, error) {
	record, err := f.journal.Read(requestHash)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	if record.Phase == buyersdk.PhaseSubmitted {
		id := uint64(0)
		if _, err := f.journal.Transition(requestHash, []buyersdk.CallPhase{buyersdk.PhaseSubmitted}, func(r *buyersdk.CallRecord) error {
			r.Phase, r.RequestID = buyersdk.PhaseAdmitted, &id
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return &buyersdk.RequestReport{Phase: buyersdk.PhaseAdmitted, Status: f.status}, nil
}

// SendLifecycle journals the send as buyersdk does and records it.
func (f *fakeBuyer) SendLifecycle(_ context.Context, requestHash, operation string) (buyersdk.CallRecord, error) {
	f.mu.Lock()
	if f.lifecycleUnsettled {
		f.mu.Unlock()
		record, err := f.journal.Read(requestHash)
		return record, errors.Join(err, buyersdk.ErrLifecycleUnsettled)
	}
	f.lifecycle = append(f.lifecycle, requestHash+" "+operation)
	sendErr := f.lifecycleErr
	f.mu.Unlock()
	phase := buyersdk.PhaseSubmitted
	switch {
	case errors.Is(sendErr, buyersdk.ErrCallNotStarted):
		phase = buyersdk.PhasePrepared
	case sendErr != nil:
		phase = buyersdk.PhaseAmbiguous
	}
	record, err := f.journal.Transition(requestHash, []buyersdk.CallPhase{buyersdk.PhaseAdmitted}, func(r *buyersdk.CallRecord) error {
		r.Lifecycle = append(r.Lifecycle, buyersdk.LifecycleSend{Operation: operation, QueryID: uint64(len(r.Lifecycle) + 1),
			Phase: phase, SentUnix: f.now().Unix()})
		return nil
	})
	if err != nil {
		return record, err
	}
	return record, sendErr
}

func (f *fakeBuyer) sentLifecycle() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lifecycle...)
}

func (f *fakeBuyer) Prepare(_ context.Context, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1,
	executionID, inputDigest [32]byte) (buyersdk.CallRecord, error) {
	if f.panics.Load() {
		panic("a defect reached by a client request")
	}
	validated, err := quoteexchange.Validate(f.network, request, value, f.now())
	if err != nil {
		return buyersdk.CallRecord{}, err
	}
	quoteHash, commitment, err := railwork.QuoteCommitment(f.network, validated.Proposal)
	if err != nil {
		return buyersdk.CallRecord{}, err
	}
	requestHash, err := railwork.RequestHash(quoteHash, executionID, inputDigest)
	if err != nil {
		return buyersdk.CallRecord{}, err
	}
	f.mu.Lock()
	f.queryID++
	query := f.queryID
	f.mu.Unlock()
	now := f.now()
	record := buyersdk.CallRecord{Schema: "tos.service.service-actor-call.v1", RequestHash: hex.EncodeToString(requestHash[:]),
		QueryID: query, NetworkID: f.network.NetworkId, BuyerWallet: request.BuyerAddress, Actor: "0:" + strings.Repeat("77", 32),
		CapabilityID: request.CapabilityId, CapabilityVersion: request.CapabilityVersion, QuoteCommitment: commitment,
		ExecutionID: hex.EncodeToString(executionID[:]), InputDigest: hex.EncodeToString(inputDigest[:]),
		TermsHash: validated.Proposal.TermsHash, PriceNanoTOS: validated.Proposal.PriceNanotos,
		StorageFeeNanoTOS: validated.Proposal.StorageFeeNanotos, AttestorKeyID: validated.Proposal.AttestorKeyId,
		PaymentNanoTOS: "700000000", ExpiresAtUnix: validated.Proposal.ExpiresAtUnixSeconds,
		Phase: buyersdk.PhasePrepared, CreatedUnix: now.Unix(), UpdatedUnix: now.Unix(),
		ResponseSLASeconds: fxResponseSLA, RefundClaimWindowSeconds: fxRefundWindow, CleanupBountyNanoTOS: fxCleanupBounty}
	if err := f.journal.Create(record, f.limits, now); err != nil {
		return buyersdk.CallRecord{}, err
	}
	return record, nil
}

func (f *fakeBuyer) Call(_ context.Context, requestHash string) (buyersdk.CallRecord, error) {
	record, err := f.journal.Read(requestHash)
	if err != nil {
		return record, err
	}
	if record.Phase != buyersdk.PhasePrepared {
		return record, errors.New("never sent again")
	}
	if uint64(f.now().Unix()) >= record.ExpiresAtUnix {
		return record, buyersdk.ErrQuoteExpired
	}
	if _, err := f.journal.BeginSend(requestHash, f.limits, f.now()); err != nil {
		return record, err
	}
	f.mu.Lock()
	f.sends = append(f.sends, requestHash)
	next, callErr := f.callNext, f.callErr
	f.mu.Unlock()
	if next == "" {
		next = buyersdk.PhaseSubmitted
	}
	updated, err := f.journal.Transition(requestHash, []buyersdk.CallPhase{buyersdk.PhaseSending}, func(r *buyersdk.CallRecord) error {
		r.Phase = next
		return nil
	})
	if err != nil {
		return record, err
	}
	return updated, callErr
}

func (f *fakeBuyer) Withdraw(requestHash string) (buyersdk.CallRecord, error) {
	return f.journal.Withdraw(requestHash, f.now())
}

func (f *fakeBuyer) Journal() *buyersdk.ServiceActorJournal { return f.journal }

func (f *fakeBuyer) Limits() buyersdk.ServiceActorLimits { return f.limits }

func (f *fakeBuyer) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sends...)
}

type fakeCarriage struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (c *fakeCarriage) CheckCarriage(context.Context, buyersdk.CallRecord, []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.err
}

func (c *fakeCarriage) set(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
}

type fixture struct {
	agent    *Agent
	buyer    *fakeBuyer
	carriage *fakeCarriage
	request  *nativev1.RequestQuoteProposalRequest
	pkg      *nativev1.QuoteProposalPackageV1
	quoteID  string
	state    string
	clock    *clock
	random   *counterRandom
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type counterRandom struct {
	mu    sync.Mutex
	value byte
}

func (r *counterRandom) Read(value []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.value++
	for index := range value {
		value[index] = r.value
	}
	return nil
}

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testLimits() buyersdk.ServiceActorLimits {
	return buyersdk.ServiceActorLimits{Window: 24 * time.Hour, MaxCalls: 10, MaxPerCallNanoTOS: big.NewInt(1_000_000_000),
		MaxWindowNanoTOS: big.NewInt(10_000_000_000), MaxPrepared: 4}
}

func quotePackage(t *testing.T, now time.Time) (*nativev1.RequestQuoteProposalRequest, *nativev1.QuoteProposalPackageV1) {
	t.Helper()
	network := servicefixture.Network()
	settlement := servicefixture.Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32),
		ActorCodeHash: bytes.Repeat([]byte{0x88}, 32), AttestorKey: mldsa44.KeyIDText(fxKeyID)}
	manifest := servicefixture.Manifest("1.0.0", settlement)
	manifestCBOR, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: fxCapability, ProviderAgentID: fxProvider, CapabilityVersion: "1.0.0", ManifestDigest: digest})
	if err != nil {
		t.Fatal(err)
	}
	terms := servicefixture.Terms(fxKeyID, metadata)
	termsHash, err := nativecore.ServiceActorTermsHash(terms)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := nativecore.AgentPacketTransportBinding(fxProvider, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-1", CapabilityId: fxCapability, CapabilityVersion: "1.0.0",
		ProviderAgentId: fxProvider, ManifestDigest: digest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(30 * time.Minute).Unix()),
		Actor:                &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
		ActorCodeHash:        "tvm-cell-sha256:" + strings.Repeat("88", 32), PolicyVersion: terms.PolicyVersion,
		TermsHash: hex.EncodeToString(termsHash[:]), PriceNanotos: "300000000", StorageFeeNanotos: "200000000",
		AttestorKeyId: mldsa44.KeyIDText(fxKeyID)}
	request := &nativev1.RequestQuoteProposalRequest{CapabilityId: fxCapability, CapabilityVersion: "1.0.0", BuyerAddress: fxBuyer}
	return request, &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR,
		TransportBindingBoc: transport.ToBOC()}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	state := privateDir(t)
	journalDir := filepath.Join(state, "journal")
	if err := os.Mkdir(journalDir, 0o700); err != nil {
		t.Fatal(err)
	}
	clk := &clock{now: fxNow}
	journal, err := buyersdk.OpenServiceActorJournal(journalDir, fxNow)
	if err != nil {
		t.Fatal(err)
	}
	network := servicefixture.Network()
	buyer := &fakeBuyer{t: t, network: network, journal: journal, limits: testLimits(), now: clk.Now}
	carriage := &fakeCarriage{}
	random := &counterRandom{}
	agent, err := Open(Config{StateDir: state, BuyerAgentID: fxBuyerAgent, Network: network, Buyer: buyer,
		Carriage: carriage, Now: clk.Now, Random: random.Read})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(agent.Close)
	request, value := quotePackage(t, fxNow)
	quoteID, err := agent.StoreQuote(request, value)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{agent: agent, buyer: buyer, carriage: carriage, request: request, pkg: value, quoteID: quoteID,
		state: state, clock: clk, random: random}
}

type entry struct {
	name     string
	body     string
	typeflag byte
}

// buildTar packs a canonical archive with the packer the MCP server uses.
func buildTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	files := make([]SourceFile, 0, len(entries))
	for _, e := range entries {
		files = append(files, SourceFile{Name: e.name, Directory: e.typeflag == tar.TypeDir, Content: []byte(e.body)})
	}
	archive, err := PackSourceArchive(files)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

// rawTar writes entries in the given order with canonical headers but no
// packer checks, for archives the packer would refuse to write.
func rawTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, e := range entries {
		header, err := canonicalHeader(e.name, e.typeflag == tar.TypeDir, int64(len(e.body)))
		if err != nil {
			t.Fatal(err)
		}
		out.Write(header)
		out.WriteString(e.body)
		out.Write(make([]byte, paddedLength(len(e.body))-len(e.body)))
	}
	out.Write(make([]byte, 2*blockSize))
	return out.Bytes()
}

func sourceTar(t *testing.T) []byte {
	return buildTar(t, entry{name: "src/", typeflag: tar.TypeDir}, entry{name: "src/main.go", body: "package main\n"})
}

func (f *fixture) prepare(t *testing.T, key string, archive []byte) PurchaseView {
	t.Helper()
	view, err := f.agent.Prepare(context.Background(), PrepareParams{QuoteID: f.quoteID, IdempotencyKey: key,
		ArchiveBase64: base64.StdEncoding.EncodeToString(archive)})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	return view
}

// requested prepares a purchase and asks for the decision without waiting.
func (f *fixture) requested(t *testing.T, key string) PurchaseView {
	t.Helper()
	view := f.prepare(t, key, sourceTar(t))
	if _, err := f.agent.RequestPayment(context.Background(), RequestPaymentParams{RequestHash: view.RequestHash}); err != nil {
		t.Fatal(err)
	}
	return view
}

func codeOf(t *testing.T, err error) string {
	t.Helper()
	var known *Error
	if !errors.As(err, &known) {
		t.Fatalf("not an agent error: %v", err)
	}
	return known.Code
}
