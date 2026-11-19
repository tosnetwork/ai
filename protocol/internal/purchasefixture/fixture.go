// Package purchasefixture builds one complete synthetic Service Actor
// purchase for tests: a Capability and its owner Agent, an actor, a Quote
// package, the call, a Receipt and its artifact, and a fake finalized
// session that serves them in any of the request's outcomes. The values are
// shape-valid and consistent with each other; none was produced by the
// contract or a real chain.
package purchasefixture

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// Fixed identities of the fixture.
const (
	CapabilityID    = "cap_3333333333333333333333333333333333333333333333333333333333333333"
	ProviderAgentID = "agent_4444444444444444444444444444444444444444444444444444444444444444"
	BuyerAgentID    = "agent_5555555555555555555555555555555555555555555555555555555555555555"
	Version         = "1.0.0"
	QueryID         = uint64(4242)
)

var (
	// Actor, Owner and Buyer are raw workchain 0 addresses.
	Actor         = "0:" + strings.Repeat("77", 32)
	Owner         = "0:" + strings.Repeat("11", 32)
	Buyer         = "0:" + strings.Repeat("21", 32)
	ActorCodeHash = "tvm-cell-sha256:" + strings.Repeat("88", 32)
	// Now is the chain time of every fixture checkpoint.
	Now = time.Unix(2_000_000_000, 0)
)

// Outcomes a session can serve.
const (
	Pending   = "pending"
	Responded = "responded"
	Refunded  = "refunded"
	Swept     = "swept"
	Refused   = "refused"
)

// Purchase is one purchase and everything derived from it.
type Purchase struct {
	Network         *nativev1.NetworkDomain
	Policy          nativecore.ServiceActorPolicyV1
	Capability      *nativev1.NativeStateV1
	Agent           *nativev1.NativeStateV1
	Manifest        nativecore.SoftwareWorkManifestV1
	ManifestCBOR    []byte
	ManifestDigest  string
	Package         *nativev1.QuoteProposalPackageV1
	PackageBytes    []byte
	QuoteCommitment string
	AcceptedQuote   string
	TermsHash       string
	ExecutionID     [32]byte
	InputDigest     [32]byte
	SourceDigest    string
	RequestHash     [32]byte
	Receipt         []byte
	ResponseHash    [32]byte
	Artifact        []byte
	Output, Report  []byte
}

// New builds the purchase.
func New() (*Purchase, error) {
	network := servicefixture.Network()
	key := bytes.Repeat([]byte{0x5a}, mldsa44.PublicKeySize)
	keyID, err := mldsa44.KeyID(key)
	if err != nil {
		return nil, err
	}
	settlement := servicefixture.Settlement{ActorAccount: bytes.Repeat([]byte{0x77}, 32),
		ActorCodeHash: bytes.Repeat([]byte{0x88}, 32), AttestorKey: mldsa44.KeyIDText(keyID)}
	manifest := servicefixture.Manifest(Version, settlement)
	manifestCBOR, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		return nil, err
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: CapabilityID, ProviderAgentID: ProviderAgentID, CapabilityVersion: Version, ManifestDigest: digest})
	if err != nil {
		return nil, err
	}
	terms := servicefixture.Terms(keyID, metadata)
	policy := nativecore.ServiceActorPolicyV1{PolicyVersion: terms.PolicyVersion, PricePerCall: terms.PricePerCall,
		StorageFee: terms.StorageFee, CleanupBounty: terms.CleanupBounty, ResponseSLA: terms.ResponseSLA,
		RefundClaimWindow: terms.RefundClaimWindow, OpenAccess: true, MetadataHash: metadata,
		ProofSchemeHash: terms.ProofSchemeHash, HasAttestor: true, AttestorKeyID: keyID, AttestorKey: key}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(nativecore.TransportBindingV1{
		SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"})
	if err != nil {
		return nil, err
	}
	termsHash, err := nativecore.ServiceActorTermsHash(terms)
	if err != nil {
		return nil, err
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-1", CapabilityId: CapabilityID, CapabilityVersion: Version,
		ProviderAgentId: ProviderAgentID, ManifestDigest: digest, TransportBindingDigest: transportDigest,
		ExpiresAtUnixSeconds: uint64(Now.Add(-time.Hour).Unix()),
		Actor:                &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)}, ActorCodeHash: ActorCodeHash,
		PolicyVersion: terms.PolicyVersion, TermsHash: hex.EncodeToString(termsHash[:]), PriceNanotos: terms.PricePerCall.String(),
		StorageFeeNanotos: terms.StorageFee.String(), AttestorKeyId: mldsa44.KeyIDText(keyID)}
	value := &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: transport.ToBOC()}
	packageBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		return nil, err
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal)
	if err != nil {
		return nil, err
	}
	var quoteHash [32]byte
	copy(quoteHash[:], quote.Hash())
	source := sha256.Sum256([]byte("buyer source archive"))
	inputDigest := railwork.InputDigest(source)
	executionID, err := railwork.ExecutionID(BuyerAgentID, [32]byte{0x0e})
	if err != nil {
		return nil, err
	}
	requestHash, err := railwork.RequestHash(quoteHash, executionID, inputDigest)
	if err != nil {
		return nil, err
	}
	purchase := &Purchase{Network: network, Policy: policy, Manifest: manifest, ManifestCBOR: manifestCBOR, ManifestDigest: digest,
		Package: value, PackageBytes: packageBytes, QuoteCommitment: commitment,
		AcceptedQuote: base64.StdEncoding.EncodeToString(quote.ToBOCWithOptions(cell.BOCSerializeOptions{})),
		TermsHash:     hex.EncodeToString(termsHash[:]), ExecutionID: executionID, InputDigest: inputDigest,
		SourceDigest: "sha256:" + hex.EncodeToString(source[:]), RequestHash: requestHash,
		Output: []byte("ok  example.com/work 0.01s\n"), Report: []byte(`{"ok":true}`)}
	purchase.Capability = &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Capability{
		Capability: &nativev1.CapabilityStateV1{CapabilityId: CapabilityID, OwnerAgentId: ProviderAgentID,
			Versions: []*nativev1.CapabilityVersionV1{{Version: Version, ManifestDigest: digest}}}}}
	purchase.Agent = &nativev1.NativeStateV1{Network: network, State: &nativev1.NativeStateV1_Agent{
		Agent: &nativev1.AgentStateV1{AgentId: ProviderAgentID}}}
	if purchase.Artifact, err = ArtifactTar(purchase.Output, purchase.Report); err != nil {
		return nil, err
	}
	receipt, responseHash, err := railwork.BuildReceipt(railwork.ReceiptBinding{QuoteCommitment: commitment, ExecutionID: executionID,
		InputDigest: inputDigest, SourceDigest: purchase.SourceDigest, Price: new(big.Int).Set(terms.PricePerCall),
		ProviderAgentID: ProviderAgentID, ToolchainDigest: manifest.ToolchainDigest, SandboxDigest: digest},
		railwork.Outcome{ResultDigest: digestText(purchase.Output), ArtifactDigest: digestText(purchase.Artifact),
			ReportDigest: digestText(purchase.Report), CompletedAtUnix: uint64(Now.Unix()) - 950, ExitCode: 0})
	if err != nil {
		return nil, err
	}
	purchase.Receipt, purchase.ResponseHash = receipt.ToBOC(), responseHash
	return purchase, nil
}

// Bundle is the evidence bundle the buyer of the purchase exports, with a
// call journaled and, for a responded purchase, the accepted result.
func (p *Purchase) Bundle(responded bool) *purchaseevidence.Bundle {
	id := uint64(0)
	bundle := &purchaseevidence.Bundle{Schema: purchaseevidence.BundleSchema, Tool: purchaseevidence.Tool{Name: "fixture"},
		ExportedUnix: Now.Unix(), Network: purchaseevidence.NetworkTuple{NetworkID: p.Network.NetworkId,
			GenesisRootHash: p.Network.GenesisRootHash, GenesisFileHash: p.Network.GenesisFileHash},
		Endpoints: []string{"http://127.0.0.1:1", "http://127.0.0.1:2", "http://127.0.0.1:3"}, Quorum: 2,
		RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("66", 32), ActorCodeHash: ActorCodeHash, Actor: Actor,
		BuyerWallet: Buyer, BuyerAgentID: BuyerAgentID,
		Offer: purchaseevidence.Offer{CapabilityID: CapabilityID, CapabilityVersion: Version, ManifestDigest: p.ManifestDigest,
			ToolchainDigest: p.Manifest.ToolchainDigest, ProviderAgentID: ProviderAgentID, RetentionSeconds: p.Manifest.RetentionSeconds},
		Quote: purchaseevidence.Quote{PackageBase64: base64.StdEncoding.EncodeToString(p.PackageBytes), RequestBuyerAddress: Buyer,
			AcceptedQuoteBOC: p.AcceptedQuote, QuoteCommitment: p.QuoteCommitment, TermsHash: p.TermsHash,
			PolicyVersion: p.Policy.PolicyVersion, PriceNanoTOS: p.Policy.PricePerCall.String(),
			StorageFeeNanoTOS: p.Policy.StorageFee.String(), PaymentNanoTOS: "500000000",
			CleanupBountyNanoTOS: p.Policy.CleanupBounty.String(), ResponseSLASeconds: p.Policy.ResponseSLA,
			RefundClaimWindowSeconds: p.Policy.RefundClaimWindow, ExpiresAtUnixSeconds: p.Package.Proposal.ExpiresAtUnixSeconds,
			AttestorKeyID: p.Package.Proposal.AttestorKeyId},
		Request: purchaseevidence.Request{RequestHash: hex.EncodeToString(p.RequestHash[:]),
			ExecutionID: hex.EncodeToString(p.ExecutionID[:]), InputDigest: hex.EncodeToString(p.InputDigest[:]),
			SourceDigest: p.SourceDigest, SourceBytes: 1024},
		Journal: purchaseevidence.Journal{Phase: "admitted", QueryID: "4242", CreatedUnix: Now.Unix() - 2000,
			SentUnix: Now.Unix() - 1900, RequestID: &id},
		Budget: purchaseevidence.Budget{WindowSeconds: 86400, MaxCalls: 10, MaxPerCallNanoTOS: "1000000000",
			MaxWindowNanoTOS: "10000000000", MaxUnconfirmed: 4, MaxLifecycleSends: 28}}
	if responded {
		bundle.Result = purchaseevidence.Result{Accepted: true, AcceptedUnix: Now.Unix() - 900,
			ResponseHash: hex.EncodeToString(p.ResponseHash[:]),
			Receipt:      &purchaseevidence.FileDigest{Name: purchaseevidence.ReceiptFile, SHA256: digestText(p.Receipt), Bytes: len(p.Receipt)},
			Artifact:     &purchaseevidence.FileDigest{Name: purchaseevidence.ArtifactFile, SHA256: digestText(p.Artifact), Bytes: len(p.Artifact)},
			Members: []purchaseevidence.FileDigest{{Name: "output.log", SHA256: digestText(p.Output), Bytes: len(p.Output)},
				{Name: "report.json", SHA256: digestText(p.Report), Bytes: len(p.Report)}},
			ResultDigest: digestText(p.Output), ArtifactDigest: digestText(p.Artifact), ReportDigest: digestText(p.Report)}
	}
	return bundle
}

func digestText(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ArtifactTar is the software-work artifact holding output and report.
func ArtifactTar(output, report []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, member := range []struct {
		name string
		body []byte
	}{{"output.log", output}, {"report.json", report}} {
		if err := writer.WriteHeader(&tar.Header{Name: member.name, Mode: 0o644, Size: int64(len(member.body)),
			Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(member.body); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Session is a fake finalized checkpoint holding the actor and the
// Registry objects. Tests edit its fields to model a lying or broken chain.
type Session struct {
	Seqno      uint64
	Capability *nativev1.NativeStateV1
	Agent      *nativev1.NativeStateV1
	Data       *nativecore.ServiceActorDataV1
	CodeHash   string
	// Transactions is the actor's complete history, newest first.
	Transactions  []toschain.ActorTransaction
	HistoryResult toschain.HistoryResult
	// GetterLie makes get_request disagree with the decoded state.
	GetterLie bool
	ReadErr   error
	// Transitions are the proven Registry transitions by kind.
	Transitions map[nativecore.RegistryTransitionKind]toschain.RegistryTransitionTx
}

// Call is the purchase's call transaction at callNow.
func (p *Purchase) Call(callNow uint32) (toschain.ActorTransaction, error) {
	return servicefixture.CallTransaction(Buyer, 0, p.RequestHash, QueryID, callNow, 10, nativecore.TermsOfPolicy(p.Policy))
}

// Session serves the purchase in one outcome. Every outcome but refused
// holds request 0.
func (p *Purchase) Session(outcome string) (*Session, error) {
	session := &Session{Seqno: 1000, Capability: proto.Clone(p.Capability).(*nativev1.NativeStateV1),
		Agent: proto.Clone(p.Agent).(*nativev1.NativeStateV1), CodeHash: ActorCodeHash, HistoryResult: toschain.HistoryComplete}
	now := uint32(Now.Unix())
	callNow := map[string]uint32{Pending: now - 100, Responded: now - 1000, Refunded: now - 5000, Swept: now - 9000, Refused: now - 100}[outcome]
	if callNow == 0 {
		return nil, errors.New("unknown outcome")
	}
	call, err := p.Call(callNow)
	if err != nil {
		return nil, err
	}
	snapshot, err := call.Snapshot.Decode()
	if err != nil {
		return nil, err
	}
	price := p.Policy.PricePerCall.String()
	var history []toschain.ActorTransaction
	var pending map[uint64]nativecore.ServiceActorRequestSnapshotV1
	next := uint64(1)
	switch outcome {
	case Pending:
		pending = map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: snapshot}
		history = []toschain.ActorTransaction{call}
	case Responded:
		respond := servicefixture.Transition(toschain.ActorTxRespond, 0, callNow+50, 11, Owner)
		respond.ResponseHash = hex.EncodeToString(p.ResponseHash[:])
		history = []toschain.ActorTransaction{respond, call}
	case Refunded:
		expire := servicefixture.Transition(toschain.ActorTxExpire, 0, callNow+3700, 11, Owner)
		claim := servicefixture.Transition(toschain.ActorTxClaim, 0, callNow+3800, 12, Buyer)
		claim.Destination = Buyer
		claim.Payouts = []toschain.ActorPayout{{Destination: Buyer, AmountNano: price, EmptyBody: true}}
		history = []toschain.ActorTransaction{claim, expire, call}
	case Swept:
		sweep := servicefixture.Transition(toschain.ActorTxSweep, 0, callNow+8000, 11, Owner)
		sweep.Payouts = []toschain.ActorPayout{{Destination: Buyer, AmountNano: price, EmptyBody: true}}
		history = []toschain.ActorTransaction{sweep, call}
	case Refused:
		call.Kind, call.Snapshot, call.ExitCode = toschain.ActorTxFailed, nil, 1928
		history, next = []toschain.ActorTransaction{call}, 0
	}
	data, err := servicefixture.ActorData(Owner, p.Policy, next, pending, nil)
	if err != nil {
		return nil, err
	}
	session.Data, session.Transactions = data, history
	return session, nil
}

func (s *Session) head() toschain.ActorTxID {
	if len(s.Transactions) == 0 {
		return toschain.ActorTxID{}
	}
	return toschain.ActorTxID{LT: s.Transactions[0].LT, Hash: s.Transactions[0].Hash}
}

// Checkpoint implements the session.
func (s *Session) Checkpoint() uint64 { return s.Seqno }

// ChainTime implements the session.
func (s *Session) ChainTime() time.Time { return Now }

// BlockHashes implements the session.
func (s *Session) BlockHashes() (string, string) {
	return "sha256:" + strings.Repeat("ab", 32), "sha256:" + strings.Repeat("cd", 32)
}

// ResolveRegistry implements the session.
func (s *Session) ResolveRegistry(_ context.Context, id string) (*nativev1.NativeStateV1, bool, error) {
	if s.ReadErr != nil {
		return nil, false, s.ReadErr
	}
	var state *nativev1.NativeStateV1
	switch id {
	case CapabilityID:
		state = s.Capability
	case ProviderAgentID:
		state = s.Agent
	default:
		return nil, false, nil
	}
	state = proto.Clone(state).(*nativev1.NativeStateV1)
	state.Reference = &nativev1.ChainReference{FinalizedCheckpoint: s.Seqno}
	return state, true, nil
}

// ReadActor implements the session.
func (s *Session) ReadActor(_ context.Context, address string) (*toschain.ActorAccount, bool, error) {
	if s.ReadErr != nil {
		return nil, false, s.ReadErr
	}
	if address != Actor {
		return nil, false, nil
	}
	return &toschain.ActorAccount{Address: address, CodeHash: s.CodeHash, BalanceNano: 1_000_000_000, Data: s.Data,
		LastTransaction: s.head()}, true, nil
}

// History implements the session.
func (s *Session) History(_ context.Context, _ string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error) {
	if anchor != nil {
		return nil, errors.New("the fixture serves only complete histories")
	}
	return &toschain.ActorHistory{Result: s.HistoryResult, Head: s.head(),
		Transactions: append([]toschain.ActorTransaction(nil), s.Transactions...)}, nil
}

// GetRequest implements the session.
func (s *Session) GetRequest(_ context.Context, _ string, id uint64) (*nativecore.ServiceActorRequestViewV1, error) {
	entry, ok := s.Data.Pending[id]
	if !ok {
		return nil, nil
	}
	view := &nativecore.ServiceActorRequestViewV1{Caller: entry.Caller, Price: entry.Price, StorageFee: entry.StorageFee,
		CleanupBounty: entry.CleanupBounty, ResponseDeadline: entry.ResponseDeadline, RefundClaimDeadline: entry.RefundClaimDeadline,
		PolicyVersion: entry.PolicyVersion, RequestHash: entry.RequestHash, TermsHash: entry.TermsHash,
		HasAttestor: entry.HasAttestor, AttestorKeyID: entry.AttestorKeyID}
	if s.GetterLie {
		view.ResponseDeadline++
	}
	return view, nil
}

// GetRefund implements the session.
func (s *Session) GetRefund(_ context.Context, _ string, id uint64) (*nativecore.ServiceActorRefundV1, error) {
	entry, ok := s.Data.Refunds[id]
	if !ok {
		return nil, nil
	}
	return &entry, nil
}

// RegistryTransition implements the session.
func (s *Session) RegistryTransition(_ context.Context, _ string, kind nativecore.RegistryTransitionKind,
	_ string) (*toschain.RegistryTransitionTx, error) {
	transition, found := s.Transitions[kind]
	if !found {
		return nil, toschain.ErrRegistryTransitionUnproven
	}
	return &transition, nil
}
