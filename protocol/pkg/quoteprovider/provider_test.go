package quoteprovider

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

// actors is a fake finalized checkpoint holding the Capability and actor.
type actors struct {
	state      *nativev1.NativeStateV1
	policy     nativecore.ServiceActorPolicyV1
	err        error
	actor      string
	sessions   int
	stateDrift bool
	beginErr   error
	resolveErr error
	absent     bool
}

func (a *actors) BeginSession(context.Context) (serviceactor.Session, error) {
	a.sessions++
	if a.beginErr != nil {
		return nil, a.beginErr
	}
	return session{a}, nil
}

type session struct{ a *actors }

func (s session) Checkpoint() uint64   { return 10 }
func (s session) ChainTime() time.Time { return time.Unix(2_000_000_000, 0) }
func (s session) ResolveRegistry(context.Context, string) (*nativev1.NativeStateV1, bool, error) {
	if s.a.resolveErr != nil {
		return nil, false, s.a.resolveErr
	}
	if s.a.absent {
		return nil, false, nil
	}
	state := proto.Clone(s.a.state).(*nativev1.NativeStateV1)
	if s.a.stateDrift {
		state.Reference.FinalizedCheckpoint = 9
	}
	return state, true, nil
}

func (s session) ReadActor(_ context.Context, actor string) (*toschain.ActorAccount, bool, error) {
	s.a.actor = actor
	if s.a.err != nil {
		return nil, false, s.a.err
	}
	return &toschain.ActorAccount{Address: actor, Data: &nativecore.ServiceActorDataV1{Active: true, Policy: s.a.policy}}, true, nil
}

func setup(t *testing.T) (*Provider, *actors, *nativev1.RequestQuoteProposalRequest, *nativev1.NetworkDomain, time.Time) {
	t.Helper()
	settlement := servicefixture.DefaultSettlement()
	manifest := servicefixture.Manifest("1.0.0", settlement)
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	network := servicefixture.Network()
	capabilityID, agentID := "cap_"+strings.Repeat("33", 32), "agent_"+strings.Repeat("44", 32)
	codeHash := "tvm-cell-sha256:" + strings.Repeat("55", 32)
	state := &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("66", 32),
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: codeHash,
			TransactionHash: "sha256:" + strings.Repeat("77", 32)},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID,
			OwnerAgentId: agentID, Versions: []*nativev1.CapabilityVersionV1{{Version: manifest.Version, ManifestDigest: manifestDigest}}}}}
	keyID, _ := mldsa44.ParseKeyIDText(settlement.AttestorKey)
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: capabilityID, ProviderAgentID: agentID, CapabilityVersion: manifest.Version, ManifestDigest: manifestDigest})
	if err != nil {
		t.Fatal(err)
	}
	source := &actors{state: state, policy: nativecore.ServiceActorPolicyV1{PolicyVersion: 2, PricePerCall: big.NewInt(300_000_000),
		StorageFee: big.NewInt(200_000_000), CleanupBounty: big.NewInt(100_000_000), ResponseSLA: 3600, RefundClaimWindow: 3600,
		OpenAccess: true, MetadataHash: metadata, ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme,
		HasAttestor: true, AttestorKeyID: keyID}}
	now := time.Unix(2_000_000_000, 0)
	provider, err := New(Config{Sessions: source, Network: network,
		RegistryCodeHash: codeHash, ProviderAgentID: agentID,
		ManifestCBOR: manifestCBOR, Transport: nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS,
			MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"},
		CallerID: "provider", Now: func() time.Time { return now }, Random: func(value []byte) error {
			for i := range value {
				value[i] = byte(i + 1)
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	request := &nativev1.RequestQuoteProposalRequest{Context: &nativev1.RequestContext{RequestId: "buyer-request"},
		CapabilityId: capabilityID, CapabilityVersion: manifest.Version, BuyerAddress: "0:" + strings.Repeat("cc", 32)}
	return provider, source, request, network, now
}

func TestProviderQuotesTheFinalizedActorPolicy(t *testing.T) {
	provider, source, request, network, now := setup(t)
	value, err := provider.RequestQuoteProposal(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := quoteexchange.Validate(network, request, value, now)
	if err != nil || value.Proposal.ProposalId != "provider-0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("validated=%+v proposal=%+v err=%v", validated, value.Proposal, err)
	}
	terms, _ := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(source.policy))
	if value.Proposal.TermsHash != hex.EncodeToString(terms[:]) || value.Proposal.PolicyVersion != 2 ||
		value.Proposal.PriceNanotos != "300000000" || value.Proposal.StorageFeeNanotos != "200000000" ||
		source.actor != "0:"+strings.Repeat("77", 32) || source.sessions != 1 {
		t.Fatalf("proposal does not carry the actor policy: %+v", value.Proposal)
	}
}

func TestProviderRefusesMisboundActorsAndWrongCapabilities(t *testing.T) {
	for name, edit := range map[string]func(*Provider, *actors, *nativev1.RequestQuoteProposalRequest){
		"wrong version": func(_ *Provider, _ *actors, r *nativev1.RequestQuoteProposalRequest) { r.CapabilityVersion = "other" },
		"wrong owner": func(p *Provider, _ *actors, _ *nativev1.RequestQuoteProposalRequest) {
			p.config.ProviderAgentID = "agent_" + strings.Repeat("dd", 32)
		},
		"no attestor": func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) { a.policy.HasAttestor = false },
		"rotated key": func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) { a.policy.AttestorKeyID[0] ^= 1 },
		"metadata":    func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) { a.policy.MetadataHash[0] ^= 1 },
		"proof scheme": func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) {
			a.policy.ProofSchemeHash[0] ^= 1
		},
		"zero price": func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) {
			a.policy.PricePerCall = big.NewInt(0)
		},
		"actor missing":      func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) { a.err = errors.New("absent") },
		"another checkpoint": func(_ *Provider, a *actors, _ *nativev1.RequestQuoteProposalRequest) { a.stateDrift = true },
	} {
		provider, source, request, _, _ := setup(t)
		edit(provider, source, request)
		if _, err := provider.RequestQuoteProposal(context.Background(), request); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A read failure keeps its fixed class and carries its cause, so a buyer
// building its own Quote learns why; PublicError leaves the class alone, for
// a caller that answers remote parties.
func TestReadFailuresCarryTheirCauseAndThePublicFormDropsIt(t *testing.T) {
	cause := errors.New("NATIVE_BAD_SEQUENCE: execute JSON-RPC request: Post \"https://rpc.example/secret-token\"")
	for name, test := range map[string]struct {
		edit  func(*actors)
		class string
		cause error
	}{
		"session":  {func(a *actors) { a.beginErr = cause }, "finalized state is unavailable", cause},
		"registry": {func(a *actors) { a.resolveErr = cause }, "Quote Capability is not available from finalized state", cause},
		"absent":   {func(a *actors) { a.absent = true }, "Quote Capability is not available from finalized state", nil},
		"actor":    {func(a *actors) { a.err = cause }, "Quote Service Actor is not active in finalized state", cause},
	} {
		provider, source, request, _, _ := setup(t)
		test.edit(source)
		_, err := provider.RequestQuoteProposal(context.Background(), request)
		var quoteErr *Error
		if !errors.As(err, &quoteErr) || quoteErr.Class() != test.class || !strings.HasPrefix(err.Error(), test.class) {
			t.Fatalf("%s: %v", name, err)
		}
		if test.cause != nil && (!errors.Is(err, test.cause) || !strings.Contains(err.Error(), test.cause.Error())) {
			t.Fatalf("%s: the cause is not carried: %v", name, err)
		}
		if name == "absent" && !strings.Contains(err.Error(), "not in the finalized registry") {
			t.Fatalf("absent: %v", err)
		}
		public := PublicError(err)
		if public.Error() != test.class || errors.Is(public, cause) {
			t.Fatalf("%s: the public form is %q", name, public)
		}
	}
	if other := errors.New("other"); PublicError(other) != other {
		t.Fatal("PublicError changed an error that is not a read failure")
	}
}

// Over Agent Packets a provider never serves a manifest whose largest Quote
// package no rail task can carry (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1
// section 5.1); the same manifest over HTTPS is served.
func TestProviderRefusesAManifestWhoseQuotesNoRailTaskCanCarry(t *testing.T) {
	agentID := "agent_" + strings.Repeat("44", 32)
	agentPackets, err := nativecore.AgentPacketTransportBinding(agentID, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	https := nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS, MaxRequestBytes: 1 << 20,
		BaseURL: "https://provider.example"}
	open := func(edit func(*nativecore.SoftwareWorkManifestV1), transport nativecore.TransportBindingV1) error {
		manifest := servicefixture.Manifest("1.0.0", servicefixture.DefaultSettlement())
		edit(&manifest)
		manifestCBOR, _, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(Config{Sessions: &actors{}, Network: servicefixture.Network(),
			RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), ProviderAgentID: agentID,
			ManifestCBOR: manifestCBOR, Transport: transport, CallerID: "provider"})
		return err
	}
	large := func(m *nativecore.SoftwareWorkManifestV1) {
		m.Description = strings.Repeat("d", 2048)
		m.Invocation.Arguments = nil
		for index := 0; index < 64; index++ {
			m.Invocation.Arguments = append(m.Invocation.Arguments, fmt.Sprintf("%02d%s", index, strings.Repeat("a", 510)))
		}
	}
	if err = open(func(*nativecore.SoftwareWorkManifestV1) {}, agentPackets); err != nil {
		t.Fatalf("a carriable manifest was refused: %v", err)
	}
	if err = open(large, agentPackets); !errors.Is(err, railwork.ErrQuoteNotCarriable) {
		t.Fatalf("an uncarriable manifest was served over Agent Packets: %v", err)
	}
	if err = open(large, https); err != nil {
		t.Fatalf("the same manifest over HTTPS was refused: %v", err)
	}
}
