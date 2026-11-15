package quotesource

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/tosnetwork/tos-service-gateway/internal/nativegateway"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

// The transport policy of the operator Quote profile is validated by the
// protocol transport-binding rules, and every proposal the public gateway
// returns is re-validated against the same rules. These tests pin what the
// gateway admits at both boundaries: profile load (NewProvider, which the
// gateway runs at startup) and the public RequestQuoteProposal call.

// Security modes are spelled as numbers so the tests read like the operator
// profile, which carries the mode as a JSON number.
const (
	modeLoopbackHTTP = 0
	modeHTTPS        = 1
	modeAgentPacket  = 2
	agentPacketBound = 1 << 20
)

var providerAgentID = "agent_" + strings.Repeat("44", 32)

type transportFixture struct {
	network  *nativev1.NetworkDomain
	request  *nativev1.RequestQuoteProposalRequest
	profile  Profile
	manifest []byte
	sessions *actorSessions
	registry string
}

// newTransportFixture loads a profile whose transport is the given policy
// and prepares a finalized actor checkpoint that quotes it. It fails the test
// only on fixture errors; the transport itself is checked by NewProvider.
func newTransportFixture(t *testing.T, mode int, maxRequestBytes uint32, baseURL string) transportFixture {
	t.Helper()
	files := newProfileFiles(t, actorCodeHash)
	document := files.document()
	document["transport"] = map[string]any{"security_mode": mode, "max_request_bytes": maxRequestBytes, "base_url": baseURL}
	profile, manifest, err := LoadProfile(files.write(t, document, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	network := testNetwork()
	capabilityID := "cap_" + strings.Repeat("33", 32)
	registryCodeHash := "tvm-cell-sha256:" + strings.Repeat("55", 32)
	state := &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("66", 32),
		Reference: &nativev1.ChainReference{FinalizedCheckpoint: 10, ContractCodeHash: registryCodeHash,
			TransactionHash: "sha256:" + strings.Repeat("77", 32)},
		State: &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capabilityID,
			OwnerAgentId: profile.ProviderAgentID, Versions: []*nativev1.CapabilityVersionV1{{Version: "1.0.0", ManifestDigest: files.digest}}}}}
	attestor, err := mldsa44.ParseKeyIDText(attestorKey)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{Network: network,
		CapabilityID: capabilityID, ProviderAgentID: profile.ProviderAgentID, CapabilityVersion: "1.0.0", ManifestDigest: files.digest})
	if err != nil {
		t.Fatal(err)
	}
	sessions := &actorSessions{state: state, policy: nativecore.ServiceActorPolicyV1{PolicyVersion: 2,
		PricePerCall: big.NewInt(300_000_000), StorageFee: big.NewInt(200_000_000), CleanupBounty: big.NewInt(100_000_000),
		ResponseSLA: 3600, RefundClaimWindow: 3600, OpenAccess: true, MetadataHash: metadata,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme, HasAttestor: true, AttestorKeyID: attestor}}
	request := &nativev1.RequestQuoteProposalRequest{Context: &nativev1.RequestContext{RequestId: "buyer-request",
		CallerId: "buyer", DeadlineUnixMillis: time.Now().Add(time.Minute).UnixMilli()},
		CapabilityId: capabilityID, CapabilityVersion: "1.0.0", BuyerAddress: "0:" + strings.Repeat("cc", 32)}
	return transportFixture{network: network, request: request, profile: profile, manifest: manifest,
		sessions: sessions, registry: registryCodeHash}
}

func (f transportFixture) provider() (nativegateway.QuoteSource, error) {
	provider, err := NewProvider(f.profile, f.manifest, f.sessions, f.network, f.registry, time.Second)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

func (f transportFixture) gateway(source nativegateway.QuoteSource) *nativegateway.Server {
	return &nativegateway.Server{Authorizer: nativegateway.NewTokenAuthorizer("read-secret", "relay-secret"),
		QuoteSource: source, Network: f.network}
}

func (f transportFixture) call(server *nativegateway.Server) (*nativev1.QuoteProposalPackageV1, error) {
	request := connect.NewRequest(proto.Clone(f.request).(*nativev1.RequestQuoteProposalRequest))
	request.Header().Set("Authorization", "Bearer read-secret")
	response, err := server.RequestQuoteProposal(context.Background(), request)
	if err != nil {
		return nil, err
	}
	return response.Msg.Package, nil
}

// transportOf returns the binding a returned package carries, after the same
// package validation a buyer runs.
func (f transportFixture) transportOf(t *testing.T, value *nativev1.QuoteProposalPackageV1) nativecore.TransportBindingV1 {
	t.Helper()
	validated, err := quoteexchange.Validate(f.network, f.request, value, time.Now())
	if err != nil {
		t.Fatalf("returned package failed validation: %v", err)
	}
	return validated.TransportBinding
}

// TestGatewayAdmitsPathPrefixedAndAgentPacketTransports pins the bindings
// the gateway now admits end to end: an operator profile carrying one loads,
// and the public RequestQuoteProposal returns the proposal with exactly that
// binding.
func TestGatewayAdmitsPathPrefixedAndAgentPacketTransports(t *testing.T) {
	cases := map[string]struct {
		mode            int
		maxRequestBytes uint32
		baseURL         string
	}{
		"https with a path prefix":         {modeHTTPS, 1 << 20, "https://provider.example/tos/quote-v1"},
		"https with a port and one prefix": {modeHTTPS, 16 << 20, "https://provider.example:8443/rpc"},
		"loopback http with a path prefix": {modeLoopbackHTTP, 1 << 20, "http://127.0.0.1:8080/provider"},
		"agent packet to the provider":     {modeAgentPacket, agentPacketBound, "agent-packet:" + providerAgentID},
		"agent packet with a small bound":  {modeAgentPacket, 1, "agent-packet:" + providerAgentID},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newTransportFixture(t, test.mode, test.maxRequestBytes, test.baseURL)
			source, err := fixture.provider()
			if err != nil {
				t.Fatalf("profile transport was refused at load: %v", err)
			}
			value, err := fixture.call(fixture.gateway(source))
			if err != nil {
				t.Fatalf("gateway refused the proposal: %v", err)
			}
			binding := fixture.transportOf(t, value)
			if int(binding.SecurityMode) != test.mode || binding.MaxRequestBytes != test.maxRequestBytes || binding.BaseURL != test.baseURL {
				t.Fatalf("proposal carries binding %+v", binding)
			}
			if value.Proposal.ProviderAgentId != providerAgentID {
				t.Fatalf("proposal provider=%q", value.Proposal.ProviderAgentId)
			}
		})
	}
}

// TestProfileLoadRefusesMalformedTransports pins the transport policies the
// gateway still refuses when it builds the Quote source at startup,
// including the new Agent Packet bounds.
func TestProfileLoadRefusesMalformedTransports(t *testing.T) {
	cases := map[string]struct {
		mode            int
		maxRequestBytes uint32
		baseURL         string
	}{
		"agent packet over 1 MiB":         {modeAgentPacket, agentPacketBound + 1, "agent-packet:" + providerAgentID},
		"agent packet zero bound":         {modeAgentPacket, 0, "agent-packet:" + providerAgentID},
		"agent packet upper-case hex":     {modeAgentPacket, 1024, "agent-packet:agent_" + strings.Repeat("4A", 32)},
		"agent packet short Agent ID":     {modeAgentPacket, 1024, "agent-packet:agent_" + strings.Repeat("44", 31)},
		"agent packet naming a cap":       {modeAgentPacket, 1024, "agent-packet:cap_" + strings.Repeat("44", 32)},
		"agent packet over https":         {modeAgentPacket, 1024, "https://provider.example"},
		"https mode with an agent packet": {modeHTTPS, 1024, "agent-packet:" + providerAgentID},
		"unknown mode with https":         {3, 1024, "https://provider.example"},
		"unknown mode with agent packet":  {3, 1024, "agent-packet:" + providerAgentID},
		"https trailing slash":            {modeHTTPS, 1024, "https://provider.example/rpc/"},
		"https empty segment":             {modeHTTPS, 1024, "https://provider.example//rpc"},
		"https dot-dot segment":           {modeHTTPS, 1024, "https://provider.example/a/../rpc"},
		"https dot segment":               {modeHTTPS, 1024, "https://provider.example/./rpc"},
		"https percent-encoded path":      {modeHTTPS, 1024, "https://provider.example/r%20pc"},
		"https query":                     {modeHTTPS, 1024, "https://provider.example/rpc?x=1"},
		"https fragment":                  {modeHTTPS, 1024, "https://provider.example/rpc#part"},
		"https user info":                 {modeHTTPS, 1024, "https://user@provider.example/rpc"},
		"https upper-case host":           {modeHTTPS, 1024, "https://Provider.example/rpc"},
		"https over 16 MiB":               {modeHTTPS, 16<<20 + 1, "https://provider.example/rpc"},
		"plaintext to a public host":      {modeLoopbackHTTP, 1024, "http://provider.example/rpc"},
		"https scheme in loopback mode":   {modeLoopbackHTTP, 1024, "https://127.0.0.1/rpc"},
		"http scheme in https mode":       {modeHTTPS, 1024, "http://provider.example/rpc"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newTransportFixture(t, test.mode, test.maxRequestBytes, test.baseURL)
			// The fixture differs from the admitted cases only in the
			// transport, so this is the transport policy refusal.
			if _, err := fixture.provider(); err == nil || err.Error() != "invalid Quote provider policy preimage" {
				t.Fatalf("malformed transport at profile load error=%v", err)
			}
		})
	}
}

// TestAgentPacketToAnotherAgentIsRefused pins the provider-recipient check:
// Agent Packets go to the Capability owner Agent and to nobody else.
func TestAgentPacketToAnotherAgentIsRefused(t *testing.T) {
	otherAgent := "agent_" + strings.Repeat("55", 32)

	// A profile whose Agent Packet binding names another Agent loads (the
	// binding is well formed), but no proposal is ever produced: the gateway
	// reports the Quote source as unavailable to every buyer.
	fixture := newTransportFixture(t, modeAgentPacket, agentPacketBound, "agent-packet:"+otherAgent)
	source, err := fixture.provider()
	if err != nil {
		t.Fatalf("a well-formed Agent Packet profile was refused at load: %v", err)
	}
	if _, err := fixture.call(fixture.gateway(source)); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("mismatched Agent Packet profile error=%v", err)
	}

	// A Quote source that hands the gateway a proposal re-pointed at another
	// Agent is refused by the gateway's own package validation.
	fixture = newTransportFixture(t, modeAgentPacket, agentPacketBound, "agent-packet:"+providerAgentID)
	honest, err := fixture.provider()
	if err != nil {
		t.Fatal(err)
	}
	forged := &repointingSource{t: t, inner: honest, binding: nativecore.TransportBindingV1{
		SecurityMode: modeAgentPacket, MaxRequestBytes: agentPacketBound, BaseURL: "agent-packet:" + otherAgent}}
	if _, err := fixture.call(fixture.gateway(forged)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("re-pointed Agent Packet proposal error=%v", err)
	}
	if forged.calls != 1 {
		t.Fatalf("quote source calls=%d", forged.calls)
	}

	// The same re-pointing to the provider itself is accepted, so the refusal
	// above is the recipient check and not the re-pointing.
	same := &repointingSource{t: t, inner: honest, binding: nativecore.TransportBindingV1{
		SecurityMode: modeAgentPacket, MaxRequestBytes: 4096, BaseURL: "agent-packet:" + providerAgentID}}
	value, err := fixture.call(fixture.gateway(same))
	if err != nil {
		t.Fatalf("re-pointed proposal to the provider was refused: %v", err)
	}
	if binding := fixture.transportOf(t, value); binding.MaxRequestBytes != 4096 {
		t.Fatalf("proposal carries binding %+v", binding)
	}
}

// repointingSource returns the inner source's proposal with its transport
// binding replaced by binding, keeping the package's preimages consistent.
type repointingSource struct {
	t       *testing.T
	inner   nativegateway.QuoteSource
	binding nativecore.TransportBindingV1
	calls   int
}

func (r *repointingSource) RequestQuoteProposal(ctx context.Context, request *nativev1.RequestQuoteProposalRequest) (*nativev1.QuoteProposalPackageV1, error) {
	r.calls++
	value, err := r.inner.RequestQuoteProposal(ctx, request)
	if err != nil {
		return nil, err
	}
	root, digest, err := nativecore.BuildTransportBindingCellV1(r.binding)
	if err != nil {
		r.t.Errorf("build re-pointed binding: %v", err)
		return nil, err
	}
	value = proto.Clone(value).(*nativev1.QuoteProposalPackageV1)
	value.TransportBindingBoc = root.ToBOC()
	value.Proposal.TransportBindingDigest = digest
	return value, nil
}
