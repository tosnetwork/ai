package nativegateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"google.golang.org/protobuf/proto"
)

type fixedQuote struct {
	value *nativev1.QuoteProposalPackageV1
}

func (q fixedQuote) RequestQuoteProposal(context.Context, *nativev1.RequestQuoteProposalRequest) (*nativev1.QuoteProposalPackageV1, error) {
	return proto.Clone(q.value).(*nativev1.QuoteProposalPackageV1), nil
}

// carriageQuote is a valid Agent Packet Quote whose manifest has a
// 2,048-byte description and extra 512-byte arguments.
func carriageQuote(t *testing.T, network *nativev1.NetworkDomain, extraArguments int) (*nativev1.QuoteProposalPackageV1,
	*nativev1.RequestQuoteProposalRequest) {
	t.Helper()
	provider := "agent_" + strings.Repeat("55", 32)
	attestor := "mldsa44:" + strings.Repeat("99", 32)
	arguments := []string{"test", "./..."}
	for index := 0; index < extraArguments; index++ {
		arguments = append(arguments, fmt.Sprintf("%02d%s", index, strings.Repeat("a", 510)))
	}
	manifest := nativecore.SoftwareWorkManifestV1{
		Protocol: nativecore.SoftwareWorkManifestProtocolV1, Version: "1.0.0", Name: "Deterministic Go test",
		Description: strings.Repeat("d", 2048), Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive"},
		InputSchemaDigest:   "sha256:" + strings.Repeat("11", 32), OutputSchemaDigest: "sha256:" + strings.Repeat("22", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("33", 32),
		Invocation: nativecore.SoftwareWorkInvocationV1{Executable: "/usr/local/bin/go", Arguments: arguments,
			WorkingDirectory: "/workspace/source"},
		NetworkPolicy: "none", Limits: nativecore.SoftwareWorkLimitsV1{CPUMillis: 120000, MemoryBytes: 1 << 30,
			ScratchBytes: 2 << 30, OutputBytes: 16 << 20, WallClockMillis: 180000},
		ArtifactMediaTypes: []string{"application/vnd.tos.service.software-artifact.v1+tar"},
		ReportMediaTypes:   []string{"application/vnd.tos.service.test-report.v1+json"},
		SuccessCondition:   "exit-code-zero-and-valid-reports", RefundConditions: []string{nativecore.NoAttestedResponseRefund},
		EndpointCommitment:           "sha256:" + strings.Repeat("44", 32),
		ExecutionSignerAuthorization: nativecore.SettlementAttestorAuthorization(attestor), RetentionSeconds: 86400,
		SupportedAssets: []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.NativeTOSAsset}},
		Settlement: nativecore.SoftwareWorkSettlementV1{Rail: nativecore.ServiceActorRail, ActorWorkchain: 0,
			ActorAccountID: bytes.Repeat([]byte{0x77}, 32), ActorCodeHash: bytes.Repeat([]byte{0x88}, 32), AttestorKey: attestor},
	}
	manifestCBOR, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := nativecore.AgentPacketTransportBinding(provider, nativecore.MaxAgentPacketTransportRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	transport, transportDigest, err := nativecore.BuildTransportBindingCellV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	proposal := &nativev1.QuoteProposalV1{ProposalId: "provider-proposal-1", CapabilityId: "cap_" + strings.Repeat("33", 32),
		CapabilityVersion: "1.0.0", ProviderAgentId: provider, ManifestDigest: manifestDigest,
		TransportBindingDigest: transportDigest, ExpiresAtUnixSeconds: uint64(time.Now().Add(30 * time.Minute).Unix()),
		Actor:         &nativev1.TOSAccountAddressV1{AccountId: bytes.Repeat([]byte{0x77}, 32)},
		ActorCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x88}, 32)), PolicyVersion: 2,
		TermsHash: strings.Repeat("ab", 32), PriceNanotos: "300000000", StorageFeeNanotos: "200000000",
		AttestorKeyId: attestor}
	request := &nativev1.RequestQuoteProposalRequest{
		Context: &nativev1.RequestContext{RequestId: "request", CallerId: "buyer",
			DeadlineUnixMillis: time.Now().Add(time.Minute).UnixMilli()},
		CapabilityId: proposal.CapabilityId, CapabilityVersion: "1.0.0", BuyerAddress: "0:" + strings.Repeat("44", 32)}
	return &nativev1.QuoteProposalPackageV1{Proposal: proposal, CanonicalManifestCbor: manifestCBOR,
		TransportBindingBoc: transport.ToBOC()}, request
}

// The gateway never proposes an Agent Packet Quote whose package no rail
// task can carry (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 5.1).
func TestTheGatewayNeverProposesAnUncarriableQuote(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	for name, extra := range map[string]int{"carriable": 0, "uncarriable": 62} {
		value, msg := carriageQuote(t, network, extra)
		server := &Server{Authorizer: NewTokenAuthorizer("read-secret", "relay-secret"), QuoteSource: fixedQuote{value},
			Network: network}
		request := connect.NewRequest(msg)
		request.Header().Set("Authorization", "Bearer read-secret")
		response, err := server.RequestQuoteProposal(context.Background(), request)
		carriable := proto.Size(value) <= railwork.MaxPackageBytes
		switch {
		case name == "carriable" && (!carriable || err != nil || response == nil):
			t.Fatalf("a carriable Quote of %d bytes: %v", proto.Size(value), err)
		case name == "uncarriable" && (carriable || connect.CodeOf(err) != connect.CodeFailedPrecondition):
			t.Fatalf("an uncarriable Quote of %d bytes: %v", proto.Size(value), err)
		}
	}
}
