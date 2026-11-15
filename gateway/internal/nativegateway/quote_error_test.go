package nativegateway

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteprovider"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

// failingSessions is a finalized reader that cannot open a checkpoint; its
// error names an endpoint URL carrying a token, as an RPC error can.
type failingSessions struct{}

func (failingSessions) BeginSession(context.Context) (serviceactor.Session, error) {
	return nil, errors.New(`resolve TOS consensus quorum: execute JSON-RPC request: Post "https://rpc.example/secret-token"`)
}

// testQuoteProvider is a real Quote provider whose finalized reads fail.
func testQuoteProvider(t *testing.T) *quoteprovider.Provider {
	t.Helper()
	attestor := "mldsa44:" + strings.Repeat("99", 32)
	manifest := nativecore.SoftwareWorkManifestV1{
		Protocol: nativecore.SoftwareWorkManifestProtocolV1, Version: "1.0.0", Name: "Deterministic Go test",
		Description: "Run the committed Go test suite without network access.", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive", "immutable-repository-commit"},
		InputSchemaDigest:   "sha256:" + strings.Repeat("11", 32), OutputSchemaDigest: "sha256:" + strings.Repeat("22", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("33", 32),
		Invocation: nativecore.SoftwareWorkInvocationV1{Executable: "/usr/local/bin/go", Arguments: []string{"test", "./..."},
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
			ActorAccountID: bytes.Repeat([]byte{0x77}, 32), ActorCodeHash: bytes.Repeat([]byte{0x8e}, 32),
			AttestorKey: attestor},
	}
	encoded, _, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := quoteprovider.New(quoteprovider.Config{Sessions: failingSessions{},
		Network: &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
			GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		RegistryCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), ProviderAgentID: "agent_" + strings.Repeat("44", 32),
		ManifestCBOR: encoded, Transport: nativecore.TransportBindingV1{SecurityMode: nativecore.TransportHTTPS,
			MaxRequestBytes: 1 << 20, BaseURL: "https://provider.example"},
		CallerID: "provider", ResolutionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}
