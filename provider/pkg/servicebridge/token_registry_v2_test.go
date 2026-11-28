package servicebridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/railgate"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// The synthetic session reuses the provider's finalized Registry fixture and
// supplies a matching token actor and call at the same checkpoint.
type tokenNodeSession struct {
	*gfSession
	account *toschain.TokenActorAccount
	call    toschain.TokenActorTransaction
}

func (s *tokenNodeSession) BeginSession(context.Context) (railgate.Session, error) { return s, nil }
func (s *tokenNodeSession) ReadTokenActor(_ context.Context, actor string) (*toschain.TokenActorAccount, bool, error) {
	return s.account, s.account.Address == actor, nil
}
func (*tokenNodeSession) ReadTokenAsset(context.Context, string, []toschain.TokenAssetPin) (*toschain.TokenAssetRecognition, error) {
	return nil, errors.New("existing liability does not consult current recognition")
}
func (s *tokenNodeSession) TokenHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenActorHistory, error) {
	return &toschain.TokenActorHistory{Result: toschain.HistoryComplete, Head: s.account.LastTransaction, Transactions: []toschain.TokenActorTransaction{s.call}}, nil
}

func syntheticTokenNode(t *testing.T, initialMode string) (*Node, Message, *tokenRetryRunner, func(string)) {
	t.Helper()
	now := time.Unix(1_900_000_000, 0)
	fixture := newGateFixture(t, now)
	read, err := fixture.chain.BeginSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	session := &tokenNodeSession{gfSession: read.(*gfSession)}
	original, err := DecodeTask(fixture.message.Body)
	if err != nil {
		t.Fatal(err)
	}
	var pack nativev1.QuoteProposalPackageV1
	if err := proto.Unmarshal(original.Package, &pack); err != nil {
		t.Fatal(err)
	}

	master, err := nativecore.StandardAddress("0:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	walletCode := cell.BeginCell().MustStoreUInt(1, 8).EndCell()
	walletHash := [32]byte(walletCode.Hash())
	decimals := uint8(6)
	code := nativecore.ServiceActorTokenTestProfileCodeHash
	manifest := fixture.manifest
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	manifest.Settlement.ActorCodeHash = code[:]
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: master.Address, WalletCodeHash: walletHash[:], Decimals: &decimals}}
	encoded, digest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := nativecore.ServiceActorMetadataHash(nativecore.ServiceActorMetadataInputV1{
		Network: testNetwork, CapabilityID: gfCapability, ProviderAgentID: testSeller, CapabilityVersion: "1.0.0", ManifestDigest: digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	previousCall := session.history[0]
	prior, err := previousCall.Snapshot.Decode()
	if err != nil {
		t.Fatal(err)
	}
	terms := nativecore.ServiceActorTokenTermsV1{ServiceActorTermsV1: prior.Terms, AssetWalletCodeHash: walletHash}
	terms.MetadataHash = metadata
	copy(terms.AssetMasterHash[:], master.Address)
	termsCell, err := nativecore.BuildServiceActorTokenTerms(terms)
	if err != nil {
		t.Fatal(err)
	}
	termsHash := [32]byte(termsCell.Hash())
	proposal := pack.Proposal
	proposal.ManifestDigest = digest
	proposal.ActorCodeHash = "tvm-cell-sha256:" + hex.EncodeToString(code[:])
	proposal.TermsHash = hex.EncodeToString(termsHash[:])
	proposal.PriceAtomic, proposal.PriceNanotos = proposal.PriceNanotos, ""
	proposal.Asset = &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{AccountId: master.Address,
		CodeHash: "tvm-cell-sha256:" + strings.Repeat("ef", 32)}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletHash[:]), Decimals: 6}
	pack.CanonicalManifestCbor = encoded
	quote, _, err := nativecore.BuildAcceptedTokenQuoteCommitment(testNetwork, proposal)
	if err != nil {
		t.Fatal(err)
	}
	request, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{
		QuoteCommitment: [32]byte(quote.Hash()), ExecutionID: testExecutionID, InputDigest: InputDigest(sha256Sum(fixture.archive)),
	})
	if err != nil {
		t.Fatal(err)
	}
	requestHash := [32]byte(request.Hash())
	snapshot := nativecore.ServiceActorTokenRequestSnapshotV1{
		RequestID: 0, Caller: prior.Caller, RequestHash: requestHash, TermsHash: termsHash, Terms: terms,
		ResponseDeadline: prior.ResponseDeadline, RefundClaimDeadline: prior.RefundClaimDeadline,
	}
	policy := session.data.Policy
	policy.MetadataHash = metadata
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: walletHash, WalletCode: walletCode, BridgeConfigParam: 79}
	initial, err := nativecore.BuildServiceActorTokenInitialData(gfOwner,
		nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: policy, MaxTokenLiability: big.NewInt(1_000_000_000_000)}, route)
	if err != nil {
		t.Fatal(err)
	}
	data, err := nativecore.DecodeServiceActorTokenData(initial)
	if err != nil {
		t.Fatal(err)
	}
	data.Active, data.NextRequestID, data.PendingCount, data.LiveCount = true, 1, 1, 1
	pending := session.data.Pending[0]
	pending.RequestHash, pending.TermsHash = requestHash, termsHash
	data.Pending[0] = pending
	ownWallet, err := nativecore.DeriveServiceActorTokenWallet(gfActor, route)
	if err != nil {
		t.Fatal(err)
	}
	session.account = &toschain.TokenActorAccount{Address: gfActor, CodeHash: proposal.ActorCodeHash,
		OwnWallet: ownWallet, Data: data, LastTransaction: session.head()}
	session.call = toschain.TokenActorTransaction{
		LT: previousCall.LT, Hash: previousCall.Hash, Now: previousCall.Now, TookEffect: true, Kind: toschain.ActorTxCall, Sender: ownWallet,
		Notification: &toschain.TokenActorNotification{From: testWallet, AmountAtomic: proposal.PriceAtomic,
			Payload: &nativecore.TokenCallPayloadV1{RequestHash: requestHash, ExpectedTermsHash: termsHash}},
		Logs: []nativecore.ServiceActorTokenLogV1{{Snapshot: &snapshot}},
	}
	session.capability.GetCapability().Versions[0].ManifestDigest = digest

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath, monitorPath := filepath.Join(dir, "manifest.cbor"), filepath.Join(dir, "monitor.json")
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	courier, err := OpenCourier(filepath.Join(dir, "outbox"), testSigner(t, testSeller), &recordingTransport{})
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{Network: testNetwork, Manifests: &MemoryManifests{}, Courier: courier,
		Config: NodeConfig{AgentID: testSeller, StateDir: dir, ActorCodeHash: proposal.ActorCodeHash,
			Provider: &ProviderNode{ManifestFile: manifestPath, CapabilityID: gfCapability, Version: "1.0.0", AttestorController: "attestor"},
			Token: &TokenProviderConfig{MonitorReport: monitorPath, Pins: []toschain.TokenAssetPin{{Master: master.Text(), WalletCodeHash: proposal.Asset.WalletCodeHash,
				MinterCodeHash: proposal.Asset.Master.CodeHash, Decimals: 6}},
				Actors: []TokenActorConfig{{Address: gfActor, CodeHash: proposal.ActorCodeHash, Master: master.Text(), AssetID: "asset",
					CapabilityID: gfCapability, Version: "1.0.0", ManifestFile: manifestPath,
					MinPriceAtomic: "1", MaxPriceAtomic: "1000000000", MaxLiabilityAtomic: "1000000000000",
					MaxStorageFeeNanoTOS: "1000000000", MaxCleanupBountyNanoTOS: "1000000000", MinActorFreeNanoTOS: "1", MinWalletNanoTOS: "1"}}},
		},
	}
	monitor := func(mode string) {
		t.Helper()
		report := TokenMonitorReport{Schema: "tos-settlement-report/1", PauseAssets: []string{}}
		report.Checkpoint.Height, report.Checkpoint.Hash, report.Checkpoint.Utime = session.Checkpoint(), strings.Repeat("a", 64), uint64(now.Unix())
		switch mode {
		case "alarm":
			report.PauseAssets = []string{"asset"}
		case "stale":
			report.Checkpoint.Utime -= 301
		}
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(monitorPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	monitor(initialMode)
	runner := &tokenRetryRunner{}
	if err := node.openProvider(t.Context(), NodeOptions{Runner: runner, Artifacts: fixedArtifact(nil), Now: func() time.Time { return now }}, &countingLifecycle{}, session); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Error(err)
		}
	})
	message, _ := taskMessage(t, &pack, fixture.archive, testBuyer)
	return node, message, runner, monitor
}
