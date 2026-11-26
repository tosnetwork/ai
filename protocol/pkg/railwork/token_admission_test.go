package railwork

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

func tokenTaskFixture(t *testing.T) *taskFixture {
	t.Helper()
	f := newTaskFixture(t)
	m, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(f.pkg.CanonicalManifestCbor)
	if err != nil {
		t.Fatal(err)
	}
	decimal := uint8(6)
	master := make([]byte, 32)
	wallet := make([]byte, 32)
	for i := range master {
		master[i] = 0xab
		wallet[i] = 0xcd
	}
	m.Settlement.Rail = nativecore.ServiceActorTokenRail
	m.Settlement.ActorCodeHash = nativecore.ServiceActorTokenTestProfileCodeHash[:]
	m.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset, MasterAccountID: master, WalletCodeHash: wallet, Decimals: &decimal}}
	raw, digest, err := nativecore.CanonicalSoftwareWorkManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	f.pkg.CanonicalManifestCbor = raw
	f.pkg.Proposal.ManifestDigest = digest
	f.pkg.Proposal.ActorCodeHash = "tvm-cell-sha256:" + hex.EncodeToString(m.Settlement.ActorCodeHash)
	f.pkg.Proposal.Asset = &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{AccountId: master, CodeHash: "tvm-cell-sha256:" + strings.Repeat("ef", 32)}, WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(wallet), Decimals: 6}
	f.pkg.Proposal.PriceAtomic = "1000000"
	f.pkg.Proposal.PriceNanotos = ""
	f.provider.Token = true
	quote, _, err := QuoteCommitment(f.provider.Network, f.pkg.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	executionID, err := ExecutionID(testBuyer, f.nonce)
	if err != nil {
		t.Fatal(err)
	}
	f.binding.RequestHash, err = RequestHash(quote, executionID, InputDigest(sha256.Sum256(f.archive)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTokenTaskRequiresAnExplicitRailAndKeepsAtomicUnits(t *testing.T) {
	f := tokenTaskFixture(t)
	a, err := f.provider.CheckTask(f.message(t))
	if err != nil {
		t.Fatal(err)
	}
	if a.TokenQuote == nil || a.Quote != nil || a.TokenQuote.Proposal.PriceAtomic != "1000000" || !a.FrameBindingMatchesQuote() {
		t.Fatalf("token admission: %+v", a)
	}
	f.provider.Token = false
	if _, err = f.provider.CheckTask(f.message(t)); err == nil {
		t.Fatal("native provider admitted token task")
	}
	f = newTaskFixture(t)
	f.provider.Token = true
	if _, err = f.provider.CheckTask(f.message(t)); err == nil {
		t.Fatal("token provider admitted native task")
	}
	f = tokenTaskFixture(t)
	f.pkg.Proposal.Asset.Decimals++
	if _, err = f.provider.CheckTask(f.message(t)); err == nil {
		t.Fatal("mismatched asset admitted")
	}
}
