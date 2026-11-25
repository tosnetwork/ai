package nativecore

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

// A native Quote Proposal sets price_nanotos and neither token-rail field;
// QuoteProposalV1 fields 18 (asset) and 19 (price_atomic) belong to the token
// rail only, so a native parse refuses a proposal that carries either.
func TestNativeQuoteRefusesTokenRailFields(t *testing.T) {
	network := testNetworkDomain()
	asset := &nativev1.TOSAssetIdentityV1{
		Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: bytes.Repeat([]byte{0x9a}, 32),
			CodeHash: "tvm-cell-sha256:" + strings.Repeat("11", 32)},
		WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("22", 32), Decimals: 6}
	for name, edit := range map[string]func(*nativev1.QuoteProposalV1){
		"asset":                func(p *nativev1.QuoteProposalV1) { p.Asset = asset },
		"empty asset message":  func(p *nativev1.QuoteProposalV1) { p.Asset = &nativev1.TOSAssetIdentityV1{} },
		"price_atomic":         func(p *nativev1.QuoteProposalV1) { p.PriceAtomic = "1000" },
		"asset and atomic":     func(p *nativev1.QuoteProposalV1) { p.Asset, p.PriceAtomic = asset, "1000" },
		"token form, no nanos": func(p *nativev1.QuoteProposalV1) { p.Asset, p.PriceAtomic, p.PriceNanotos = asset, "1000", "" },
	} {
		proposal := testRailProposal()
		edit(proposal)
		if _, err := ParseServiceActorQuoteRail(proposal); !errors.Is(err, ErrTokenRailFieldsOnNativeQuote) {
			t.Errorf("%s: ParseServiceActorQuoteRail err = %v, want ErrTokenRailFieldsOnNativeQuote", name, err)
		}
		if _, _, err := BuildAcceptedQuoteCommitment(network, proposal); !errors.Is(err, ErrTokenRailFieldsOnNativeQuote) {
			t.Errorf("%s: BuildAcceptedQuoteCommitment err = %v, want ErrTokenRailFieldsOnNativeQuote", name, err)
		}
	}
}

func TestNativeQuoteWithoutTokenRailFieldsStillParses(t *testing.T) {
	proposal := testRailProposal()
	if proposal.Asset != nil || proposal.PriceAtomic != "" {
		t.Fatal("the fixture is not the plain native form")
	}
	rail, err := ParseServiceActorQuoteRail(proposal)
	if err != nil || rail.Price.String() != "300000000" {
		t.Fatalf("rail=%+v err=%v", rail, err)
	}
	if _, _, err := BuildAcceptedQuoteCommitment(testNetworkDomain(), proposal); err != nil {
		t.Fatal(err)
	}
}
