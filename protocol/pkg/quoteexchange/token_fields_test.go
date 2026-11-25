package quoteexchange

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// A native Quote Proposal package whose proposal carries a token-rail field
// (QuoteProposalV1 asset = 18 or price_atomic = 19) is refused; the plain
// native package still validates.
func TestValidateRefusesTokenRailFieldsOnANativeProposal(t *testing.T) {
	asset := &nativev1.TOSAssetIdentityV1{
		Master: &nativev1.TOSContractIdentityV1{Workchain: 0, AccountId: bytes.Repeat([]byte{0x9a}, 32),
			CodeHash: "tvm-cell-sha256:" + strings.Repeat("11", 32)},
		WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("22", 32), Decimals: 6}
	for name, edit := range map[string]func(*nativev1.QuoteProposalV1){
		"asset":        func(p *nativev1.QuoteProposalV1) { p.Asset = asset },
		"price_atomic": func(p *nativev1.QuoteProposalV1) { p.PriceAtomic = "1000" },
	} {
		network, request, value, now := validPackage(t)
		edit(value.Proposal)
		if _, err := Validate(network, request, value, now); !errors.Is(err, nativecore.ErrTokenRailFieldsOnNativeQuote) {
			t.Errorf("%s: Validate err = %v, want ErrTokenRailFieldsOnNativeQuote", name, err)
		}
		if _, err := ValidatePortable(network, request, value); !errors.Is(err, nativecore.ErrTokenRailFieldsOnNativeQuote) {
			t.Errorf("%s: ValidatePortable err = %v, want ErrTokenRailFieldsOnNativeQuote", name, err)
		}
	}
	network, request, value, now := validPackage(t)
	if _, err := Validate(network, request, value, now); err != nil {
		t.Fatalf("the plain native package was refused: %v", err)
	}
}
