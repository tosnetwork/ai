package nativegateway

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

func tokenCarriageNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + strings.Repeat("11", 32),
		GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

func tokenCarriageQuote(t *testing.T, network *nativev1.NetworkDomain) (*nativev1.QuoteProposalPackageV1, *nativev1.RequestQuoteProposalRequest) {
	t.Helper()
	value, request := carriageQuote(t, network, 0)
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(value.CanonicalManifestCbor)
	if err != nil {
		t.Fatal(err)
	}
	decimals := uint8(6)
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset,
		MasterAccountID: bytes.Repeat([]byte{0x31}, 32), WalletCodeHash: bytes.Repeat([]byte{0x32}, 32), Decimals: &decimals}}
	value.CanonicalManifestCbor, value.Proposal.ManifestDigest, err = nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	value.Proposal.PriceNanotos = ""
	value.Proposal.PriceAtomic = "1000"
	value.Proposal.Asset = &nativev1.TOSAssetIdentityV1{
		Master:         &nativev1.TOSContractIdentityV1{AccountId: bytes.Repeat([]byte{0x31}, 32), CodeHash: "tvm-cell-sha256:" + strings.Repeat("33", 32)},
		WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("32", 32), Decimals: 6,
	}
	return value, request
}

func callCarriedQuote(t *testing.T, value *nativev1.QuoteProposalPackageV1, request *nativev1.RequestQuoteProposalRequest, network *nativev1.NetworkDomain) (*nativev1.RequestQuoteProposalResponse, error) {
	t.Helper()
	server := &Server{Authorizer: NewTokenAuthorizer("read-secret", "relay-secret"), QuoteSource: fixedQuote{value}, Network: network}
	call := connect.NewRequest(request)
	call.Header().Set("Authorization", "Bearer read-secret")
	response, err := server.RequestQuoteProposal(context.Background(), call)
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func TestTokenQuoteCarriagePreservesEveryProposalField(t *testing.T) {
	network := tokenCarriageNetwork()
	for _, price := range []string{"1000", "1001"} {
		value, request := tokenCarriageQuote(t, network)
		value.Proposal.PriceAtomic = price
		before := proto.Clone(value).(*nativev1.QuoteProposalPackageV1)
		response, err := callCarriedQuote(t, value, request, network)
		if err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(response.Package, before) || !proto.Equal(value, before) {
			t.Fatal("gateway changed the source Quote package")
		}
		if response.Package.Proposal.Asset == nil || response.Package.Proposal.PriceAtomic != price || response.Package.Proposal.PriceNanotos != "" {
			t.Fatal("token fields were stripped, replaced or converted")
		}
	}
}

func TestNativeQuoteWithTokenFieldsNeverSelectsTheTokenRail(t *testing.T) {
	network := tokenCarriageNetwork()
	for name, change := range map[string]func(*nativev1.QuoteProposalV1){
		"asset":        func(p *nativev1.QuoteProposalV1) { p.Asset = &nativev1.TOSAssetIdentityV1{} },
		"atomic price": func(p *nativev1.QuoteProposalV1) { p.PriceAtomic = "1000" },
		"token-shaped": func(p *nativev1.QuoteProposalV1) {
			p.PriceNanotos = ""
			p.PriceAtomic = "1000"
			p.Asset = &nativev1.TOSAssetIdentityV1{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, request := carriageQuote(t, network, 0)
			change(value.Proposal)
			if _, err := callCarriedQuote(t, value, request, network); connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("mixed native Quote accepted: %v", err)
			}
		})
	}
}

func TestMalformedTokenQuoteCannotBeRepairedByTheGateway(t *testing.T) {
	network := tokenCarriageNetwork()
	for name, change := range map[string]func(*nativev1.QuoteProposalPackageV1){
		"asset mismatch":     func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.Asset.Master.AccountId[0] ^= 1 },
		"missing asset":      func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.Asset = nil },
		"missing price":      func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.PriceAtomic = "" },
		"native price":       func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.PriceNanotos = "1000" },
		"noncanonical price": func(v *nativev1.QuoteProposalPackageV1) { v.Proposal.PriceAtomic = "01000" },
		"manifest mismatch":  func(v *nativev1.QuoteProposalPackageV1) { v.CanonicalManifestCbor[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			value, request := tokenCarriageQuote(t, network)
			change(value)
			before := proto.Clone(value).(*nativev1.QuoteProposalPackageV1)
			if _, err := callCarriedQuote(t, value, request, network); connect.CodeOf(err) != connect.CodeFailedPrecondition {
				t.Fatalf("invalid token Quote accepted: %v", err)
			}
			if !proto.Equal(value, before) {
				t.Fatal("gateway rewrote a refused Quote")
			}
		})
	}
}
