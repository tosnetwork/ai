package nativegateway

import (
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
)

// quoteTransport validates the selected rail without constructing or rewriting
// any proposal field. The canonical manifest selects the rail, never the mere
// presence of token fields on a proposal.
func quoteTransport(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1, now time.Time) (nativecore.TransportBindingV1, error) {
	if value == nil {
		return nativecore.TransportBindingV1{}, errors.New("Quote package is missing")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(value.CanonicalManifestCbor)
	if err != nil {
		return nativecore.TransportBindingV1{}, err
	}
	if manifest.Settlement.Rail == nativecore.ServiceActorTokenRail {
		validated, err := quoteexchange.ValidateToken(network, request, value, now)
		if err != nil {
			return nativecore.TransportBindingV1{}, err
		}
		return validated.TransportBinding, nil
	}
	validated, err := quoteexchange.Validate(network, request, value, now)
	if err != nil {
		return nativecore.TransportBindingV1{}, err
	}
	return validated.TransportBinding, nil
}
