package buyeragent

import (
	"context"
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/capabilitycatalog"
)

// Hint is one candidate Capability version a hint source lists. It carries
// identifiers only: everything the agent returns about it is read from
// finalized state, and its text from the manifest the finalized digest
// commits to.
type Hint struct {
	CapabilityID string
	Version      string
}

// HintSource lists candidate Capability versions and serves manifest bytes
// by digest. It holds no authority (section 4.3).
type HintSource interface {
	Hints(ctx context.Context, query string, limit int) ([]Hint, error)
	Manifest(ctx context.Context, digest string) ([]byte, error)
}

// QuoteGateway serves gateway Quote packages; nativeclient.Client is one.
type QuoteGateway interface {
	RequestQuoteProposal(ctx context.Context, request *nativev1.RequestQuoteProposalRequest) (*nativev1.RequestQuoteProposalResponse, error)
}

// DiscoveryGateway is a gateway's CapabilityDiscoveryService as the agent
// reads it; nativeclient.Client is one.
type DiscoveryGateway interface {
	ListCapabilities(ctx context.Context, request *nativev1.ListCapabilitiesRequest) (*nativev1.ListCapabilitiesResponse, error)
	SearchCapabilities(ctx context.Context, request *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error)
	GetSoftwareWorkManifest(ctx context.Context, request *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error)
}

// hintCaller names the agent in the request contexts it sends.
const hintCaller = "tos-service-buyer"

// GatewayRequestDeadline is the deadline every gateway request states; a
// gateway refuses a request context without one, and one more than 15
// minutes ahead.
const GatewayRequestDeadline = time.Minute

// gatewayContext is the request context of one gateway request: its ID,
// the caller and a deadline GatewayRequestDeadline from now.
func gatewayContext(requestID, caller string, now time.Time) *nativev1.RequestContext {
	return &nativev1.RequestContext{RequestId: requestID, CallerId: caller,
		DeadlineUnixMillis: now.Add(GatewayRequestDeadline).UnixMilli()}
}

// GatewayHints lists a gateway's discovery results as hints. Now is the
// clock of the request deadlines; nil is time.Now.
type GatewayHints struct {
	Gateway DiscoveryGateway
	Now     func() time.Time
}

func (g GatewayHints) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// Hints lists the gateway's Capabilities, or its search results for query.
func (g GatewayHints) Hints(ctx context.Context, query string, limit int) ([]Hint, error) {
	if g.Gateway == nil || limit <= 0 {
		return nil, errors.New("the gateway hint source is not configured")
	}
	request := gatewayContext("buyer-search", hintCaller, g.now())
	if query == "" {
		response, err := g.Gateway.ListCapabilities(ctx, &nativev1.ListCapabilitiesRequest{Context: request,
			PageSize: uint32(limit)})
		if err != nil {
			return nil, err
		}
		return versionHints(response.GetCapabilities(), limit), nil
	}
	response, err := g.Gateway.SearchCapabilities(ctx, &nativev1.SearchCapabilitiesRequest{Context: request, Query: query,
		PageSize: uint32(limit)})
	if err != nil {
		return nil, err
	}
	return searchHints(response.GetResults(), limit), nil
}

// Manifest fetches manifest bytes from the gateway.
func (g GatewayHints) Manifest(ctx context.Context, digest string) ([]byte, error) {
	if g.Gateway == nil {
		return nil, errors.New("the gateway hint source is not configured")
	}
	response, err := g.Gateway.GetSoftwareWorkManifest(ctx, &nativev1.GetSoftwareWorkManifestRequest{
		Context: gatewayContext("buyer-manifest", hintCaller, g.now()), ManifestDigest: digest})
	if err != nil {
		return nil, err
	}
	return response.GetCanonicalCbor(), nil
}

// CatalogSource is a capability catalog as the agent reads it;
// capabilitycatalog.Catalog is one.
type CatalogSource interface {
	List(ctx context.Context, pageSize uint32, after string) (*capabilitycatalog.Page, error)
	Search(ctx context.Context, query string, pageSize uint32, after string) (*capabilitycatalog.SearchPage, error)
	Manifest(digest string) ([]byte, error)
}

// CatalogHints lists a capability catalog's entries as hints.
type CatalogHints struct{ Catalog CatalogSource }

// Hints lists the catalog's Capabilities, or its search results for query.
func (c CatalogHints) Hints(ctx context.Context, query string, limit int) ([]Hint, error) {
	if c.Catalog == nil || limit <= 0 {
		return nil, errors.New("the catalog hint source is not configured")
	}
	if query == "" {
		page, err := c.Catalog.List(ctx, uint32(limit), "")
		if err != nil {
			return nil, err
		}
		return versionHints(page.Capabilities, limit), nil
	}
	page, err := c.Catalog.Search(ctx, query, uint32(limit), "")
	if err != nil {
		return nil, err
	}
	return searchHints(page.Results, limit), nil
}

// Manifest reads manifest bytes from the catalog.
func (c CatalogHints) Manifest(_ context.Context, digest string) ([]byte, error) {
	if c.Catalog == nil {
		return nil, errors.New("the catalog hint source is not configured")
	}
	return c.Catalog.Manifest(digest)
}

// versionHints lists every version a hint source shows of each Capability,
// at most limit.
func versionHints(states []*nativev1.NativeStateV1, limit int) []Hint {
	var hints []Hint
	for _, state := range states {
		capability := state.GetCapability()
		for _, version := range capability.GetVersions() {
			if len(hints) == limit {
				return hints
			}
			if version != nil && !version.Revoked {
				hints = append(hints, Hint{CapabilityID: capability.GetCapabilityId(), Version: version.Version})
			}
		}
	}
	return hints
}

func searchHints(results []*nativev1.CapabilitySearchResultV1, limit int) []Hint {
	var hints []Hint
	for _, result := range results {
		if len(hints) == limit {
			break
		}
		hints = append(hints, Hint{CapabilityID: result.GetCapability().GetCapability().GetCapabilityId(),
			Version: result.GetCapabilityVersion()})
	}
	return hints
}
