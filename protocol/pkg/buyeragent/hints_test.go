package buyeragent

import (
	"context"
	"reflect"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/capabilitycatalog"
)

func capabilityState(id string, versions ...*nativev1.CapabilityVersionV1) *nativev1.NativeStateV1 {
	return &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Capability{
		Capability: &nativev1.CapabilityStateV1{CapabilityId: id, Versions: versions}}}
}

var hintStates = []*nativev1.NativeStateV1{
	capabilityState("cap_a", &nativev1.CapabilityVersionV1{Version: "1"}, &nativev1.CapabilityVersionV1{Version: "0", Revoked: true}),
	capabilityState("cap_b", &nativev1.CapabilityVersionV1{Version: "2"}, &nativev1.CapabilityVersionV1{Version: "3"}),
}

var hintResults = []*nativev1.CapabilitySearchResultV1{
	{Capability: capabilityState("cap_c"), CapabilityVersion: "4"},
	{Capability: capabilityState("cap_d"), CapabilityVersion: "5"},
}

type fakeDiscovery struct{ query string }

func (d *fakeDiscovery) ListCapabilities(context.Context, *nativev1.ListCapabilitiesRequest) (*nativev1.ListCapabilitiesResponse, error) {
	return &nativev1.ListCapabilitiesResponse{Capabilities: hintStates}, nil
}

func (d *fakeDiscovery) SearchCapabilities(_ context.Context, request *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error) {
	d.query = request.Query
	return &nativev1.SearchCapabilitiesResponse{Results: hintResults}, nil
}

func (d *fakeDiscovery) GetSoftwareWorkManifest(context.Context, *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error) {
	return &nativev1.GetSoftwareWorkManifestResponse{CanonicalCbor: []byte{1}}, nil
}

type fakeCatalog struct{ query string }

func (c *fakeCatalog) List(context.Context, uint32, string) (*capabilitycatalog.Page, error) {
	return &capabilitycatalog.Page{Capabilities: hintStates}, nil
}

func (c *fakeCatalog) Search(_ context.Context, query string, _ uint32, _ string) (*capabilitycatalog.SearchPage, error) {
	c.query = query
	return &capabilitycatalog.SearchPage{Results: hintResults}, nil
}

func (c *fakeCatalog) Manifest(string) ([]byte, error) { return []byte{2}, nil }

// Hint sources yield identifiers only: unrevoked versions of the listed
// Capabilities, or the versions search results name, at most the limit.
func TestGatewayAndCatalogHintsYieldIdentifiersWithinTheLimit(t *testing.T) {
	gateway, catalog := &fakeDiscovery{}, &fakeCatalog{}
	for name, source := range map[string]HintSource{"gateway": GatewayHints{Gateway: gateway}, "catalog": CatalogHints{Catalog: catalog}} {
		listed, err := source.Hints(context.Background(), "", 10)
		if err != nil || !reflect.DeepEqual(listed, []Hint{{"cap_a", "1"}, {"cap_b", "2"}, {"cap_b", "3"}}) {
			t.Errorf("%s list: %v %v", name, listed, err)
		}
		if bounded, _ := source.Hints(context.Background(), "", 2); len(bounded) != 2 {
			t.Errorf("%s list over its limit: %v", name, bounded)
		}
		found, err := source.Hints(context.Background(), "go", 10)
		if err != nil || !reflect.DeepEqual(found, []Hint{{"cap_c", "4"}, {"cap_d", "5"}}) {
			t.Errorf("%s search: %v %v", name, found, err)
		}
		if bounded, _ := source.Hints(context.Background(), "go", 1); len(bounded) != 1 {
			t.Errorf("%s search over its limit: %v", name, bounded)
		}
		if raw, err := source.Manifest(context.Background(), "sha256:x"); err != nil || len(raw) != 1 {
			t.Errorf("%s manifest: %v", name, err)
		}
	}
	if gateway.query != "go" || catalog.query != "go" {
		t.Fatal("the query did not reach the source")
	}
	if _, err := (GatewayHints{}).Hints(context.Background(), "", 1); err == nil {
		t.Fatal("an unconfigured gateway listed hints")
	}
}
