package railwork

import (
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
)

// A card a gateway serves next to a Quote is later carried in rail frames,
// so its bound is the frames' key card bound.
func TestTheQuoteCarriedProviderKeyCardBoundEqualsTheFrameBound(t *testing.T) {
	if quoteexchange.MaxProviderKeyCardBytes != MaxKeyCardBytes || MaxKeyCardBytes != 16384 {
		t.Fatalf("provider key card bound %d differs from the frame bound %d",
			quoteexchange.MaxProviderKeyCardBytes, MaxKeyCardBytes)
	}
}
