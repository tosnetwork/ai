package toschain

import (
	"context"
	"errors"
	"syscall"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

func TestQuorumStaleFallbackNeedsOnlyTransportFailures(t *testing.T) {
	nodes := []*rpcNode{{}, {}, {}}
	if _, _, err := quorumRead(t.Context(), nodes, 2, func(context.Context, *rpcNode) (string, error) {
		return "", syscall.ECONNREFUSED
	}); !errors.Is(err, nativecore.ErrFinalizedReadUnavailable) {
		t.Fatalf("all endpoints unreachable: %v", err)
	}
	for _, mixed := range []error{nil, errors.New("malformed finalized response")} {
		_, _, err := quorumRead(t.Context(), nodes, 2, func(_ context.Context, node *rpcNode) (string, error) {
			if node == nodes[0] {
				return "observed finalized state", mixed
			}
			return "", syscall.ECONNREFUSED
		})
		if err == nil || errors.Is(err, nativecore.ErrFinalizedReadUnavailable) {
			t.Fatalf("mixed response wrongly classified as an outage: %v", err)
		}
	}
}
