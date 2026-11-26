package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tlb"
)

// tokenWalletAnchorSession serves one newest-first wallet history at
// checkpoint 42 from three agreeing endpoints, and counts the transactions
// the endpoints returned.
func tokenWalletAnchorSession(t *testing.T, history []tlb.Transaction, bound int) (*ServiceActorSession, *atomic.Int64) {
	t.Helper()
	domain := &nativev1.NetworkDomain{NetworkId: "tos:token-wallet-anchor", GenesisRootHash: "sha256:" + strings.Repeat("31", 32), GenesisFileHash: "sha256:" + strings.Repeat("32", 32)}
	block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
	served := new(atomic.Int64)
	serve := func() string {
		node := historyServer(t, history, nil)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var call struct {
				ID     uint64          `json:"id"`
				Method string          `json:"method"`
				Params json.RawMessage `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
				t.Error(err)
				return
			}
			var result any
			switch call.Method {
			case "getMasterchainInfo":
				result = map[string]any{"@type": "blocks.masterchainInfo", "last": block, "init": map[string]any{"root_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)), "file_hash": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))}}
			case "getAddressInformation":
				result = map[string]any{"@type": "raw.fullAccountState", "state": "active", "block_id": block, "last_transaction_id": headID(history[0])}
			case "getTransactions":
				var params struct {
					Address string `json:"address"`
					Limit   int    `json:"limit"`
					LT      string `json:"lt"`
					Hash    string `json:"hash"`
				}
				if err := json.Unmarshal(call.Params, &params); err != nil {
					t.Error(err)
					return
				}
				var page []rawTransaction
				if err := node.client.Call(r.Context(), "getTransactions", params, &page); err != nil {
					t.Error(err)
					return
				}
				served.Add(int64(len(page)))
				result = page
			default:
				t.Errorf("anchored wallet read consulted %s", call.Method)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
		}))
		t.Cleanup(server.Close)
		return server.URL
	}
	adapter, err := New(Config{Network: domain.NetworkId, Endpoints: []string{serve(), serve(), serve()}, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	return &ServiceActorSession{reader: &ServiceActorReader{chain: adapter, network: domain, maxHistory: bound}, seqno: 42, nodes: adapter.nodes}, served
}

func tokenAnchorID(tx tlb.Transaction) ActorTxID {
	return ActorTxID{LT: tx.LT, Hash: hex.EncodeToString(tx.Hash)}
}

// TestTokenWalletTransactionWalksOnlyFromTheHeadToTheNamedHop uses a wallet
// whose whole history is far beyond the bound. A named transaction a few
// steps below the finalized head is still proven, across history pages,
// without reading the older history.
func TestTokenWalletTransactionWalksOnlyFromTheHeadToTheNamedHop(t *testing.T) {
	history := linearHistory(t, 700)
	const bound = 400
	t.Run("the complete history exceeds the bound", func(t *testing.T) {
		session, _ := tokenWalletAnchorSession(t, history, bound)
		if _, err := session.TokenWalletHistory(context.Background(), testActor, nil); !errors.Is(err, ErrHistoryBoundExceeded) {
			t.Fatalf("a from-genesis walk was expected to exceed its bound: %v", err)
		}
	})
	for name, index := range map[string]int{"head": 0, "near the head": 3, "on a later page": 300, "at the bound": bound} {
		t.Run(name, func(t *testing.T) {
			session, served := tokenWalletAnchorSession(t, history, bound)
			want := history[index]
			tx, err := session.TokenWalletTransaction(context.Background(), testActor, tokenAnchorID(want))
			if err != nil {
				t.Fatal(err)
			}
			if tx.LT != want.LT || tx.Hash != hex.EncodeToString(want.Hash) || !tx.TookEffect {
				t.Fatalf("anchored read returned %+v", tx)
			}
			pages := index/actorHistoryPage + 1
			if served.Load() > int64(3*pages*actorHistoryPage) {
				t.Fatalf("anchored read fetched %d transactions for %d pages", served.Load(), pages)
			}
		})
	}
	t.Run("beyond the bound", func(t *testing.T) {
		session, _ := tokenWalletAnchorSession(t, history, bound)
		if _, err := session.TokenWalletTransaction(context.Background(), testActor, tokenAnchorID(history[bound+1])); !errors.Is(err, ErrHistoryBoundExceeded) {
			t.Fatalf("a hop beyond the bound was accepted: %v", err)
		}
	})
	t.Run("a hash that is not on the chain", func(t *testing.T) {
		session, _ := tokenWalletAnchorSession(t, history, bound)
		id := tokenAnchorID(history[3])
		id.Hash = strings.Repeat("ab", 32)
		if _, err := session.TokenWalletTransaction(context.Background(), testActor, id); !errors.Is(err, ErrHistoryAnchorMissing) {
			t.Fatalf("an unlinked hop was accepted: %v", err)
		}
	})
	t.Run("a logical time between transactions", func(t *testing.T) {
		session, _ := tokenWalletAnchorSession(t, history, bound)
		id := tokenAnchorID(history[3])
		id.LT++
		if _, err := session.TokenWalletTransaction(context.Background(), testActor, id); !errors.Is(err, ErrHistoryAnchorMissing) {
			t.Fatalf("an unlinked hop was accepted: %v", err)
		}
	})
	t.Run("malformed names", func(t *testing.T) {
		session, _ := tokenWalletAnchorSession(t, history, bound)
		good := tokenAnchorID(history[3])
		for _, id := range []ActorTxID{{LT: 0, Hash: good.Hash}, {LT: good.LT, Hash: strings.ToUpper(good.Hash)}, {LT: good.LT, Hash: good.Hash[:62]}} {
			if _, err := session.TokenWalletTransaction(context.Background(), testActor, id); err == nil {
				t.Fatalf("malformed hop name accepted: %+v", id)
			}
		}
	})
}
