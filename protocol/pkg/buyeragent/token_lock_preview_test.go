package buyeragent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/tokenissuer"
)

func TestTokenLockPreviewUsesStoredQuoteAndItsAssetBudget(t *testing.T) {
	f, _ := tokenOffersFixture(t)
	request, pkg, _, err := f.offers.Quote(context.Background(), localParams())
	if err != nil {
		t.Fatal(err)
	}
	quoteID, err := f.agent.StoreQuote(request, pkg)
	if err != nil {
		t.Fatal(err)
	}
	buyer := f.agent.config.Buyer.(*fakeBuyer)
	buyer.limits.TokenAssets = f.offers.config.TokenAssets
	code := sha256.Sum256([]byte{0x60, 0})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var value any
		switch q.Method {
		case "eth_chainId":
			value = "0x1"
		case "eth_getBlockByNumber":
			value = map[string]any{"number": "0x7", "hash": "0x" + strings.Repeat("ab", 32), "timestamp": fmt.Sprintf("0x%x", time.Now().Unix())}
		case "eth_getCode":
			value = "0x6000"
		case "eth_call":
			var c map[string]string
			if err := json.Unmarshal(q.Params[0], &c); err != nil {
				t.Error(err)
				return
			}
			n := 0
			switch c["data"][:10] {
			case "0xdd644f72":
				n = 19
			case "0x35390714":
				n = 1000000
			}
			value = fmt.Sprintf("0x%064x", n)
		default:
			t.Error("unexpected source method")
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": value}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	master := "0:" + hex.EncodeToString(pkg.Proposal.Asset.Master.AccountId)
	f.agent.config.TokenIssuers = map[string]tokenissuer.Policy{master: {RPCURL: server.URL, ChainID: 1, Token: "0x" + strings.Repeat("12", 20), Bridge: "0x" + strings.Repeat("34", 20), CodeSHA256: hex.EncodeToString(code[:]), Profile: tokenissuer.Legacy}}
	records, err := buyer.journal.Records()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := f.agent.PreviewTokenLock(context.Background(), TokenLockPreviewParams{QuoteID: quoteID, NominalAtomic: "300500000"})
	if err != nil {
		t.Fatal(err)
	}
	if preview.AssetMaster != master || preview.ActorPriceAtomic != "300000000" || preview.MintedAtomic != "299929050" || preview.BudgetDebitAtomic != preview.MintedAtomic || preview.Warning == "" {
		t.Fatalf("preview: %+v", preview)
	}
	after, err := buyer.journal.Records()
	if err != nil || len(after) != len(records) || len(buyer.sends) != 0 {
		t.Fatalf("preview wrote or sent: %v", err)
	}
	delete(f.agent.config.TokenIssuers, master)
	if _, err = f.agent.PreviewTokenLock(context.Background(), TokenLockPreviewParams{QuoteID: quoteID, NominalAtomic: "300500000"}); err == nil {
		t.Fatal("missing issuer policy guessed fee zero")
	}
	if _, err = f.agent.StoreQuote(request, pkg); err != nil {
		t.Fatal(err)
	}
	if servicefixture.Network().NetworkId != f.agent.config.Network.NetworkId {
		t.Fatal("fixture network changed")
	}
}
