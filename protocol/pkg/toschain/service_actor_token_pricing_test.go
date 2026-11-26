package toschain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// TestTokenPricingFollowsTheContractsThreeSteps covers section 11: the
// positive slot; if it does not parse, the negative slot; if neither parses,
// the 0.3 TOS reserve allowance and zero wallet gas. A read that cannot be
// finalized stays an error and never selects a fallback.
func TestTokenPricingFollowsTheContractsThreeSteps(t *testing.T) {
	type slot struct{ positive, negative string }
	modes := map[string]slot{
		"present":                    {"good", "good"},
		"absent":                     {"absent", "good"},
		"malformed":                  {"empty", "good"},
		"truncated-prices":           {"short-prices", "good"},
		"neither-parses":             {"empty", "short-prices"},
		"both-absent":                {"absent", "absent"},
		"unavailable":                {"unavailable", "good"},
		"negative-unavailable":       {"empty", "unavailable"},
		"trailing-data-still-parses": {"trailing", "good"},
	}
	for mode, slots := range modes {
		t.Run(mode, func(t *testing.T) {
			_, _, _, _, param, _ := tokenBridgeFixture(t)
			var negativeReads atomic.Int32
			serve := func() string {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var call struct {
						ID     uint64 `json:"id"`
						Method string `json:"method"`
						Params struct {
							Param     int    `json:"param"`
							Seqno     uint64 `json:"seqno"`
							WithProof bool   `json:"with_proof"`
							Method    string `json:"method"`
						} `json:"params"`
					}
					if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
						t.Error(err)
						return
					}
					if call.Params.Seqno != 42 {
						t.Error("unfinalized pricing read")
					}
					var result any
					block := tokenTestBlock(bytes.Repeat([]byte{8}, 32), 42)
					if call.Method == "runGetMethod" {
						stack := []any{[]any{"num", "-1"}}
						if call.Params.Method == "get_funding_prices" {
							stack = []any{}
							for i := 6; i >= 1; i-- {
								stack = append(stack, []any{"num", string(rune('0' + i))})
							}
						}
						result = map[string]any{"@type": "smc.runResult", "exit_code": 0, "block_id": block, "stack": stack}
					} else {
						if !call.Params.WithProof {
							t.Error("configuration lacks block binding")
						}
						var value *cell.Cell
						kind := ""
						switch call.Params.Param {
						case -79:
							negativeReads.Add(1)
							kind = slots.negative
						case 79:
							kind = slots.positive
						}
						if kind == "absent" || kind == "unavailable" {
							reason, code := "CONFIG_PARAM_ABSENT", -32004
							if kind == "unavailable" {
								reason = "BLOCK_UNAVAILABLE"
								code = -32001
							}
							_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": code, "message": "unavailable", "data": map[string]any{"reason": reason, "retryable": false}}})
							return
						}
						switch kind {
						case "good":
							value = param
						case "empty":
							value = cell.BeginCell().EndCell()
						case "short-prices":
							value = tokenBridgeParamWithPrices(t, param, cell.BeginCell().MustStoreBigCoins(big.NewInt(1)).MustStoreBigCoins(big.NewInt(2)).MustStoreBigCoins(big.NewInt(3)).EndCell())
						case "trailing":
							value = tokenBridgeParamWithPrices(t, param, cell.BeginCell().MustStoreBigCoins(big.NewInt(1)).MustStoreBigCoins(big.NewInt(2)).MustStoreBigCoins(big.NewInt(77)).MustStoreBigCoins(big.NewInt(88)).MustStoreUInt(5, 9).EndCell())
						}
						switch call.Params.Param {
						case 19:
							value = cell.BeginCell().MustStoreInt(42, 32).EndCell()
						case 25:
							value = cell.BeginCell().MustStoreUInt(0xea, 8).MustStoreUInt(1, 64).MustStoreUInt(2, 64).MustStoreUInt(3, 64).MustStoreUInt(4, 32).MustStoreUInt(5, 16).MustStoreUInt(6, 16).EndCell()
						}
						result = map[string]any{"@type": "configInfo", "config": map[string]string{"@type": "tvm.cell", "bytes": bocText(value)}, "block_id": block, "state_proof": "", "config_proof": ""}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
				}))
				t.Cleanup(server.Close)
				return server.URL
			}
			session := testSession(t, serve(), serve(), serve())
			terms, err := session.ReadTokenWalletTerms(context.Background(), 79)
			switch mode {
			case "unavailable":
				if err == nil || negativeReads.Load() != 0 {
					t.Fatalf("an unfinalized primary read fell back: %v %d", err, negativeReads.Load())
				}
				return
			case "negative-unavailable":
				if err == nil {
					t.Fatal("an unfinalized fallback read selected the allowance")
				}
				return
			}
			if err != nil || terms.MinimumStorage == nil || terms.GasConsumption == nil {
				t.Fatalf("terms: %+v %v", terms, err)
			}
			if (slots.positive == "good" || slots.positive == "trailing") != (negativeReads.Load() == 0) {
				t.Fatalf("wrong fallback decision: %d negative reads", negativeReads.Load())
			}
			want, err := parseTokenBridgeTermsForTest(param)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "neither-parses", "both-absent":
				want = TokenWalletTerms{GasConsumption: big.NewInt(0), MinimumStorage: big.NewInt(300_000_000)}
			case "trailing-data-still-parses":
				want = TokenWalletTerms{GasConsumption: big.NewInt(88), MinimumStorage: big.NewInt(77)}
			}
			if terms.MinimumStorage.Cmp(want.MinimumStorage) != 0 || terms.GasConsumption.Cmp(want.GasConsumption) != 0 {
				t.Fatalf("terms %v/%v, want %v/%v", terms.MinimumStorage, terms.GasConsumption, want.MinimumStorage, want.GasConsumption)
			}
			prices, err := session.GetTokenFundingPrices(context.Background(), testActor)
			if err != nil || prices[0].Int64() != 1 || prices[5].Int64() != 6 {
				t.Fatalf("prices %v %v", prices, err)
			}
			accepted, err := session.GetTokenAcceptingTokens(context.Background(), testActor)
			if err != nil || !accepted {
				t.Fatalf("accepting %v %v", accepted, err)
			}
			forward, err := session.ReadTokenForwardPrices(context.Background())
			if err != nil || forward.FirstFraction != 5 || forward.CellPrice != 3 {
				t.Fatalf("forward %+v %v", forward, err)
			}
			global, err := session.ReadTokenGlobalID(context.Background())
			if err != nil || global != 42 {
				t.Fatalf("global %d %v", global, err)
			}
		})
	}
}

func TestTokenExistingRoutePinsDoNotDependOnRecognitionStatus(t *testing.T) {
	_, pin, _, bridge, _, _ := tokenBridgeFixture(t)
	codes, err := decodeTokenBridgeCodes(bridge)
	if err != nil {
		t.Fatal(err)
	}
	master, err := nativecore.DecodeMsgAddressCell(cell.BeginCell().MustStoreAddr(rawAddress(t, pin.Master)).EndCell())
	if err != nil {
		t.Fatal(err)
	}
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCodeHash: toHash(codes.Wallet.Hash()), WalletCode: codes.Wallet, BridgeConfigParam: pin.BridgeConfigParam}
	if _, err = MatchTokenAssetPin(route, pin.Decimals, []TokenAssetPin{pin}); err != nil {
		t.Fatal(err)
	}
	bad := route
	bad.BridgeConfigParam = 81
	if _, err = MatchTokenAssetPin(bad, pin.Decimals, []TokenAssetPin{pin}); err == nil {
		t.Fatal("different bridge accepted")
	}
	bad = route
	bad.WalletCodeHash[0] ^= 1
	if _, err = MatchTokenAssetPin(bad, pin.Decimals, []TokenAssetPin{pin}); err == nil {
		t.Fatal("different wallet accepted")
	}
	if _, err = MatchTokenAssetPin(route, pin.Decimals+1, []TokenAssetPin{pin}); err == nil {
		t.Fatal("different decimals accepted")
	}
	if _, err = MatchTokenAssetPin(route, pin.Decimals, []TokenAssetPin{pin, pin}); err == nil {
		t.Fatal("duplicate pin accepted")
	}
}
func toHash(value []byte) (out [32]byte) { copy(out[:], value); return }

// tokenBridgeParamWithPrices keeps the bridge parameter's header and oracles
// and replaces its prices reference.
func tokenBridgeParamWithPrices(t *testing.T, param *cell.Cell, prices *cell.Cell) *cell.Cell {
	t.Helper()
	s, err := param.BeginParse()
	if err != nil {
		t.Fatal(err)
	}
	head, err := s.LoadSlice(8 + 256 + 256)
	if err != nil {
		t.Fatal(err)
	}
	oracles, err := s.LoadMaybeRef()
	if err != nil {
		t.Fatal(err)
	}
	mid, err := s.LoadUInt(8)
	if err != nil {
		t.Fatal(err)
	}
	b := cell.BeginCell().MustStoreSlice(head, 8+256+256)
	if oracles == nil {
		b.MustStoreBoolBit(false)
	} else {
		root, err := oracles.ToCell()
		if err != nil {
			t.Fatal(err)
		}
		b.MustStoreMaybeRef(root)
	}
	return b.MustStoreUInt(mid, 8).MustStoreRef(prices).EndCell()
}

// parseTokenBridgeTermsForTest reads the fixture's own third and fourth price
// Coins independently of the production parser.
func parseTokenBridgeTermsForTest(param *cell.Cell) (TokenWalletTerms, error) {
	s, err := param.BeginParse()
	if err != nil {
		return TokenWalletTerms{}, err
	}
	if err := s.SkipBits(8 + 256 + 256); err != nil {
		return TokenWalletTerms{}, err
	}
	if _, err := s.LoadMaybeRef(); err != nil {
		return TokenWalletTerms{}, err
	}
	if err := s.SkipBits(8); err != nil {
		return TokenWalletTerms{}, err
	}
	prices, err := s.LoadRef()
	if err != nil {
		return TokenWalletTerms{}, err
	}
	var values [4]*big.Int
	for i := range values {
		if values[i], err = prices.LoadBigCoins(); err != nil {
			return TokenWalletTerms{}, err
		}
	}
	if values[2] == nil || values[3] == nil {
		return TokenWalletTerms{}, errors.New("fixture prices are missing")
	}
	return TokenWalletTerms{MinimumStorage: values[2], GasConsumption: values[3]}, nil
}
