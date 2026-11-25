package toschain

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestTokenPricingUsesOneCheckpointAndFallbackOnlyForAbsence(t *testing.T) {
	for _, mode := range []string{"present", "absent", "malformed", "unavailable"} {
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
						if call.Params.Param == 79 && (mode == "absent" || mode == "unavailable") {
							reason, code := "CONFIG_PARAM_ABSENT", -32004
							if mode == "unavailable" {
								reason = "BLOCK_UNAVAILABLE"
								code = -32001
							}
							_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "error": map[string]any{"code": code, "message": "unavailable", "data": map[string]any{"reason": reason, "retryable": false}}})
							return
						}
						var value *cell.Cell
						switch call.Params.Param {
						case -79:
							negativeReads.Add(1)
							value = param
						case 79:
							value = param
							if mode == "malformed" {
								value = cell.BeginCell().EndCell()
							}
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
			if mode == "malformed" || mode == "unavailable" {
				if err == nil || negativeReads.Load() != 0 {
					t.Fatalf("invalid primary fell back: %v %d", err, negativeReads.Load())
				}
				return
			}
			if err != nil || terms.MinimumStorage == nil || terms.GasConsumption == nil {
				t.Fatalf("terms: %+v %v", terms, err)
			}
			if (mode == "absent") != (negativeReads.Load() > 0) {
				t.Fatal("wrong fallback decision")
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
