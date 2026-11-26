package main

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// tokenAssetConfig is custody-owned policy. No quote or gateway can add an asset.
type tokenAssetConfig struct {
	Master            string `json:"master"`
	Bridge            string `json:"bridge"`
	BridgeConfigParam uint32 `json:"bridge_config_param"`
	Decimals          uint8  `json:"decimals"`
	SourceChainID     uint32 `json:"source_chain_id"`
	SourceToken       string `json:"source_token"`
	BridgeCodeHash    string `json:"bridge_code_hash"`
	MinterCodeHash    string `json:"minter_code_hash"`
	WalletCodeHash    string `json:"wallet_code_hash"`
	MaxPerCallAtomic  string `json:"max_per_call_atomic"`
	MaxWindowAtomic   string `json:"max_window_atomic"`
}

func tokenPolicy(configs []tokenAssetConfig) ([]toschain.TokenAssetPin, map[string]buyersdk.TokenAssetLimits, error) {
	if len(configs) > 16 {
		return nil, nil, errors.New("at most 16 pinned token assets are allowed")
	}
	var pins []toschain.TokenAssetPin
	limits := make(map[string]buyersdk.TokenAssetLimits, len(configs))
	seen := map[string]bool{}
	for _, c := range configs {
		if !rawTokenAddress(c.Master) || !strings.HasPrefix(c.Bridge, "-1:") || !rawTokenAddress("0:"+strings.TrimPrefix(c.Bridge, "-1:")) || c.SourceChainID == 0 ||
			!tokenHash(c.BridgeCodeHash) || !tokenHash(c.MinterCodeHash) || !tokenHash(c.WalletCodeHash) {
			return nil, nil, errors.New("invalid pinned token asset identity")
		}
		switch c.BridgeConfigParam {
		case 79, 81, 82, 83:
		default:
			return nil, nil, errors.New("invalid token bridge config parameter")
		}
		source, err := hex.DecodeString(c.SourceToken)
		if err != nil || len(source) != 20 || c.SourceToken != strings.ToLower(c.SourceToken) || strings.Trim(c.SourceToken, "0") == "" {
			return nil, nil, errors.New("source token must be 40 nonzero lowercase hex digits")
		}
		per, ok := new(big.Int).SetString(c.MaxPerCallAtomic, 10)
		window, okWindow := new(big.Int).SetString(c.MaxWindowAtomic, 10)
		if !ok || !okWindow || per.Sign() <= 0 || per.BitLen() > 120 || per.String() != c.MaxPerCallAtomic || window.Cmp(per) < 0 || window.BitLen() > 120 || window.String() != c.MaxWindowAtomic {
			return nil, nil, errors.New("token limits must be canonical positive atomic amounts below 2^120, with window >= per-call")
		}
		if seen[c.Master] {
			return nil, nil, errors.New("duplicate pinned token master")
		}
		seen[c.Master] = true
		pin := toschain.TokenAssetPin{Master: c.Master, Bridge: c.Bridge, BridgeConfigParam: c.BridgeConfigParam, Decimals: c.Decimals, SourceChainID: c.SourceChainID, BridgeCodeHash: c.BridgeCodeHash, MinterCodeHash: c.MinterCodeHash, WalletCodeHash: c.WalletCodeHash}
		copy(pin.SourceToken[:], source)
		pins = append(pins, pin)
		limits[buyersdk.TokenAssetBudgetKey(c.Master, c.WalletCodeHash, c.Decimals)] = buyersdk.TokenAssetLimits{MaxPerCallAtomic: per, MaxWindowAtomic: window}
	}
	return pins, limits, nil
}

func tokenHash(v string) bool {
	s, ok := strings.CutPrefix(v, "tvm-cell-sha256:")
	b, e := hex.DecodeString(s)
	return ok && e == nil && len(b) == 32 && strings.ToLower(s) == s && strings.Trim(s, "0") != ""
}
func rawTokenAddress(v string) bool {
	s, ok := strings.CutPrefix(v, "0:")
	b, e := hex.DecodeString(s)
	return ok && e == nil && len(b) == 32 && strings.ToLower(s) == s && strings.Trim(s, "0") != ""
}
