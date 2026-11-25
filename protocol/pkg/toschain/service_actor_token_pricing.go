package toschain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

type TokenWalletTerms struct{ GasConsumption, MinimumStorage *big.Int }
type TokenForwardPrices struct {
	LumpPrice, BitPrice, CellPrice uint64
	FirstFraction                  uint16
}

func (s *ServiceActorSession) GetTokenFundingPrices(ctx context.Context, actor string) ([6]*big.Int, error) {
	var out [6]*big.Int
	stack, err := s.actorGetter(ctx, actor, "get_funding_prices", nil)
	if err != nil {
		return out, err
	}
	if len(stack) != len(out) {
		return out, errors.New("invalid token funding price stack")
	}
	for i, v := range stack {
		if v.Kind != "num" || v.Number == nil || v.Number.Sign() < 0 || v.Number.BitLen() > 120 {
			return out, errors.New("invalid token funding price")
		}
		out[i] = new(big.Int).Set(v.Number)
	}
	return out, nil
}
func (s *ServiceActorSession) GetTokenAcceptingTokens(ctx context.Context, actor string) (bool, error) {
	result, err := runDNSGetter(ctx, s.nodes, s.reader.chain.quorum, actor, s.seqno, "get_accepting_tokens", nil)
	if err != nil {
		return false, err
	}
	root, file, err := blockHashes(result.BlockID)
	if err != nil || result.BlockID.Workchain != -1 {
		return false, errors.New("token accepting getter is not masterchain finalized")
	}
	if err = s.pinHashes(root, file); err != nil {
		return false, err
	}
	if len(result.Stack) != 1 {
		return false, errors.New("invalid token accepting stack")
	}
	kind, raw, err := stackPair(result.Stack, 0)
	if err != nil || kind != "num" {
		return false, errors.New("invalid token accepting number")
	}
	var text string
	if err = json.Unmarshal(raw, &text); err != nil {
		return false, err
	}
	if text == "0" {
		return false, nil
	}
	if text != "-1" {
		return false, errors.New("invalid token accepting boolean")
	}
	return true, nil
}

func (s *ServiceActorSession) ReadTokenWalletTerms(ctx context.Context, param uint32) (TokenWalletTerms, error) {
	var out TokenWalletTerms
	if param != 79 && param != 81 && param != 82 && param != 83 {
		return out, errors.New("unsupported bridge config slot")
	}
	root, found, err := s.tokenOptionalConfigAt(ctx, int(param))
	if err != nil {
		return out, err
	}
	if !found {
		root, found, err = s.tokenOptionalConfigAt(ctx, -int(param))
		if err != nil {
			return out, err
		}
	}
	if !found {
		return out, errors.New("bridge configuration is absent")
	}
	slice, err := tokenOrdinary(root)
	if err != nil {
		return out, err
	}
	if err = slice.SkipBits(8 + 256 + 256); err != nil {
		return out, err
	}
	if _, err = slice.LoadDict(256); err != nil {
		return out, err
	}
	if err = slice.SkipBits(8); err != nil {
		return out, err
	}
	prices, err := slice.LoadRef()
	if err != nil {
		return out, err
	}
	for i := 0; i < 4; i++ {
		v, e := prices.LoadBigCoins()
		if e != nil {
			return out, e
		}
		if i == 2 {
			out.MinimumStorage = v
		}
		if i == 3 {
			out.GasConsumption = v
		}
	}
	return out, nil
}
func (s *ServiceActorSession) ReadTokenForwardPrices(ctx context.Context) (TokenForwardPrices, error) {
	var out TokenForwardPrices
	root, err := s.tokenConfigAt(ctx, 25)
	if err != nil {
		return out, err
	}
	slice, err := tokenOrdinary(root)
	if err != nil {
		return out, err
	}
	tag, err := slice.LoadUInt(8)
	if err != nil || tag != 0xea {
		return out, errors.New("invalid forwarding prices tag")
	}
	for _, dst := range []*uint64{&out.LumpPrice, &out.BitPrice, &out.CellPrice} {
		*dst, err = slice.LoadUInt(64)
		if err != nil {
			return out, err
		}
	}
	if err = slice.SkipBits(32); err != nil {
		return out, err
	}
	frac, err := slice.LoadUInt(16)
	if err != nil {
		return out, err
	}
	out.FirstFraction = uint16(frac)
	if err = slice.SkipBits(16); err != nil {
		return out, err
	}
	return out, tokenExhausted(slice)
}
func (s *ServiceActorSession) ReadTokenGlobalID(ctx context.Context) (int32, error) {
	root, err := s.tokenConfigAt(ctx, 19)
	if err != nil {
		return 0, err
	}
	slice, err := tokenOrdinary(root)
	if err != nil {
		return 0, err
	}
	value, err := slice.LoadInt(32)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, errors.New("invalid zero global id")
	}
	return int32(value), tokenExhausted(slice)
}

// MatchTokenAssetPin binds an existing request's immutable route and quote to
// owner policy. It does not consult current recognition status: retirement stops
// new admissions, not completion of already admitted requests.
func MatchTokenAssetPin(route nativecore.ServiceActorTokenAssetRouteV1, decimals uint8, pins []TokenAssetPin) (TokenAssetPin, error) {
	if len(pins) == 0 || len(pins) > 2 {
		return TokenAssetPin{}, errors.New("one or two token pins are required")
	}
	master, ok := route.Master.RawStandard()
	if !ok || route.Master.Workchain != 0 {
		return TokenAssetPin{}, errors.New("invalid route master")
	}
	seen := map[string]bool{}
	var selected *TokenAssetPin
	for i := range pins {
		p := pins[i]
		if err := p.validate(); err != nil {
			return TokenAssetPin{}, err
		}
		if seen[p.Master] {
			return TokenAssetPin{}, errors.New("duplicate token pin")
		}
		seen[p.Master] = true
		if p.Master == master {
			selected = &p
		}
	}
	if selected == nil {
		return TokenAssetPin{}, errors.New("token master is not pinned")
	}
	hash, err := hexDigest(selected.WalletCodeHash, "tvm-cell-sha256:")
	if err != nil {
		return TokenAssetPin{}, err
	}
	if hash != route.WalletCodeHash || selected.Decimals != decimals || selected.BridgeConfigParam != route.BridgeConfigParam {
		return TokenAssetPin{}, errors.New("token route or decimals differ from pin")
	}
	if err = nativecore.ValidateServiceActorTokenWalletCodeGraph(route.WalletCode); err != nil {
		return TokenAssetPin{}, err
	}
	if !bytes.Equal(route.WalletCode.Hash(), route.WalletCodeHash[:]) {
		return TokenAssetPin{}, errors.New("route wallet code differs from hash")
	}
	return *selected, nil
}
