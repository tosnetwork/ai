package toschain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
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
	// The contract's bridge_wallet_terms: the positive slot; if it does not
	// parse (absent included), the negative slot; if neither parses, the
	// 0.3 TOS reserve allowance and zero wallet gas. A read that cannot be
	// finalized is an error, never a value that "does not parse".
	for _, slot := range []int{int(param), -int(param)} {
		root, found, err := s.tokenOptionalConfigAt(ctx, slot)
		if err != nil {
			return out, err
		}
		if !found {
			continue
		}
		if terms, ok := parseTokenBridgeWalletTerms(root); ok {
			return terms, nil
		}
	}
	return TokenWalletTerms{GasConsumption: new(big.Int), MinimumStorage: big.NewInt(TokenWalletAllowance)}, nil
}

// TokenWalletAllowance is the contract's TOKEN_WALLET_ALLOWANCE: the reserve
// it prices when neither bridge parameter slot parses.
const TokenWalletAllowance = 300_000_000

// parseTokenBridgeWalletTerms is the contract's bridge_wallet_terms_of: 8 +
// 256 + 256 bits skipped, the oracles dictionary, 8 bits, then the prices
// reference, whose third and fourth Coins are the storage reserve and the
// wallet gas. Like the contract it does not require the cells to end there.
func parseTokenBridgeWalletTerms(root *cell.Cell) (TokenWalletTerms, bool) {
	var out TokenWalletTerms
	slice, err := tokenOrdinary(root)
	if err != nil {
		return out, false
	}
	if err = slice.SkipBits(8 + 256 + 256); err != nil {
		return out, false
	}
	if _, err = slice.LoadMaybeRef(); err != nil {
		return out, false
	}
	if err = slice.SkipBits(8); err != nil {
		return out, false
	}
	prices, err := slice.LoadRef()
	if err != nil {
		return out, false
	}
	values := make([]*big.Int, 4)
	for i := range values {
		if values[i], err = prices.LoadBigCoins(); err != nil {
			return out, false
		}
	}
	return TokenWalletTerms{MinimumStorage: values[2], GasConsumption: values[3]}, true
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
