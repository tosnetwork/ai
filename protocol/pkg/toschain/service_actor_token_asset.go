package toschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/chain"
	"math/big"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const settlementAssetCellBudget = 1024

// TokenAssetPin is owner policy, never learned from the recognition dictionary.
// Each supported asset pins its namespace and all three audited releases.
type TokenAssetPin struct {
	Master            string
	Bridge            string
	BridgeConfigParam uint32
	Decimals          uint8
	SourceChainID     uint32
	SourceToken       [20]byte
	BridgeCodeHash    string
	MinterCodeHash    string
	WalletCodeHash    string
}

// SettlementAssetV1 is a strictly decoded recognition record.
type SettlementAssetV1 struct {
	Master               string
	Status               uint8
	Decimals             uint8
	MinterCodeHash       [32]byte
	WalletCodeHash       [32]byte
	MaxLiabilityPerActor *big.Int
	OriginKind           uint8
	Bridge               string
	SourceChainID        uint32
	SourceToken          [20]byte
}

// SettlementAssetsV1 retains every valid dictionary entry. Selecting supported
// assets is separate from strict decoding so unrelated entries are ignored.
type SettlementAssetsV1 struct {
	Entries        map[string]SettlementAssetV1
	ValueHash      string
	OverEntryLimit bool
}

// DecodeSettlementAssets strictly decodes the whole installed parameter. The
// governance entry-count limit is observable, not an admission failure.
func DecodeSettlementAssets(root *cell.Cell) (*SettlementAssetsV1, error) {
	if err := tokenCellBudget(root, settlementAssetCellBudget); err != nil {
		return nil, err
	}
	s, err := tokenOrdinary(root)
	if err != nil {
		return nil, err
	}
	tag, err := s.LoadUInt(8)
	if err != nil || tag != 1 {
		return nil, errors.New("invalid settlement-assets root tag")
	}
	dictionary, err := s.LoadDict(256)
	if err != nil {
		return nil, err
	}
	if err = tokenExhausted(s); err != nil {
		return nil, err
	}
	entries, err := tokenDictionaryEntries(dictionary, 256)
	if err != nil {
		return nil, err
	}
	result := &SettlementAssetsV1{Entries: make(map[string]SettlementAssetV1, len(entries)), ValueHash: "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), OverEntryLimit: len(entries) > 16}
	for _, entry := range entries {
		key, err := entry.Key.LoadSlice(256)
		if err != nil || tokenExhausted(entry.Key) != nil {
			return nil, errors.New("invalid settlement-assets key")
		}
		record, err := decodeSettlementAsset(entry.Value)
		if err != nil {
			return nil, err
		}
		record.Master = "0:" + hex.EncodeToString(key)
		if _, duplicate := result.Entries[record.Master]; duplicate {
			return nil, errors.New("duplicate settlement asset")
		}
		result.Entries[record.Master] = record
	}
	return result, nil
}

func decodeSettlementAsset(s *cell.Slice) (SettlementAssetV1, error) {
	var record SettlementAssetV1
	if s == nil || s.IsSpecial() {
		return record, errors.New("invalid settlement asset cell")
	}
	tag, err := s.LoadUInt(8)
	if err != nil || tag != 1 {
		return record, errors.New("invalid settlement asset tag")
	}
	status, err := s.LoadUInt(8)
	if err != nil || status < 1 || status > 3 {
		return record, errors.New("invalid settlement asset status")
	}
	record.Status = uint8(status)
	decimals, err := s.LoadUInt(8)
	if err != nil {
		return record, err
	}
	record.Decimals = uint8(decimals)
	raw, err := s.LoadSlice(256)
	if err != nil {
		return record, err
	}
	copy(record.MinterCodeHash[:], raw)
	raw, err = s.LoadSlice(256)
	if err != nil {
		return record, err
	}
	copy(record.WalletCodeHash[:], raw)
	if record.MaxLiabilityPerActor, err = tokenLoadCoins(s); err != nil || record.MaxLiabilityPerActor.Sign() <= 0 {
		return record, errors.New("invalid settlement asset liability cap")
	}
	origin, err := s.LoadRef()
	if err != nil {
		return record, err
	}
	if err = tokenExhausted(s); err != nil {
		return record, err
	}
	if origin.IsSpecial() {
		return record, errors.New("invalid settlement origin cell")
	}
	kind, err := origin.LoadUInt(8)
	if err != nil || (kind != 1 && kind != 2) {
		return record, errors.New("invalid settlement origin kind")
	}
	record.OriginKind = uint8(kind)
	raw, err = origin.LoadSlice(256)
	if err != nil {
		return record, err
	}
	record.Bridge = "-1:" + hex.EncodeToString(raw)
	chain, err := origin.LoadUInt(32)
	if err != nil {
		return record, err
	}
	record.SourceChainID = uint32(chain)
	raw, err = origin.LoadSlice(160)
	if err != nil {
		return record, err
	}
	copy(record.SourceToken[:], raw)
	return record, tokenExhausted(origin)
}

func (pin TokenAssetPin) validate() error {
	master, err := CanonicalAddress(pin.Master)
	if err != nil || master != pin.Master || !strings.HasPrefix(master, "0:") {
		return errors.New("invalid pinned token master")
	}
	bridge, err := CanonicalAddress(pin.Bridge)
	if err != nil || bridge != pin.Bridge || !strings.HasPrefix(bridge, "-1:") {
		return errors.New("invalid pinned token bridge")
	}
	if !tokenBridgeSlot(pin.BridgeConfigParam) || pin.SourceChainID == 0 || pin.SourceToken == [20]byte{} {
		return errors.New("invalid pinned source namespace")
	}
	for _, digest := range []string{pin.BridgeCodeHash, pin.MinterCodeHash, pin.WalletCodeHash} {
		if _, err := hexDigest(digest, "tvm-cell-sha256:"); err != nil {
			return err
		}
	}
	return nil
}
func tokenBridgeSlot(slot uint32) bool { return slot == 79 || slot == 81 || slot == 82 || slot == 83 }

// TokenAssetRecognition includes the exact parameter hash and entry-count
// observation used by an admission decision at one finalized checkpoint.
type TokenAssetRecognition struct {
	Record           SettlementAssetV1
	ConfigHash       string
	EntryCount       int
	OverEntryLimit   bool
	Checkpoint       uint64
	BridgeConfigHash string
}

// ReadTokenAsset self-verifies only an explicitly pinned, active asset. Every
// account, config and getter read shares this session's checkpoint and block.
func (s *ServiceActorSession) ReadTokenAsset(ctx context.Context, master string, pins []TokenAssetPin) (*TokenAssetRecognition, error) {
	if s == nil || s.reader == nil || len(pins) == 0 || len(pins) > 2 {
		return nil, errors.New("one or two token asset pins are required")
	}
	pins = append([]TokenAssetPin(nil), pins...)
	var selected *TokenAssetPin
	seen := make(map[string]bool, len(pins))
	for index := range pins {
		pin := &pins[index]
		if err := pin.validate(); err != nil {
			return nil, err
		}
		if seen[pin.Master] {
			return nil, errors.New("duplicate pinned token master")
		}
		seen[pin.Master] = true
		if pin.Master == master {
			selected = pin
		}
	}
	if selected == nil {
		return nil, errors.New("token master is not pinned")
	}
	param, err := s.tokenConfigAt(ctx, 84)
	if err != nil {
		return nil, err
	}
	assets, err := DecodeSettlementAssets(param)
	if err != nil {
		return nil, err
	}
	record, found := assets.Entries[master]
	if !found {
		return nil, errors.New("pinned token master is not recognized")
	}
	if record.Status != 1 {
		return nil, errors.New("pinned token is not active")
	}
	minterHash, _ := hexDigest(selected.MinterCodeHash, "tvm-cell-sha256:")
	walletHash, _ := hexDigest(selected.WalletCodeHash, "tvm-cell-sha256:")
	if record.Decimals != selected.Decimals || record.MinterCodeHash != minterHash || record.WalletCodeHash != walletHash || record.OriginKind != 1 || record.Bridge != selected.Bridge || record.SourceChainID != selected.SourceChainID || record.SourceToken != selected.SourceToken {
		return nil, errors.New("recognition record differs from the pinned asset")
	}
	bridgeParam, err := s.tokenConfigAt(ctx, int(selected.BridgeConfigParam))
	if err != nil {
		return nil, err
	}
	configuredBridge, err := decodeTokenBridgeAddress(bridgeParam)
	if err != nil || configuredBridge != selected.Bridge {
		return nil, errors.New("bridge configuration names another bridge")
	}
	vote, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, selected.Bridge, s.seqno, s.reader.network, selected.BridgeCodeHash)
	})
	if err != nil {
		return nil, err
	}
	if err = s.pin(vote); err != nil {
		return nil, err
	}
	if !vote.Found {
		return nil, errors.New("pinned bridge is not deployed")
	}
	bridgeData, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, err
	}
	codes, err := decodeTokenBridgeCodes(bridgeData)
	if err != nil {
		return nil, err
	}
	if codes.SourceChainID != record.SourceChainID || !bytes.Equal(codes.Minter.Hash(), minterHash[:]) || !bytes.Equal(codes.Wallet.Hash(), walletHash[:]) {
		return nil, errors.New("bridge-stored codes differ from pinned releases")
	}
	derived, err := deriveTokenMinter(record, codes.Minter, codes.Wallet)
	if err != nil || derived != master {
		return nil, errors.New("token master address does not derive from the pinned bridge codes")
	}
	minter, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, master, s.seqno, s.reader.network, selected.MinterCodeHash)
	})
	if err != nil {
		return nil, err
	}
	if err = s.pin(minter); err != nil {
		return nil, err
	}
	if !minter.Found {
		return nil, errors.New("recognized minter is not deployed")
	}
	minterData, err := decodeCellBOC(minter.Data)
	if err != nil {
		return nil, err
	}
	if err = verifyTokenMinterData(minterData, record, codes.Wallet); err != nil {
		return nil, err
	}
	stack, err := s.actorGetter(ctx, master, "get_wrapped_token_data", nil)
	if err != nil {
		return nil, err
	}
	if len(stack) != 3 || stack[0].Kind != "num" || stack[1].Kind != "num" || stack[2].Kind != "num" || stack[0].Number == nil || stack[1].Number == nil || stack[2].Number == nil || stack[0].Number.Cmp(new(big.Int).SetUint64(uint64(record.SourceChainID))) != 0 || stack[1].Number.Cmp(new(big.Int).SetBytes(record.SourceToken[:])) != 0 || stack[2].Number.Cmp(new(big.Int).SetUint64(uint64(record.Decimals))) != 0 {
		return nil, errors.New("minter wrapped-token data differs from recognition")
	}
	return &TokenAssetRecognition{Record: record, ConfigHash: assets.ValueHash, EntryCount: len(assets.Entries), OverEntryLimit: assets.OverEntryLimit, Checkpoint: s.seqno, BridgeConfigHash: "tvm-cell-sha256:" + hex.EncodeToString(bridgeParam.Hash())}, nil
}

type tokenConfigResult struct {
	Absent bool   `json:"-"`
	Type   string `json:"@type"`
	Config struct {
		Type  string `json:"@type"`
		Bytes string `json:"bytes"`
	} `json:"config"`
	BlockID     blockID `json:"block_id"`
	StateProof  string  `json:"state_proof"`
	ConfigProof string  `json:"config_proof"`
}

func (s *ServiceActorSession) tokenConfigAt(ctx context.Context, param int) (*cell.Cell, error) {
	result, found, err := s.tokenOptionalConfigAt(ctx, param)
	if err == nil && !found {
		err = errors.New("configuration parameter is absent")
	}
	return result, err
}

func (s *ServiceActorSession) tokenOptionalConfigAt(ctx context.Context, param int) (*cell.Cell, bool, error) {
	result, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (tokenConfigResult, error) {
		var result tokenConfigResult
		if err := node.client.Call(ctx, "getConfigParam", struct {
			Param     int    `json:"param"`
			Seqno     uint64 `json:"seqno"`
			WithProof bool   `json:"with_proof"`
		}{param, s.seqno, true}, &result); err != nil {
			var rpcErr *chain.RPCError
			if errors.As(err, &rpcErr) && rpcErr.Code == -32004 {
				var details struct {
					Reason    string `json:"reason"`
					Retryable bool   `json:"retryable"`
				}
				if json.Unmarshal(rpcErr.Data, &details) == nil && details.Reason == "CONFIG_PARAM_ABSENT" {
					return tokenConfigResult{Absent: true}, nil
				}
			}
			return result, err
		}
		if result.Type != "configInfo" || result.Config.Type != "tvm.cell" || result.BlockID.Type != "tos.blockIdExt" || result.BlockID.Workchain != -1 || result.BlockID.Seqno != s.seqno {
			return result, errors.New("configuration read is not checkpoint-finalized")
		}
		if _, _, err := blockHashes(result.BlockID); err != nil {
			return result, err
		}
		// Proof serialization is not a quorum vote; block and config cells are.
		result.StateProof, result.ConfigProof = "", ""
		return result, nil
	})
	if err != nil {
		return nil, false, err
	}
	if result.Absent {
		return nil, false, nil
	}
	root, file, err := blockHashes(result.BlockID)
	if err != nil {
		return nil, false, err
	}
	if err = s.pinHashes(root, file); err != nil {
		return nil, false, err
	}
	rootCell, err := decodeCellBOC(result.Config.Bytes)
	return rootCell, true, err
}

type tokenBridgeCodes struct {
	Minter, Wallet *cell.Cell
	SourceChainID  uint32
}

func decodeTokenBridgeCodes(root *cell.Cell) (tokenBridgeCodes, error) {
	var out tokenBridgeCodes
	s, err := tokenOrdinary(root)
	if err != nil {
		return out, err
	}
	if err = s.SkipBits(64); err != nil {
		return out, err
	}
	chain, err := s.LoadUInt(32)
	if err != nil {
		return out, err
	}
	out.SourceChainID = uint32(chain)
	if err = s.SkipBits(160 + 32 + 64 + 2); err != nil {
		return out, err
	}
	if _, err = s.LoadAddr(); err != nil {
		return out, err
	}
	if out.Minter, err = s.LoadRefCell(); err != nil {
		return out, err
	}
	if out.Wallet, err = s.LoadRefCell(); err != nil {
		return out, err
	}
	if err = nativecore.ValidateServiceActorTokenWalletCodeGraph(out.Wallet); err != nil {
		return out, err
	}
	if err = tokenCellBudget(out.Minter, 8192); err != nil {
		return out, err
	}
	state, err := s.LoadRef()
	if err != nil {
		return out, err
	}
	if err = tokenExhausted(s); err != nil {
		return out, err
	}
	if _, err = state.LoadUInt(64); err != nil {
		return out, err
	}
	if _, err = state.LoadDict(64); err != nil {
		return out, err
	}
	if _, err = state.LoadDict(256); err != nil {
		return out, err
	}
	if _, err = state.LoadUInt(32); err != nil {
		return out, err
	}
	if err = tokenExhausted(state); err != nil {
		return out, err
	}
	if out.Minter.GetType() != cell.OrdinaryCellType || out.Wallet.GetType() != cell.OrdinaryCellType {
		return out, errors.New("bridge code is not ordinary")
	}
	return out, nil
}

func decodeTokenBridgeAddress(root *cell.Cell) (string, error) {
	s, err := tokenOrdinary(root)
	if err != nil {
		return "", err
	}
	tag, err := s.LoadUInt(8)
	if err != nil || tag != 1 {
		return "", errors.New("unsupported bridge configuration")
	}
	raw, err := s.LoadSlice(256)
	if err != nil {
		return "", err
	}
	bridge := "-1:" + hex.EncodeToString(raw)
	if err = s.SkipBits(256); err != nil {
		return "", err
	}
	oracles, err := s.LoadDict(256)
	if err != nil {
		return "", err
	}
	entries, err := tokenDictionaryEntries(oracles, 256)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if _, err = entry.Value.LoadSlice(256); err != nil {
			return "", err
		}
		if err = tokenExhausted(entry.Value); err != nil {
			return "", err
		}
	}
	if _, err = s.LoadUInt(8); err != nil {
		return "", err
	}
	prices, err := s.LoadRef()
	if err != nil {
		return "", err
	}
	for i := 0; i < 6; i++ {
		if _, err = tokenLoadCoins(prices); err != nil {
			return "", err
		}
	}
	if err = tokenExhausted(prices); err != nil {
		return "", err
	}
	if _, err = s.LoadSlice(256); err != nil {
		return "", err
	}
	return bridge, tokenExhausted(s)
}

func deriveTokenMinter(record SettlementAssetV1, minterCode, walletCode *cell.Cell) (string, error) {
	bridge, err := nativecore.StandardAddress(record.Bridge)
	if err != nil {
		return "", err
	}
	content := cell.BeginCell()
	if err = content.StoreUInt(uint64(record.SourceChainID), 32); err != nil {
		return "", err
	}
	if err = content.StoreSlice(record.SourceToken[:], 160); err != nil {
		return "", err
	}
	if err = content.StoreUInt(uint64(record.Decimals), 8); err != nil {
		return "", err
	}
	settlement := cell.BeginCell()
	if err = settlement.StoreSlice(bridge.Bits, bridge.BitLen); err != nil {
		return "", err
	}
	if err = settlement.StoreUInt(0, 64+64+1); err != nil {
		return "", err
	}
	// The larger zero fields are stored in chunks because uint64 cannot hold them.
	for i := 0; i < 4; i++ {
		if err = settlement.StoreUInt(0, 64); err != nil {
			return "", err
		}
	}
	if err = settlement.StoreUInt(0, 32); err != nil {
		return "", err
	}
	for i := 0; i < 3; i++ {
		if err = settlement.StoreBoolBit(false); err != nil {
			return "", err
		}
	}
	data := cell.BeginCell()
	if err = data.StoreBigInt(new(big.Int), 128); err != nil {
		return "", err
	}
	for i := 0; i < 4; i++ {
		if err = data.StoreBigCoins(new(big.Int)); err != nil {
			return "", err
		}
	}
	for _, ref := range []*cell.Cell{content.EndCell(), walletCode, settlement.EndCell()} {
		if err = data.StoreRef(ref); err != nil {
			return "", err
		}
	}
	init := cell.BeginCell()
	if err = init.StoreUInt(0, 2); err != nil {
		return "", err
	}
	if err = init.StoreMaybeRef(minterCode); err != nil {
		return "", err
	}
	if err = init.StoreMaybeRef(data.EndCell()); err != nil {
		return "", err
	}
	if err = init.StoreBoolBit(false); err != nil {
		return "", err
	}
	return "0:" + hex.EncodeToString(init.EndCell().Hash()), nil
}

func verifyTokenMinterData(root *cell.Cell, record SettlementAssetV1, walletCode *cell.Cell) error {
	s, err := tokenOrdinary(root)
	if err != nil {
		return err
	}
	if _, err = s.LoadBigInt(128); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		if _, err = tokenLoadCoins(s); err != nil {
			return err
		}
	}
	content, err := s.LoadRef()
	if err != nil {
		return err
	}
	wallet, err := s.LoadRefCell()
	if err != nil {
		return err
	}
	state, err := s.LoadRef()
	if err != nil {
		return err
	}
	if err = tokenExhausted(s); err != nil {
		return err
	}
	chain, err := content.LoadUInt(32)
	if err != nil {
		return err
	}
	token, err := content.LoadSlice(160)
	if err != nil {
		return err
	}
	decimals, err := content.LoadUInt(8)
	if err != nil {
		return err
	}
	if tokenExhausted(content) != nil || chain != uint64(record.SourceChainID) || !bytes.Equal(token, record.SourceToken[:]) || decimals != uint64(record.Decimals) || !bytes.Equal(wallet.Hash(), walletCode.Hash()) {
		return errors.New("deployed minter content differs from recognition")
	}
	address, err := tokenLoadAddress(state)
	standard, canonical := address.RawStandard()
	if err != nil || !canonical || standard != record.Bridge {
		return errors.New("deployed minter names another bridge")
	}
	if err = state.SkipBits(64 + 64 + 1 + 64 + 64 + 64 + 64 + 32); err != nil {
		return err
	}
	for _, width := range []uint{64, 64, 256} {
		if _, err = state.LoadDict(width); err != nil {
			return err
		}
	}
	return tokenExhausted(state)
}

func tokenOrdinary(root *cell.Cell) (*cell.Slice, error) {
	if root == nil || root.GetType() != cell.OrdinaryCellType {
		return nil, errors.New("expected an ordinary cell")
	}
	return root.BeginParse()
}
func tokenExhausted(s *cell.Slice) error {
	if s == nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return errors.New("trailing cell data")
	}
	return nil
}
func tokenLoadCoins(s *cell.Slice) (*big.Int, error) {
	n, err := s.LoadUInt(4)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return new(big.Int), nil
	}
	raw, err := s.LoadSlice(uint(n) * 8)
	if err != nil || len(raw) == 0 || raw[0] == 0 {
		return nil, errors.New("non-canonical Coins")
	}
	return new(big.Int).SetBytes(raw), nil
}
func tokenCellBudget(root *cell.Cell, limit int) error {
	if root == nil {
		return errors.New("missing cell")
	}
	seen := make(map[[32]byte]bool)
	work := []*cell.Cell{root}
	for len(work) > 0 {
		last := len(work) - 1
		c := work[last]
		work = work[:last]
		if c.GetType() != cell.OrdinaryCellType {
			return errors.New("non-ordinary configuration cell")
		}
		var hash [32]byte
		copy(hash[:], c.Hash())
		if seen[hash] {
			continue
		}
		seen[hash] = true
		if len(seen) > limit {
			return errors.New("configuration cell budget exceeded")
		}
		for i := 0; i < int(c.RefsNum()); i++ {
			ref, err := c.PeekRef(i)
			if err != nil {
				return err
			}
			work = append(work, ref)
		}
	}
	return nil
}

// DeriveTokenMinterAddress exposes the independent client derivation used to
// bind a recognition record to codes read from its pinned live bridge.
func DeriveTokenMinterAddress(record SettlementAssetV1, minterCode, walletCode *cell.Cell) (string, error) {
	if minterCode == nil || walletCode == nil || record.OriginKind != 1 {
		return "", errors.New("incomplete bridged token identity")
	}
	return deriveTokenMinter(record, minterCode, walletCode)
}

// tokenDictionaryEntries validates branch arity as well as leaf values. A
// generic dictionary walk may otherwise discard trailing bits on fork cells.
func tokenDictionaryEntries(dictionary *cell.Dictionary, width uint) ([]cell.DictKV, error) {
	root := dictionary.AsCell()
	if root == nil {
		return nil, nil
	}
	type frame struct {
		root      *cell.Cell
		remaining uint
		prefix    *big.Int
	}
	work := []frame{{root, width, new(big.Int)}}
	var result []cell.DictKV
	visited := 0
	for len(work) > 0 {
		visited++
		if visited > settlementAssetCellBudget*4 {
			return nil, errors.New("dictionary traversal budget exceeded")
		}
		at := len(work) - 1
		current := work[at]
		work = work[:at]
		s, err := tokenOrdinary(current.root)
		if err != nil {
			return nil, err
		}
		n, label, err := tokenDictionaryLabel(s, current.remaining)
		if err != nil {
			return nil, err
		}
		prefix := new(big.Int).Lsh(current.prefix, n)
		prefix.Or(prefix, label)
		if n == current.remaining {
			key := cell.BeginCell()
			if err = key.StoreBigUInt(prefix, width); err != nil {
				return nil, err
			}
			slice, err := key.EndCell().BeginParse()
			if err != nil {
				return nil, err
			}
			result = append(result, cell.DictKV{Key: slice, Value: s})
			continue
		}
		if s.BitsLeft() != 0 || s.RefsNum() != 2 {
			return nil, errors.New("dictionary fork has trailing data or wrong arity")
		}
		left, err := s.LoadRefCell()
		if err != nil {
			return nil, err
		}
		right, err := s.LoadRefCell()
		if err != nil {
			return nil, err
		}
		base := new(big.Int).Lsh(prefix, 1)
		next := current.remaining - n - 1
		work = append(work, frame{right, next, new(big.Int).Or(new(big.Int).Set(base), big.NewInt(1))}, frame{left, next, base})
	}
	return result, nil
}
func tokenDictionaryLabel(s *cell.Slice, remaining uint) (uint, *big.Int, error) {
	first, err := s.LoadBoolBit()
	if err != nil {
		return 0, nil, err
	}
	var length uint64
	var repeated bool
	var value bool
	if !first {
		for {
			bit, err := s.LoadBoolBit()
			if err != nil {
				return 0, nil, err
			}
			if !bit {
				break
			}
			length++
			if length > uint64(remaining) {
				return 0, nil, errors.New("dictionary label exceeds key")
			}
		}
	} else {
		same, err := s.LoadBoolBit()
		if err != nil {
			return 0, nil, err
		}
		repeated = same
		if same {
			value, err = s.LoadBoolBit()
			if err != nil {
				return 0, nil, err
			}
		}
		bits := uint(0)
		for n := remaining; n != 0; n >>= 1 {
			bits++
		}
		length, err = s.LoadUInt(bits)
		if err != nil {
			return 0, nil, err
		}
		if length > uint64(remaining) {
			return 0, nil, errors.New("dictionary label exceeds key")
		}
	}
	if repeated {
		result := new(big.Int)
		if value {
			result.Sub(new(big.Int).Lsh(big.NewInt(1), uint(length)), big.NewInt(1))
		}
		return uint(length), result, nil
	}
	result, err := s.LoadBigUInt(uint(length))
	return uint(length), result, err
}
