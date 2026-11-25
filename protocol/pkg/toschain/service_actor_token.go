package toschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// TokenActorAccount is exact account data, not a get-method projection.
// Reading this account alone never reads recognition, so suspended assets
// remain inspectable and their existing payouts remain actionable.
type TokenActorAccount struct {
	Address         string
	CodeHash        string
	BalanceNano     uint64
	Data            *nativecore.ServiceActorTokenDataV1
	OwnWallet       string
	LastTransaction ActorTxID
}

// ReadTokenActor decodes and validates a token actor at this session's one
// finalized checkpoint. The reader's code hash must be the chosen token rail
// release; the caller performs its separate admission recognition read.
func (s *ServiceActorSession) ReadTokenActor(ctx context.Context, actor string) (*TokenActorAccount, bool, error) {
	if s == nil || s.reader == nil {
		return nil, false, errors.New("token actor session is not configured")
	}
	canonical, err := CanonicalAddress(actor)
	if err != nil || canonical != actor || !strings.HasPrefix(canonical, "0:") {
		return nil, false, errors.New("token actor must be canonical on workchain 0")
	}
	vote, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, canonical, s.seqno, s.reader.network, s.reader.codeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if err = s.pin(vote); err != nil {
		return nil, false, err
	}
	if !vote.Found {
		return nil, false, nil
	}
	root, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, err
	}
	data, err := nativecore.DecodeServiceActorTokenData(root)
	if err != nil {
		return nil, false, err
	}
	if err = nativecore.ValidateServiceActorTokenLiveState(data); err != nil {
		return nil, false, err
	}
	wallet, err := nativecore.DeriveServiceActorTokenWallet(actor, data.Route)
	if err != nil {
		return nil, false, err
	}
	lt, hash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, err
	}
	return &TokenActorAccount{Address: canonical, CodeHash: s.reader.codeHash, BalanceNano: vote.Balance, Data: data, OwnWallet: wallet, LastTransaction: ActorTxID{LT: lt, Hash: hex.EncodeToString(hash)}}, true, nil
}

// ResolvedTokenActor separates optional admission recognition from account
// inspection. Both, when requested, are resolved through this same session.
type ResolvedTokenActor struct {
	Account     *TokenActorAccount
	Recognition *TokenAssetRecognition
	Checkpoint  uint64
	BlockRoot   string
	BlockFile   string
}

func (s *ServiceActorSession) ResolveTokenActor(ctx context.Context, actor string, pins []TokenAssetPin, requireRecognition bool) (*ResolvedTokenActor, error) {
	pins = append([]TokenAssetPin(nil), pins...)
	account, found, err := s.ReadTokenActor(ctx, actor)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("token actor is not deployed")
	}
	result := &ResolvedTokenActor{Account: account, Checkpoint: s.seqno}
	if requireRecognition {
		master, ok := account.Data.Route.Master.RawStandard()
		if !ok || !strings.HasPrefix(master, "0:") {
			return nil, errors.New("invalid token actor master")
		}
		recognition, err := s.ReadTokenAsset(ctx, master, pins)
		if err != nil {
			return nil, err
		}
		if recognition.Record.WalletCodeHash != account.Data.Route.WalletCodeHash {
			return nil, errors.New("actor wallet code differs from recognition")
		}
		var selected *TokenAssetPin
		for index := range pins {
			if pins[index].Master == master {
				selected = &pins[index]
				break
			}
		}
		if selected == nil || account.Data.Route.BridgeConfigParam != selected.BridgeConfigParam {
			return nil, errors.New("actor bridge slot differs from pinned asset")
		}
		result.Recognition = recognition
	}
	result.BlockRoot, result.BlockFile = s.BlockHashes()
	return result, nil
}

// TokenWalletAccount is the independently derived wallet and its exact balances.
type TokenWalletAccount struct {
	Address         string
	Owner           string
	Master          string
	CodeHash        string
	BalanceAtomic   *big.Int
	BalanceNano     uint64
	LastTransaction ActorTxID
}

// ReadTokenWallet checks code and stored owner/master at the same checkpoint
// as its caller's actor and recognition reads.
func (s *ServiceActorSession) ReadTokenWallet(ctx context.Context, owner string, route nativecore.ServiceActorTokenAssetRouteV1) (*TokenWalletAccount, bool, error) {
	if s == nil || s.reader == nil {
		return nil, false, errors.New("token session is required")
	}
	address, err := nativecore.DeriveServiceActorTokenWallet(owner, route)
	if err != nil {
		return nil, false, err
	}
	codeHash := "tvm-cell-sha256:" + hex.EncodeToString(route.WalletCodeHash[:])
	vote, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, address, s.seqno, s.reader.network, codeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if err = s.pin(vote); err != nil {
		return nil, false, err
	}
	if !vote.Found {
		return nil, false, nil
	}
	root, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, err
	}
	slice, err := tokenOrdinary(root)
	if err != nil {
		return nil, false, err
	}
	amount, err := tokenLoadCoins(slice)
	if err != nil {
		return nil, false, err
	}
	storedOwner, err := tokenLoadAddress(slice)
	if err != nil {
		return nil, false, err
	}
	storedMaster, err := tokenLoadAddress(slice)
	if err != nil {
		return nil, false, err
	}
	expectedOwner, err := nativecore.StandardAddress(owner)
	if err != nil {
		return nil, false, err
	}
	if !storedOwner.Equal(expectedOwner) || !storedMaster.Equal(route.Master) {
		return nil, false, errors.New("token wallet names another owner or master")
	}
	code, err := slice.LoadRefCell()
	if err != nil || !bytes.Equal(code.Hash(), route.WalletCodeHash[:]) {
		return nil, false, errors.New("token wallet stores another wallet code")
	}
	settlement, err := slice.LoadRef()
	if err != nil {
		return nil, false, err
	}
	if err = settlement.SkipBits(64 + 64 + 1 + 32 + 64 + 64 + 64); err != nil {
		return nil, false, err
	}
	if _, err = settlement.LoadDict(64); err != nil {
		return nil, false, err
	}
	if err = settlement.SkipBits(64 + 64); err != nil {
		return nil, false, err
	}
	if _, err = settlement.LoadDict(64); err != nil {
		return nil, false, err
	}
	if err = tokenExhausted(settlement); err != nil {
		return nil, false, err
	}
	count, err := slice.LoadUInt(16)
	if err != nil {
		return nil, false, err
	}
	refusals, err := slice.LoadDict(64)
	if err != nil {
		return nil, false, err
	}
	if err = tokenExhausted(slice); err != nil {
		return nil, false, err
	}
	entries, err := tokenDictionaryEntries(refusals, 64)
	if err != nil || uint64(len(entries)) != count {
		return nil, false, errors.New("wallet refusal count differs from its entries")
	}
	for _, entry := range entries {
		if _, err = tokenLoadCoins(entry.Value); err != nil {
			return nil, false, err
		}
		if err = tokenExhausted(entry.Value); err != nil {
			return nil, false, err
		}
	}
	lt, hash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, err
	}
	master, _ := route.Master.RawStandard()
	return &TokenWalletAccount{Address: address, Owner: owner, Master: master, CodeHash: codeHash, BalanceAtomic: amount, BalanceNano: vote.Balance, LastTransaction: ActorTxID{LT: lt, Hash: hex.EncodeToString(hash)}}, true, nil
}

func tokenLoadAddress(s *cell.Slice) (nativecore.MsgAddressV1, error) {
	before := s.Copy()
	if _, err := s.LoadAddr(); err != nil {
		return nativecore.MsgAddressV1{}, err
	}
	bits := before.BitsLeft() - s.BitsLeft()
	data, err := before.LoadSlice(bits)
	if err != nil {
		return nativecore.MsgAddressV1{}, err
	}
	builder := cell.BeginCell()
	if err = builder.StoreSlice(data, bits); err != nil {
		return nativecore.MsgAddressV1{}, err
	}
	return nativecore.DecodeMsgAddressCell(builder.EndCell())
}
