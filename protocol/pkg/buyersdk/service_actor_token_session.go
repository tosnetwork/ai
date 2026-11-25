package buyersdk

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// TokenBuildSession supplies one strict-majority finalized checkpoint. A result
// never opens a second session or combines a live getter with historical state.
type TokenBuildSession interface {
	Checkpoint() uint64
	ChainTime() time.Time
	BlockHashes() (string, string)
	ResolveTokenActor(context.Context, string, []toschain.TokenAssetPin, bool) (*toschain.ResolvedTokenActor, error)
	ReadTokenWallet(context.Context, string, nativecore.ServiceActorTokenAssetRouteV1) (*toschain.TokenWalletAccount, bool, error)
	GetTokenFundingPrices(context.Context, string) ([6]*big.Int, error)
	GetTokenAcceptingTokens(context.Context, string) (bool, error)
	ReadTokenWalletTerms(context.Context, uint32) (toschain.TokenWalletTerms, error)
	ReadTokenForwardPrices(context.Context) (toschain.TokenForwardPrices, error)
	ReadTokenGlobalID(context.Context) (int32, error)
}

// PrepareTokenAtSession reads all inputs through the caller's already-open
// finalized session. Recognition is required only when admitting a new call;
// payout and recovery retain the immutable route stored by the actor.
func PrepareTokenAtSession(ctx context.Context, session TokenBuildSession, actor string, pins []toschain.TokenAssetPin, request TokenBuildRequest, verify func([]byte, []byte, [32]byte) error) (*TokenPreparedMessage, error) {
	if session == nil || (reflect.ValueOf(session).Kind() == reflect.Pointer && reflect.ValueOf(session).IsNil()) {
		return nil, errors.New("token build session is required")
	}
	seq, clock := session.Checkpoint(), session.ChainTime()
	if seq > math.MaxUint32 || clock.Unix() < 0 || clock.Unix() > math.MaxUint32 {
		return nil, errors.New("token checkpoint is out of range")
	}
	resolved, err := session.ResolveTokenActor(ctx, actor, pins, request.Operation == "call")
	if err != nil {
		return nil, err
	}
	if resolved == nil || resolved.Account == nil || resolved.Account.Data == nil {
		return nil, errors.New("token actor is absent")
	}
	root, file := session.BlockHashes()
	if root == "" || file == "" || resolved.Checkpoint != seq || resolved.BlockRoot != root || resolved.BlockFile != file {
		return nil, errors.New("token actor has no matching checkpoint identity")
	}
	a := resolved.Account
	d := a.Data
	profile := ""
	switch a.CodeHash {
	case "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]):
		profile = "release"
	case "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTokenTestProfileCodeHash[:]):
		profile = "test"
	default:
		return nil, errors.New("unrecognized token actor code")
	}
	hash, err := nativecore.ServiceActorTokenTermsHash(nativecore.TokenTermsOfPolicy(d.Policy, d.Route))
	if err != nil {
		return nil, err
	}
	snapshot := TokenBuildSnapshot{Actor: a.Address, CodeProfile: profile, ReadAt: TokenReadAt{Seqno: uint32(seq), RootHash: strings.TrimPrefix(root, "sha256:"), GenUtime: uint32(clock.Unix())}, Balance: new(big.Int).SetUint64(a.BalanceNano), Data: d, TermsHash: hash, OwnWallet: a.OwnWallet, VerifyResponse: verify}
	snapshot.FundingPrices, err = session.GetTokenFundingPrices(ctx, actor)
	if err != nil {
		return nil, err
	}
	_, snapshot.CurrentAttestorKeyStored = d.AttestorKeys[d.Policy.AttestorKeyID]
	sender, err := tokenRaw(request.Sender, false)
	if err != nil {
		return nil, err
	}
	callerHash, err := sender.SliceHash()
	if err != nil {
		return nil, err
	}
	snapshot.CallerLive = d.CallerLiveCounts[callerHash]
	snapshot.CallerReturned = d.CallerReturnedCounts[callerHash]
	if pending, ok := d.Pending[request.ID]; ok {
		snapshot.Request = &nativecore.ServiceActorRequestViewV1{Caller: pending.Caller, Price: pending.Price, StorageFee: pending.StorageFee, CleanupBounty: pending.CleanupBounty, ResponseDeadline: pending.ResponseDeadline, RefundClaimDeadline: pending.RefundClaimDeadline, PolicyVersion: pending.PolicyVersion, RequestHash: pending.RequestHash, TermsHash: pending.TermsHash, HasAttestor: pending.HasAttestor, AttestorKeyID: pending.AttestorKeyID}
		if pending.HasAttestor {
			snapshot.RequestAttestorKey = append([]byte(nil), d.AttestorKeys[pending.AttestorKeyID].Key...)
		}
	}
	if value, ok := d.Refunds[request.ID]; ok {
		snapshot.Refund = &value
	}
	if value, ok := d.Returned[request.ID]; ok {
		snapshot.Returned = &value
	}
	if value, ok := d.Payouts[request.ID]; ok {
		snapshot.Payout = &value
	}
	if request.Operation == "call" {
		if resolved.Recognition == nil {
			return nil, errors.New("token recognition is required")
		}
		r := resolved.Recognition.Record
		for _, pin := range pins {
			if pin.Master == r.Master {
				rawHash, decodeErr := hex.DecodeString(strings.TrimPrefix(pin.WalletCodeHash, "tvm-cell-sha256:"))
				if decodeErr != nil || len(rawHash) != 32 || !strings.HasPrefix(pin.WalletCodeHash, "tvm-cell-sha256:") {
					return nil, errors.New("invalid pinned token wallet code hash")
				}
				var pinnedHash [32]byte
				copy(pinnedHash[:], rawHash)
				snapshot.AssetPin = &TokenAssetPin{Master: pin.Master, WalletCodeHash: pinnedHash, Decimals: pin.Decimals}
				break
			}
		}
		// ResolveTokenActor verifies the independently pinned wallet code before
		// returning recognition; the builder repeats the asset identity checks.
		snapshot.Asset = &TokenRecognizedAsset{Status: r.Status, WalletCodeHash: r.WalletCodeHash, Decimals: r.Decimals, MaxLiabilityPerActor: r.MaxLiabilityPerActor}
		snapshot.AcceptingTokens, err = session.GetTokenAcceptingTokens(ctx, actor)
		if err != nil {
			return nil, err
		}
		terms, e := session.ReadTokenWalletTerms(ctx, d.Route.BridgeConfigParam)
		if e != nil {
			return nil, e
		}
		snapshot.WalletTerms = &TokenWalletTerms{GasConsumption: terms.GasConsumption, MinimumStorage: terms.MinimumStorage}
		prices, e := session.ReadTokenForwardPrices(ctx)
		if e != nil {
			return nil, e
		}
		snapshot.ForwardPrices = &TokenForwardPrices{LumpPrice: prices.LumpPrice, BitPrice: prices.BitPrice, CellPrice: prices.CellPrice, FirstFraction: prices.FirstFraction}
		wallet, found, e := session.ReadTokenWallet(ctx, request.Sender, d.Route)
		if e != nil {
			return nil, e
		}
		if !found || wallet == nil {
			return nil, errors.New("sender token wallet is absent")
		}
		snapshot.SenderTokenBalance = wallet.BalanceAtomic
	}
	if request.Operation == "top-up-wallet" || request.Operation == "recover-surplus" {
		wallet, found, e := session.ReadTokenWallet(ctx, actor, d.Route)
		if e != nil {
			return nil, e
		}
		snapshot.OwnWalletDeployed = found
		if found {
			if wallet == nil || wallet.Address != a.OwnWallet {
				return nil, errors.New("actor wallet identity differs")
			}
			snapshot.OwnWalletBalance = wallet.BalanceAtomic
		}
	}
	if request.Operation == "respond" && snapshot.Request != nil && snapshot.Request.HasAttestor {
		global, e := session.ReadTokenGlobalID(ctx)
		if e != nil {
			return nil, e
		}
		snapshot.GlobalID = &global
	}
	endRoot, endFile := session.BlockHashes()
	if session.Checkpoint() != seq || !session.ChainTime().Equal(clock) || endRoot != root || endFile != file {
		return nil, errors.New("token build reads changed checkpoint")
	}
	return PrepareTokenMessage(snapshot, request)
}

var _ TokenBuildSession = (*toschain.ServiceActorSession)(nil)
