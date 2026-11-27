package railgate

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type tokenSession interface {
	Session
	serviceactor.TokenSession
	serviceactor.TokenLifecycleSession
}

// verifyToken retains atomic token units and the exact asset throughout the
// shared at-most-once gate. A token claim never falls back to native admission.
func (v *Verifier) verifyToken(ctx context.Context, claim Claim, budget time.Duration, started time.Time) (*Verified, error) {
	if len(v.config.TokenPins) == 0 || v.config.CheckExecution == nil {
		return nil, errors.New("railgate: token execution needs pins and a safety guard")
	}
	proposal := claim.Package.Proposal
	validated, err := quoteexchange.ValidateTokenPortable(v.config.Network, &nativev1.RequestQuoteProposalRequest{CapabilityId: proposal.CapabilityId, CapabilityVersion: proposal.CapabilityVersion, BuyerAddress: claim.BuyerWallet}, claim.Package)
	if err != nil {
		return nil, err
	}
	supported := false
	for _, pin := range v.config.TokenPins {
		if pin.Master == "0:"+hex.EncodeToString(validated.Rail.Asset.Master.AccountId) && pin.WalletCodeHash == validated.Rail.Asset.WalletCodeHash && pin.MinterCodeHash == validated.Rail.Asset.Master.CodeHash && uint32(pin.Decimals) == validated.Rail.Asset.Decimals {
			supported = true
		}
	}
	if !supported {
		return nil, errors.New("railgate: execution token differs from independent pins")
	}
	limit := time.Duration(validated.Manifest.Limits.WallClockMillis) * time.Millisecond
	if limit <= 0 || limit > v.config.ExecutionBudget {
		return nil, errors.New("railgate: token execution exceeds budget")
	}
	quote, commitment, err := nativecore.BuildAcceptedTokenQuoteCommitment(v.config.Network, proposal)
	if err != nil {
		return nil, err
	}
	var quoteHash, requestHash [32]byte
	copy(quoteHash[:], quote.Hash())
	requestCell, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: quoteHash, ExecutionID: claim.ExecutionID, InputDigest: claim.InputDigest})
	if err != nil {
		return nil, err
	}
	copy(requestHash[:], requestCell.Hash())
	raw, err := v.config.Reader.BeginSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResolverUnavailable, err)
	}
	session, ok := raw.(tokenSession)
	if !ok {
		return nil, errors.New("railgate: finalized session lacks token reads")
	}
	evidence, err := serviceactor.GatherTokenEvidence(ctx, session, v.config.Network, v.config.Manifests, proposal.CapabilityId, proposal.CapabilityVersion, v.config.TokenPins, false)
	if err != nil {
		return nil, err
	}
	actor := validated.Rail.Actor
	if evidence.Actor == nil || evidence.Actor.Address != actor {
		return nil, errors.New("railgate: token actor differs from quote")
	}
	history, err := session.TokenHistory(ctx, actor, nil)
	if err != nil {
		return nil, err
	}
	if history == nil || history.Result != toschain.HistoryComplete || history.Head != evidence.Actor.LastTransaction {
		return nil, errors.New("railgate: incomplete finalized token history")
	}
	var call *toschain.TokenActorTransaction
	for i := range history.Transactions {
		tx := &history.Transactions[i]
		n := tx.Notification
		if !tx.TookEffect || tx.Kind != toschain.ActorTxCall || tx.Sender != evidence.Actor.OwnWallet || n == nil || n.From != claim.BuyerWallet || n.Payload == nil || n.Payload.RequestHash != requestHash || n.Payload.ExpectedTermsHash != validated.Rail.TermsHash {
			continue
		}
		if call != nil {
			return nil, errors.New("railgate: duplicate token request hash")
		}
		call = tx
	}
	if call == nil || call.LT != claim.Call.LT || call.Hash != claim.Call.Hash {
		return nil, errors.New("railgate: token call does not match its exact transaction")
	}
	acceptance, err := serviceactor.ProveAcceptance(ctx, session, &evidence.Evidence, toschain.ActorTransaction{LT: call.LT, Hash: call.Hash})
	if err != nil {
		return nil, err
	}
	existing, err := serviceactor.VerifyTokenExistingRequest(evidence, v.codeHash, &validated.Rail, proposal, *call, claim.BuyerWallet, requestHash, acceptance)
	if err != nil {
		return nil, err
	}
	if existing.Snapshot.RequestID != claim.RequestID {
		return nil, errors.New("railgate: token request id differs")
	}
	requests, err := serviceactor.ReplayTokenRequests(evidence.Actor, history, session.ChainTime())
	if err != nil {
		return nil, err
	}
	request := requests[claim.RequestID]
	if request == nil || request.Call.LT != call.LT || request.Call.Hash != call.Hash || request.Status != serviceactor.StatusPending {
		return nil, errors.New("railgate: token request is not pending")
	}
	if err = checkSlack(currentTime(session.ChainTime(), started, v.config.Now()), request.Snapshot.ResponseDeadline, budget); err != nil {
		return nil, err
	}
	if err = v.config.CheckExecution(ctx, session); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExecutionGuard, err)
	}
	var master [32]byte
	if len(validated.Rail.Asset.Master.AccountId) != 32 {
		return nil, errors.New("railgate: invalid token master")
	}
	copy(master[:], validated.Rail.Asset.Master.AccountId)
	return &Verified{AssetMaster: &master, Checkpoint: session.Checkpoint(), ChainTime: session.ChainTime(), Actor: actor, RequestID: claim.RequestID, RequestHash: requestHash, QuoteCommitment: commitment, ExecutionID: claim.ExecutionID, InputDigest: claim.InputDigest, BuyerWallet: claim.BuyerWallet, CapabilityID: proposal.CapabilityId, Version: proposal.CapabilityVersion, ProviderAgentID: proposal.ProviderAgentId, ManifestDigest: proposal.ManifestDigest, Manifest: validated.Manifest, Transport: validated.TransportBinding, Price: new(big.Int).Set(request.Snapshot.Terms.PricePerCall), ResponseDeadline: request.Snapshot.ResponseDeadline, Call: claim.Call}, nil
}
