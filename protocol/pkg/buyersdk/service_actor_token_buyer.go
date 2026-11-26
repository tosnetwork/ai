package buyersdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// TokenMessageSender submits the exact prepared token wallet body. It must not
// rebuild the transfer or change the confirmed funding amounts.
type TokenMessageSender interface {
	PreflightToken(context.Context, *TokenPreparedMessage) error
	SendToken(context.Context, *TokenPreparedMessage) error
}

type tokenBuyerSession interface {
	ServiceActorSession
	TokenBuildSession
	serviceactor.TokenSession
	serviceactor.TokenLifecycleSession
}

func isTokenPackage(p *nativev1.QuoteProposalPackageV1) bool {
	return p != nil && p.Proposal != nil && (p.Proposal.Asset != nil || p.Proposal.PriceAtomic != "")
}

func (b *ServiceActorBuyer) tokenAdmission(ctx context.Context, v *quoteexchange.ValidatedToken) (tokenBuyerSession, *serviceactor.TokenAdmission, error) {
	s, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return nil, nil, err
	}
	session, ok := s.(tokenBuyerSession)
	if !ok {
		return nil, nil, errors.New("buyer session does not support finalized token reads")
	}
	evidence, err := serviceactor.GatherTokenEvidence(ctx, session, b.config.Network, b.config.Manifests, v.Proposal.CapabilityId, v.Proposal.CapabilityVersion, b.config.TokenPins, true)
	if err != nil {
		return nil, nil, err
	}
	admission, err := serviceactor.VerifyTokenAdmission(evidence, b.codeHash, &v.Rail, v.Proposal, b.config.BuyerWallet)
	return session, admission, err
}

func (b *ServiceActorBuyer) prepareToken(ctx context.Context, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1, executionID, inputDigest [32]byte) (CallRecord, error) {
	if b.config.TokenSender == nil {
		return CallRecord{}, errors.New("token sender is not configured")
	}
	now := b.config.Now()
	v, err := quoteexchange.ValidateToken(b.config.Network, request, value, now)
	if err != nil {
		return CallRecord{}, err
	}
	session, admission, err := b.tokenAdmission(ctx, v)
	if err != nil {
		return CallRecord{}, err
	}
	quote, commitment, err := nativecore.BuildAcceptedTokenQuoteCommitment(b.config.Network, v.Proposal)
	if err != nil {
		return CallRecord{}, err
	}
	var qh [32]byte
	copy(qh[:], quote.Hash())
	req, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: qh, ExecutionID: executionID, InputDigest: inputDigest})
	if err != nil {
		return CallRecord{}, err
	}
	var rh [32]byte
	copy(rh[:], req.Hash())
	query, err := b.queryID()
	if err != nil {
		return CallRecord{}, err
	}
	prepared, err := PrepareTokenAtSession(ctx, session, admission.Binding.Actor, b.config.TokenPins, TokenBuildRequest{Operation: "call", Sender: b.config.BuyerWallet, QueryID: query, RequestHash: rh, ExpectedTermsHash: v.Rail.TermsHash}, nil)
	if err != nil {
		return CallRecord{}, err
	}
	raw, err := canonicalPackageBytes(value)
	if err != nil {
		return CallRecord{}, err
	}
	if err = railwork.CheckCarriablePackage(len(raw), v.TransportBinding); err != nil {
		return CallRecord{}, err
	}
	r := CallRecord{Schema: tokenCallRecordSchema, Rail: nativecore.ServiceActorTokenRail,
		AssetMaster: "0:" + hex.EncodeToString(v.Rail.Asset.Master.AccountId), AssetWalletCodeHash: v.Rail.Asset.WalletCodeHash, AssetDecimals: uint8(v.Rail.Asset.Decimals), PriceAtomic: v.Rail.PriceAtomic.String(), PreparedTokenMessage: prepared,
		RequestHash: hex.EncodeToString(rh[:]), QueryID: query, NetworkID: b.config.Network.NetworkId, GenesisRootHash: b.config.Network.GenesisRootHash, GenesisFileHash: b.config.Network.GenesisFileHash, BuyerWallet: b.config.BuyerWallet, Actor: admission.Binding.Actor, ActorCodeHash: b.config.ActorCodeHash,
		CapabilityID: v.Proposal.CapabilityId, CapabilityVersion: v.Proposal.CapabilityVersion, PackageBase64: base64.StdEncoding.EncodeToString(raw), BuyerAddressInReq: request.BuyerAddress, AcceptedQuoteBOC: base64.StdEncoding.EncodeToString(quote.ToBOCWithOptions(cell.BOCSerializeOptions{})), QuoteCommitment: commitment,
		ExecutionID: hex.EncodeToString(executionID[:]), InputDigest: hex.EncodeToString(inputDigest[:]), TermsHash: hex.EncodeToString(v.Rail.TermsHash[:]), PolicyVersion: v.Rail.PolicyVersion, StorageFeeNanoTOS: v.Rail.StorageFee.String(), AttestorKeyID: mldsa44.KeyIDText(admission.Binding.AttestorKeyID), PaymentNanoTOS: prepared.ValueNanotos,
		ExpiresAtUnix: v.Proposal.ExpiresAtUnixSeconds, Phase: PhasePrepared, CreatedUnix: now.Unix(), UpdatedUnix: now.Unix(), ResponseSLASeconds: admission.Policy.ResponseSLA, RefundClaimWindowSeconds: admission.Policy.RefundClaimWindow, CleanupBountyNanoTOS: admission.Policy.CleanupBounty.String()}
	if err = b.config.Journal.Create(r, b.config.Limits, now); err != nil {
		return CallRecord{}, err
	}
	return r, nil
}

func (b *ServiceActorBuyer) reconstructToken(r CallRecord) (*quoteexchange.ValidatedToken, [32]byte, error) {
	var rh [32]byte
	if r.NetworkID != b.config.Network.NetworkId || r.GenesisRootHash != b.config.Network.GenesisRootHash || r.GenesisFileHash != b.config.Network.GenesisFileHash || r.BuyerWallet != b.config.BuyerWallet || r.ActorCodeHash != b.config.ActorCodeHash || r.Schema != tokenCallRecordSchema || r.Rail != nativecore.ServiceActorTokenRail || r.PreparedTokenMessage == nil {
		return nil, rh, errors.New("token journal belongs to another network, buyer or release")
	}
	raw, err := base64.StdEncoding.DecodeString(r.PackageBase64)
	if err != nil {
		return nil, rh, err
	}
	p := &nativev1.QuoteProposalPackageV1{}
	if err = proto.Unmarshal(raw, p); err != nil {
		return nil, rh, err
	}
	if _, err = canonicalPackageBytes(p); err != nil {
		return nil, rh, err
	}
	v, err := quoteexchange.ValidateTokenPortable(b.config.Network, &nativev1.RequestQuoteProposalRequest{CapabilityId: r.CapabilityID, CapabilityVersion: r.CapabilityVersion, BuyerAddress: r.BuyerAddressInReq}, p)
	if err != nil {
		return nil, rh, err
	}
	if r.BuyerAddressInReq != r.BuyerWallet || r.ExpiresAtUnix != v.Proposal.ExpiresAtUnixSeconds || r.PolicyVersion != v.Rail.PolicyVersion || r.AttestorKeyID != mldsa44.KeyIDText(v.Rail.AttestorKeyID) {
		return nil, rh, errors.New("token journal policy or expiry differs from Quote")
	}
	q, commitment, err := nativecore.BuildAcceptedTokenQuoteCommitment(b.config.Network, v.Proposal)
	if err != nil || commitment != r.QuoteCommitment || base64.StdEncoding.EncodeToString(q.ToBOCWithOptions(cell.BOCSerializeOptions{})) != r.AcceptedQuoteBOC {
		return nil, rh, errors.New("token Accepted Quote does not reproduce")
	}
	var qh, execution, input [32]byte
	copy(qh[:], q.Hash())
	for dst, text := range map[*[32]byte]string{&execution: r.ExecutionID, &input: r.InputDigest, &rh: r.RequestHash} {
		raw, err := hex.DecodeString(text)
		if err != nil || len(raw) != 32 {
			return nil, rh, errors.New("invalid token journal digest")
		}
		copy(dst[:], raw)
	}
	req, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: qh, ExecutionID: execution, InputDigest: input})
	if err != nil || !bytes.Equal(req.Hash(), rh[:]) {
		return nil, rh, errors.New("token request hash does not reproduce")
	}
	if v.Rail.Actor != r.Actor || hex.EncodeToString(v.Rail.TermsHash[:]) != r.TermsHash || v.Rail.PriceAtomic.String() != r.PriceAtomic || v.Rail.StorageFee.String() != r.StorageFeeNanoTOS || "0:"+hex.EncodeToString(v.Rail.Asset.Master.AccountId) != r.AssetMaster || v.Rail.Asset.WalletCodeHash != r.AssetWalletCodeHash || uint8(v.Rail.Asset.Decimals) != r.AssetDecimals || r.PreparedTokenMessage.ValueNanotos != r.PaymentNanoTOS {
		return nil, rh, errors.New("token journal rail does not reproduce")
	}
	return v, rh, nil
}

func sameTokenMessage(a, b *TokenPreparedMessage) bool {
	return a != nil && b != nil && a.Version == b.Version && a.Operation == b.Operation && a.Rail == b.Rail && a.CodeProfile == b.CodeProfile && a.Actor == b.Actor && a.Sender == b.Sender && a.Destination == b.Destination && a.ValueNanotos == b.ValueNanotos && a.Bounce == b.Bounce && a.BodyBOC == b.BodyBOC && a.BodyHash == b.BodyHash
}

func (b *ServiceActorBuyer) callToken(ctx context.Context, r CallRecord) (CallRecord, error) {
	if b.config.TokenSender == nil {
		return r, errors.New("token sender is not configured")
	}
	v, rh, err := b.reconstructToken(r)
	if err != nil {
		return r, err
	}
	if uint64(b.config.Now().Unix()) >= r.ExpiresAtUnix {
		return r, ErrQuoteExpired
	}
	s, _, err := b.tokenAdmission(ctx, v)
	if err != nil {
		return r, err
	}
	forward, ok := new(big.Int).SetString(r.PreparedTokenMessage.Details["forward_tos_amount"], 10)
	if !ok {
		return r, errors.New("invalid confirmed token funding")
	}
	value, ok := new(big.Int).SetString(r.PaymentNanoTOS, 10)
	if !ok {
		return r, errors.New("invalid confirmed token wallet value")
	}
	fresh, err := PrepareTokenAtSession(ctx, s, r.Actor, b.config.TokenPins, TokenBuildRequest{Operation: "call", Sender: r.BuyerWallet, QueryID: r.QueryID, RequestHash: rh, ExpectedTermsHash: v.Rail.TermsHash, ForwardTOS: forward, WalletValue: value}, nil)
	if err != nil {
		return r, err
	}
	if !sameTokenMessage(r.PreparedTokenMessage, fresh) {
		return r, errors.New("token funding changed; withdraw this preparation and prepare again")
	}
	r, err = b.config.Journal.BeginSend(r.RequestHash, b.config.Limits, b.config.Now())
	if err != nil {
		return r, err
	}
	sendCtx, cancel := context.WithDeadline(ctx, time.Unix(int64(r.ExpiresAtUnix), 0))
	defer cancel()
	defer func() {
		if v := recover(); v != nil {
			_, _ = b.config.Journal.Transition(r.RequestHash, []CallPhase{PhaseSending}, func(x *CallRecord) error { x.Phase = PhaseAmbiguous; x.UpdatedUnix = b.config.Now().Unix(); return nil })
			panic(v)
		}
	}()
	err = b.config.TokenSender.PreflightToken(sendCtx, fresh)
	if err == nil {
		err = b.config.TokenSender.SendToken(sendCtx, fresh)
	}
	next := PhaseSubmitted
	if errors.Is(err, ErrCallNotStarted) {
		next = PhasePrepared
	} else if err != nil {
		next = PhaseAmbiguous
	}
	updated, writeErr := b.config.Journal.Transition(r.RequestHash, []CallPhase{PhaseSending}, func(x *CallRecord) error { x.Phase = next; x.UpdatedUnix = b.config.Now().Unix(); return nil })
	if writeErr != nil {
		return r, writeErr
	}
	return updated, err
}

func (b *ServiceActorBuyer) resolveToken(ctx context.Context, r CallRecord) (*RequestReport, error) {
	v, rh, err := b.reconstructToken(r)
	if err != nil {
		return nil, err
	}
	raw, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return nil, err
	}
	s, ok := raw.(tokenBuyerSession)
	if !ok {
		return nil, errors.New("buyer session does not support token history")
	}
	e, err := serviceactor.GatherTokenEvidence(ctx, s, b.config.Network, b.config.Manifests, r.CapabilityID, r.CapabilityVersion, b.config.TokenPins, false)
	if err != nil {
		return nil, err
	}
	history, err := s.TokenHistory(ctx, r.Actor, nil)
	if err != nil {
		return nil, err
	}
	requests, err := serviceactor.ReplayTokenRequests(e.Actor, history, s.ChainTime())
	if err != nil {
		return nil, err
	}
	report := &RequestReport{Checkpoint: s.Checkpoint(), ChainTime: s.ChainTime().Unix(), Phase: r.Phase}
	var matches []toschain.TokenActorTransaction
	for _, tx := range history.Transactions {
		n := tx.Notification
		if n != nil && tx.Sender == e.Actor.OwnWallet && n.QueryID == r.QueryID && n.From == r.BuyerWallet && n.AmountAtomic == r.PriceAtomic && n.Payload != nil && n.Payload.RequestHash == rh && n.Payload.ExpectedTermsHash == v.Rail.TermsHash {
			matches = append(matches, tx)
		}
	}
	if len(matches) == 0 {
		return report, nil
	}
	if len(matches) != 1 {
		return nil, errors.New("multiple finalized token notifications match this purchase")
	}
	call := matches[0]
	report.Found = true
	report.CallTransaction = &toschain.ActorTxID{LT: call.LT, Hash: call.Hash}
	var admitted *serviceactor.TokenRequest
	for _, req := range requests {
		if req.Call.Hash == call.Hash {
			if admitted != nil {
				return nil, errors.New("duplicate token request admission")
			}
			admitted = req
		}
	}
	if admitted == nil {
		refusals, err := serviceactor.ResolveTokenFundingRefusals(e.Actor, history)
		if err != nil {
			return nil, err
		}
		for _, refusal := range refusals {
			if refusal.Call.Hash == call.Hash {
				report.Status = serviceactor.Status(refusal.State)
				report.PayoutID = &refusal.ActivePayoutID
				report.ReturnedID = &refusal.PayoutID
				report.RequiredAction = "wait for authenticated funding return"
				if refusal.State == "returned" {
					report.RequiredAction = "claim-returned"
				}
				if refusal.State == "surplus" {
					updated, err := b.markOutcome(r, PhaseFundingSurplus, nil, toschain.ActorTransaction{LT: call.LT, Hash: call.Hash})
					if err != nil {
						return nil, err
					}
					report.Phase = updated.Phase
					report.PayoutID, report.ReturnedID = nil, nil
					report.RequiredAction = ""
				}
				if refusal.State == "funding_returned" {
					updated, err := b.markOutcome(r, PhaseRefused, nil, toschain.ActorTransaction{LT: call.LT, Hash: call.Hash})
					if err != nil {
						return nil, err
					}
					report.Phase = updated.Phase
					report.RequiredAction = ""
				}
				return report, nil
			}
		}
		return report, errors.New("token notification has neither admission nor authenticated funding outcome")
	}
	acceptance, err := serviceactor.ProveAcceptance(ctx, s, &e.Evidence, toschain.ActorTransaction{LT: call.LT, Hash: call.Hash})
	if err != nil {
		return nil, err
	}
	existing, err := serviceactor.VerifyTokenExistingRequest(e, b.codeHash, &v.Rail, v.Proposal, call, r.BuyerWallet, rh, acceptance)
	if err != nil {
		return nil, err
	}
	id := existing.Snapshot.RequestID
	updated, err := b.markOutcome(r, PhaseAdmitted, &id, toschain.ActorTransaction{LT: call.LT, Hash: call.Hash})
	if err != nil {
		return nil, err
	}
	report.Phase = updated.Phase
	report.RequestID = &id
	report.Status = admitted.Status
	report.RequiredAction = serviceactor.TokenRequestAction(admitted.Status)
	report.PayoutID = &admitted.PayoutID
	report.ReturnedID = &admitted.ReturnedID
	report.ResponseDeadline = admitted.Snapshot.ResponseDeadline
	report.RefundClaimDeadline = admitted.Snapshot.RefundClaimDeadline
	report.TokenOutcome = admitted.Terminal
	report.ResponseHash = admitted.ResponseHash
	return report, nil
}

// sendTokenLifecycle derives the destination and funding from one finalized
// snapshot, persists the exact message before custody, and never guesses that
// a paying return has arrived. Earlier attempts require exact actor execution.
func (b *ServiceActorBuyer) sendTokenLifecycle(ctx context.Context, r CallRecord, operation string) (CallRecord, error) {
	if b.config.TokenSender == nil {
		return r, ErrNoLifecycleSender
	}
	switch operation {
	case "expire", "claim-refund", "sweep-expired-request", "claim-returned", "sweep-returned", "recheck-payout":
	default:
		return r, errors.New("unsupported token lifecycle operation")
	}
	if _, _, err := b.reconstructToken(r); err != nil {
		return r, err
	}
	if r.Phase != PhaseAdmitted && r.Phase != PhaseSubmitted && r.Phase != PhaseAmbiguous {
		return r, errors.New("token purchase has no lifecycle liability")
	}
	raw, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return r, err
	}
	session, ok := raw.(tokenBuyerSession)
	if !ok {
		return r, errors.New("missing token lifecycle session")
	}
	account, found, err := session.ReadTokenActor(ctx, r.Actor)
	if err != nil {
		return r, err
	}
	if !found || account == nil {
		return r, errors.New("missing token actor")
	}
	history, err := session.TokenHistory(ctx, r.Actor, nil)
	if err != nil {
		return r, err
	}
	requests, err := serviceactor.ReplayTokenRequests(account, history, session.ChainTime())
	if err != nil {
		return r, err
	}
	var current *serviceactor.TokenRequest
	for _, q := range requests {
		if q.Call.Hash == r.CallTransactionHex && r.CallTransactionHex != "" {
			current = q
		}
	}
	var id uint64
	switch operation {
	case "claim-returned", "sweep-returned", "recheck-payout":
		if current != nil {
			if operation == "recheck-payout" {
				if current.Status != serviceactor.StatusPaying {
					return r, errors.New("token request is not paying")
				}
				id = current.PayoutID
			} else {
				if current.Status != serviceactor.StatusReturned {
					return r, errors.New("token request is not returned")
				}
				id = current.ReturnedID
			}
		}
		if current == nil {
			refusals, err := serviceactor.ResolveTokenFundingRefusals(account, history)
			if err != nil {
				return r, err
			}
			for _, f := range refusals {
				n := f.Call.Notification
				if n != nil && n.QueryID == r.QueryID && n.From == r.BuyerWallet && n.Payload != nil && hex.EncodeToString(n.Payload.RequestHash[:]) == r.RequestHash {
					if operation == "recheck-payout" && f.State == "paying" {
						id = f.ActivePayoutID
					} else if operation != "recheck-payout" && f.State == "returned" {
						id = f.PayoutID
					}
				}
			}
		}
		if id == 0 {
			return r, errors.New("no matching token payout or returned entry")
		}
	default:
		if current == nil || r.RequestID == nil {
			return r, errors.New("no admitted token request")
		}
		id = *r.RequestID
	}
	for _, old := range r.Lifecycle {
		if old.Operation != operation || old.Phase == PhasePrepared {
			continue
		}
		executed := false
		for _, tx := range history.Transactions {
			if tx.Sender == r.BuyerWallet && tx.QueryID == old.QueryID {
				executed = true
			}
		}
		if !executed {
			return r, ErrLifecycleUnsettled
		}
	}
	query, err := b.queryID()
	if err != nil {
		return r, err
	}
	request := TokenBuildRequest{Operation: operation, Sender: r.BuyerWallet, QueryID: query, ID: id}
	if operation == "claim-refund" || operation == "claim-returned" {
		request.Destination = r.BuyerWallet
	}
	prepared, err := PrepareTokenAtSession(ctx, session, r.Actor, b.config.TokenPins, request, nil)
	if err != nil {
		return r, err
	}
	if len(prepared.Warnings) != 0 {
		return r, ErrLifecycleUnsettled
	}
	now := b.config.Now()
	record, err := b.config.Journal.beginTokenLifecycle(r, LifecycleSend{Operation: operation, QueryID: query, Phase: PhaseSending, SentUnix: now.Unix(), PreparedTokenMessage: prepared}, b.config.Limits, now)
	if err != nil {
		return r, err
	}
	finish := func(phase CallPhase) (CallRecord, error) {
		return b.config.Journal.Transition(r.RequestHash, []CallPhase{record.Phase}, func(x *CallRecord) error {
			for i := range x.Lifecycle {
				if x.Lifecycle[i].QueryID == query && x.Lifecycle[i].Phase == PhaseSending {
					x.Lifecycle[i].Phase = phase
				}
			}
			x.UpdatedUnix = b.config.Now().Unix()
			return nil
		})
	}
	defer func() {
		if value := recover(); value != nil {
			_, _ = finish(PhaseAmbiguous)
			panic(value)
		}
	}()
	sendCtx, cancel := context.WithTimeout(ctx, LifecycleSendTimeout)
	defer cancel()
	sendErr := b.config.TokenSender.PreflightToken(sendCtx, prepared)
	if sendErr == nil {
		sendErr = b.config.TokenSender.SendToken(sendCtx, prepared)
	}
	phase := PhaseSubmitted
	if errors.Is(sendErr, ErrCallNotStarted) {
		phase = PhasePrepared
	} else if sendErr != nil {
		phase = PhaseAmbiguous
	}
	updated, err := finish(phase)
	if err != nil {
		return record, err
	}
	return updated, sendErr
}
