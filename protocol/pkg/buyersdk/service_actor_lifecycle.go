package buyersdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// Lifecycle operations: the buyer's refund duties on a Service Actor
// request (SERVICE_ACTOR_TVM_V1 sections 7.3 to 7.5). Their names are the
// tosctl operation names.
const (
	LifecycleExpire      = "expire"
	LifecycleClaimRefund = "claim-refund"
	LifecycleSweep       = "sweep-expired-request"
)

func validLifecycle(operation string) bool {
	switch operation {
	case LifecycleExpire, LifecycleClaimRefund, LifecycleSweep:
		return true
	}
	return false
}

// LifecycleIntent is one lifecycle send. Destination is the claim_refund
// destination; the buyer always sets it to its own wallet.
type LifecycleIntent struct {
	Operation   string
	Actor       string
	RequestID   uint64
	QueryID     uint64
	Destination string
}

// ServiceActorLifecycleSender hands a lifecycle send to custody.
// ErrCallNotStarted means custody was never started; any other error
// leaves the outcome ambiguous.
type ServiceActorLifecycleSender interface {
	SendLifecycle(ctx context.Context, intent LifecycleIntent) error
}

// checkSubmissionEndpoints requires every endpoint tosctl would submit
// through to be a verified endpoint of the verified network.
func (s *TOSCTLServiceActorSender) checkSubmissionEndpoints(ctx context.Context) error {
	endpoints, err := effectiveChainEndpoints(s.runner.config)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, endpoint := range s.endpoints.Endpoints() {
		allowed[endpoint] = true
	}
	for _, endpoint := range endpoints {
		if !allowed[endpoint] {
			return fmt.Errorf("tosctl would submit through %s, which is not a verified endpoint", endpoint)
		}
		if err := s.endpoints.CheckEndpointGenesis(ctx, endpoint); err != nil {
			return fmt.Errorf("tosctl endpoint %s is not on the verified network: %w", endpoint, err)
		}
	}
	return nil
}

// SendLifecycle runs `tosctl agent service send --operation <op>` for one
// request. claim-refund always names the buyer's destination. tosctl attaches
// the operation's allowance; its unused part returns.
func (s *TOSCTLServiceActorSender) SendLifecycle(ctx context.Context, intent LifecycleIntent) error {
	if s == nil || ctx == nil || !validLifecycle(intent.Operation) || !isRawAddress(intent.Actor) || intent.QueryID == 0 {
		return ErrCallNotStarted
	}
	if intent.Operation == LifecycleClaimRefund && !isRawAddress(intent.Destination) {
		return ErrCallNotStarted
	}
	if err := s.checkSubmissionEndpoints(ctx); err != nil {
		return errors.Join(ErrCallNotStarted, err)
	}
	args := []string{"agent", "service", "send", "--operation", intent.Operation, "--address", intent.Actor,
		"--from", s.wallet, "--query-id", strconv.FormatUint(intent.QueryID, 10),
		"--request-id", strconv.FormatUint(intent.RequestID, 10)}
	if intent.Operation == LifecycleClaimRefund {
		args = append(args, "--destination", intent.Destination)
	}
	output, err := s.runWithPath(ctx, append(args, "--yes")...)
	if errors.Is(err, ErrCallNotStarted) {
		return err
	}
	if err != nil {
		return fmt.Errorf("tosctl %s outcome is ambiguous: %w", intent.Operation, err)
	}
	if !bytes.Contains(output, []byte("Service Actor "+intent.Operation+" message submitted to")) {
		return fmt.Errorf("tosctl %s outcome is ambiguous: no submission report", intent.Operation)
	}
	return nil
}

// LifecycleSend is one lifecycle send in a call's journal record. Its phase
// is sending, submitted or ambiguous, like a call's. Finalized history, not
// this entry, says whether the send took effect; the entry only bounds how
// often the buyer sends.
type LifecycleSend struct {
	Operation string    `json:"operation"`
	QueryID   uint64    `json:"query_id"`
	Phase     CallPhase `json:"phase"`
	SentUnix  int64     `json:"sent_unix"`
	// WalletSeqno is the buyer wallet's seqno at a finalized checkpoint read
	// before the send.
	WalletSeqno uint32 `json:"wallet_seqno"`
	// ValidUntilBoundUnix bounds the valid_until of the wallet message the
	// send signs: the message can execute only before it.
	ValidUntilBoundUnix int64 `json:"valid_until_bound_unix"`
}

// Lifecycle send timing. custody is given LifecycleSendTimeout to sign and
// broadcast; the wallet message it signs is valid for WalletMessageLifetime
// from signing (tosctl's wallet message lifetime); LifecycleClockSkew covers
// the difference between the local clock and chain time. Their sum bounds
// the message's valid_until.
const (
	LifecycleSendTimeout  = 3 * time.Minute
	WalletMessageLifetime = 2 * time.Minute
	LifecycleClockSkew    = 5 * time.Minute
	// LifecycleDeliveryAllowance bounds how long a wallet's internal message
	// to the actor may take after the wallet accepted it.
	LifecycleDeliveryAllowance = 10 * time.Minute
)

// LifecycleValidUntilBound is the valid_until bound of a send started at
// sent.
func LifecycleValidUntilBound(sent time.Time) int64 {
	return sent.Add(LifecycleSendTimeout + WalletMessageLifetime + LifecycleClockSkew).Unix()
}

var (
	// ErrNoLifecycleSender reports a buyer configured without one.
	ErrNoLifecycleSender = errors.New("the buyer has no lifecycle sender")
	// ErrLifecycleUnsettled reports an earlier send of the same operation
	// whose message may still execute: it is not sent again until finalized
	// state proves that the earlier message executed or can never execute.
	ErrLifecycleUnsettled = errors.New("an earlier send of this operation may still execute")
)

// SendLifecycle sends one lifecycle operation for an admitted call. The
// send is journaled before custody starts. A crash or a panic during it
// leaves the entry ambiguous. The destination of a claim_refund is always
// the buyer wallet, which made the call.
//
// An operation already handed to custody is sent again only when every
// earlier send of it is settled at a fresh finalized checkpoint (see
// lifecycleSettled); otherwise SendLifecycle returns ErrLifecycleUnsettled
// and sends nothing.
func (b *ServiceActorBuyer) SendLifecycle(ctx context.Context, requestHash, operation string) (CallRecord, error) {
	if b.config.Lifecycle == nil {
		return CallRecord{}, ErrNoLifecycleSender
	}
	if !validLifecycle(operation) {
		return CallRecord{}, fmt.Errorf("unknown lifecycle operation %q", operation)
	}
	before, err := b.config.Journal.Read(requestHash)
	if err != nil {
		return CallRecord{}, err
	}
	session, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return before, errors.Join(ErrCallNotStarted, err)
	}
	seqno, err := session.WalletSeqno(ctx, b.config.BuyerWallet)
	if err != nil {
		return before, errors.Join(ErrCallNotStarted, fmt.Errorf("read the buyer wallet seqno: %w", err))
	}
	if err := b.lifecycleSettled(ctx, session, before, operation, seqno); err != nil {
		return before, err
	}
	queryID, err := b.queryID()
	if err != nil {
		return CallRecord{}, err
	}
	now := b.config.Now()
	record, err := b.config.Journal.Transition(requestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		if r.RequestID == nil {
			return errors.New("an admitted call without a request ID has no lifecycle duties")
		}
		if len(r.Lifecycle) != len(before.Lifecycle) {
			return ErrLifecycleUnsettled
		}
		r.Lifecycle = append(r.Lifecycle, LifecycleSend{Operation: operation, QueryID: queryID, Phase: PhaseSending,
			SentUnix: now.Unix(), WalletSeqno: seqno, ValidUntilBoundUnix: LifecycleValidUntilBound(now)})
		r.UpdatedUnix = now.Unix()
		return nil
	})
	if err != nil {
		return record, err
	}
	finish := func(phase CallPhase) (CallRecord, error) {
		return b.config.Journal.Transition(requestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
			for index := range r.Lifecycle {
				if r.Lifecycle[index].QueryID == queryID && r.Lifecycle[index].Phase == PhaseSending {
					r.Lifecycle[index].Phase = phase
				}
			}
			r.UpdatedUnix = b.config.Now().Unix()
			return nil
		})
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			_, _ = finish(PhaseAmbiguous)
			panic(recovered)
		}
	}()
	// The deadline bounds when custody can sign, and so the message's
	// valid_until that the journal entry records.
	sendContext, cancel := context.WithDeadline(ctx, now.Add(LifecycleSendTimeout))
	defer cancel()
	sendErr := b.config.Lifecycle.SendLifecycle(sendContext, LifecycleIntent{Operation: operation, Actor: record.Actor,
		RequestID: *record.RequestID, QueryID: queryID, Destination: record.BuyerWallet})
	phase := PhaseSubmitted
	switch {
	case errors.Is(sendErr, ErrCallNotStarted):
		phase = PhasePrepared
	case sendErr != nil:
		phase = PhaseAmbiguous
	}
	updated, err := finish(phase)
	if err != nil {
		return record, err
	}
	return updated, sendErr
}

// lifecycleSettled requires every earlier send of operation that was handed
// to custody to be settled at the session checkpoint, whose chain time is
// the clock. An earlier send is settled when one of these holds:
//
//  1. the actor's finalized history since the call holds a transaction from
//     the buyer wallet carrying the send's query_id: the message executed,
//     whatever its outcome, and cannot execute twice;
//  2. the checkpoint is past the send's valid_until bound and the wallet's
//     seqno is the one read before the send: the wallet accepted no message
//     since, and the send's message has expired, so it never will;
//  3. the checkpoint is past the bound plus LifecycleDeliveryAllowance, the
//     wallet's seqno has moved, and the history since the call holds no
//     transaction from the wallet that could be the send's: whatever the
//     wallet accepted, the send's message did not reach the actor in time
//     and has expired.
//
// Anything else leaves the earlier message possibly in flight, and the
// operation is not sent again.
func (b *ServiceActorBuyer) lifecycleSettled(ctx context.Context, session ServiceActorSession, record CallRecord,
	operation string, seqno uint32) error {
	chainTime := session.ChainTime().Unix()
	var history *toschain.ActorHistory
	for _, sent := range record.Lifecycle {
		if sent.Operation != operation || sent.Phase == PhasePrepared {
			continue
		}
		if sent.ValidUntilBoundUnix <= 0 {
			return ErrLifecycleUnsettled
		}
		if chainTime > sent.ValidUntilBoundUnix && seqno == sent.WalletSeqno {
			continue
		}
		if history == nil {
			anchor := &toschain.ActorTxID{LT: record.CallTransactionLT, Hash: record.CallTransactionHex}
			if anchor.LT == 0 || anchor.Hash == "" {
				return ErrLifecycleUnsettled
			}
			read, err := session.History(ctx, record.Actor, anchor)
			if err != nil {
				return errors.Join(ErrCallNotStarted, fmt.Errorf("read the actor history since the call: %w", err))
			}
			if read.Result != toschain.HistoryAnchorReached {
				return ErrLifecycleUnsettled
			}
			history = read
		}
		executed, possible := false, false
		for _, transaction := range history.Transactions {
			if transaction.Sender != record.BuyerWallet {
				continue
			}
			query, known := transaction.InboundQueryID()
			switch {
			case !known:
				possible = true
			case query == sent.QueryID:
				executed = true
			}
		}
		if executed {
			continue
		}
		if !possible && seqno != sent.WalletSeqno &&
			chainTime > sent.ValidUntilBoundUnix+int64(LifecycleDeliveryAllowance/time.Second) {
			continue
		}
		return ErrLifecycleUnsettled
	}
	return nil
}
