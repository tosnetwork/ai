package buyersdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
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
}

// ErrNoLifecycleSender reports a buyer configured without one.
var ErrNoLifecycleSender = errors.New("the buyer has no lifecycle sender")

// SendLifecycle sends one lifecycle operation for an admitted call. The
// send is journaled before custody starts. A crash or a panic during it
// leaves the entry ambiguous. The destination of a claim_refund is always
// the buyer wallet, which made the call.
func (b *ServiceActorBuyer) SendLifecycle(ctx context.Context, requestHash, operation string) (CallRecord, error) {
	if b.config.Lifecycle == nil {
		return CallRecord{}, ErrNoLifecycleSender
	}
	if !validLifecycle(operation) {
		return CallRecord{}, fmt.Errorf("unknown lifecycle operation %q", operation)
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
		r.Lifecycle = append(r.Lifecycle, LifecycleSend{Operation: operation, QueryID: queryID, Phase: PhaseSending,
			SentUnix: now.Unix()})
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
	sendErr := b.config.Lifecycle.SendLifecycle(ctx, LifecycleIntent{Operation: operation, Actor: record.Actor,
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
