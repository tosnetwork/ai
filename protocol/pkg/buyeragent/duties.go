package buyeragent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

// Refund duties (MCP_BUYER_ADAPTER_V1 section 11).
const (
	// LifecycleRetry is how long a send of one operation stands before the
	// agent considers sending it again. Even then the buyer sends it only
	// once finalized state settles the earlier send
	// (buyersdk.ErrLifecycleUnsettled).
	LifecycleRetry = 10 * time.Minute
	// MaxDutyInterval bounds how long the agent waits between rounds of
	// duties.
	MaxDutyInterval = 60 * time.Second
)

// lifecycleFor maps a request's finalized status to the operation it
// requires (section 11.2).
func lifecycleFor(status serviceactor.Status) string {
	switch status {
	case serviceactor.StatusOverdue:
		return buyersdk.LifecycleExpire
	case serviceactor.StatusRefundable:
		return buyersdk.LifecycleClaimRefund
	case serviceactor.StatusLapsed:
		return buyersdk.LifecycleSweep
	}
	return ""
}

// DutyView is the outcome of one duty check.
type DutyView struct {
	RequestHash string `json:"request_hash"`
	Reference   string `json:"purchase_reference"`
	// Status is the request's finalized status, or the journal phase for a
	// call that was never admitted.
	Status string `json:"status"`
	// Operation is the lifecycle operation the status requires, if any.
	Operation string `json:"operation,omitempty"`
	// Sent reports that this check handed the operation to custody.
	Sent bool `json:"sent"`
	// Waiting reports that the operation was already sent recently and is
	// waiting for finalized history.
	Waiting bool `json:"waiting_for_finalized_history,omitempty"`
	// Delivery is the task delivery round of a pending request.
	Delivery *DeliveryView `json:"delivery,omitempty"`
	// Result is the result round of a responded request.
	Result *ResultView `json:"result,omitempty"`
}

// TaskDeliverer delivers the task of an admitted, pending purchase;
// Carrier implements it.
type TaskDeliverer interface {
	DeliverTask(ctx context.Context, task TaskDelivery) (DeliveryView, error)
}

// deliver runs the task delivery round of a pending request (section 7.2):
// the duty round carries the task as it carries the refund duties, with or
// without an MCP session.
func (a *Agent) deliver(ctx context.Context, view DutyView, requestHash string, purchase PurchaseRecord,
	report *buyersdk.RequestReport) (DutyView, error) {
	record, err := a.config.Buyer.Journal().Read(requestHash)
	if err != nil {
		return view, err
	}
	archive, err := readPrivate(a.store.archivePath(requestHash))
	if err != nil {
		return view, err
	}
	if sum := sha256.Sum256(archive); "sha256:"+hex.EncodeToString(sum[:]) != purchase.SourceDigest {
		return view, errors.New("the stored source archive does not match its digest")
	}
	delivered, err := a.config.Delivery.DeliverTask(ctx, TaskDelivery{Record: record, Archive: archive,
		ExecutionNonce: purchase.ExecutionNonce, ProviderAgentID: purchase.ProviderAgentID,
		ResponseDeadline: time.Unix(int64(report.ResponseDeadline), 0), RetentionSeconds: purchase.RetentionSeconds,
		ChainTime: time.Unix(report.ChainTime, 0)})
	view.Delivery = &delivered
	switch {
	case err == nil:
		return view, nil
	case errors.Is(err, ErrNoRelayAccepted), errors.Is(err, ErrNoProviderCard):
		return view, refusal(CodeDependencyUnavailable, "the task is not yet held by a relay of the provider", err)
	case errors.Is(err, ErrTaskDeadlinePassed):
		return view, nil
	}
	return view, refusal(CodeInternal, "the task could not be delivered", err)
}

// RefundNow runs the duty of one purchase now: the expire, claim_refund or
// sweep its finalized status requires. The agent runs the same duty on its
// own schedule; this only advances it.
func (a *Agent) RefundNow(ctx context.Context, requestHash string) (DutyView, error) {
	if err := checkRequestHash(requestHash); err != nil {
		return DutyView{}, err
	}
	a.duties.Lock()
	defer a.duties.Unlock()
	return a.duty(ctx, requestHash)
}

// Duties runs every open purchase's duty once and returns the errors of
// those that failed; one failure never stops the others.
func (a *Agent) Duties(ctx context.Context) []error {
	a.duties.Lock()
	defer a.duties.Unlock()
	records, err := a.config.Buyer.Journal().Records()
	if err != nil {
		return []error{err}
	}
	var failures []error
	for _, record := range records {
		switch record.Phase {
		case buyersdk.PhaseSubmitted, buyersdk.PhaseAmbiguous, buyersdk.PhaseAdmitted:
		default:
			continue
		}
		if _, err := a.store.readPurchase(record.RequestHash); err != nil {
			continue
		}
		if _, err := a.duty(ctx, record.RequestHash); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

// RunDuties runs Duties every interval, at most MaxDutyInterval, until ctx
// ends. It needs no MCP session: the agent alone carries the refund
// duties.
func (a *Agent) RunDuties(ctx context.Context, interval time.Duration, report func([]error)) {
	if interval <= 0 || interval > MaxDutyInterval {
		interval = MaxDutyInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if failures := a.Duties(ctx); len(failures) != 0 && report != nil {
			report(failures)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Agent) duty(ctx context.Context, requestHash string) (DutyView, error) {
	view := DutyView{RequestHash: requestHash, Reference: PurchaseReference(requestHash)}
	purchase, err := a.store.readPurchase(requestHash)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return view, refusal(CodeNotFound, "no purchase has this request hash", err)
		}
		return view, err
	}
	record, err := a.config.Buyer.Journal().Read(requestHash)
	if err != nil {
		return view, err
	}
	switch record.Phase {
	case buyersdk.PhaseSubmitted, buyersdk.PhaseAmbiguous, buyersdk.PhaseAdmitted:
	default:
		view.Status = string(record.Phase)
		return view, nil
	}
	report, err := a.config.Buyer.Resolve(ctx, requestHash)
	if err != nil {
		return view, refusal(CodeDependencyUnavailable, "the request could not be resolved at a finalized checkpoint", err)
	}
	view.Status = string(report.Status)
	if view.Status == "" {
		view.Status = string(report.Phase)
	}
	if report.Status == serviceactor.StatusPending && a.config.Delivery != nil {
		return a.deliver(ctx, view, requestHash, purchase, report)
	}
	if report.Status == serviceactor.StatusResponded && a.config.Results != nil {
		return a.receive(ctx, view, requestHash, purchase, report)
	}
	view.Operation = lifecycleFor(report.Status)
	if view.Operation == "" {
		return view, nil
	}
	record, err = a.config.Buyer.Journal().Read(requestHash)
	if err != nil {
		return view, err
	}
	now := a.now()
	for _, sent := range record.Lifecycle {
		if sent.Operation == view.Operation && sent.Phase != buyersdk.PhasePrepared &&
			now.Before(time.Unix(sent.SentUnix, 0).Add(LifecycleRetry)) {
			view.Waiting = true
			return view, nil
		}
	}
	if sends, err := a.lifecycleSends(now); err != nil {
		return view, err
	} else if sends >= a.config.MaxLifecycleSends {
		return view, refusal(CodeOverBudget, "the lifecycle send budget of the window is used up", nil)
	}
	updated, err := a.config.Buyer.SendLifecycle(ctx, requestHash, view.Operation)
	switch {
	case errors.Is(err, buyersdk.ErrLifecycleUnsettled):
		// An earlier send may still execute; it is not repeated until
		// finalized state settles it (section 11.2).
		view.Waiting = true
		return view, nil
	case errors.Is(err, buyersdk.ErrCallNotStarted):
		return view, refusal(CodeDependencyUnavailable, "the lifecycle send was not handed to custody", err)
	case err != nil && lastPhase(updated) == buyersdk.PhaseAmbiguous:
		return view, refusal(CodeAmbiguous, "the lifecycle send may have been submitted; finalized history decides", err)
	case err != nil:
		return view, refusal(CodeInternal, "the lifecycle send failed", err)
	}
	view.Sent = true
	return view, nil
}

func lastPhase(record buyersdk.CallRecord) buyersdk.CallPhase {
	if len(record.Lifecycle) == 0 {
		return ""
	}
	return record.Lifecycle[len(record.Lifecycle)-1].Phase
}

// lifecycleSends counts the lifecycle sends handed to custody within the
// budget window, across every purchase.
func (a *Agent) lifecycleSends(now time.Time) (int, error) {
	records, err := a.config.Buyer.Journal().Records()
	if err != nil {
		return 0, err
	}
	window := a.config.Buyer.Limits().Window
	count := 0
	for _, record := range records {
		for _, sent := range record.Lifecycle {
			if sent.Phase != buyersdk.PhasePrepared && now.Before(time.Unix(sent.SentUnix, 0).Add(window)) {
				count++
			}
		}
	}
	return count, nil
}
