package provideragent

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// decideWait is how long a decide call waits for the apply it started
// before it answers applying; the apply goes on in the agent.
const decideWait = 20 * time.Second

var versionPattern = regexp.MustCompile(`^[!-~]{1,128}$`)

// offerInputs are the model's offer terms as an action stores and binds
// them, defaults filled in.
type offerInputs struct {
	PriceNanoTOS             string `json:"price_nanotos"`
	StorageFeeNanoTOS        string `json:"storage_fee_nanotos"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	CapabilityVersion        string `json:"capability_version"`
	RetentionSeconds         uint64 `json:"retention_seconds"`
}

// offerPreview is the stored preview of an offer.
type offerPreview struct {
	Offer        *servicebridge.OfferPreview `json:"offer"`
	PlannedSteps []string                    `json:"planned_steps"`
	Steps        []servicebridge.SetupStep   `json:"steps"`
}

// withdrawInputs are the client's withdrawal request.
type withdrawInputs struct {
	AmountNanoTOS string `json:"amount_nanotos,omitempty"`
	All           bool   `json:"all,omitempty"`
}

// withdrawPreview is the stored preview of a withdrawal: the confirmed
// exact amount, which an "all" request was turned into.
type withdrawPreview struct {
	Withdraw      *servicebridge.WithdrawPreview `json:"withdraw"`
	AmountNanoTOS string                         `json:"amount_nanotos"`
}

func badInput(message string) error { return agentapi.Refusal(agentapi.CodeBadInput, message, nil) }

func checkKey(key string) error {
	if !idempotencyKeyPattern.MatchString(key) {
		return badInput("idempotency_key must be 16 to 64 of [A-Za-z0-9_-]")
	}
	return nil
}

// terms validates the model's offer terms against the operator's offer
// bounds and the contract's own bounds.
func (a *Agent) terms(params agentapi.OfferPreviewParams) (offerInputs, servicebridge.ActorTerms, error) {
	inputs := offerInputs{PriceNanoTOS: params.PriceNanoTOS, StorageFeeNanoTOS: params.StorageFeeNanoTOS,
		CleanupBountyNanoTOS: params.CleanupBountyNanoTOS, ResponseSLASeconds: params.ResponseSLASeconds,
		RefundClaimWindowSeconds: params.RefundClaimWindowSeconds, CapabilityVersion: params.CapabilityVersion,
		RetentionSeconds: params.RetentionSeconds}
	if inputs.CapabilityVersion == "" {
		inputs.CapabilityVersion = servicebridge.DefaultOfferVersion
	}
	if inputs.RetentionSeconds == 0 {
		inputs.RetentionSeconds = servicebridge.DefaultRetentionSeconds
	}
	var terms servicebridge.ActorTerms
	var ok bool
	for _, field := range []struct {
		text  string
		value *uint64
	}{{inputs.PriceNanoTOS, &terms.PriceNano}, {inputs.StorageFeeNanoTOS, &terms.StorageFeeNano},
		{inputs.CleanupBountyNanoTOS, &terms.CleanupBountyNano}} {
		if *field.value, ok = parseAmount(field.text); !ok || *field.value == 0 {
			return inputs, terms, badInput("each amount must be a decimal nanoTOS string greater than zero and at most 2^64-1")
		}
	}
	terms.ResponseSLA, terms.RefundClaimWindow = inputs.ResponseSLASeconds, inputs.RefundClaimWindowSeconds
	if !versionPattern.MatchString(inputs.CapabilityVersion) || inputs.CapabilityVersion[0] == '-' {
		return inputs, terms, badInput("capability_version must be 1 to 128 bytes of 0x21 to 0x7e")
	}
	bounds := a.config.Bounds
	switch {
	case terms.PriceNano < bounds.minPrice || terms.PriceNano > bounds.maxPrice:
		return inputs, terms, badInput("the price lies outside the operator's offer bounds")
	case terms.StorageFeeNano > bounds.maxStorage:
		return inputs, terms, badInput("the storage fee lies above the operator's offer bound")
	case terms.CleanupBountyNano > bounds.maxBounty:
		return inputs, terms, badInput("the cleanup bounty lies above the operator's offer bound")
	case terms.ResponseSLA < bounds.MinResponseSLASeconds || terms.ResponseSLA > bounds.MaxResponseSLASeconds:
		return inputs, terms, badInput("the response SLA lies outside the operator's offer bounds")
	case terms.RefundClaimWindow < bounds.MinRefundClaimWindowSeconds ||
		terms.RefundClaimWindow > bounds.MaxRefundClaimWindowSeconds:
		return inputs, terms, badInput("the refund claim window lies outside the operator's offer bounds")
	case inputs.RetentionSeconds < bounds.MinRetentionSeconds || inputs.RetentionSeconds > bounds.MaxRetentionSeconds:
		return inputs, terms, badInput("retention_seconds lies outside the operator's offer bounds")
	}
	if err := terms.ValidateFor(a.config.Offer.TestProfileActor); err != nil {
		return inputs, terms, agentapi.Refusal(agentapi.CodeBadInput, "the terms lie outside the contract's bounds", err)
	}
	return inputs, terms, nil
}

// offerInput builds the library's offer input from the stored terms and
// the operator's offer inputs.
func (a *Agent) offerInput(inputs offerInputs, yes bool) (servicebridge.OfferInput, error) {
	var terms servicebridge.ActorTerms
	var ok bool
	if terms.PriceNano, ok = parseAmount(inputs.PriceNanoTOS); !ok {
		return servicebridge.OfferInput{}, errors.New("the stored price is invalid")
	}
	if terms.StorageFeeNano, ok = parseAmount(inputs.StorageFeeNanoTOS); !ok {
		return servicebridge.OfferInput{}, errors.New("the stored storage fee is invalid")
	}
	if terms.CleanupBountyNano, ok = parseAmount(inputs.CleanupBountyNanoTOS); !ok {
		return servicebridge.OfferInput{}, errors.New("the stored cleanup bounty is invalid")
	}
	terms.ResponseSLA, terms.RefundClaimWindow = inputs.ResponseSLASeconds, inputs.RefundClaimWindowSeconds
	offer := a.config.Offer
	return servicebridge.OfferInput{Terms: terms, Version: inputs.CapabilityVersion,
		RetentionSeconds: inputs.RetentionSeconds, AttestorController: offer.AttestorController,
		ExecutorSocket: offer.ExecutorSocket, ExecutorBinary: offer.ExecutorBinary, ExecutorSHA256: offer.ExecutorSHA256,
		ContainerdSocket: offer.ContainerdSocket, FIFODir: offer.FIFODir, RespondBudgetSeconds: offer.RespondBudgetSeconds,
		DeployFundingNano: a.config.deployFunding, OfferPath: offer.OfferPath, GatewayCardPath: offer.GatewayCardPath,
		TestProfileActor: offer.TestProfileActor, Yes: yes}, nil
}

// previewOffer runs the offer with Yes false, which signs and sends
// nothing, and returns its preview.
func (a *Agent) previewOffer(ctx context.Context, inputs offerInputs) (offerPreview, any, error) {
	in, err := a.offerInput(inputs, false)
	if err != nil {
		return offerPreview{}, nil, err
	}
	result, err := a.lib.Offer(ctx, in)
	if result == nil {
		result = &servicebridge.OfferResult{}
	}
	switch {
	case errors.Is(err, servicebridge.ErrConfirmationRequired) && result.Preview != nil:
	case err == nil:
		return offerPreview{}, result, agentapi.Refusal(agentapi.CodeAlreadyOffered, "the offer is already published", nil)
	case errors.Is(err, servicebridge.ErrSetupBusy):
		return offerPreview{}, nil, agentapi.Refusal(agentapi.CodeConflict, "another setup run holds the state directory", err)
	case errors.Is(err, servicebridge.ErrSetupInputChanged):
		return offerPreview{}, nil, agentapi.Refusal(agentapi.CodeConflict, "an unfinished offer under other inputs "+
			"holds the setup journal", err)
	default:
		return offerPreview{}, result, agentapi.Refusal(agentapi.CodeNotReady, "the offer preview did not complete; "+
			"its steps are attached", err)
	}
	preview := offerPreview{Offer: result.Preview, PlannedSteps: []string{}, Steps: result.Steps}
	for _, step := range result.Steps {
		if step.Status == servicebridge.SetupPlanned {
			preview.PlannedSteps = append(preview.PlannedSteps, step.ID)
		}
	}
	return preview, nil, nil
}

// OfferPreview is the offer_preview method (section 4.9).
func (a *Agent) OfferPreview(ctx context.Context, role agentsocket.Role, params agentapi.OfferPreviewParams) (any, error) {
	if err := checkKey(params.IdempotencyKey); err != nil {
		return nil, err
	}
	inputs, _, err := a.terms(params)
	if err != nil {
		return nil, err
	}
	if err := a.limit(role, ratePreview, false); err != nil {
		return nil, err
	}
	if rail, err := a.lib.Config(); err != nil {
		return nil, err
	} else if rail.Provider != nil {
		return nil, agentapi.Refusal(agentapi.CodeAlreadyOffered, "the node's offer is published; a terms change is "+
			"out of this adapter", nil)
	}
	record, err := a.storeAction(ctx, agentapi.KindOffer, params.IdempotencyKey, inputs, func() (any, any, error) {
		// The preview reads finalized state and the attestor through tosctl,
		// whose own deadlines are longer than the method's bound.
		previewCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
		defer cancel()
		preview, failed, previewErr := a.previewOffer(previewCtx, inputs)
		return preview, failed, previewErr
	})
	if err != nil {
		return a.failure(role, err)
	}
	return a.renderAction(role, record)
}

// failure renders a refusal that came with what it is about, such as the
// earlier withdrawal record or the offer's steps.
func (a *Agent) failure(role agentsocket.Role, err error) (any, error) {
	var failed failedResult
	if !errors.As(err, &failed) {
		return nil, err
	}
	rendered, renderErr := a.out(role, failed.value)
	if renderErr != nil {
		return nil, failed.err
	}
	return rendered, failed.err
}

// previewWithdraw runs the withdrawal with Yes false at one finalized
// checkpoint.
func (a *Agent) previewWithdraw(ctx context.Context, in servicebridge.WithdrawInput) (withdrawPreview, any, error) {
	in.Yes = false
	result, err := a.lib.Withdraw(ctx, in)
	if result == nil {
		result = &servicebridge.WithdrawResult{}
	}
	switch {
	case errors.Is(err, servicebridge.ErrConfirmationRequired) && result.Preview != nil:
	case errors.Is(err, servicebridge.ErrWithdrawZero):
		return withdrawPreview{}, nil, agentapi.Refusal(agentapi.CodeBadInput, "the amount must be greater than zero", err)
	case errors.Is(err, servicebridge.ErrWithdrawOverCredit):
		return withdrawPreview{}, nil, agentapi.Refusal(agentapi.CodeNothingToDo, "the amount is more than the "+
			"credited revenue", err)
	case errors.Is(err, servicebridge.ErrNothingToWithdraw):
		return withdrawPreview{}, nil, agentapi.Refusal(agentapi.CodeNothingToDo, "nothing is credited to withdraw", err)
	case errors.Is(err, servicebridge.ErrWithdrawalPending):
		return withdrawPreview{}, result, agentapi.Refusal(agentapi.CodeAmbiguous, "an earlier withdrawal is not yet "+
			"decided by finalized state; its record is attached", err)
	case errors.Is(err, servicebridge.ErrSetupBusy):
		return withdrawPreview{}, nil, agentapi.Refusal(agentapi.CodeConflict, "another setup run holds the state directory", err)
	case err == nil:
		return withdrawPreview{}, nil, agentapi.Refusal(agentapi.CodeInternal, "the withdrawal preview sent something", nil)
	default:
		return withdrawPreview{}, nil, chainRefusal(err)
	}
	return withdrawPreview{Withdraw: result.Preview, AmountNanoTOS: result.Preview.AmountNano}, nil, nil
}

// WithdrawPreview is the withdraw_preview method (section 4.10). With all,
// the request becomes the exact credited amount the preview read, so the
// human confirms one amount and the send moves exactly that.
func (a *Agent) WithdrawPreview(ctx context.Context, role agentsocket.Role, params agentapi.WithdrawPreviewParams) (any, error) {
	if err := checkKey(params.IdempotencyKey); err != nil {
		return nil, err
	}
	inputs := withdrawInputs{AmountNanoTOS: params.AmountNanoTOS, All: params.All}
	in := servicebridge.WithdrawInput{All: params.All}
	switch {
	case params.All && params.AmountNanoTOS != "":
		return nil, badInput("give amount_nanotos or all, not both")
	case !params.All:
		amount, ok := parseAmount(params.AmountNanoTOS)
		if !ok || amount == 0 {
			return nil, badInput("amount_nanotos must be a decimal nanoTOS string greater than zero")
		}
		in.AmountNano = amount
	}
	if err := a.limit(role, ratePreview, true); err != nil {
		return nil, err
	}
	if rail, err := a.lib.Config(); err != nil {
		return nil, err
	} else if rail.Provider == nil {
		return nil, agentapi.Refusal(agentapi.CodeNotOffered, "the node has no published offer yet", nil)
	}
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	defer cancel()
	record, err := a.storeAction(ctx, agentapi.KindWithdraw, params.IdempotencyKey, inputs, func() (any, any, error) {
		preview, failed, previewErr := a.previewWithdraw(readCtx, in)
		return preview, failed, previewErr
	})
	if err != nil {
		return a.failure(role, err)
	}
	return a.renderAction(role, record)
}

// storeAction returns the action of an idempotency key used before with the
// same inputs, refuses a key used with other inputs, and otherwise builds
// the preview and stores a new action awaiting confirmation. On a refusal
// the returned value is what the refusal is about, if anything.
func (a *Agent) storeAction(ctx context.Context, kind, key string, inputs any,
	build func() (any, any, error)) (actionRecord, error) {
	canonicalInputs, err := canonicalJSON(inputs)
	if err != nil {
		return actionRecord{}, err
	}
	id := actionID(kind, key, canonicalInputs)
	waitCtx, cancelWait := context.WithTimeout(ctx, previewWait)
	release, err := a.holdPreviews(waitCtx)
	cancelWait()
	if err != nil {
		return actionRecord{}, agentapi.Refusal(agentapi.CodeConflict, "another preview or a confirmed action is "+
			"using the state directory; ask again shortly", err)
	}
	defer release()
	var existing keyRecord
	var found bool
	a.withLock(func() { existing, found, err = a.store.readKey(kind, key) })
	if err != nil {
		return actionRecord{}, err
	}
	if found {
		if existing.ActionID != id {
			return actionRecord{}, agentapi.Refusal(agentapi.CodeConflict, "the idempotency key was used with other inputs", nil)
		}
		var record actionRecord
		a.withLock(func() { record, err = a.loadLocked(id) })
		return record, err
	}
	// The action is written before its key, so a crash between the two
	// leaves an action without a key. Its id is derived from the kind, the
	// key and the inputs, so an action stored under this id is this
	// request's: the key is written now and the action returned, as for a
	// retry after a lost answer.
	var orphan actionRecord
	var orphanErr error
	a.withLock(func() {
		if orphan, orphanErr = a.loadLocked(id); orphanErr == nil {
			err = a.store.writeKey(kind, key, id)
		}
	})
	var refusal *agentapi.Error
	switch {
	case orphanErr == nil:
		return orphan, err
	case !errors.As(orphanErr, &refusal) || refusal.Code != agentapi.CodeNotFound:
		return actionRecord{}, orphanErr
	}
	var awaiting int
	a.withLock(func() { awaiting, err = a.awaitingLocked() })
	if err != nil {
		return actionRecord{}, err
	}
	if awaiting >= agentapi.MaxAwaitingConfirmation {
		return actionRecord{}, agentapi.Refusal(agentapi.CodeOverLimit, "4 actions already await confirmation", nil)
	}
	preview, failed, err := build()
	if err != nil {
		if failed != nil {
			return actionRecord{}, failedResult{value: failed, err: err}
		}
		return actionRecord{}, err
	}
	canonicalPreview, err := canonicalJSON(preview)
	if err != nil {
		return actionRecord{}, err
	}
	digest, err := previewDigest(canonicalInputs, canonicalPreview)
	if err != nil {
		return actionRecord{}, err
	}
	now := a.now()
	record := actionRecord{ActionID: id, Kind: kind, IdempotencyKey: key, Inputs: canonicalInputs,
		Preview: canonicalPreview, PreviewDigest: digest, State: agentapi.StateAwaitingConfirmation,
		CreatedUnix: now.Unix(), UpdatedUnix: now.Unix(), ExpiresUnix: now.Add(agentapi.ActionLifetime).Unix()}
	a.withLock(func() {
		if err = a.store.writeAction(record, true); err == nil {
			err = a.store.writeKey(kind, key, id)
		}
		a.notifyLocked()
	})
	return record, err
}

// failedResult carries a refusal together with what it is about.
type failedResult struct {
	value any
	err   error
}

func (f failedResult) Error() string { return f.err.Error() }
func (f failedResult) Unwrap() error { return f.err }

// awaitingLocked counts actions still awaiting confirmation.
func (a *Agent) awaitingLocked() (int, error) {
	records, err := a.store.actions()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, record := range records {
		if a.refreshLocked(&record) == nil && record.State == agentapi.StateAwaitingConfirmation {
			count++
		}
	}
	return count, nil
}

// refreshLocked moves an action whose preview lifetime passed to expired,
// durably. The caller holds a.mutex.
func (a *Agent) refreshLocked(record *actionRecord) error {
	if record.State != agentapi.StateAwaitingConfirmation || a.now().Unix() < record.ExpiresUnix {
		return nil
	}
	record.State, record.FailureCode = agentapi.StateExpired, agentapi.CodeExpired
	record.FailureMessage = "the preview's lifetime passed before a confirmation"
	record.ConfirmationNonce, record.PresentedUnix, record.UpdatedUnix = "", 0, a.now().Unix()
	if err := a.store.writeAction(*record, false); err != nil {
		return err
	}
	a.notifyLocked()
	return nil
}

func (a *Agent) loadLocked(id string) (actionRecord, error) {
	record, err := a.store.readAction(id)
	if err != nil {
		return record, err
	}
	return record, a.refreshLocked(&record)
}

// rawView renders stored JSON for role.
func (a *Agent) rawView(role agentsocket.Role, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || role == agentsocket.RoleCustody {
		return raw, nil
	}
	return a.redactor().view(raw)
}

func (a *Agent) actionView(role agentsocket.Role, record actionRecord) (agentapi.ActionView, error) {
	view := agentapi.ActionView{ActionID: record.ActionID, Reference: actionReference(record.ActionID),
		Kind: record.Kind, State: record.State, PreviewDigest: record.PreviewDigest,
		Requested: record.RequestedUnix != 0, CreatedUnix: record.CreatedUnix, UpdatedUnix: record.UpdatedUnix,
		ExpiresUnix: record.ExpiresUnix, FailureCode: record.FailureCode, FailureMessage: record.FailureMessage}
	var err error
	if view.Inputs, err = a.rawView(role, record.Inputs); err != nil {
		return view, err
	}
	if view.Preview, err = a.rawView(role, record.Preview); err != nil {
		return view, err
	}
	if view.Result, err = a.rawView(role, record.Result); err != nil {
		return view, err
	}
	return view, nil
}

func (a *Agent) renderAction(role agentsocket.Role, record actionRecord) (any, error) {
	return a.actionView(role, record)
}

// RequestConfirmation is the request_confirmation method (section 4.12):
// it makes the action visible to the confirmer and waits up to
// wait_seconds for the human's decision. It draws no code.
func (a *Agent) RequestConfirmation(ctx context.Context, role agentsocket.Role,
	params agentapi.RequestConfirmationParams) (any, error) {
	wait := agentapi.DefaultWaitSeconds
	if params.WaitSeconds != nil {
		wait = *params.WaitSeconds
	}
	if wait < 0 || wait > agentapi.MaxWaitSeconds {
		return nil, badInput("wait_seconds must be 0 to 300")
	}
	var record actionRecord
	var err error
	a.withLock(func() {
		record, err = a.loadLocked(params.ActionID)
		if err == nil && record.State == agentapi.StateAwaitingConfirmation && record.RequestedUnix == 0 {
			record.RequestedUnix, record.UpdatedUnix = a.now().Unix(), a.now().Unix()
			err = a.store.writeAction(record, false)
			a.notifyLocked()
		}
	})
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(time.Duration(wait) * time.Second)
	defer timer.Stop()
	for {
		var changed chan struct{}
		a.withLock(func() {
			record, err = a.loadLocked(params.ActionID)
			changed = a.changed
		})
		if err != nil {
			return nil, err
		}
		if record.State != agentapi.StateAwaitingConfirmation {
			return a.renderAction(role, record)
		}
		select {
		case <-changed:
		case <-timer.C:
			return a.renderAction(role, record)
		case <-ctx.Done():
			return a.renderAction(role, record)
		}
	}
}

// Actions is the actions method (section 4.13).
func (a *Agent) Actions(role agentsocket.Role, params agentapi.ActionsParams) (any, error) {
	if params.PageSize == 0 {
		params.PageSize = 20
	}
	if params.PageSize < 1 || params.PageSize > agentapi.MaxActionsPage {
		return nil, badInput("page_size must be 1 to 50")
	}
	if params.ActionID != "" && !actionIDPattern.MatchString(params.ActionID) {
		return nil, badInput("action_id must be 64 lowercase hex digits")
	}
	if params.State != "" && !knownState(params.State) {
		return nil, badInput("state is not an action state")
	}
	return a.list(role, params.PageSize, func(record actionRecord) bool {
		return (params.ActionID == "" || record.ActionID == params.ActionID) &&
			(params.State == "" || record.State == params.State)
	})
}

func knownState(state string) bool {
	return terminal(state) || state == agentapi.StateAwaitingConfirmation || state == agentapi.StateApplying ||
		state == agentapi.StateAmbiguous
}

func (a *Agent) list(role agentsocket.Role, pageSize int, keep func(actionRecord) bool) (agentapi.ActionsView, error) {
	view := agentapi.ActionsView{Actions: []agentapi.ActionView{}}
	var records []actionRecord
	var err error
	a.withLock(func() {
		records, err = a.store.actions()
		for index := range records {
			if err == nil {
				err = a.refreshLocked(&records[index])
			}
		}
	})
	if err != nil {
		return view, err
	}
	for _, record := range records {
		if !keep(record) {
			continue
		}
		if len(view.Actions) == pageSize {
			break
		}
		rendered, err := a.actionView(role, record)
		if err != nil {
			return view, err
		}
		view.Actions = append(view.Actions, rendered)
	}
	return view, nil
}

// Cancel is the cancel method: an action still awaiting confirmation
// becomes cancelled; any later state is refused with the action.
func (a *Agent) Cancel(role agentsocket.Role, params agentapi.ActionParams) (any, error) {
	var record actionRecord
	var err error
	a.withLock(func() {
		record, err = a.loadLocked(params.ActionID)
		if err != nil || record.State != agentapi.StateAwaitingConfirmation {
			return
		}
		record.State, record.ConfirmationNonce, record.PresentedUnix = agentapi.StateCancelled, "", 0
		record.UpdatedUnix = a.now().Unix()
		err = a.store.writeAction(record, false)
		a.notifyLocked()
	})
	if err != nil {
		return nil, err
	}
	view, err := a.actionView(role, record)
	if err != nil {
		return nil, err
	}
	if record.State != agentapi.StateCancelled {
		return view, agentapi.Refusal(agentapi.CodeConflict, "the action is no longer awaiting confirmation", nil)
	}
	return view, nil
}

// Pending lists the actions a client asked the human to decide.
func (a *Agent) Pending() (any, error) {
	return a.list(agentsocket.RoleCustody, agentapi.MaxActionsPage, func(record actionRecord) bool {
		return record.RequestedUnix != 0 && record.State == agentapi.StateAwaitingConfirmation
	})
}

func (a *Agent) fieldsOf(record actionRecord) confirmationFields {
	return confirmationFields{NetworkID: a.rail.Network.NetworkID, ProviderAgentID: a.rail.AgentID,
		OwnerWallet: a.rail.WalletAddress, Kind: record.Kind, ActionID: record.ActionID,
		PreviewDigest: record.PreviewDigest}
}

// checkDigestLocked recomputes the stored preview digest, so a record
// altered on disk is never presented or applied.
func checkDigest(record actionRecord) error {
	digest, err := previewDigest(record.Inputs, record.Preview)
	if err != nil {
		return err
	}
	if digest != record.PreviewDigest {
		return errors.New("the stored action does not match its preview digest")
	}
	return nil
}

// Present draws the presentation's nonce, unless the current one is still
// valid, and returns the code with the action. Only the confirmer's fetch
// draws a nonce, so a client can never rotate or learn the code.
func (a *Agent) Present(params agentapi.ActionParams) (any, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	record, err := a.loadLocked(params.ActionID)
	if err != nil {
		return nil, err
	}
	if record.State != agentapi.StateAwaitingConfirmation || record.RequestedUnix == 0 {
		return nil, agentapi.Refusal(agentapi.CodeConflict, "the action is not waiting for a decision", nil)
	}
	if err := checkDigest(record); err != nil {
		return nil, err
	}
	now := a.now()
	if record.ConfirmationNonce == "" || !now.Before(time.Unix(record.PresentedUnix, 0).Add(ConfirmationLifetime)) {
		var nonce [confirmationNonceBytes]byte
		if err := a.random(nonce[:]); err != nil {
			return nil, err
		}
		record.ConfirmationNonce, record.PresentedUnix = hex.EncodeToString(nonce[:]), now.Unix()
		if err := a.store.writeAction(record, false); err != nil {
			return nil, err
		}
	}
	nonce, err := parseNonce(record.ConfirmationNonce)
	if err != nil {
		return nil, err
	}
	view, err := a.actionView(agentsocket.RoleCustody, record)
	if err != nil {
		return nil, err
	}
	presentation := agentapi.Presentation{Action: view, NetworkID: a.rail.Network.NetworkID,
		ProviderAgentID: a.rail.AgentID, OwnerWallet: a.rail.WalletAddress, NowUnix: now.Unix(),
		Code:           confirmationCode(nonce, a.fieldsOf(record)),
		ValidUntilUnix: time.Unix(record.PresentedUnix, 0).Add(ConfirmationLifetime).Unix()}
	a.untrustedText(record, &presentation)
	return presentation, nil
}

// untrustedText fills the text read from files that the confirmer shows
// apart from the protocol fields: the manifest's name and description for
// an offer, and the pause reason for a resume.
func (a *Agent) untrustedText(record actionRecord, presentation *agentapi.Presentation) {
	switch record.Kind {
	case agentapi.KindOffer:
		var preview offerPreview
		var inputs offerInputs
		if json.Unmarshal(record.Preview, &preview) != nil || json.Unmarshal(record.Inputs, &inputs) != nil ||
			preview.Offer == nil || preview.Offer.Actor == "" || preview.Offer.AttestorKeyID == "" {
			return
		}
		_, _, manifest, err := servicebridge.BuildManifest(servicebridge.ManifestInput{
			ProviderAgentID: preview.Offer.ProviderAgentID, Actor: preview.Offer.Actor,
			ActorCodeHash: preview.Offer.ActorCodeHash, Attestor: preview.Offer.AttestorKeyID,
			Version: inputs.CapabilityVersion, RetentionSeconds: inputs.RetentionSeconds})
		if err == nil {
			presentation.UntrustedName, presentation.UntrustedDescription = manifest.Name, manifest.Description
		}
	case agentapi.KindResume:
		var preview resumePreview
		if json.Unmarshal(record.Preview, &preview) == nil && preview.Marker != nil {
			presentation.UntrustedReason = preview.Marker.Reason
		} else if raw, err := base64.StdEncoding.DecodeString(preview.MarkerBase64); err == nil {
			presentation.UntrustedReason = string(raw)
		}
	}
}

// Decide applies the human's decision. A confirmation applies only when the
// typed code equals the code the agent recomputes from its own records and
// the stored nonce, compared in constant time; three wrong codes cancel the
// action. A matching code is spent at once and the action enters applying
// durably under the action lock, so it is applied at most once.
func (a *Agent) Decide(ctx context.Context, params agentapi.DecideParams) (any, error) {
	if params.Decision != agentapi.DecisionConfirm && params.Decision != agentapi.DecisionDecline {
		return nil, badInput("decision must be confirm or decline")
	}
	if len(params.Code) > 64 || (params.Decision == agentapi.DecisionDecline && params.Code != "") {
		return nil, badInput("code is longer than 64 characters or given with a decline")
	}
	var record actionRecord
	var err error
	var release func()
	a.withLock(func() { record, release, err = a.decideLocked(params) })
	if err != nil {
		view, viewErr := a.actionView(agentsocket.RoleCustody, record)
		if viewErr != nil || record.ActionID == "" {
			return nil, err
		}
		return view, err
	}
	if release == nil {
		return a.actionView(agentsocket.RoleCustody, record)
	}
	done := make(chan struct{})
	a.applying.Add(1)
	go func() {
		defer close(done)
		a.apply(record, release)
	}()
	timer := time.NewTimer(decideWait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	case <-ctx.Done():
	}
	a.withLock(func() { record, err = a.loadLocked(record.ActionID) })
	if err != nil {
		return nil, err
	}
	return a.actionView(agentsocket.RoleCustody, record)
}

// decideLocked applies a decision under the agent's lock. For a matching
// code it returns the release of the action lock, which the apply holds
// until it ends.
func (a *Agent) decideLocked(params agentapi.DecideParams) (actionRecord, func(), error) {
	record, err := a.loadLocked(params.ActionID)
	if err != nil {
		return actionRecord{}, nil, err
	}
	now := a.now()
	if record.State != agentapi.StateAwaitingConfirmation || record.RequestedUnix == 0 || record.ConfirmationNonce == "" {
		return record, nil, agentapi.Refusal(agentapi.CodeConflict, "the action has no current presentation", nil)
	}
	if !now.Before(time.Unix(record.PresentedUnix, 0).Add(ConfirmationLifetime)) {
		record.ConfirmationNonce, record.PresentedUnix = "", 0
		if err := a.store.writeAction(record, false); err != nil {
			return record, nil, err
		}
		return record, nil, agentapi.Refusal(agentapi.CodeConflict, "the confirmation code expired; present the "+
			"action again", nil)
	}
	finish := func(state, code, message string) (actionRecord, func(), error) {
		record.State, record.FailureCode, record.FailureMessage = state, code, message
		record.ConfirmationNonce, record.PresentedUnix, record.UpdatedUnix = "", 0, now.Unix()
		if err := a.store.writeAction(record, false); err != nil {
			return record, nil, err
		}
		a.notifyLocked()
		return record, nil, nil
	}
	if params.Decision == agentapi.DecisionDecline {
		return finish(agentapi.StateDeclined, agentapi.CodeDeclined, "the human declined")
	}
	nonce, err := parseNonce(record.ConfirmationNonce)
	if err != nil {
		return record, nil, err
	}
	if !codesMatch(confirmationCode(nonce, a.fieldsOf(record)), params.Code) {
		record.CodeFailures++
		if record.CodeFailures >= MaxCodeFailures {
			record, _, err = finish(agentapi.StateCancelled, agentapi.CodeDeclined, "too many wrong confirmation codes")
			if err != nil {
				return record, nil, err
			}
			return record, nil, agentapi.Refusal(agentapi.CodeDeclined, "too many wrong codes; the action was cancelled", nil)
		}
		if err := a.store.writeAction(record, false); err != nil {
			return record, nil, err
		}
		return record, nil, badInput("the code does not match")
	}
	if err := checkDigest(record); err != nil {
		return record, nil, err
	}
	release, err := tryLock(a.actionLockPath())
	if errors.Is(err, errLockHeld) {
		return record, nil, agentapi.Refusal(agentapi.CodeConflict, "another action is being applied; decide again "+
			"when it ends", nil)
	}
	if err != nil {
		return record, nil, err
	}
	record.State, record.ApplyingUnix, record.UpdatedUnix = agentapi.StateApplying, now.Unix(), now.Unix()
	record.ConfirmationNonce, record.PresentedUnix = "", 0
	if err := a.store.writeAction(record, false); err != nil {
		release()
		return record, nil, err
	}
	a.notifyLocked()
	return record, release, nil
}

func (a *Agent) actionLockPath() string { return filepath.Join(a.config.StateDir, actionLock) }

// outcome is how one apply ended.
type outcome struct {
	state   string
	code    string
	message string
	result  any
}

// apply carries out a confirmed action, holding the action lock: a fresh
// preview compared with the confirmed one, then the send with the stored
// inputs, then the result stored.
func (a *Agent) apply(record actionRecord, release func()) {
	defer a.applying.Done()
	defer release()
	var result outcome
	switch record.Kind {
	case agentapi.KindOffer:
		result = a.applyOffer(a.ctx, record)
	case agentapi.KindWithdraw:
		result = a.applyWithdraw(a.ctx, record)
	case agentapi.KindResume:
		result = a.applyResume(a.ctx, record)
	default:
		result = outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "unknown action kind"}
	}
	a.finishApply(record.ActionID, result)
}

func (a *Agent) finishApply(id string, result outcome) {
	a.withLock(func() {
		record, err := a.store.readAction(id)
		if err != nil {
			a.Report("apply", err)
			return
		}
		record.State, record.FailureCode, record.FailureMessage = result.state, result.code, result.message
		record.UpdatedUnix = a.now().Unix()
		if result.result != nil {
			if record.Result, err = canonicalJSON(result.result); err != nil {
				a.Report("apply", err)
				record.Result = nil
			}
		}
		if err := a.store.writeAction(record, false); err != nil {
			a.Report("apply", err)
		}
		a.notifyLocked()
	})
}

var errChanged = outcome{state: agentapi.StateExpired, code: agentapi.CodeExpired,
	message: "the fresh preview differs from the confirmed one; nothing was sent"}

func (a *Agent) applyOffer(ctx context.Context, record actionRecord) outcome {
	var inputs offerInputs
	var confirmed offerPreview
	if err := json.Unmarshal(record.Inputs, &inputs); err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored inputs do not decode"}
	}
	if err := json.Unmarshal(record.Preview, &confirmed); err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored preview does not decode"}
	}
	// The slot is held across the fresh preview and the send, so a client
	// preview at the same moment waits instead of holding the run lock
	// under either call.
	release, err := a.holdPreviews(ctx)
	if err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal,
			message: "the agent stopped before the offer was sent; nothing was sent"}
	}
	defer release()
	fresh, _, err := a.previewOffer(ctx, inputs)
	if err != nil || !sameOffer(confirmed, fresh) {
		return errChanged
	}
	in, err := a.offerInput(inputs, true)
	if err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored inputs are invalid"}
	}
	result, err := a.lib.Offer(ctx, in)
	if err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady,
			message: "the offer stopped part way; its steps are kept, and a new preview finishes it", result: result}
	}
	return outcome{state: agentapi.StateApplied, result: result}
}

// sameOffer is the offer comparison of section 6.1.1: every preview field
// and the list of planned steps.
func sameOffer(confirmed, fresh offerPreview) bool {
	left, err := canonicalJSON(confirmed.Offer)
	if err != nil {
		return false
	}
	right, err := canonicalJSON(fresh.Offer)
	if err != nil || !bytes.Equal(left, right) || len(confirmed.PlannedSteps) != len(fresh.PlannedSteps) {
		return false
	}
	for index := range confirmed.PlannedSteps {
		if confirmed.PlannedSteps[index] != fresh.PlannedSteps[index] {
			return false
		}
	}
	return true
}

func (a *Agent) applyWithdraw(ctx context.Context, record actionRecord) outcome {
	var confirmed withdrawPreview
	if err := json.Unmarshal(record.Preview, &confirmed); err != nil || confirmed.Withdraw == nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored preview does not decode"}
	}
	amount, ok := parseAmount(confirmed.AmountNanoTOS)
	if !ok || amount == 0 {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored amount is invalid"}
	}
	// The slot is held across the fresh preview and the send (see applyOffer).
	release, err := a.holdPreviews(ctx)
	if err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal,
			message: "the agent stopped before the withdrawal was sent; nothing was sent"}
	}
	defer release()
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	fresh, _, err := a.previewWithdraw(readCtx, servicebridge.WithdrawInput{AmountNano: amount})
	cancel()
	if err != nil || !sameWithdraw(confirmed, fresh, amount) {
		return errChanged
	}
	// Recovery after a crash finds this send's own withdrawal record as the
	// one whose query id is not among the records that exist now, so the
	// ids are stored durably before the send and no clock takes part.
	if err := a.recordPriorWithdrawals(record.ActionID); err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeDependencyUnavailable,
			message: "the withdrawal records could not be read or noted; nothing was sent"}
	}
	// The send moves the confirmed exact amount, never "all".
	result, err := a.lib.Withdraw(ctx, servicebridge.WithdrawInput{AmountNano: amount, Yes: true})
	switch {
	case err == nil:
		return outcome{state: agentapi.StateApplied, result: result}
	case errors.Is(err, servicebridge.ErrOutcomeUnknown) || errors.Is(err, servicebridge.ErrWithdrawalPending):
		return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous,
			message: "the withdrawal may have been sent; finalized history decides it", result: result}
	}
	return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady, message: "the withdrawal was not completed",
		result: result}
}

// recordPriorWithdrawals stores, in the applying action, the query ids of
// every withdrawal record the node holds before the send.
func (a *Agent) recordPriorWithdrawals(id string) error {
	records, err := a.lib.Withdrawals()
	if err != nil {
		return err
	}
	prior := make([]uint64, 0, len(records))
	for _, withdrawal := range records {
		prior = append(prior, withdrawal.QueryID)
	}
	a.withLock(func() {
		var record actionRecord
		if record, err = a.store.readAction(id); err != nil {
			return
		}
		if record.State != agentapi.StateApplying {
			err = errors.New("the action left applying before its send")
			return
		}
		record.PriorWithdrawals, record.PriorRecorded = prior, true
		err = a.store.writeAction(record, false)
	})
	return err
}

// sameWithdraw is the withdrawal comparison of section 6.1.1.
func sameWithdraw(confirmed, fresh withdrawPreview, amount uint64) bool {
	if fresh.Withdraw == nil {
		return false
	}
	credited, ok := parseAmount(fresh.Withdraw.CreditedNano)
	return ok && fresh.Withdraw.Actor == confirmed.Withdraw.Actor &&
		fresh.Withdraw.Destination == confirmed.Withdraw.Destination &&
		fresh.Withdraw.AttachedNano == confirmed.Withdraw.AttachedNano &&
		fresh.Withdraw.AmountNano == strconv.FormatUint(amount, 10) && credited >= amount
}

func (a *Agent) applyResume(ctx context.Context, record actionRecord) outcome {
	var confirmed resumePreview
	if err := json.Unmarshal(record.Preview, &confirmed); err != nil {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored preview does not decode"}
	}
	marker, err := base64.StdEncoding.DecodeString(confirmed.MarkerBase64)
	if err != nil || len(marker) == 0 {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "the stored marker is invalid"}
	}
	a.pauses.Lock()
	defer a.pauses.Unlock()
	current, err := readMarkerBytes(a.rail.StateDir)
	if err != nil || !bytes.Equal(current, marker) {
		return errChanged
	}
	preflightCtx, cancel := context.WithTimeout(ctx, preflightTimeout)
	report := a.lib.Preflight(preflightCtx)
	cancel()
	if !passesApartFromAdmission(report) {
		return errChanged
	}
	if a.beforeRemove != nil {
		a.beforeRemove()
	}
	if _, err := servicebridge.ResumeAdmissionIf(a.rail.StateDir, marker); err != nil {
		if errors.Is(err, servicebridge.ErrPauseMarkerChanged) {
			return outcome{state: agentapi.StateFailed, code: agentapi.CodeConflict,
				message: "the marker changed between the check and the removal; it was left in place"}
		}
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady, message: "the marker could not be removed"}
	}
	a.withLock(func() { err = a.dropStaleOriginLocked() })
	if err != nil {
		a.Report("resume", err)
	}
	return outcome{state: agentapi.StateApplied, result: map[string]bool{"resumed": true}}
}

// recoverApplying resolves, at open, every action a crash left applying,
// from the node's own records and never by sending again on the strength
// of the old confirmation (section 8.1).
func (a *Agent) recoverApplying() error {
	release, err := tryLock(a.actionLockPath())
	if err != nil {
		return err
	}
	defer release()
	a.mutex.Lock()
	defer a.mutex.Unlock()
	records, err := a.store.actions()
	if err != nil {
		return err
	}
	now := a.now().Unix()
	for _, record := range records {
		if terminal(record.State) && now-record.UpdatedUnix > terminalRetentionSeconds {
			if err := a.store.removeAction(record); err != nil {
				return err
			}
			continue
		}
		if record.State != agentapi.StateApplying {
			continue
		}
		result := a.resolve(record)
		record.State, record.FailureCode, record.FailureMessage = result.state, result.code, result.message
		record.UpdatedUnix = now
		if result.result != nil {
			if record.Result, err = canonicalJSON(result.result); err != nil {
				return err
			}
		}
		if err := a.store.writeAction(record, false); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) resolve(record actionRecord) outcome {
	switch record.Kind {
	case agentapi.KindOffer:
		rail, err := a.lib.Config()
		if err == nil && rail.Provider != nil {
			return outcome{state: agentapi.StateApplied, result: map[string]string{
				"resolved_from": "the rail configuration's provider section", "capability_id": rail.Provider.CapabilityID}}
		}
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady, message: "the agent stopped while the " +
			"offer was applied; the setup journal keeps its steps, and a new preview finishes it"}
	case agentapi.KindWithdraw:
		var confirmed withdrawPreview
		if err := json.Unmarshal(record.Preview, &confirmed); err != nil || confirmed.Withdraw == nil {
			return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous,
				message: "the stored preview does not decode; read the withdrawal records"}
		}
		// The prior query ids are stored before the send, so without them
		// the send never started.
		if !record.PriorRecorded {
			return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady,
				message: "the agent stopped before the withdrawal was sent; nothing was sent"}
		}
		records, err := a.lib.Withdrawals()
		if err != nil {
			return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous,
				message: "the withdrawal records cannot be read; status shows them once they can"}
		}
		prior := make(map[uint64]bool, len(record.PriorWithdrawals))
		for _, queryID := range record.PriorWithdrawals {
			prior[queryID] = true
		}
		// The send's own record is the one that did not exist before it,
		// whatever the clocks of the agent and the library said.
		for _, withdrawal := range records {
			if prior[withdrawal.QueryID] || withdrawal.AmountNano != confirmed.AmountNanoTOS ||
				withdrawal.Actor != confirmed.Withdraw.Actor {
				continue
			}
			switch withdrawal.State {
			case servicebridge.WithdrawalFinalized:
				return outcome{state: agentapi.StateApplied, result: withdrawal}
			case servicebridge.WithdrawalFailed, servicebridge.WithdrawalNotIncluded:
				return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady,
					message: "the withdrawal was not included", result: withdrawal}
			}
			return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous,
				message: "the withdrawal may have been sent; finalized history decides it", result: withdrawal}
		}
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady,
			message: "the agent stopped before the withdrawal was recorded; nothing was sent"}
	case agentapi.KindResume:
		if _, err := readMarkerBytes(a.rail.StateDir); errors.Is(err, os.ErrNotExist) {
			return outcome{state: agentapi.StateApplied, result: map[string]bool{"resumed": true}}
		}
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady,
			message: "the agent stopped before the marker was removed; it is still in place"}
	}
	return outcome{state: agentapi.StateFailed, code: agentapi.CodeInternal, message: "unknown action kind"}
}
