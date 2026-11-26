package provideragent

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// TokenLibrary extends custody operations without making the MCP process link
// the signing boundary. The runtime remains usable with no external host app.
type TokenLibrary interface {
	TokenAction(context.Context, servicebridge.TokenActionInput, bool, string) (*servicebridge.TokenActionRecord, error)
	TokenOffer(context.Context, string) (*serviceactor.TokenAdmission, error)
	TokenSafety(context.Context) error
	TokenStatus(context.Context, string) (*servicebridge.TokenStatus, error)
}

func (r Rail) TokenAction(ctx context.Context, in servicebridge.TokenActionInput, yes bool, digest string) (*servicebridge.TokenActionRecord, error) {
	c, err := r.Config()
	if err != nil {
		return nil, err
	}
	return servicebridge.RunTokenAction(ctx, c, in, yes, digest, servicebridge.TokenEnv{SetupEnv: r.env()})
}
func (r Rail) TokenOffer(ctx context.Context, address string) (*serviceactor.TokenAdmission, error) {
	c, err := r.Config()
	if err != nil {
		return nil, err
	}
	return servicebridge.TokenOffer(ctx, c, address, servicebridge.TokenEnv{SetupEnv: r.env()})
}
func (r Rail) TokenSafety(ctx context.Context) error {
	c, err := r.Config()
	if err != nil {
		return err
	}
	return servicebridge.CheckTokenSafety(ctx, c, servicebridge.TokenEnv{SetupEnv: r.env()})
}

func (a *Agent) TokenPreview(ctx context.Context, role agentsocket.Role, p agentapi.TokenPreviewParams) (any, error) {
	if err := a.limit(role, rateRead, false); err != nil {
		return nil, err
	}
	if err := checkKey(p.IdempotencyKey); err != nil {
		return nil, err
	}
	library, ok := a.lib.(TokenLibrary)
	if !ok {
		return nil, badInput("token provider is not configured")
	}
	var policy *servicebridge.TokenPolicyInput
	if p.Policy != nil {
		policy = &servicebridge.TokenPolicyInput{PriceAtomic: p.Policy.PriceAtomic, StorageFeeNanoTOS: p.Policy.StorageFeeNanoTOS, CleanupBountyNanoTOS: p.Policy.CleanupBountyNanoTOS, MaxLiabilityAtomic: p.Policy.MaxLiabilityAtomic, ResponseSLA: p.Policy.ResponseSLA, RefundClaimWindow: p.Policy.RefundClaimWindow}
	}
	var id uint64
	if p.ID != "" {
		var err error
		id, err = strconv.ParseUint(p.ID, 10, 64)
		if err != nil || strconv.FormatUint(id, 10) != p.ID {
			return nil, badInput("invalid token payout id")
		}
	}
	in := servicebridge.TokenActionInput{Actor: p.Actor, Operation: p.Operation, TokenAmount: p.TokenAmount, TOSAmount: p.TOSAmount, AllTokens: p.AllTokens, AllTOS: p.AllTOS, ID: id, Policy: policy, IdempotencyKey: p.IdempotencyKey}
	if err := servicebridge.ValidateTokenActionInput(in); err != nil {
		return nil, badInput("token input is invalid")
	}

	record, err := a.storeAction(ctx, agentapi.KindToken, p.IdempotencyKey, in, func() (any, any, error) {
		preview, err := library.TokenAction(ctx, in, false, "")
		if errors.Is(err, servicebridge.ErrConfirmationRequired) && preview != nil {
			return preview, nil, nil
		}
		return nil, nil, chainRefusal(err)
	})
	if err != nil {
		return nil, err
	}
	return a.actionView(role, record)
}
func (a *Agent) TokenOffer(ctx context.Context, role agentsocket.Role, p agentapi.TokenActorParams) (any, error) {
	if err := a.limit(role, rateRead, false); err != nil {
		return nil, err
	}
	library, ok := a.lib.(TokenLibrary)
	if !ok {
		return nil, badInput("token provider is not configured")
	}
	admission, err := library.TokenOffer(ctx, p.Actor)
	if err != nil {
		return nil, chainRefusal(err)
	}
	// Only public policy is returned; raw cells and custody configuration do not
	// enter a client response.
	return a.out(role, map[string]any{"actor": admission.Binding.Actor, "master": admission.Recognition.Record.Master, "decimals": admission.Recognition.Record.Decimals, "price_atomic": admission.Policy.PricePerCall.String(), "max_token_liability": admission.Policy.MaxTokenLiability.String(), "checkpoint": admission.Recognition.Checkpoint})
}
func (a *Agent) applyToken(ctx context.Context, record actionRecord) outcome {
	release, lockErr := a.holdPreviews(ctx)
	if lockErr != nil {
		return errChanged
	}
	defer release()
	library, ok := a.lib.(TokenLibrary)
	if !ok {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady, message: "token provider unavailable"}
	}
	var in servicebridge.TokenActionInput
	var preview servicebridge.TokenActionRecord
	if json.Unmarshal(record.Inputs, &in) != nil || json.Unmarshal(record.Preview, &preview) != nil {
		return errChanged
	}
	result, err := library.TokenAction(ctx, in, true, preview.Preview.Digest)
	if result != nil && result.State != "preview" {
		state := agentapi.StateAmbiguous
		if result.State == "finalized" || result.State == "delivered" || result.State == "returned" || result.State == "abandoned" {
			state = agentapi.StateApplied
		}
		if tokenFailedState(result.State) {
			state = agentapi.StateFailed
		}
		if state == agentapi.StateApplied {
			return outcome{state: state, result: result}
		}
		if state == agentapi.StateFailed {
			return outcome{state: state, code: agentapi.CodeNotReady, message: "token action failed in finalized state", result: result}
		}
		return outcome{state: state, code: agentapi.CodeAmbiguous, message: "token action is reconciled by its durable query and exact body; never resubmit blindly", result: result}
	}
	if err != nil {
		return errChanged
	}
	return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous, message: "token outcome is unresolved", result: result}
}
func (a *Agent) resolveToken(record actionRecord) outcome {
	library, ok := a.lib.(TokenLibrary)
	if !ok {
		return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous, message: "token custody unavailable"}
	}
	var in servicebridge.TokenActionInput
	if json.Unmarshal(record.Inputs, &in) != nil {
		return errChanged
	}
	result, err := library.TokenAction(a.ctx, in, false, "")
	if errors.Is(err, servicebridge.ErrConfirmationRequired) {
		return outcome{state: agentapi.StateFailed, code: agentapi.CodeNotReady, message: "no token journal was written before interruption"}
	}
	if err != nil || result == nil {
		return outcome{state: agentapi.StateAmbiguous, code: agentapi.CodeAmbiguous, message: "token reconciliation unavailable"}
	}
	state := agentapi.StateAmbiguous
	switch result.State {
	case "finalized", "delivered", "returned", "abandoned":
		state = agentapi.StateApplied
	case "failed", "refused", "never_sent", "expired", "superseded":
		state = agentapi.StateFailed
	}
	return outcome{state: state, result: result}
}

func (r Rail) TokenStatus(ctx context.Context, address string) (*servicebridge.TokenStatus, error) {
	c, err := r.Config()
	if err != nil {
		return nil, err
	}
	return servicebridge.ReadTokenStatus(ctx, c, address, servicebridge.TokenEnv{SetupEnv: r.env()})
}
func (a *Agent) TokenStatus(ctx context.Context, role agentsocket.Role, p agentapi.TokenActorParams) (any, error) {
	if err := a.limit(role, rateRead, false); err != nil {
		return nil, err
	}
	library, ok := a.lib.(TokenLibrary)
	if !ok {
		return nil, badInput("token provider unavailable")
	}
	status, err := library.TokenStatus(ctx, p.Actor)
	if err != nil {
		return nil, chainRefusal(err)
	}
	return a.out(role, status)
}

// Refresh only unresolved token actions. This observes the same durable
// operation; it cannot sign, allocate a new key, or resubmit after interruption.
func (a *Agent) refreshTokenActions(ctx context.Context) {
	library, ok := a.lib.(TokenLibrary)
	if !ok {
		return
	}
	var records []actionRecord
	var err error
	a.withLock(func() { records, err = a.store.actions() })
	if err != nil {
		return
	}
	for _, record := range records {
		if record.Kind != agentapi.KindToken || record.State != agentapi.StateAmbiguous {
			continue
		}
		var in servicebridge.TokenActionInput
		if json.Unmarshal(record.Inputs, &in) != nil {
			continue
		}
		result, e := library.TokenAction(ctx, in, false, "")
		if e != nil || result == nil {
			continue
		}
		state := ""
		switch result.State {
		case "finalized", "delivered", "returned", "abandoned":
			state = agentapi.StateApplied
		case "failed", "refused", "never_sent", "expired", "superseded":
			state = agentapi.StateFailed
		}
		if state == "" {
			continue
		}
		a.withLock(func() {
			latest, e := a.store.readAction(record.ActionID)
			if e != nil || latest.State != agentapi.StateAmbiguous {
				return
			}
			latest.State = state
			latest.Result, e = canonicalJSON(result)
			if e != nil {
				return
			}
			latest.FailureCode = ""
			latest.FailureMessage = ""
			latest.UpdatedUnix = a.now().Unix()
			if e = a.store.writeAction(latest, false); e != nil {
				a.Report("token reconciliation", e)
			}
			a.notifyLocked()
		})
	}
}

func tokenFailedState(s string) bool {
	switch s {
	case "failed", "refused", "never_sent", "expired", "superseded":
		return true
	}
	return false
}
