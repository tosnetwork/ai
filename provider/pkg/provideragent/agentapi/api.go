// Package agentapi is the provider agent's socket API
// (spec/docs/MCP_PROVIDER_ADAPTER_V1.md section 2.3): the schema, the
// methods and the roles that may call them, the parameters, the views the
// agent answers with, the error codes and a client. It holds no custody
// code and imports nothing of the rail node library, so the MCP server
// links only this package.
package agentapi

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
)

// Schema names the socket's request and response objects. The API is local
// between binaries of one release.
const Schema = "tos.service.mcp-provider.agent-api.v1"

// Methods.
const (
	MethodStatus              = "status"
	MethodRecords             = "records"
	MethodPreflight           = "preflight"
	MethodOfferDescribe       = "offer_describe"
	MethodExportOffer         = "export_offer"
	MethodPause               = "pause"
	MethodResume              = "resume"
	MethodOfferPreview        = "offer_preview"
	MethodWithdrawPreview     = "withdraw_preview"
	MethodRequestConfirmation = "request_confirmation"
	MethodActions             = "actions"
	MethodCancel              = "cancel"
	MethodPending             = "pending"
	MethodPresent             = "present"
	MethodDecide              = "decide"
)

var (
	both    = map[agentsocket.Role]bool{agentsocket.RoleClient: true, agentsocket.RoleCustody: true}
	custody = map[agentsocket.Role]bool{agentsocket.RoleCustody: true}
)

// Methods maps each method to the roles that may call it (section 2.3).
// Only the custody account lists, presents or decides what awaits the human.
var Methods = map[string]map[agentsocket.Role]bool{
	MethodStatus: both, MethodRecords: both, MethodPreflight: both, MethodOfferDescribe: both,
	MethodExportOffer: both, MethodPause: both, MethodResume: both, MethodOfferPreview: both,
	MethodWithdrawPreview: both, MethodRequestConfirmation: both, MethodActions: both, MethodCancel: both,
	MethodPending: custody, MethodPresent: custody, MethodDecide: custody,
}

// Allowed reports whether role may call method.
func Allowed(role agentsocket.Role, method string) bool { return Methods[method][role] }

// Error codes (section 7).
const (
	CodeBadInput              = "MCP_PROVIDER_BAD_INPUT"
	CodeNotFound              = "MCP_PROVIDER_NOT_FOUND"
	CodeNotOffered            = "MCP_PROVIDER_NOT_OFFERED"
	CodeAlreadyOffered        = "MCP_PROVIDER_ALREADY_OFFERED"
	CodeNotReady              = "MCP_PROVIDER_NOT_READY"
	CodeNothingToDo           = "MCP_PROVIDER_NOTHING_TO_DO"
	CodeOverLimit             = "MCP_PROVIDER_OVER_LIMIT"
	CodeExpired               = "MCP_PROVIDER_EXPIRED"
	CodeConflict              = "MCP_PROVIDER_CONFLICT"
	CodeDeclined              = "MCP_PROVIDER_DECLINED"
	CodeDependencyUnavailable = "MCP_PROVIDER_DEPENDENCY_UNAVAILABLE"
	CodeAgentUnavailable      = "MCP_PROVIDER_AGENT_UNAVAILABLE"
	CodeAmbiguous             = "MCP_PROVIDER_AMBIGUOUS"
	CodePermissionDenied      = "MCP_PROVIDER_PERMISSION_DENIED"
	CodeNotConfigured         = "MCP_PROVIDER_NOT_CONFIGURED"
	CodeRateLimited           = "MCP_PROVIDER_RATE_LIMITED"
	CodeInternal              = "MCP_PROVIDER_INTERNAL"

	DispositionNever              = "NEVER"
	DispositionSameAfterBackoff   = "SAME_REQUEST_AFTER_BACKOFF"
	DispositionResolveBeforeRetry = "RESOLVE_BEFORE_RETRY"
)

// Error is a refusal as the socket carries it.
type Error = agentsocket.Error

// Refusal builds a refusal with the disposition of its code. message must
// be fixed text: it reaches the client.
func Refusal(code, message string, cause error) *Error {
	disposition := DispositionNever
	switch code {
	case CodeDependencyUnavailable, CodeAgentUnavailable, CodeRateLimited:
		disposition = DispositionSameAfterBackoff
	case CodeAmbiguous:
		disposition = DispositionResolveBeforeRetry
	}
	return agentsocket.NewError(code, disposition, message, cause)
}

// AsError maps any error to the refusal a caller sees; an error that is not
// already one becomes an internal error with a fixed message.
func AsError(err error) *Error {
	var known *Error
	if errors.As(err, &known) {
		return known
	}
	return Refusal(CodeInternal, "the provider agent could not complete the request", err)
}

// SocketCodes are the refusals the socket sends before a method runs.
func SocketCodes() agentsocket.Codes {
	return agentsocket.Codes{
		BadInput: Refusal(CodeBadInput, "the request is not one strict JSON object of at most 2 MiB "+
			"for a known method of this schema", nil),
		PermissionDenied: Refusal(CodePermissionDenied, "this account may not call this method", nil),
		Internal:         Refusal(CodeInternal, "the provider agent failed while handling the request", nil),
	}
}

// NewClient names the agent socket.
func NewClient(socketPath string, timeout time.Duration) (*agentsocket.Client, error) {
	return agentsocket.NewClient(socketPath, Schema, timeout, agentsocket.ClientCodes{
		BadInput:    Refusal(CodeBadInput, "the request exceeds the 2 MiB bound", nil),
		Unavailable: Refusal(CodeAgentUnavailable, "the provider agent socket does not answer", nil),
		Internal:    Refusal(CodeInternal, "the provider agent sent an answer that does not decode", nil),
	})
}

// Bounds of the tool inputs (section 4).
const (
	MaxWaitSeconds          = 300
	DefaultWaitSeconds      = 45
	MaxRecordsPage          = 100
	DefaultRecordsPage      = 20
	MaxActionsPage          = 50
	MaxPauseReasonBytes     = 200
	MaxAwaitingConfirmation = 4
	// ActionLifetime is how long a preview may be confirmed.
	ActionLifetime = 10 * time.Minute
)

// Action kinds.
const (
	KindOffer    = "offer"
	KindWithdraw = "withdraw"
	KindResume   = "resume"
)

// Action states (section 8.1).
const (
	StateAwaitingConfirmation = "awaiting_confirmation"
	StateCancelled            = "cancelled"
	StateDeclined             = "declined"
	StateExpired              = "expired"
	StateApplying             = "applying"
	StateApplied              = "applied"
	StateFailed               = "failed"
	StateAmbiguous            = "ambiguous"
)

// Empty is the params of a method that takes none.
type Empty struct{}

// RecordsParams pages the provider's requests.
type RecordsParams struct {
	OperatorState string `json:"operator_state,omitempty"`
	PageSize      int    `json:"page_size,omitempty"`
	PageToken     string `json:"page_token,omitempty"`
}

// PauseParams asks the agent to stop admission.
type PauseParams struct {
	Reason string `json:"reason,omitempty"`
}

// ResumeParams asks the agent to admit again.
type ResumeParams struct {
	IdempotencyKey string `json:"idempotency_key"`
}

// OfferPreviewParams are the terms the model chooses for an offer. Every
// other offer input is the operator's (section 2.4).
type OfferPreviewParams struct {
	PriceNanoTOS             string `json:"price_nanotos"`
	StorageFeeNanoTOS        string `json:"storage_fee_nanotos"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	CapabilityVersion        string `json:"capability_version,omitempty"`
	RetentionSeconds         uint64 `json:"retention_seconds,omitempty"`
	IdempotencyKey           string `json:"idempotency_key"`
}

// WithdrawPreviewParams asks for a withdrawal of an exact amount or of all
// credited revenue.
type WithdrawPreviewParams struct {
	AmountNanoTOS  string `json:"amount_nanotos,omitempty"`
	All            bool   `json:"all,omitempty"`
	IdempotencyKey string `json:"idempotency_key"`
}

// RequestConfirmationParams makes an action visible to the confirmer and
// waits for the human's decision.
type RequestConfirmationParams struct {
	ActionID    string `json:"action_id"`
	WaitSeconds *int   `json:"wait_seconds,omitempty"`
}

// ActionsParams lists actions.
type ActionsParams struct {
	ActionID string `json:"action_id,omitempty"`
	State    string `json:"state,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
}

// ActionParams names one action.
type ActionParams struct {
	ActionID string `json:"action_id"`
}

// Decisions.
const (
	DecisionConfirm = "confirm"
	DecisionDecline = "decline"
)

// DecideParams is the confirmer's decision.
type DecideParams struct {
	ActionID string `json:"action_id"`
	Decision string `json:"decision"`
	Code     string `json:"code,omitempty"`
}

// ActionView is an action as a caller sees it. Inputs, Preview and Result
// are redacted for the client account.
type ActionView struct {
	ActionID      string          `json:"action_id"`
	Reference     string          `json:"action_reference"`
	Kind          string          `json:"kind"`
	State         string          `json:"state"`
	Inputs        json.RawMessage `json:"inputs"`
	Preview       json.RawMessage `json:"preview"`
	PreviewDigest string          `json:"preview_digest"`
	Requested     bool            `json:"confirmation_requested"`
	CreatedUnix   int64           `json:"created_unix"`
	UpdatedUnix   int64           `json:"updated_unix"`
	ExpiresUnix   int64           `json:"expires_at_unix"`
	Result        json.RawMessage `json:"result,omitempty"`
	// FailureCode and FailureMessage say why an action failed, expired or is
	// ambiguous, in fixed agent text.
	FailureCode    string `json:"failure_code,omitempty"`
	FailureMessage string `json:"failure_message,omitempty"`
}

// ActionsView is a page of actions.
type ActionsView struct {
	Actions []ActionView `json:"actions"`
}

// PauseView is the answer to a pause.
type PauseView struct {
	Paused         bool   `json:"paused"`
	AlreadyPaused  bool   `json:"already_paused"`
	Origin         string `json:"origin"`
	PreviousOrigin string `json:"previous_origin,omitempty"`
	Restamped      bool   `json:"restamped,omitempty"`
	PausedUnix     int64  `json:"paused_unix,omitempty"`
	// RecordedAs is what the agent's pause-origin record holds for the
	// marker: model, wallet_floor, or empty for a pause the agent did not
	// write.
	RecordedAs string `json:"recorded_as,omitempty"`
}

// Resume outcomes.
const (
	ResumeResumed     = "resumed"
	ResumeNotPaused   = "not_paused"
	ResumeFloorPause  = "wallet_floor_pause"
	ResumeConfirmable = "awaiting_confirmation"
)

// ResumeView is the answer to a resume: resumed at once, nothing to do, the
// wallet floor's own pause (lifted by the agent once the floor is met), or a
// confirmable action.
type ResumeView struct {
	Outcome string      `json:"outcome"`
	Action  *ActionView `json:"action,omitempty"`
	// Balance is the owner wallet's finalized balance when it was read.
	Balance json.RawMessage `json:"wallet_balance,omitempty"`
	// Preflight is the report when one ran.
	Preflight json.RawMessage `json:"preflight,omitempty"`
}

// ExportView carries the offer file's bytes for the MCP server to write.
type ExportView struct {
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	SHA256            string `json:"sha256"`
	Bytes             int    `json:"bytes"`
	OfferBase64       string `json:"offer_base64"`
}

// Presentation is what the confirmer shows for one action. It is sent only
// to the custody account.
type Presentation struct {
	Action          ActionView `json:"action"`
	NetworkID       string     `json:"network_id"`
	ProviderAgentID string     `json:"provider_agent_id"`
	OwnerWallet     string     `json:"owner_wallet"`
	// UntrustedName and UntrustedDescription are the manifest's text for an
	// offer; UntrustedReason is the pause reason for a resume. They are read
	// from files, not from TOS.
	UntrustedName        string `json:"untrusted_name,omitempty"`
	UntrustedDescription string `json:"untrusted_description,omitempty"`
	UntrustedReason      string `json:"untrusted_reason,omitempty"`
	NowUnix              int64  `json:"now_unix"`
	Code                 string `json:"confirmation_code"`
	ValidUntilUnix       int64  `json:"code_valid_until_unix"`
}
