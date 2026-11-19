package buyeragent

import "errors"

// Error codes and retry dispositions (MCP_BUYER_ADAPTER_V1 section 12;
// dispositions from PUBLIC_ERRORS_V1).
const (
	CodeBadInput              = "MCP_BUYER_BAD_INPUT"
	CodeNotFound              = "MCP_BUYER_NOT_FOUND"
	CodeOfferInvalid          = "MCP_BUYER_OFFER_INVALID"
	CodeNotCarriable          = "MCP_BUYER_NOT_CARRIABLE"
	CodeCardWindowTooLong     = "MCP_BUYER_CARD_WINDOW_TOO_LONG"
	CodeOverBudget            = "MCP_BUYER_OVER_BUDGET"
	CodeQuoteExpired          = "MCP_BUYER_QUOTE_EXPIRED"
	CodeConflict              = "MCP_BUYER_CONFLICT"
	CodeDeclined              = "MCP_BUYER_DECLINED"
	CodeResultNotReady        = "MCP_BUYER_RESULT_NOT_READY"
	CodeDependencyUnavailable = "MCP_BUYER_DEPENDENCY_UNAVAILABLE"
	CodeAgentUnavailable      = "MCP_BUYER_AGENT_UNAVAILABLE"
	CodeAmbiguous             = "MCP_BUYER_AMBIGUOUS"
	CodePermissionDenied      = "MCP_BUYER_PERMISSION_DENIED"
	// CodeNotConfigured refuses a request the agent's configuration does
	// not serve: a gateway Quote without a gateway, or a search with
	// neither a hint source nor a capability_id.
	CodeNotConfigured = "MCP_BUYER_NOT_CONFIGURED"
	// CodeRateLimited refuses a search or quote over the per-minute bound;
	// the same request may be sent again after a backoff.
	CodeRateLimited = "MCP_BUYER_RATE_LIMITED"
	CodeInternal    = "MCP_BUYER_INTERNAL"

	DispositionNever              = "NEVER"
	DispositionSameAfterBackoff   = "SAME_REQUEST_AFTER_BACKOFF"
	DispositionResolveBeforeRetry = "RESOLVE_BEFORE_RETRY"
)

// Error is a refusal the agent reports to a client. Message is fixed text
// chosen by the agent; it never carries untrusted text, a path or an
// endpoint.
type Error struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Message     string `json:"message"`
	cause       error
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Unwrap returns the underlying error, which is never sent to a client.
func (e *Error) Unwrap() error { return e.cause }

func refusal(code, message string, cause error) *Error {
	disposition := DispositionNever
	switch code {
	case CodeDependencyUnavailable, CodeAgentUnavailable, CodeResultNotReady, CodeRateLimited:
		disposition = DispositionSameAfterBackoff
	case CodeAmbiguous:
		disposition = DispositionResolveBeforeRetry
	}
	return &Error{Code: code, Disposition: disposition, Message: message, cause: cause}
}

// carriageRefusal maps a failed carriage check to its refusal: a purchase
// whose buyer card would outlive the card lifetime has its own code, so a
// client can tell it from a transient failure and pick a shorter offer.
func carriageRefusal(err error) *Error {
	if errors.Is(err, ErrCardWindowTooLong) {
		return refusal(CodeCardWindowTooLong,
			"the Quote expiry, response SLA and result retention together exceed the 30-day key card lifetime", err)
	}
	return refusal(CodeNotCarriable, "the purchase cannot be carried to its provider", err)
}

// asError maps any error to the Error a client sees; an error that is not
// already one becomes an internal error with a fixed message.
func asError(err error) *Error {
	var known *Error
	if errors.As(err, &known) {
		return known
	}
	return refusal(CodeInternal, "the agent could not complete the request", err)
}
