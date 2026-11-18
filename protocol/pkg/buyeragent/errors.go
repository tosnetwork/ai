package buyeragent

import "errors"

// Error codes and retry dispositions (MCP_BUYER_ADAPTER_V1 section 12;
// dispositions from PUBLIC_ERRORS_V1).
const (
	CodeBadInput              = "MCP_BUYER_BAD_INPUT"
	CodeNotFound              = "MCP_BUYER_NOT_FOUND"
	CodeOfferInvalid          = "MCP_BUYER_OFFER_INVALID"
	CodeNotCarriable          = "MCP_BUYER_NOT_CARRIABLE"
	CodeOverBudget            = "MCP_BUYER_OVER_BUDGET"
	CodeQuoteExpired          = "MCP_BUYER_QUOTE_EXPIRED"
	CodeConflict              = "MCP_BUYER_CONFLICT"
	CodeDeclined              = "MCP_BUYER_DECLINED"
	CodeDependencyUnavailable = "MCP_BUYER_DEPENDENCY_UNAVAILABLE"
	CodeAmbiguous             = "MCP_BUYER_AMBIGUOUS"
	CodePermissionDenied      = "MCP_BUYER_PERMISSION_DENIED"
	CodeInternal              = "MCP_BUYER_INTERNAL"

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
	case CodeDependencyUnavailable:
		disposition = DispositionSameAfterBackoff
	case CodeAmbiguous:
		disposition = DispositionResolveBeforeRetry
	}
	return &Error{Code: code, Disposition: disposition, Message: message, cause: cause}
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
