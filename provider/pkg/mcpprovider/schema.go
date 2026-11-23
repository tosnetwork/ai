package mcpprovider

// The tools' input and output schemas are written by hand, as constants of
// the binary, so that they use only the JSON Schema keywords both Claude
// Code and Codex load (spec section 4.1): type, properties, required, enum,
// minimum, maximum, minLength, maxLength, pattern and description, every
// object closed with additionalProperties false, and no $ref, oneOf,
// anyOf, allOf, not or conditional keyword at any depth. A generated schema
// would spell an optional integer as a type list with null.

// object is the schema of an object with the given properties, of which
// required must be present.
func object(properties map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func stringPattern(pattern, description string) map[string]any {
	return map[string]any{"type": "string", "pattern": pattern, "description": description}
}

func integer(minimum, maximum uint64, description string) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum, "maximum": maximum, "description": description}
}

func enum(values []string, description string) map[string]any {
	return map[string]any{"type": "string", "enum": values, "description": description}
}

// Input patterns. The agent checks every one again (spec section 2.3).
const (
	idempotencyKeyPattern = `^[A-Za-z0-9_-]{16,64}$`
	actionIDPattern       = `^[0-9a-f]{64}$`
	// nanoPattern is a decimal nanoTOS amount greater than zero with no
	// leading zero; the server also refuses one above 2^64-1.
	nanoPattern       = `^[1-9][0-9]{0,19}$`
	versionPattern    = `^[!-~]{1,128}$`
	pageTokenPattern  = `^[1-9][0-9]{0,5}$`
	pauseReasonPrefix = `^[ -~]*$`
)

func idempotencyKey(what string) map[string]any {
	return stringPattern(idempotencyKeyPattern, "16 to 64 characters of [A-Za-z0-9_-]; the same key with the same "+
		"inputs returns the same "+what)
}

func actionID() map[string]any {
	return stringPattern(actionIDPattern, "the action's action_id: 64 lowercase hex digits")
}

func nano(description string) map[string]any {
	return stringPattern(nanoPattern, description+", as a decimal nanoTOS string greater than zero and at most "+
		"18446744073709551615 (1 TOS = 1000000000 nanoTOS)")
}

// OperatorStates are the node's operator states a records filter may name.
var OperatorStates = []string{"admitted", "executing", "result_available", "responded", "refunded", "swept",
	"outcome_unknown"}

// ActionStates are the states of an action (spec section 8.1).
var ActionStates = []string{"awaiting_confirmation", "cancelled", "declined", "expired", "applying", "applied",
	"failed", "ambiguous"}

var (
	emptyInput   = object(map[string]any{})
	recordsInput = object(map[string]any{
		"operator_state": enum(OperatorStates, "only requests in this operator state"),
		"page_size":      integer(1, 100, "records per page, 1 to 100; default 20"),
		"page_token":     stringPattern(pageTokenPattern, "the next_page_token of the previous page"),
	})
	pauseInput = object(map[string]any{
		"reason": map[string]any{"type": "string", "maxLength": 200, "pattern": pauseReasonPrefix,
			"description": "why admission stops: one line of at most 200 printable ASCII characters"},
	})
	resumeInput       = object(map[string]any{"idempotency_key": idempotencyKey("answer")}, "idempotency_key")
	offerPreviewInput = object(map[string]any{
		"price_nanotos":          nano("what one call pays the provider"),
		"storage_fee_nanotos":    nano("the storage fee a buyer pays per call, not refunded"),
		"cleanup_bounty_nanotos": nano("the bounty for sweeping an expired request"),
		"response_sla_seconds": integer(1, 4294967295, "seconds the provider has to respond; the agent's "+
			"offer bounds decide what it accepts"),
		"refund_claim_window_seconds": integer(1, 4294967295, "seconds a buyer has to claim a refund; the "+
			"agent's offer bounds decide what it accepts"),
		"capability_version": stringPattern(versionPattern, "1 to 128 printable ASCII characters without "+
			"spaces; default 1.0.0"),
		"retention_seconds": integer(3600, 2592000, "seconds a result is kept after the response deadline, "+
			"3600 to 2592000; default 86400"),
		"idempotency_key": idempotencyKey("action"),
	}, "price_nanotos", "storage_fee_nanotos", "cleanup_bounty_nanotos", "response_sla_seconds",
		"refund_claim_window_seconds", "idempotency_key")
	withdrawPreviewInput = object(map[string]any{
		"amount_nanotos":  nano("the amount to withdraw; give this or all, not both"),
		"all":             map[string]any{"type": "boolean", "description": "withdraw the whole credited revenue the preview reads; give this or amount_nanotos, not both"},
		"idempotency_key": idempotencyKey("action"),
	}, "idempotency_key")
	requestConfirmationInput = object(map[string]any{
		"action_id": actionID(),
		"wait_seconds": integer(0, 300, "seconds to wait for the human's decision, 0 to 300; default 45, "+
			"which stays inside a client's 60-second tool timeout"),
	}, "action_id")
	actionsInput = object(map[string]any{
		"action_id": actionID(),
		"state":     enum(ActionStates, "only actions in this state"),
		"page_size": integer(1, 50, "actions per page, 1 to 50; default 20"),
	})
	cancelInput = object(map[string]any{"action_id": actionID()}, "action_id")

	// output is every tool's output schema: the agent's answer as this
	// server shows it, or a refusal.
	output = object(map[string]any{
		"result": map[string]any{"description": "the provider agent's answer, redacted by the agent; every " +
			"field named untrusted_* holds third-party text as {text, bytes, sha256}"},
		"error": object(map[string]any{
			"code":        map[string]any{"type": "string", "description": "an MCP_PROVIDER_* code"},
			"disposition": enum([]string{"NEVER", "SAME_REQUEST_AFTER_BACKOFF", "RESOLVE_BEFORE_RETRY"}, "whether and how to retry"),
			"message":     map[string]any{"type": "string", "description": "fixed server text"},
			"state":       map[string]any{"type": "string", "description": "the action's state, when the refusal is about one"},
		}, "code", "disposition", "message", "state"),
	})
)
