package mcpprovider

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
)

const ToolTokenPreview = "tos_provider_token_preview"
const ToolTokenOffer = "tos_provider_token_offer_describe"

var tokenPreviewInput = object(map[string]any{
	"actor":              map[string]any{"type": "string", "minLength": 66, "maxLength": 66, "description": "canonical workchain-zero actor, checked again by custody"},
	"operation":          enum([]string{"withdraw-revenue", "recover-surplus", "recheck-payout", "abandon-payout", "update-policy", "pause", "resume"}, "the operation to preview; a human must confirm"),
	"token_amount":       stringPattern(`^[0-9]{1,37}$`, "exact atomic token amount"),
	"tos_amount_nanotos": stringPattern(`^[0-9]{1,37}$`, "exact TOS revenue in nanoTOS"),
	"all_tokens":         map[string]any{"type": "boolean", "description": "preview all credited token revenue, bound to the exact confirmed amount"},
	"all_tos":            map[string]any{"type": "boolean", "description": "preview all credited TOS revenue, preserving the backing and configured floors"},
	"id":                 stringPattern(`^[0-9]{1,20}$`, "payout id as a decimal string"),
	"policy":             object(map[string]any{"price_atomic": stringPattern(`^[1-9][0-9]{0,36}$`, "price in atomic units"), "storage_fee_nanotos": nano("storage fee"), "cleanup_bounty_nanotos": nano("cleanup bounty"), "max_liability_atomic": stringPattern(`^[1-9][0-9]{0,36}$`, "liability bound"), "response_sla_seconds": integer(1, 4294967295, "response SLA"), "refund_claim_window_seconds": integer(1, 4294967295, "refund claim window")}, "price_atomic", "storage_fee_nanotos", "cleanup_bounty_nanotos", "max_liability_atomic", "response_sla_seconds", "refund_claim_window_seconds"),
	"idempotency_key":    idempotencyKey("token action"),
}, "actor", "operation", "idempotency_key")

func (t *Tools) tokenPreview(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, Output, error) {
	var p agentapi.TokenPreviewParams
	if err := decodeInput(args, &p); err != nil {
		return t.refuse(err)
	}
	answer, err := t.call(ctx, ToolTimeout, agentapi.MethodTokenPreview, p)
	return t.action(answer, err, "Token action previewed; nothing signed or sent. "+confirmerNote)
}
func (t *Tools) tokenOffer(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, Output, error) {
	var p agentapi.TokenActorParams
	if err := decodeInput(args, &p); err != nil {
		return t.refuse(err)
	}
	answer, err := t.call(ctx, ToolTimeout, agentapi.MethodTokenOffer, p)
	return t.finish(answer, err, "Token offer verified at one finalized checkpoint.")
}

const ToolTokenStatus = "tos_provider_token_status"

func (t *Tools) tokenStatus(ctx context.Context, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, Output, error) {
	var p agentapi.TokenActorParams
	if err := decodeInput(args, &p); err != nil {
		return t.refuse(err)
	}
	answer, err := t.call(ctx, ToolTimeout, agentapi.MethodTokenStatus, p)
	return t.finish(answer, err, "Token state and floors at one finalized checkpoint.")
}
