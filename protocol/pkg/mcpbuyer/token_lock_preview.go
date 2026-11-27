package mcpbuyer

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

const ToolTokenLockPreview = "tos_buyer_preview_token_lock"

func (t *Tools) registerTokenLockPreview(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: ToolTokenLockPreview, Title: "Preview a source token lock", Description: "Reads owner-pinned issuer state at a finalized hash-pinned block and previews the issuer fee, minted delta and per-asset budget. It signs and sends nothing. Actor admission is rechecked by prepare; already-minted TOS token transfers are exact." + untrustedNote, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}}, t.tokenLockPreview)
}

func (t *Tools) tokenLockPreview(ctx context.Context, _ *mcp.CallToolRequest, input buyeragent.TokenLockPreviewParams) (*mcp.CallToolResult, buyersdk.TokenLockPreview, error) {
	var preview buyersdk.TokenLockPreview
	if err := t.agent.Call(ctx, "token_lock_preview", input, &preview); err != nil {
		return nil, preview, err
	}
	text := fmt.Sprintf("Source lock: nominal %s atomic; issuer fee %s; minted %s. Funding budget uses %s minted atomic units for asset %s. Actor %s requires exactly %s already-minted tokens. Nothing signed or sent. %s", preview.NominalAtomic, preview.IssuerFeeAtomic, preview.MintedAtomic, preview.BudgetDebitAtomic, preview.AssetMaster, preview.Actor, preview.ActorPriceAtomic, preview.Warning)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, preview, nil
}
