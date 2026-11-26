package provideragent

import (
	"context"
	"encoding/json"
	"net"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
)

// ServerOptions adjust the socket server; a deployment leaves them zero.
type ServerOptions struct {
	// CustodyUID and AgentGID replace the process's own uid and gid, and
	// Peer the kernel peer lookup, so tests play both roles from one account.
	CustodyUID uint32
	AgentGID   uint32
	Peer       func(*net.UnixConn) (uint32, error)
}

// Listen binds the agent socket in the configured socket directory, with
// the role table of section 2.3.
func (a *Agent) Listen(options ServerOptions) (*agentsocket.Server, error) {
	config := agentsocket.Config{Schema: agentapi.Schema, SocketDir: a.config.SocketDir,
		PrivateDirs: []string{a.config.StateDir, a.rail.StateDir}, ClientUID: a.config.ClientUID,
		CustodyUID: options.CustodyUID, AgentGID: options.AgentGID, Methods: agentapi.Methods, Handle: a.Handle,
		ErrorOf: agentapi.AsError, Codes: agentapi.SocketCodes(), Peer: options.Peer}
	return agentsocket.Listen(config)
}

func decode(raw json.RawMessage, value any) error {
	if err := agentsocket.DecodeParams(raw, value); err != nil {
		return agentapi.Refusal(agentapi.CodeBadInput, "params do not decode strictly", err)
	}
	return nil
}

// Handle runs one method for an admitted peer. The socket has already
// checked the schema, the method and the role.
func (a *Agent) Handle(ctx context.Context, role agentsocket.Role, method string, raw json.RawMessage) (any, error) {
	switch method {
	case agentapi.MethodTokenPreview:
		var p agentapi.TokenPreviewParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return a.TokenPreview(ctx, role, p)
	case agentapi.MethodTokenStatus:
		var p agentapi.TokenActorParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return a.TokenStatus(ctx, role, p)
	case agentapi.MethodTokenOffer:
		var p agentapi.TokenActorParams
		if err := decode(raw, &p); err != nil {
			return nil, err
		}
		return a.TokenOffer(ctx, role, p)
	case agentapi.MethodStatus, agentapi.MethodPreflight, agentapi.MethodOfferDescribe, agentapi.MethodExportOffer,
		agentapi.MethodPending:
		var params agentapi.Empty
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		switch method {
		case agentapi.MethodStatus:
			return a.Status(ctx, role)
		case agentapi.MethodPreflight:
			return a.Preflight(ctx, role)
		case agentapi.MethodOfferDescribe:
			return a.OfferDescribe(ctx, role)
		case agentapi.MethodExportOffer:
			return a.ExportOffer(ctx, role)
		}
		return a.Pending()
	case agentapi.MethodRecords:
		var params agentapi.RecordsParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.Records(ctx, role, params)
	case agentapi.MethodPause:
		var params agentapi.PauseParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.Pause(role, params)
	case agentapi.MethodResume:
		var params agentapi.ResumeParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.Resume(ctx, role, params)
	case agentapi.MethodOfferPreview:
		var params agentapi.OfferPreviewParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.OfferPreview(ctx, role, params)
	case agentapi.MethodWithdrawPreview:
		var params agentapi.WithdrawPreviewParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.WithdrawPreview(ctx, role, params)
	case agentapi.MethodRequestConfirmation:
		var params agentapi.RequestConfirmationParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.RequestConfirmation(ctx, role, params)
	case agentapi.MethodActions:
		var params agentapi.ActionsParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.Actions(role, params)
	case agentapi.MethodCancel, agentapi.MethodPresent:
		var params agentapi.ActionParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		if method == agentapi.MethodCancel {
			return a.Cancel(role, params)
		}
		return a.Present(params)
	case agentapi.MethodDecide:
		var params agentapi.DecideParams
		if err := decode(raw, &params); err != nil {
			return nil, err
		}
		return a.Decide(ctx, params)
	}
	return nil, agentapi.Refusal(agentapi.CodeBadInput, "unknown method", nil)
}
