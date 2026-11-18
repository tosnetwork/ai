package toschain

import (
	"context"
	"errors"
	"fmt"
)

// WalletSeqno runs the wallet's seqno getter at the session checkpoint by
// quorum. Every wallet version a buyer sends from (V3R2, V4R2, V5R1) has it.
// The seqno only moves when the wallet accepts an external message, so an
// unchanged seqno at a later checkpoint proves the wallet accepted no
// message in between.
func (s *ServiceActorSession) WalletSeqno(ctx context.Context, wallet string) (uint32, error) {
	canonical, err := CanonicalAddress(wallet)
	if err != nil {
		return 0, fmt.Errorf("wallet address: %w", err)
	}
	stack, err := s.actorGetter(ctx, canonical, "seqno", nil)
	if err != nil {
		return 0, err
	}
	if len(stack) != 1 || stack[0].Kind != "num" || stack[0].Number == nil || stack[0].Number.Sign() < 0 ||
		stack[0].Number.BitLen() > 32 {
		return 0, errors.New("the wallet seqno getter did not return one 32-bit number")
	}
	return uint32(stack[0].Number.Uint64()), nil
}

// InboundQueryID returns the query_id of the transaction's inbound message
// body. ok is false when the body cannot show one: a failed transaction
// whose body is shorter than an opcode and a query_id. A transaction with no
// lifecycle body (a transfer, a bounce, an external or system transaction)
// has query_id 0 with ok true: it carries no buyer message.
func (t ActorTransaction) InboundQueryID() (uint64, bool) {
	switch t.Kind {
	case ActorTxTransfer, ActorTxBounced, ActorTxExternal, ActorTxNoInput, ActorTxSystem:
		return 0, true
	case ActorTxFailed:
		if t.Call != nil {
			return t.Call.QueryID, true
		}
		body, err := decodeCellBOC(t.BodyBOC)
		if err != nil {
			return 0, false
		}
		slice, err := body.BeginParse()
		if err != nil {
			return 0, false
		}
		if _, err := slice.LoadUInt(32); err != nil {
			return 0, false
		}
		query, err := slice.LoadUInt(64)
		if err != nil {
			return 0, false
		}
		return query, true
	case ActorTxCall:
		if t.Call != nil {
			return t.Call.QueryID, true
		}
		return t.QueryID, true
	}
	return t.QueryID, true
}
