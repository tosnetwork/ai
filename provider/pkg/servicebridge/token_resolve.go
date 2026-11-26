package servicebridge

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// Reconciliation never opens a second checkpoint and never resubmits.
func resolveTokenAction(ctx context.Context, s TokenSession, c NodeConfig, r *TokenActionRecord) error {

	inputHash, err := tokenInputHash(r.Input)
	if err != nil || r.Schema != "tos.service.provider-token-action.v1" || r.Network != c.Network || r.InputHash != inputHash {
		return errors.New("invalid token action journal identity")
	}
	if r.State == "building" || r.State == "signed" || r.State == "never_sent" {
		r.State = "never_sent"
		return nil
	}
	resolved, err := s.ResolveTokenActor(ctx, r.Input.Actor, c.Token.Pins, false)
	if err != nil {
		return err
	}
	if resolved == nil || resolved.Account == nil || resolved.Account.Data == nil {
		return errors.New("token actor disappeared")
	}
	a := resolved.Account
	config, err := c.Token.Actor(r.Input.Actor)
	if err != nil {
		return err
	}
	if a.CodeHash != config.CodeHash || a.Data.Owner.Text() != c.WalletAddress || a.Data.Route.Master.Text() != config.Master {
		return errors.New("token reconciliation identity mismatch")
	}
	anchor := r.Anchor
	if r.Call != nil {
		anchor = toschain.ActorTxID{LT: r.Call.LT, Hash: r.Call.Hash}
	}
	history, err := s.TokenHistory(ctx, a.Address, &anchor)
	if err != nil {
		return err
	}
	if history == nil || history.Result != toschain.HistoryAnchorReached || history.Head != a.LastTransaction {
		return errors.New("token history must reach the action anchor")
	}
	var call *toschain.TokenActorTransaction
	if r.Call != nil {
		body, e := decodeCellBOCText(r.Call.BodyBOC)
		if e != nil || hex.EncodeToString(body.Hash()) != r.BodyHash || r.Call.QueryID != r.QueryID || r.Call.Sender != c.WalletAddress {
			return errors.New("stored token call identity mismatch")
		}
		saved := *r.Call
		call = &saved
	}
	for i := range history.Transactions {
		tx := &history.Transactions[i]
		if tx.LT <= r.Anchor.LT || tx.Sender != c.WalletAddress || tx.QueryID != r.QueryID {
			continue
		}
		body, err := decodeCellBOCText(tx.BodyBOC)
		if err != nil {
			return err
		}
		if hex.EncodeToString(body.Hash()) != r.BodyHash {
			continue
		}
		if call != nil {
			return errors.New("token action has more than one execution")
		}
		call = tx
	}
	if call == nil {
		return tokenDeliveryMissing(ctx, s, c, r)
	}
	r.Call = call
	transactions := append([]toschain.TokenActorTransaction(nil), history.Transactions...)
	if anchor.LT == call.LT {
		transactions = append(transactions, *call)
	}
	sort.Slice(transactions, func(i, j int) bool { return transactions[i].LT < transactions[j].LT })
	id := toschain.ActorTxID{LT: call.LT, Hash: call.Hash}
	r.Transaction = &id
	if !call.TookEffect {
		r.State = "refused"
		r.Failure = fmt.Sprintf("actor refused token action with exit code %d", call.ExitCode)
		return nil
	}
	r.PayoutID = 0
	r.State = "finalized"
	if r.Input.Operation == "abandon-payout" {
		r.State = "abandoned"
		return nil
	}
	if r.Input.Operation == "recover-surplus" || r.Input.Operation == "recheck-payout" {
		done, err := resolveTokenBalanceQuery(a, r, *call, transactions)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	} else if r.Input.Operation == "withdraw-revenue" {
		for _, out := range call.Outputs {
			if out.Destination != a.OwnWallet || out.Bounced {
				continue
			}
			body, err := decodeCellBOCText(out.BodyBOC)
			if err != nil {
				return err
			}
			p, err := nativecore.DecodeServiceActorTokenReportedTransfer(body)
			if err == nil {
				if r.PayoutID != 0 {
					return errors.New("multiple withdrawal payouts")
				}
				r.PayoutID = p.QueryID
			}
		}
	}
	if r.PayoutID == 0 {
		if r.Input.Operation == "withdraw-revenue" && r.Preview.Message.Details["token_amount"] != "0" {
			return errors.New("token withdrawal has no payout creation")
		}
		return nil
	}

	r.State = "paying"
	var original *nativecore.ServiceActorTokenReportedTransferV1
	var createdLT uint64
	for _, creation := range transactions {
		if creation.LT < call.LT || !creation.TookEffect {
			continue
		}
		for _, out := range creation.Outputs {
			if out.Destination != a.OwnWallet || out.Bounced {
				continue
			}
			body, e := decodeCellBOCText(out.BodyBOC)
			if e != nil {
				return e
			}
			payout, e := nativecore.DecodeServiceActorTokenReportedTransfer(body)
			if e != nil || payout.QueryID != r.PayoutID {
				continue
			}
			if original != nil {
				return errors.New("token payout id has multiple creation envelopes")
			}
			original = &payout
			createdLT = creation.LT
		}
	}
	if original == nil {
		return errors.New("token payout has no authenticated creation envelope")
	}
	for _, tx := range transactions {
		if tx.LT <= createdLT || !tx.TookEffect {
			continue
		}
		for _, log := range tx.Logs {
			o := log.Outcome
			if o == nil || o.PayoutID != r.PayoutID || o.Outcome == 4 {
				continue
			}
			kind := uint8(3)
			if r.Input.Operation == "recover-surplus" {
				kind = 6
			}
			if o.Kind != kind || o.RequestID != 0 || !o.Recipient.Equal(original.Destination) || o.Amount.Cmp(original.Amount) != 0 {
				return errors.New("token outcome differs from payout creation")
			}
			switch o.Outcome {
			case 0:
				r.State = "delivered"
			case 1, 2, 3:
				r.State = "failed"
			case 5:
				r.State = "abandoned"
			}
		}
		body, e := decodeCellBOCText(tx.BodyBOC)
		if e != nil || tx.Bounced {
			continue
		}
		report, e := nativecore.DecodeServiceActorTokenOutcomeInput(body)
		if e != nil || report.QueryID != r.PayoutID || report.Amount.Cmp(original.Amount) != 0 {
			continue
		}
		if report.Opcode == 0x52544431 {
			wallet, e := nativecore.DeriveServiceActorTokenWallet(original.Destination.Text(), a.Data.Route)
			if e != nil {
				return e
			}
			if tx.Sender == wallet && report.Recipient.Equal(original.Destination) {
				r.State = "delivered"
			}
		}
		if (report.Opcode == 0x52544631 || report.Opcode == 0x52545232) && tx.Sender == a.OwnWallet {
			r.State = "failed"
		}
	}
	if _, ok := a.Data.Payouts[r.PayoutID]; ok {
		r.State = "paying"
	}
	return nil
}

// A balance query has its own monotonic id, taken from the actor's actual
// provide_balance output. The owner's inbound query_id is a different domain.
func tokenQueryID(tx toschain.TokenActorTransaction, wallet string) (uint64, error) {
	var id uint64
	found := false
	for _, out := range tx.Outputs {
		if out.Destination != wallet || out.Bounced || !out.Bounce {
			continue
		}
		op, q, e := tokenBodyPrefix(out.BodyBOC, false)
		if e != nil || op != 0x52544231 {
			continue
		}
		if found {
			return 0, errors.New("token call emitted multiple balance queries")
		}
		id = q
		found = true
	}
	if !found || id == 0 {
		return 0, errors.New("token call has no provide_balance output")
	}
	return id, nil
}
func tokenBodyPrefix(text string, bounced bool) (uint32, uint64, error) {
	body, e := decodeCellBOCText(text)
	if e != nil {
		return 0, 0, e
	}
	s, e := body.BeginParse()
	if e != nil {
		return 0, 0, e
	}
	if bounced {
		prefix, e := s.LoadUInt(32)
		if e != nil || prefix != 0xffffffff {
			return 0, 0, errors.New("invalid bounce prefix")
		}
	}
	op, e := s.LoadUInt(32)
	if e != nil {
		return 0, 0, e
	}
	q, e := s.LoadUInt(64)
	return uint32(op), q, e
}
func resolveTokenBalanceQuery(a *toschain.TokenActorAccount, r *TokenActionRecord, call toschain.TokenActorTransaction, transactions []toschain.TokenActorTransaction) (bool, error) {
	query, err := tokenQueryID(call, a.OwnWallet)
	if err != nil {
		return false, err
	}
	r.State = "paying"
	for _, tx := range transactions {
		if tx.LT <= call.LT || !tx.TookEffect {
			continue
		}
		if tx.Bounced && tx.Sender == a.OwnWallet {
			op, id, e := tokenBodyPrefix(tx.BodyBOC, true)
			if e == nil && op == 0x52544231 && id == query {
				r.State = "failed"
				r.Failure = "provide_balance bounced"
				return true, nil
			}
		}
		for _, log := range tx.Logs {
			b := log.Balance
			if b == nil || b.QueryID != query {
				continue
			}
			if r.Input.Operation == "recover-surplus" && (b.Purpose != 0 || b.Target != 0) || r.Input.Operation == "recheck-payout" && (b.Purpose != 1 || b.Target != r.Input.ID) {
				return false, errors.New("balance log differs from the submitted query")
			}
			if b.Result != 0 {
				r.State = "failed"
				r.Failure = fmt.Sprintf("balance query refused with %d", b.Result)
				return true, nil
			}
			if r.Input.Operation == "recheck-payout" {
				if b.PayoutID != r.Input.ID {
					return false, errors.New("recheck result names another payout")
				}
				return true, finishTokenRecheck(a, r, tx, transactions)
			}
			r.PayoutID = b.PayoutID
			return false, nil
		}
		// A newer successful query supersedes the old slot only after the TTL.
		// Process the suffix in order so an old reply is resolved before a later
		// replacement, even when its best-effort log was dropped.
		if uint64(tx.Now) >= uint64(call.Now)+3600 {
			if next, e := tokenQueryID(tx, a.OwnWallet); e == nil && next != query {
				r.State = "superseded"
				r.Failure = "balance query superseded after its TTL"
				return true, nil
			}
			if tx.Opcode == nativecore.ServiceActorTokenAbandonOpcode {
				r.State = "superseded"
				r.Failure = "balance query cleared after its TTL"
				return true, nil
			}
		}
		op, id, e := tokenBodyPrefix(tx.BodyBOC, false)
		if e == nil && !tx.Bounced && tx.Sender == a.OwnWallet && op == 0x52544232 && id == query {
			if r.Input.Operation == "recheck-payout" {
				if _, stillPaying := a.Data.Payouts[r.Input.ID]; stillPaying {
					r.State = "failed"
					r.Failure = "recheck balance reply left the payout in flight"
					return true, nil
				}
				return true, finishTokenRecheck(a, r, tx, transactions)
			}
			for _, out := range tx.Outputs {
				if out.Destination != a.OwnWallet || out.Bounced {
					continue
				}
				body, e := decodeCellBOCText(out.BodyBOC)
				if e != nil {
					return false, e
				}
				payout, e := nativecore.DecodeServiceActorTokenReportedTransfer(body)
				if e != nil {
					continue
				}
				if r.PayoutID != 0 || payout.Amount.String() != r.Input.TokenAmount || payout.Destination.Text() != a.Data.Owner.Text() {
					return false, errors.New("surplus payout differs from the submitted recovery")
				}
				r.PayoutID = payout.QueryID
			}
			if r.PayoutID != 0 {
				return false, nil
			}
			r.State = "failed"
			r.Failure = "surplus balance reply produced no payout"
			return true, nil
		}
	}
	return true, nil
}

func finishTokenRecheck(a *toschain.TokenActorAccount, r *TokenActionRecord, reply toschain.TokenActorTransaction, transactions []toschain.TokenActorTransaction) error {
	target := r.Preview.Recheck
	if target == nil {
		return errors.New("missing recheck target snapshot")
	}
	if entry, ok := a.Data.Returned[target.ReturnedID]; ok && entry.Paying == 0 {
		if entry.Caller.Text() != target.Recipient || entry.Amount == nil || entry.Amount.String() != target.Amount {
			return errors.New("returned entry differs from rechecked payout")
		}
		r.State = "returned"
		return nil
	}
	for _, later := range transactions {
		if later.LT > reply.LT && later.TookEffect && later.RequestID == target.ReturnedID && (later.Opcode == nativecore.ServiceActorTokenClaimReturnedOpcode || later.Opcode == nativecore.ServiceActorTokenSweepReturnedOpcode) {
			r.State = "finalized"
			return nil
		}
	}
	return errors.New("recheck did not restore the original returned entry")
}
