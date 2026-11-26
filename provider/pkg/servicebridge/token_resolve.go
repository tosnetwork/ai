package servicebridge

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// Reconciliation never opens a second checkpoint and never resubmits.
func resolveTokenAction(ctx context.Context, s TokenSession, c NodeConfig, r *TokenActionRecord) error {
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
	history, err := s.TokenHistory(ctx, a.Address, nil)
	if err != nil {
		return err
	}
	if history == nil || history.Result != toschain.HistoryComplete || history.Head != a.LastTransaction || len(history.Transactions) > 100000 {
		return errors.New("complete token history required")
	}
	var call *toschain.TokenActorTransaction
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
		r.State = "unknown"
		return nil
	}
	id := toschain.ActorTxID{LT: call.LT, Hash: call.Hash}
	r.Transaction = &id
	if !call.TookEffect {
		r.State = "failed"
		return nil
	}
	r.PayoutID = 0
	r.State = "finalized"
	if r.Input.Operation == "abandon-payout" {
		r.State = "abandoned"
		return nil
	}
	if r.Input.Operation == "recover-surplus" || r.Input.Operation == "recheck-payout" {
		r.State = "paying"
		for _, tx := range history.Transactions {
			if tx.LT < call.LT || !tx.TookEffect {
				continue
			}
			for _, log := range tx.Logs {
				if b := log.Balance; b != nil && b.QueryID == r.QueryID {
					if b.Result != 0 {
						r.State = "failed"
						return nil
					}
					if r.Input.Operation == "recheck-payout" {
						if b.Purpose != 1 || b.Target != r.Input.ID {
							return errors.New("recheck log mismatch")
						}
						requests, err := serviceactor.ReplayTokenRequests(a, history, s.ChainTime())
						if err != nil {
							return err
						}
						r.State = "finalized"
						for _, request := range requests {
							if request.PayoutID == r.Input.ID && request.Status == serviceactor.StatusReturned {
								r.State = "returned"
							}
						}
						return nil
					}
					if b.Purpose != 0 {
						return errors.New("surplus balance purpose mismatch")
					}
					r.PayoutID = b.PayoutID
				}
			}
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
	for _, creation := range history.Transactions {
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
	for _, tx := range history.Transactions {
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
