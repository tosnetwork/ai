package serviceactor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	StatusPaying   Status = "paying"
	StatusReturned Status = "returned"
)

// TokenRequest is derived from a complete finalized actor history and its
// account at that same checkpoint. Paying never implies receipt or refund.
type TokenRequest struct {
	Snapshot     nativecore.ServiceActorTokenRequestSnapshotV1
	Call         toschain.TokenActorTransaction
	Status       Status
	PayoutID     uint64
	ReturnedID   uint64
	Destination  string
	ResponseHash string
	Terminal     *toschain.TokenActorTransaction
}

type tokenPayout struct {
	ID             uint64
	Kind           uint8
	RequestField   uint64
	Recipient      string
	Requester      string
	Amount         *big.Int
	Request        *TokenRequest
	Previous       Status
	ReturnedOrigin uint64
}

type TokenLifecycleSession interface {
	Checkpoint() uint64
	ChainTime() time.Time
	ReadTokenActor(context.Context, string) (*toschain.TokenActorAccount, bool, error)
	TokenHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenActorHistory, error)
}

// ResolveTokenRequests opens no second checkpoint. A missing history, incomplete
// window or account/history disagreement is an error, never a terminal result.
func ResolveTokenRequests(ctx context.Context, session TokenLifecycleSession, actor string) (*toschain.TokenActorAccount, map[uint64]*TokenRequest, error) {
	if session == nil {
		return nil, nil, errors.New("missing token session")
	}
	account, found, err := session.ReadTokenActor(ctx, actor)
	if err != nil {
		return nil, nil, err
	}
	if !found || account == nil {
		return nil, nil, errors.New("token actor is not deployed")
	}
	history, err := session.TokenHistory(ctx, actor, nil)
	if err != nil {
		return nil, nil, err
	}
	requests, err := ReplayTokenRequests(account, history, session.ChainTime())
	if err != nil {
		return nil, nil, err
	}
	return account, requests, nil
}

func tokenBody(text string) (*cell.Cell, error) {
	if len(text) == 0 || len(text) > 2<<20 {
		return nil, errors.New("missing or oversized token body")
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("token body exceeds limit")
	}
	return cell.FromBOC(raw)
}
func tokenAtomic(text string) (*big.Int, error) {
	if len(text) == 0 || len(text) > 37 || (len(text) > 1 && text[0] == '0') {
		return nil, errors.New("invalid token atomic amount")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid token atomic amount")
		}
	}
	n, ok := new(big.Int).SetString(text, 10)
	if !ok || n.Sign() < 0 || n.Cmp(nativecore.MaxServiceActorCoins) >= 0 {
		return nil, errors.New("token amount outside bounds")
	}
	return n, nil
}

func reportedPayout(tx toschain.TokenActorTransaction, ownWallet string) (*nativecore.ServiceActorTokenReportedTransferV1, error) {
	var result *nativecore.ServiceActorTokenReportedTransferV1
	for _, out := range tx.Outputs {
		if out.Destination != ownWallet || out.Bounced {
			continue
		}
		body, err := tokenBody(out.BodyBOC)
		if err != nil {
			return nil, err
		}
		s, err := body.BeginParse()
		if err != nil {
			return nil, err
		}
		op, err := s.LoadUInt(32)
		if err != nil || op != 0x52545231 {
			continue
		}
		payout, err := nativecore.DecodeServiceActorTokenReportedTransfer(body)
		if err != nil {
			return nil, err
		}
		if result != nil || !out.Bounce || out.HasStateInit {
			return nil, errors.New("ambiguous token payout creation")
		}
		result = &payout
	}
	return result, nil
}

// ReplayTokenRequests treats accepted report inputs as authority even if their
// best-effort SAO1 log was dropped. Every observed log is cross-checked against
// its original payout; a mismatch report leaves the payout in flight.
func ReplayTokenRequests(account *toschain.TokenActorAccount, history *toschain.TokenActorHistory, chainTime time.Time) (map[uint64]*TokenRequest, error) {
	if account == nil || account.Data == nil || history == nil || history.Result != toschain.HistoryComplete || len(history.Transactions) > 100000 || history.Head != account.LastTransaction {
		return nil, errors.New("token account requires its complete checkpoint history")
	}
	if chainTime.Unix() < 0 {
		return nil, errors.New("invalid checkpoint time")
	}
	requests := map[uint64]*TokenRequest{}
	payouts := map[uint64]*tokenPayout{}
	seenPayouts := map[uint64]bool{}
	returned := map[uint64]*TokenRequest{}
	chronological := append([]toschain.TokenActorTransaction(nil), history.Transactions...)
	sort.Slice(chronological, func(i, j int) bool { return chronological[i].LT < chronological[j].LT })
	var previous uint64
	for _, tx := range chronological {
		if tx.LT == 0 || tx.LT <= previous || len(tx.Hash) != 64 || uint64(tx.Now) > uint64(chainTime.Unix()) {
			return nil, errors.New("invalid token history order or time")
		}
		previous = tx.LT
		if !tx.TookEffect {
			continue
		}
		completed := map[uint64]struct {
			p       *tokenPayout
			outcome uint8
		}{}
		for _, log := range tx.Logs {
			if log.Snapshot == nil {
				continue
			}
			s := log.Snapshot
			if tx.Notification == nil || tx.Sender != account.OwnWallet || tx.Notification.Payload == nil || s.Terms.PricePerCall == nil || s.Caller.Text() != tx.Notification.From || s.RequestHash != tx.Notification.Payload.RequestHash || s.TermsHash != tx.Notification.Payload.ExpectedTermsHash || tx.Notification.AmountAtomic != s.Terms.PricePerCall.String() || requests[s.RequestID] != nil {
				return nil, errors.New("token snapshot is not its authenticated funding")
			}
			terms, err := nativecore.BuildServiceActorTokenTerms(s.Terms)
			if err != nil || !bytes.Equal(terms.Hash(), s.TermsHash[:]) || s.ResponseDeadline != uint64(tx.Now)+uint64(s.Terms.ResponseSLA) || s.RefundClaimDeadline < s.ResponseDeadline || s.RefundClaimDeadline-s.ResponseDeadline != uint64(s.Terms.RefundClaimWindow) {
				return nil, errors.New("invalid token snapshot terms or deadlines")
			}
			requests[s.RequestID] = &TokenRequest{Snapshot: *s, Call: tx, Status: StatusPending}
		}
		// A bounced reported-transfer body is truncated after its amount. The
		// transaction header, not an arbitrary body prefix, authenticates a bounce.
		if tx.Bounced {
			body, err := tokenBody(tx.BodyBOC)
			if err != nil {
				return nil, err
			}
			s, err := body.BeginParse()
			if err != nil {
				return nil, err
			}
			prefix, err := s.LoadUInt(32)
			if err == nil && prefix == 0xffffffff {
				op, e := s.LoadUInt(32)
				if e == nil && op == 0x52545231 {
					id, e := s.LoadUInt(64)
					if e == nil {
						amount, e := s.LoadBigCoins()
						if e == nil {
							if p := payouts[id]; p != nil && tx.Sender == account.OwnWallet && p.Amount.Cmp(amount) == 0 {
								if err = finishTokenPayout(p, 2, tx, returned); err != nil {
									return nil, err
								}
								completed[id] = struct {
									p       *tokenPayout
									outcome uint8
								}{p, 2}
								delete(payouts, id)
							}
						}
					}
				}
			}
		} else if body, err := tokenBody(tx.BodyBOC); err == nil {
			if report, err := nativecore.DecodeServiceActorTokenOutcomeInput(body); err == nil {
				if p := payouts[report.QueryID]; p != nil && report.Amount.Cmp(p.Amount) == 0 {
					expected := account.OwnWallet
					outcome := uint8(1)
					// A delivery report naming another recipient is not this
					// payout's outcome. It is skipped locally: the rest of the
					// transaction (request opcodes, created payouts, logs) is still
					// replayed.
					recipientMatches := true
					if report.Opcode == 0x52544431 {
						route := account.Data.Route
						wallet, e := nativecore.DeriveServiceActorTokenWallet(p.Recipient, route)
						if e != nil {
							return nil, e
						}
						expected = wallet
						outcome = 0
						recipientMatches = report.Recipient.Text() == p.Recipient
					}
					if recipientMatches && report.Opcode != 0x52544232 && tx.Sender == expected {
						if err = finishTokenPayout(p, outcome, tx, returned); err != nil {
							return nil, err
						}
						completed[p.ID] = struct {
							p       *tokenPayout
							outcome uint8
						}{p, outcome}
						delete(payouts, p.ID)
					}
				}
			}
		}
		r := requests[tx.RequestID]
		if r != nil && tx.Opcode == nativecore.ServiceActorTokenRespondOpcode {
			if r.Status != StatusPending || tx.Sender != account.Data.Owner.Text() || uint64(tx.Now) >= r.Snapshot.ResponseDeadline || tx.Signed != r.Snapshot.Terms.HasAttestor {
				return nil, errors.New("invalid finalized token response")
			}
			r.Status = StatusResponded
			r.ResponseHash = tx.ResponseHash
			copyTx := tx
			r.Terminal = &copyTx
		}
		if r != nil && tx.Opcode == nativecore.ServiceActorTokenExpireOpcode {
			if r.Status != StatusPending || uint64(tx.Now) < r.Snapshot.ResponseDeadline || uint64(tx.Now) >= r.Snapshot.RefundClaimDeadline {
				return nil, errors.New("invalid finalized token expiration")
			}
			r.Status = StatusRefundable
		}
		created, err := reportedPayout(tx, account.OwnWallet)
		if err != nil {
			return nil, err
		}
		if created != nil {
			if created.QueryID == 0 || seenPayouts[created.QueryID] {
				return nil, errors.New("token payout id reused")
			}
			seenPayouts[created.QueryID] = true
			kind := uint8(0)
			requestField := tx.RequestID
			var target *TokenRequest
			var origin uint64
			switch tx.Opcode {
			case nativecore.ServiceActorTokenClaimRefundOpcode:
				kind = 1
				target = r
			case nativecore.ServiceActorTokenSweepOpcode:
				kind = 2
				target = r
			case nativecore.ServiceActorTokenClaimReturnedOpcode:
				kind = 5
				origin = tx.RequestID
				target = returned[origin]
			case nativecore.ServiceActorTokenSweepReturnedOpcode:
				kind = 7
				origin = tx.RequestID
				target = returned[origin]
			default:
				for _, log := range tx.Logs {
					if log.Funding != nil && log.Funding.PayoutID == created.QueryID {
						kind = 4
						requestField = 0
					}
				}
				if kind == 0 {
					for _, log := range tx.Logs {
						if log.Balance != nil && log.Balance.Result == 0 && log.Balance.Purpose == 0 && log.Balance.PayoutID == created.QueryID {
							kind = 6
							requestField = 0
						}
					}
				}
				if kind == 0 && tx.Opcode == nativecore.ServiceActorTokenWithdrawOpcode {
					kind = 3
					requestField = 0
				}
			}
			if kind == 0 {
				return nil, errors.New("unclassified finalized token payout")
			}
			p := &tokenPayout{ID: created.QueryID, Kind: kind, RequestField: requestField, Recipient: created.Destination.Text(), Requester: created.ResponseDestination.Text(), Amount: created.Amount, Request: target, ReturnedOrigin: origin}
			if (kind == 1 || kind == 2) && target == nil {
				return nil, errors.New("token payout has no admitted request")
			}
			if (kind == 1 || kind == 2) && target != nil {
				if (kind == 1 && (target.Status != StatusRefundable || tx.Sender != target.Snapshot.Caller.Text() || uint64(tx.Now) >= target.Snapshot.RefundClaimDeadline || p.Recipient != tx.Destination)) || (kind == 2 && ((target.Status != StatusPending && target.Status != StatusRefundable) || uint64(tx.Now) < target.Snapshot.RefundClaimDeadline || p.Recipient != target.Snapshot.Caller.Text())) || p.Amount.Cmp(target.Snapshot.Terms.PricePerCall) != 0 {
					return nil, errors.New("token request payout differs from its origin")
				}
			}
			if (kind == 5 || kind == 7) && target == nil {
				// An earlier best-effort recheck log may be absent. A successful returned
				// claim proves the entry existed; its globally unique id still binds it
				// to the known original buyer payout.
				if old := payouts[origin]; old != nil && (old.Kind == 1 || old.Kind == 2) {
					target = old.Request
					if target != nil {
						target.Status = StatusReturned
						target.ReturnedID = origin
					}
					p.Request = target
					returned[origin] = target
					delete(payouts, origin)
				}
			}
			if (kind == 5 || kind == 7) && target != nil {
				if target.Status != StatusReturned || p.Amount.Cmp(target.Snapshot.Terms.PricePerCall) != 0 || (kind == 5 && (tx.Sender != target.Snapshot.Caller.Text() || p.Recipient != tx.Destination)) || (kind == 7 && p.Recipient != target.Snapshot.Caller.Text()) {
					return nil, errors.New("returned payout differs from original buyer")
				}
			}
			if target != nil {
				p.Previous = target.Status
				target.Status = StatusPaying
				target.PayoutID = p.ID
				target.Destination = p.Recipient
				target.ReturnedID = origin
			}
			payouts[p.ID] = p
		}
		for _, log := range tx.Logs {
			if log.Outcome == nil {
				continue
			}
			o := log.Outcome
			p := payouts[o.PayoutID]
			if p == nil {
				if done, ok := completed[o.PayoutID]; ok {
					p = done.p
					if o.Outcome != done.outcome || p.Kind != o.Kind || p.RequestField != o.RequestID || p.Recipient != o.Recipient.Text() || p.Amount.Cmp(o.Amount) != 0 {
						return nil, errors.New("token outcome log differs from authenticated outcome")
					}
					continue
				}
				return nil, errors.New("token outcome has no original payout")
			}
			if p.Kind != o.Kind || p.RequestField != o.RequestID || p.Recipient != o.Recipient.Text() || (o.Outcome != 4 && p.Amount.Cmp(o.Amount) != 0) {
				return nil, errors.New("token outcome log differs from its payout")
			}
			if o.Outcome == 4 {
				continue
			}
			if err = finishTokenPayout(p, o.Outcome, tx, returned); err != nil {
				return nil, err
			}
			delete(payouts, p.ID)
		}
	}
	for id, r := range requests {
		d := account.Data
		pending, hasPending := d.Pending[id]
		refund, hasRefund := d.Refunds[id]
		if hasPending {
			if r.Status != StatusPending || !pending.Caller.Equal(r.Snapshot.Caller) || pending.RequestHash != r.Snapshot.RequestHash || pending.TermsHash != r.Snapshot.TermsHash || pending.Price == nil || pending.Price.Cmp(r.Snapshot.Terms.PricePerCall) != 0 || pending.ResponseDeadline != r.Snapshot.ResponseDeadline || pending.RefundClaimDeadline != r.Snapshot.RefundClaimDeadline {
				return nil, errors.New("token pending cell disagrees with history")
			}
		} else if hasRefund {
			if r.Status != StatusRefundable || !refund.Caller.Equal(r.Snapshot.Caller) || refund.Price == nil || refund.Price.Cmp(r.Snapshot.Terms.PricePerCall) != 0 || refund.RefundClaimDeadline != r.Snapshot.RefundClaimDeadline {
				return nil, errors.New("token refund cell disagrees with history")
			}
		} else if r.Status == StatusPending || r.Status == StatusRefundable {
			return nil, errors.New("token live request disappeared without a proven outcome")
		}
		if r.Status == StatusPaying {
			p, ok := d.Payouts[r.PayoutID]
			if !ok { // A finalized returned cell can prove a recheck conversion whose log was dropped.
				entry, found := d.Returned[r.PayoutID]
				if found && entry.Paying == 0 && entry.Caller.Equal(r.Snapshot.Caller) && entry.Amount.Cmp(r.Snapshot.Terms.PricePerCall) == 0 {
					r.Status = StatusReturned
					r.ReturnedID = r.PayoutID
					continue
				}
				return nil, errors.New("token in-flight payout is missing from finalized data")
			}
			if p.Amount == nil || p.Amount.Cmp(r.Snapshot.Terms.PricePerCall) != 0 || p.Recipient.Text() != r.Destination {
				return nil, errors.New("token payout cell differs from history")
			}
		}
		if r.Status == StatusReturned {
			entry, ok := d.Returned[r.ReturnedID]
			if !ok || entry.Paying != 0 || !entry.Caller.Equal(r.Snapshot.Caller) || entry.Amount.Cmp(r.Snapshot.Terms.PricePerCall) != 0 {
				return nil, errors.New("token returned cell differs from history")
			}
		}
		if r.Status == StatusPending {
			if uint64(chainTime.Unix()) >= r.Snapshot.RefundClaimDeadline {
				r.Status = StatusLapsed
			} else if uint64(chainTime.Unix()) >= r.Snapshot.ResponseDeadline {
				r.Status = StatusOverdue
			}
		}
	}
	return requests, nil
}

func finishTokenPayout(p *tokenPayout, outcome uint8, tx toschain.TokenActorTransaction, returned map[uint64]*TokenRequest) error {
	if outcome > 5 {
		return errors.New("unknown token payout outcome")
	}
	r := p.Request
	if r == nil {
		return nil
	}
	switch outcome {
	case 0:
		if p.Kind == 1 || p.Kind == 5 {
			r.Status = StatusRefunded
		} else if p.Kind == 2 || p.Kind == 7 {
			r.Status = StatusSwept
		} else {
			return errors.New("unexpected request payout kind")
		}
		if p.ReturnedOrigin != 0 {
			delete(returned, p.ReturnedOrigin)
		}
	case 1, 3:
		r.Status = StatusReturned
		if p.Kind == 1 || p.Kind == 2 {
			r.ReturnedID = p.ID
			returned[p.ID] = r
		} else {
			r.ReturnedID = p.ReturnedOrigin
			returned[p.ReturnedOrigin] = r
		}
	case 2:
		if p.Kind == 1 || p.Kind == 2 {
			r.Status = p.Previous
		} else {
			r.Status = StatusReturned
			r.ReturnedID = p.ReturnedOrigin
			returned[p.ReturnedOrigin] = r
		}
	case 4:
		return nil
	case 5:
		return errors.New("a buyer payout cannot be abandoned")
	}
	copyTx := tx
	r.Terminal = &copyTx
	return nil
}

func TokenRequestAction(status Status) string {
	switch status {
	case StatusOverdue:
		return "expire, then claim_refund before the refund deadline"
	case StatusRefundable:
		return "claim_refund before the refund deadline"
	case StatusReturned:
		return "claim_returned with the returned entry id"
	case StatusPaying:
		return "wait for an authenticated outcome; recheck_payout only after its age bound"
	case StatusLapsed:
		return "sweep_expired_request"
	default:
		return ""
	}
}

func TokenRequestSummary(id uint64, r *TokenRequest) string {
	if r == nil {
		return "unresolved"
	}
	return fmt.Sprintf("request %d: %s", id, r.Status)
}
