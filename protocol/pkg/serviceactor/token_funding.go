package serviceactor

import (
	"errors"
	"math/big"
	"sort"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// TokenFundingRefusal is not an admitted request. Its amount remains accounted
// for independently, including while a funding return is paying or returned.
type TokenFundingRefusal struct {
	Call           toschain.TokenActorTransaction `json:"call"`
	Reason         uint16                         `json:"reason"`
	PayoutID       uint64                         `json:"payout_id"`
	ActivePayoutID uint64                         `json:"active_payout_id"`
	Caller         string                         `json:"caller"`
	Amount         *big.Int                       `json:"-"`
	AmountAtomic   string                         `json:"amount_atomic"`
	State          string                         `json:"state"`
}

// checkTokenFundingLog refuses the SAF1 combinations the contract cannot emit.
// A refusal names payout id 0 whenever no funding return was made: an
// underfunded notification (1929), a zero amount, the funding-return cap, an
// exhausted payout id, a sender off workchain 0 (1934) or a return whose
// ledgers would not fit in Coins. Every admission reason can therefore appear
// with payout id 0; only a return of a positive amount to a canonical
// workchain-0 sender carries a payout id.
func checkTokenFundingLog(f *nativecore.ServiceActorTokenFundingLogV1) error {
	info, err := nativecore.ServiceActorTokenRefusalInfo(f.Reason)
	if err != nil || !info.Reason {
		return errors.New("funding refusal reason is outside the admission set")
	}
	if f.PayoutID == 0 {
		return nil
	}
	_, standard := f.From.RawStandard()
	switch {
	case f.Reason == 1929:
		return errors.New("underfunded refusal carries a payout id")
	case f.Reason == 1934:
		return errors.New("refusal of a sender off workchain 0 carries a payout id")
	case f.Amount.Sign() == 0:
		return errors.New("refusal of a zero amount carries a payout id")
	case !standard || f.From.Workchain != 0:
		return errors.New("funding return names a sender off workchain 0")
	}
	return nil
}

// ResolveTokenFundingRefusals requires the same complete history as request
// replay. An absent best-effort log is not invented from an off-chain journal.
func ResolveTokenFundingRefusals(account *toschain.TokenActorAccount, history *toschain.TokenActorHistory) ([]TokenFundingRefusal, error) {
	if account == nil || account.Data == nil || history == nil || history.Result != toschain.HistoryComplete || history.Head != account.LastTransaction || len(history.Transactions) > 100000 {
		return nil, errors.New("funding refusal needs its complete finalized history")
	}
	transactions := append([]toschain.TokenActorTransaction(nil), history.Transactions...)
	sort.Slice(transactions, func(i, j int) bool { return transactions[i].LT < transactions[j].LT })
	var result []TokenFundingRefusal
	byID := map[uint64]int{}
	kinds := map[uint64]uint8{}
	origins := map[uint64]uint64{}
	recipients := map[uint64]string{}
	for _, tx := range transactions {
		if !tx.TookEffect {
			continue
		}
		for _, log := range tx.Logs {
			f := log.Funding
			if f == nil {
				continue
			}
			if tx.Sender != account.OwnWallet || tx.Notification == nil || tx.Notification.QueryID != f.QueryID || tx.Notification.From != f.From.Text() || f.Amount == nil || f.Amount.Sign() < 0 || tx.Notification.AmountAtomic != f.Amount.String() {
				return nil, errors.New("funding refusal differs from authenticated notification")
			}
			if err := checkTokenFundingLog(f); err != nil {
				return nil, err
			}
			item := TokenFundingRefusal{Call: tx, Reason: f.Reason, PayoutID: f.PayoutID, ActivePayoutID: f.PayoutID, Caller: f.From.Text(), Amount: new(big.Int).Set(f.Amount), AmountAtomic: f.Amount.String(), State: "paying"}
			if f.PayoutID == 0 {
				// No funding return was made: the tokens are surplus, recoverable
				// only by the owner's recover_surplus. Nothing is owed to the
				// sender and no payout or returned cell tracks them.
				item.State = "surplus"
			} else {
				if _, exists := byID[f.PayoutID]; exists {
					return nil, errors.New("funding payout id reused")
				}
				byID[f.PayoutID] = len(result)
				kinds[f.PayoutID] = 4
				recipients[f.PayoutID] = f.From.Text()
			}
			result = append(result, item)
		}
		if tx.Opcode == nativecore.ServiceActorTokenClaimReturnedOpcode || tx.Opcode == nativecore.ServiceActorTokenSweepReturnedOpcode {
			if index, ok := byID[tx.RequestID]; ok {
				f := &result[index]
				payout, err := reportedPayout(tx, account.OwnWallet)
				if err != nil {
					return nil, err
				}
				if payout != nil {
					if payout.Amount.Cmp(f.Amount) != 0 || (tx.Opcode == nativecore.ServiceActorTokenClaimReturnedOpcode && (tx.Sender != f.Caller || payout.Destination.Text() != tx.Destination)) || (tx.Opcode == nativecore.ServiceActorTokenSweepReturnedOpcode && payout.Destination.Text() != f.Caller) {
						return nil, errors.New("returned funding claim differs")
					}
					if _, duplicate := byID[payout.QueryID]; duplicate {
						return nil, errors.New("funding claim payout reused")
					}
					recipients[payout.QueryID] = payout.Destination.Text()
					byID[payout.QueryID] = index
					origins[payout.QueryID] = tx.RequestID
					kinds[payout.QueryID] = 5
					if tx.Opcode == nativecore.ServiceActorTokenSweepReturnedOpcode {
						kinds[payout.QueryID] = 7
					}
					f.ActivePayoutID = payout.QueryID
					f.State = "paying"
				}
			}
		}
		// Logs are authenticated by the executed, pinned actor. Reports without a
		// log are independently authenticated by the original recipient wallet.
		for _, log := range tx.Logs {
			o := log.Outcome
			if o == nil {
				continue
			}
			index, ok := byID[o.PayoutID]
			if !ok {
				continue
			}
			f := &result[index]
			if o.Kind != kinds[o.PayoutID] || o.RequestID != origins[o.PayoutID] || o.Recipient.Text() != recipients[o.PayoutID] || (o.Outcome != 4 && (o.Amount == nil || o.Amount.Cmp(f.Amount) != 0)) {
				return nil, errors.New("funding outcome differs from its payout")
			}
			switch o.Outcome {
			case 0:
				f.State = "funding_returned"
			case 1, 2, 3:
				f.State = "returned"
			case 4:
			default:
				return nil, errors.New("invalid funding outcome")
			}
		}
		if body, err := tokenBody(tx.BodyBOC); err == nil && !tx.Bounced {
			if report, err := nativecore.DecodeServiceActorTokenOutcomeInput(body); err == nil {
				index, ok := byID[report.QueryID]
				if !ok {
					continue
				}
				f := &result[index]
				if report.Amount.Cmp(f.Amount) != 0 {
					continue
				}
				if report.Opcode == 0x52544431 {
					wallet, err := nativecore.DeriveServiceActorTokenWallet(recipients[report.QueryID], account.Data.Route)
					if err != nil {
						return nil, err
					}
					if tx.Sender == wallet && report.Recipient.Text() == recipients[report.QueryID] {
						f.State = "funding_returned"
					}
				} else if (report.Opcode == 0x52544631 || report.Opcode == 0x52545232) && tx.Sender == account.OwnWallet {
					f.State = "returned"
				}
			}
		}
	}
	for i := range result {
		f := &result[i]
		if f.PayoutID == 0 {
			continue
		}
		if p, ok := account.Data.Payouts[f.ActivePayoutID]; ok {
			if p.Kind != kinds[f.ActivePayoutID] || p.Amount == nil || p.Amount.Cmp(f.Amount) != 0 || p.Recipient.Text() != recipients[f.ActivePayoutID] {
				return nil, errors.New("funding payout cell differs")
			}
			f.State = "paying"
		} else if r, ok := account.Data.Returned[f.PayoutID]; ok {
			if r.Amount == nil || r.Amount.Cmp(f.Amount) != 0 || r.Caller.Text() != f.Caller {
				return nil, errors.New("funding returned cell differs")
			}
			f.State = "returned"
			if r.Paying != 0 {
				f.State = "paying"
			}
		} else if f.State != "funding_returned" {
			// A later returned claim may have completed. Its authenticated outcome is
			// required; lack of a cell alone is never evidence of payment.
			return nil, errors.New("funding liability disappeared without delivery evidence")
		}
	}
	return result, nil
}
