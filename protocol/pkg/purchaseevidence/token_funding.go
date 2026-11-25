package purchaseevidence

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

func verifyTokenFunding(ctx context.Context, s TokenSession, a *toschain.TokenActorAccount, b *TokenBundle, r *serviceactor.TokenRequest) error {
	senderWallet, err := nativecore.DeriveServiceActorTokenWallet(b.BuyerWallet, a.Data.Route)
	if err != nil {
		return err
	}
	for _, owner := range []string{b.BuyerWallet, a.Address} {
		wallet, found, err := s.ReadTokenWallet(ctx, owner, a.Data.Route)
		if err != nil {
			return err
		}
		expectedWallet, deriveErr := nativecore.DeriveServiceActorTokenWallet(owner, a.Data.Route)
		if deriveErr != nil {
			return deriveErr
		}
		if !found || wallet == nil || wallet.Address != expectedWallet || wallet.Owner != owner || wallet.Master != a.Data.Route.Master.Text() || wallet.CodeHash != "tvm-cell-sha256:"+hex.EncodeToString(a.Data.Route.WalletCodeHash[:]) {
			return errors.New("funding wallet is not deployed with pinned identity")
		}
	}
	expected := []string{b.BuyerWallet, senderWallet, a.OwnWallet}
	var chain [3]toschain.TokenActorTransaction
	for i, hop := range b.Funding {
		if hop.Account != expected[i] || hop.Transaction.LT == 0 {
			return errors.New("funding hop account differs from derived wallet")
		}
		if _, err := hex32(hop.Transaction.Hash); err != nil {
			return err
		}
		history, err := s.TokenWalletHistory(ctx, hop.Account, nil)
		if err != nil {
			return err
		}
		if history == nil || history.Result != toschain.HistoryComplete {
			return errors.New("funding history does not prove its anchor")
		}
		found := false
		for _, tx := range history.Transactions {
			if tx.LT == hop.Transaction.LT && tx.Hash == hop.Transaction.Hash {
				if found {
					return errors.New("duplicate funding transaction")
				}
				chain[i] = tx
				found = true
			}
		}
		if !found || !chain[i].TookEffect || chain[i].Bounced {
			return errors.New("funding hop did not execute")
		}
	}
	// The payer's exact output is the sender token wallet's input, which then
	// sends the exact recipient-wallet input, which sends the actor notification.
	next := []toschain.TokenActorTransaction{chain[1], chain[2], r.Call}
	for i, tx := range chain {
		count := 0
		target := a.Address
		if i < 2 {
			target = expected[i+1]
		}
		for _, out := range tx.Outputs {
			if out.Hash == next[i].InboundMessageHash && out.Destination == target && !out.Bounced {
				count++
			}
		}
		if count != 1 || next[i].Sender != expected[i] {
			return errors.New("funding message hashes or senders do not link")
		}
	}
	body, err := tokenEvidenceCell(chain[1].BodyBOC)
	if err != nil {
		return err
	}
	funding, err := nativecore.DecodeServiceActorTokenFundingTransfer(body)
	if err != nil {
		return err
	}
	if funding.Amount.Cmp(r.Snapshot.Terms.PricePerCall) != 0 || funding.Destination.Text() != a.Address || funding.ResponseDestination.Text() != b.BuyerWallet || funding.QueryID != r.Call.QueryID || funding.Payload.RequestHash != r.Snapshot.RequestHash || funding.Payload.ExpectedTermsHash != r.Snapshot.TermsHash {
		return errors.New("funding transfer differs from admitted terms")
	}
	return nil
}
