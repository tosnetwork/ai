package purchaseevidence

import (
	"fmt"
	"strings"
)

// Summary renders a verdict for a person. The JSON verdict is the record;
// the summary only restates it.
func Summary(verdict *Verdict) string {
	var out strings.Builder
	if verdict == nil {
		return "no verdict\n"
	}
	fmt.Fprintf(&out, "verdict: %s\n", strings.ToUpper(verdict.Result))
	fmt.Fprintf(&out, "network: %s (genesis root %s)\n", verdict.Network.NetworkID, verdict.Network.GenesisRootHash)
	if verdict.Reads != nil {
		agreeing := 0
		for _, endpoint := range verdict.Reads.Endpoints {
			if endpoint.GenesisOK {
				agreeing++
			}
		}
		fmt.Fprintf(&out, "endpoints: %d given, %d on this genesis, quorum %d\n", len(verdict.Reads.Endpoints), agreeing,
			verdict.Reads.Quorum)
	}
	if checkpoint := verdict.Checkpoint; checkpoint != nil {
		fmt.Fprintf(&out, "finalized checkpoint: %d (chain time %d)\n", checkpoint.Seqno, checkpoint.ChainTime)
	}
	if actor := verdict.Actor; actor != nil {
		match := "matches"
		if !actor.CodeHashMatches {
			match = "DIFFERS FROM"
		}
		fmt.Fprintf(&out, "actor %s: code %s the pinned release; owner %s; %d requests\n", actor.Address, match, actor.Owner,
			actor.NextRequestID)
	}
	for _, request := range verdict.Requests {
		id := "-"
		if request.RequestID != nil {
			id = fmt.Sprint(*request.RequestID)
		}
		fmt.Fprintf(&out, "request %s (%s): %s", id, request.RequestHash, request.State)
		if request.Status != "" && request.Status != request.State {
			fmt.Fprintf(&out, ", %s at the checkpoint", request.Status)
		}
		fmt.Fprintf(&out, "\n  call %s lt %d from %s, price %s, storage fee %s\n", request.Call.Hash, request.Call.LT,
			request.Caller, request.PriceNanoTOS, request.StorageFeeNanoTOS)
		if request.Respond != nil {
			fmt.Fprintf(&out, "  respond %s lt %d from provider wallet %s, response_hash %s\n", request.Respond.Hash,
				request.Respond.LT, request.ProviderWallet, request.ResponseHash)
		}
		for _, step := range []struct {
			name string
			tx   *TxReport
		}{{"expire", request.Expire}, {"claim_refund", request.ClaimRefund}, {"sweep", request.Sweep}} {
			if step.tx != nil {
				fmt.Fprintf(&out, "  %s %s lt %d from %s\n", step.name, step.tx.Hash, step.tx.LT, step.tx.Sender)
			}
		}
		if request.Receipt != nil {
			fmt.Fprintf(&out, "  receipt %s, artifact digest %s\n", request.Receipt.SHA256, request.Receipt.ArtifactDigest)
		}
	}
	failed := 0
	for _, check := range verdict.Checks {
		if !check.OK {
			failed++
			fmt.Fprintf(&out, "FAILED %s %s: %s\n", check.ID, check.Subject, check.Detail)
		}
	}
	fmt.Fprintf(&out, "%d checks, %d failed\n", len(verdict.Checks), failed)
	fmt.Fprintf(&out, "not claimed: %s\n", strings.Join(verdict.NotClaimed, "; "))
	return out.String()
}
