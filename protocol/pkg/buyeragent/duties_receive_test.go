package buyeragent

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
)

// fakeReceiver records the result rounds the duty round asks for.
type fakeReceiver struct {
	mu     sync.Mutex
	rounds []ResultRound
	err    error
}

func (r *fakeReceiver) ReceiveResult(_ context.Context, round ResultRound) (ResultView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rounds = append(r.rounds, round)
	return ResultView{Examined: len(r.rounds)}, r.err
}

// The duty round runs the result round of a responded request, and only
// of a responded one, with the finalized response hash, the checkpoint's
// chain time and the Receipt binding of the purchase.
func TestTheDutyRoundReceivesTheResultOfARespondedRequest(t *testing.T) {
	f := newFixture(t)
	receiver := &fakeReceiver{}
	f.agent.config.Results = receiver
	view := f.paid(t, keyA)
	f.buyer.responseDeadline = uint64(fxNow.Add(time.Hour).Unix())
	f.buyer.chainTime = fxNow.Add(2 * time.Hour).Unix()
	f.buyer.responseHash = strings.Repeat("7e", 32)
	f.setStatus(serviceactor.StatusPending)
	if out, err := f.agent.RefundNow(context.Background(), view.RequestHash); err != nil || out.Result != nil {
		t.Fatalf("a pending request ran a result round: %+v %v", out, err)
	}
	f.setStatus(serviceactor.StatusResponded)
	out, err := f.agent.RefundNow(context.Background(), view.RequestHash)
	if err != nil || out.Result == nil || out.Result.Examined != 1 {
		t.Fatalf("a responded request: %+v %v", out, err)
	}
	round := receiver.rounds[0]
	record, err := f.buyer.Journal().Read(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	purchase, err := f.agent.store.readPurchase(view.RequestHash)
	if err != nil {
		t.Fatal(err)
	}
	if round.ProviderAgentID != fxProvider || round.Record.RequestHash != view.RequestHash ||
		round.ResponseHash[0] != 0x7e || round.ResponseHash[31] != 0x7e ||
		!round.ResponseDeadline.Equal(fxNow.Add(time.Hour)) || !round.ChainTime.Equal(fxNow.Add(2*time.Hour)) ||
		round.RetentionSeconds != purchase.RetentionSeconds {
		t.Fatalf("result round %+v", round)
	}
	receipt := round.Receipt
	if receipt.QuoteCommitment != record.QuoteCommitment || receipt.SourceDigest != purchase.SourceDigest ||
		receipt.ProviderAgentID != fxProvider || receipt.ToolchainDigest == "" ||
		receipt.ToolchainDigest != purchase.ToolchainDigest || receipt.SandboxDigest != purchase.ManifestDigest ||
		receipt.Price.String() != record.PriceNanoTOS || hex.EncodeToString(receipt.ExecutionID[:]) != record.ExecutionID ||
		hex.EncodeToString(receipt.InputDigest[:]) != record.InputDigest {
		t.Fatalf("receipt binding %+v", receipt)
	}
	// A responded request without a response hash is not received.
	f.buyer.responseHash = ""
	if _, err := f.agent.RefundNow(context.Background(), view.RequestHash); err == nil || len(receiver.rounds) != 1 {
		t.Fatalf("a respond without a response hash: %v", err)
	}
	f.buyer.responseHash = strings.Repeat("7e", 32)
	receiver.err = errors.New("disk full")
	if _, err := f.agent.RefundNow(context.Background(), view.RequestHash); err == nil || codeOf(t, err) != CodeInternal {
		t.Fatalf("a failed result round: %v", err)
	}
}

// The poller's lookup finds only admitted purchases, with their provider,
// Capability, Accepted Quote and frame binding.
func TestLookupPurchaseFindsOnlyAdmittedPurchases(t *testing.T) {
	f := newFixture(t)
	view := f.paid(t, keyA)
	if _, found, err := f.agent.LookupPurchase(view.RequestHash); err != nil || found {
		t.Fatalf("a purchase not yet admitted: %v %v", found, err)
	}
	f.setStatus(serviceactor.StatusPending)
	if _, err := f.agent.RefundNow(context.Background(), view.RequestHash); err != nil {
		t.Fatal(err)
	}
	purchase, found, err := f.agent.LookupPurchase(view.RequestHash)
	record, readErr := f.buyer.Journal().Read(view.RequestHash)
	if err != nil || !found || readErr != nil {
		t.Fatalf("an admitted purchase: %v %v %v", found, err, readErr)
	}
	binding, err := taskBinding(record)
	if err != nil || purchase.ProviderAgentID != fxProvider || purchase.CapabilityID != record.CapabilityID ||
		purchase.QuoteCommitment != record.QuoteCommitment || purchase.Binding != binding {
		t.Fatalf("lookup %+v %v", purchase, err)
	}
	for _, unknown := range []string{strings.Repeat("00", 32), "../x"} {
		if _, found, err := f.agent.LookupPurchase(unknown); err != nil || found {
			t.Fatalf("%q: %v %v", unknown, found, err)
		}
	}
}
