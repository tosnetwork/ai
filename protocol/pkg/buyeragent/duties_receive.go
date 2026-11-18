package buyeragent

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// ResultReceiver accepts the result of a responded purchase; Carrier
// implements it.
type ResultReceiver interface {
	ReceiveResult(ctx context.Context, round ResultRound) (ResultView, error)
}

// receive runs the result round of a responded request (section 7.3), on
// the duty round's schedule and its finalized checkpoint.
func (a *Agent) receive(ctx context.Context, view DutyView, requestHash string, purchase PurchaseRecord,
	report *buyersdk.RequestReport) (DutyView, error) {
	record, err := a.config.Buyer.Journal().Read(requestHash)
	if err != nil {
		return view, err
	}
	responseHash, err := decodeHex32(report.ResponseHash)
	if err != nil {
		return view, errors.New("the finalized respond carries no response hash")
	}
	receipt, err := receiptBinding(record, purchase)
	if err != nil {
		return view, err
	}
	result, err := a.config.Results.ReceiveResult(ctx, ResultRound{Record: record, ProviderAgentID: purchase.ProviderAgentID,
		Receipt: receipt, ResponseHash: responseHash, ResponseDeadline: time.Unix(int64(report.ResponseDeadline), 0),
		RetentionSeconds: purchase.RetentionSeconds, ChainTime: time.Unix(report.ChainTime, 0)})
	view.Result = &result
	if err != nil {
		return view, refusal(CodeInternal, "the result round failed", err)
	}
	return view, nil
}

// receiptBinding is everything the purchase's Receipt must bind (frames
// 7.2 item 2), from the journal record and the validated Quote.
func receiptBinding(record buyersdk.CallRecord, purchase PurchaseRecord) (railwork.ReceiptBinding, error) {
	executionID, err := decodeHex32(record.ExecutionID)
	if err != nil {
		return railwork.ReceiptBinding{}, errors.New("the journaled execution ID is not 64 hex")
	}
	inputDigest, err := decodeHex32(record.InputDigest)
	if err != nil {
		return railwork.ReceiptBinding{}, errors.New("the journaled input digest is not 64 hex")
	}
	price, ok := new(big.Int).SetString(record.PriceNanoTOS, 10)
	if !ok || price.Sign() <= 0 {
		return railwork.ReceiptBinding{}, errors.New("the journaled price is not a positive integer")
	}
	return railwork.ReceiptBinding{QuoteCommitment: record.QuoteCommitment, ExecutionID: executionID,
		InputDigest: inputDigest, SourceDigest: purchase.SourceDigest, Price: price,
		ProviderAgentID: purchase.ProviderAgentID, ToolchainDigest: purchase.ToolchainDigest,
		SandboxDigest: purchase.ManifestDigest}, nil
}

func decodeHex32(value string) ([32]byte, error) {
	var out [32]byte
	if !hex64Pattern.MatchString(value) {
		return out, errors.New("not 64 lowercase hex digits")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	copy(out[:], raw)
	return out, nil
}

// LookupPurchase finds the admitted purchase a frame's request hash names,
// for the carrier's poller: its provider, Capability, Accepted Quote and
// frame binding. A request hash of no purchase, or of one not yet
// admitted, is not found.
func (a *Agent) LookupPurchase(requestHash string) (InboundPurchase, bool, error) {
	if !hex64Pattern.MatchString(requestHash) {
		return InboundPurchase{}, false, nil
	}
	purchase, err := a.store.readPurchase(requestHash)
	if errors.Is(err, os.ErrNotExist) {
		return InboundPurchase{}, false, nil
	}
	if err != nil {
		return InboundPurchase{}, false, err
	}
	record, err := a.config.Buyer.Journal().Read(requestHash)
	if errors.Is(err, os.ErrNotExist) {
		return InboundPurchase{}, false, nil
	}
	if err != nil {
		return InboundPurchase{}, false, err
	}
	// Only the admission of the call sets its request ID.
	if record.RequestID == nil {
		return InboundPurchase{}, false, nil
	}
	binding, err := taskBinding(record)
	if err != nil {
		return InboundPurchase{}, false, nil
	}
	return InboundPurchase{ProviderAgentID: purchase.ProviderAgentID, CapabilityID: record.CapabilityID,
		QuoteCommitment: record.QuoteCommitment, Binding: binding}, true, nil
}
