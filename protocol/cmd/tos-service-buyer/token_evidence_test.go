package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"strings"
	"testing"
)

func TestTokenFundingPredecessorNeedsTheExactExecutedMessage(t *testing.T) {
	next := toschain.TokenActorTransaction{Sender: "payer", InboundMessageHash: "message"}
	tx := toschain.TokenActorTransaction{LT: 1, Hash: "transaction", TookEffect: true, Outputs: []toschain.TokenActorOutput{{Hash: "message"}}}
	complete := func(txs ...toschain.TokenActorTransaction) *toschain.TokenWalletHistory {
		return &toschain.TokenWalletHistory{Result: toschain.HistoryComplete, Transactions: txs}
	}
	if got, err := fundingPredecessor(complete(tx), "payer", next); err != nil || got.Hash != tx.Hash {
		t.Fatalf("exact predecessor: %v", err)
	}
	tests := map[string]*toschain.TokenWalletHistory{"missing": nil, "absent": complete(), "duplicate": complete(tx, tx)}
	skipped := tx
	skipped.TookEffect = false
	tests["skipped"] = complete(skipped)
	bounced := tx
	bounced.Bounced = true
	tests["bounced"] = complete(bounced)
	unrelated := tx
	unrelated.Outputs = []toschain.TokenActorOutput{{Hash: "another"}}
	tests["unrelated"] = complete(unrelated)
	for name, history := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := fundingPredecessor(history, "payer", next); err == nil {
				t.Fatal("invalid funding history accepted")
			}
		})
	}
	if _, err := fundingPredecessor(complete(tx), "other", next); err == nil {
		t.Fatal("wrong sender accepted")
	}
}

func TestTokenEvidenceReproducesThePrefixedQuoteAndRequest(t *testing.T) {
	quote := cell.BeginCell().MustStoreUInt(7, 8).EndCell()
	var commitment, execution, input [32]byte
	copy(commitment[:], quote.Hash())
	execution[0] = 1
	input[0] = 2
	request, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: commitment, ExecutionID: execution, InputDigest: input})
	if err != nil {
		t.Fatal(err)
	}
	record := buyersdk.CallRecord{QuoteCommitment: "tvm-cell-sha256:" + hex.EncodeToString(commitment[:]), AcceptedQuoteBOC: base64.StdEncoding.EncodeToString(quote.ToBOCWithOptions(cell.BOCSerializeOptions{})), ExecutionID: hex.EncodeToString(execution[:]), InputDigest: hex.EncodeToString(input[:]), RequestHash: hex.EncodeToString(request.Hash())}
	if got, err := serviceRequestFromTokenRecord(record); err != nil || hex.EncodeToString(got.Hash()) != record.RequestHash {
		t.Fatalf("real journal hash shape: %v", err)
	}
	for _, field := range []string{"prefix", "quote", "request"} {
		t.Run(field, func(t *testing.T) {
			bad := record
			switch field {
			case "prefix":
				bad.QuoteCommitment = strings.TrimPrefix(bad.QuoteCommitment, "tvm-cell-sha256:")
			case "quote":
				bad.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("00", 32)
			case "request":
				bad.RequestHash = strings.Repeat("00", 32)
			}
			if _, err := serviceRequestFromTokenRecord(bad); err == nil {
				t.Fatal("mismatched commitment accepted")
			}
		})
	}
}

// The embedded interface supplies unrelated getters; the tested path must use
// this source's exact-hop proof rather than assuming discovery is sufficient.
type tokenExportProofFixture struct {
	purchaseevidence.TokenSession
	history   *toschain.TokenWalletHistory
	proven    *toschain.TokenActorTransaction
	err       error
	account   string
	requested toschain.ActorTxID
}

func (f *tokenExportProofFixture) TokenWalletHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenWalletHistory, error) {
	return f.history, nil
}
func (f *tokenExportProofFixture) TokenWalletTransaction(_ context.Context, account string, id toschain.ActorTxID) (*toschain.TokenActorTransaction, error) {
	f.account = account
	f.requested = id
	return f.proven, f.err
}

func TestTokenExporterRequiresTheExactNamedFundingProof(t *testing.T) {
	next := toschain.TokenActorTransaction{Sender: "payer", InboundMessageHash: "message"}
	tx := toschain.TokenActorTransaction{LT: 1, Hash: strings.Repeat("ab", 32), TookEffect: true, Outputs: []toschain.TokenActorOutput{{Hash: "message"}}}
	fresh := func() *tokenExportProofFixture {
		copyTx := tx
		return &tokenExportProofFixture{history: &toschain.TokenWalletHistory{Result: toschain.HistoryComplete, Transactions: []toschain.TokenActorTransaction{tx}}, proven: &copyTx}
	}
	f := fresh()
	if got, err := provenFundingPredecessor(context.Background(), f, "payer", next); err != nil || got.Hash != tx.Hash || f.account != "payer" || f.requested.LT != tx.LT || f.requested.Hash != tx.Hash {
		t.Fatalf("exact hop not proven: %+v %v", f, err)
	}
	for name, change := range map[string]func(*tokenExportProofFixture){
		"absent":        func(f *tokenExportProofFixture) { f.proven = nil },
		"error":         func(f *tokenExportProofFixture) { f.err = errors.New("proof unavailable") },
		"lt":            func(f *tokenExportProofFixture) { f.proven.LT++ },
		"hash":          func(f *tokenExportProofFixture) { f.proven.Hash = strings.Repeat("cd", 32) },
		"not executed":  func(f *tokenExportProofFixture) { f.proven.TookEffect = false },
		"bounced":       func(f *tokenExportProofFixture) { f.proven.Bounced = true },
		"other message": func(f *tokenExportProofFixture) { f.proven.Outputs = []toschain.TokenActorOutput{{Hash: "another"}} },
	} {
		t.Run(name, func(t *testing.T) {
			f := fresh()
			change(f)
			if _, err := provenFundingPredecessor(context.Background(), f, "payer", next); err == nil {
				t.Fatal("invalid funding proof accepted")
			}
		})
	}
}
