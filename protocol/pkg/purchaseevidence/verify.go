package purchaseevidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// Session is one quorum-finalized checkpoint: every read a verification
// makes is taken in it. *toschain.ServiceActorSession implements it.
type Session interface {
	serviceactor.Session
	serviceactor.TransitionSession
	BlockHashes() (string, string)
	History(ctx context.Context, actor string, anchor *toschain.ActorTxID) (*toschain.ActorHistory, error)
	GetRequest(ctx context.Context, actor string, requestID uint64) (*nativecore.ServiceActorRequestViewV1, error)
	GetRefund(ctx context.Context, actor string, requestID uint64) (*nativecore.ServiceActorRefundV1, error)
}

// Input is everything a verification is given. Network, ActorCodeHash and
// Actor are the verifier's own pinned public inputs; the selectors name the
// requests; Bundle, Receipt and Artifact are untrusted files.
type Input struct {
	Network       *nativev1.NetworkDomain
	ActorCodeHash string
	Actor         string
	RequestIDs    []uint64
	RequestHashes []string
	Bundle        *Bundle
	// Receipt and Artifact are nil when not given. Both name the one
	// selected request.
	Receipt  []byte
	Artifact []byte
}

// Results of a verification.
const (
	ResultPass = "pass"
	ResultFail = "fail"
)

// Request states a report gives: the contract lifecycle, or refused for a
// call that the actor aborted.
const (
	StateRefused = "refused"
)

// Verdict is the outcome of one verification (schema VerdictSchema). Result
// is pass only when every check passed; a verification that could not read
// what it needed fails.
type Verdict struct {
	Schema     string          `json:"schema"`
	Result     string          `json:"result"`
	Tool       *Tool           `json:"tool,omitempty"`
	Network    NetworkTuple    `json:"network"`
	Reads      *Reads          `json:"reads,omitempty"`
	Inputs     []FileDigest    `json:"inputs,omitempty"`
	Checkpoint *Checkpoint     `json:"checkpoint,omitempty"`
	Actor      *ActorReport    `json:"actor,omitempty"`
	Requests   []RequestReport `json:"requests"`
	Checks     []Check         `json:"checks"`
	// NotClaimed lists what a pass does not establish.
	NotClaimed []string `json:"not_claimed"`
}

// Reads describes the endpoints a verification read from.
type Reads struct {
	Endpoints []EndpointReport `json:"endpoints"`
	Quorum    int              `json:"quorum"`
}

// EndpointReport is one endpoint and its own genesis check, made without a
// quorum. An endpoint that did not answer is reported, not failed: the
// quorum decides.
type EndpointReport struct {
	URL       string `json:"url"`
	GenesisOK bool   `json:"genesis_ok"`
	Error     string `json:"error,omitempty"`
}

// Checkpoint is the finalized checkpoint every read was taken at.
type Checkpoint struct {
	Seqno     uint64 `json:"seqno"`
	ChainTime int64  `json:"chain_time"`
	BlockRoot string `json:"block_root_hash,omitempty"`
	BlockFile string `json:"block_file_hash,omitempty"`
}

// ActorReport is the actor account at the checkpoint.
type ActorReport struct {
	Address         string             `json:"address"`
	CodeHash        string             `json:"code_hash"`
	PinnedCodeHash  string             `json:"pinned_code_hash"`
	CodeHashMatches bool               `json:"code_hash_matches"`
	Owner           string             `json:"owner"`
	Active          bool               `json:"active"`
	BalanceNanoTOS  string             `json:"balance_nanotos"`
	PolicyVersion   uint32             `json:"policy_version"`
	NextRequestID   uint64             `json:"next_request_id"`
	PendingCount    uint32             `json:"pending_count"`
	LiveCount       uint32             `json:"live_count"`
	LastTransaction toschain.ActorTxID `json:"last_transaction"`
	HistoryLength   int                `json:"history_transactions"`
}

// RequestReport is one request at the checkpoint.
type RequestReport struct {
	RequestID            *uint64   `json:"request_id,omitempty"`
	RequestHash          string    `json:"request_hash"`
	State                string    `json:"state"`
	Status               string    `json:"status,omitempty"`
	Caller               string    `json:"caller"`
	PriceNanoTOS         string    `json:"price_nanotos,omitempty"`
	StorageFeeNanoTOS    string    `json:"storage_fee_nanotos,omitempty"`
	CleanupBountyNanoTOS string    `json:"cleanup_bounty_nanotos,omitempty"`
	TermsHash            string    `json:"terms_hash,omitempty"`
	PolicyVersion        uint32    `json:"policy_version,omitempty"`
	AttestorKeyID        string    `json:"attestor_key_id,omitempty"`
	ResponseDeadline     uint64    `json:"response_deadline,omitempty"`
	RefundClaimDeadline  uint64    `json:"refund_claim_deadline,omitempty"`
	Call                 TxReport  `json:"call"`
	Respond              *TxReport `json:"respond,omitempty"`
	Expire               *TxReport `json:"expire,omitempty"`
	ClaimRefund          *TxReport `json:"claim_refund,omitempty"`
	Sweep                *TxReport `json:"sweep,omitempty"`
	// ProviderWallet is the respond's sender, the actor owner.
	ProviderWallet string          `json:"provider_wallet,omitempty"`
	ResponseHash   string          `json:"response_hash,omitempty"`
	Receipt        *ReceiptReport  `json:"receipt,omitempty"`
	Artifact       *ArtifactReport `json:"artifact,omitempty"`
}

// TxReport is one finalized transaction of the actor.
type TxReport struct {
	LT           uint64                 `json:"lt"`
	Hash         string                 `json:"hash"`
	Now          uint32                 `json:"now"`
	Sender       string                 `json:"sender"`
	ValueNanoTOS string                 `json:"value_nanotos,omitempty"`
	QueryID      string                 `json:"query_id,omitempty"`
	ExitCode     int32                  `json:"exit_code,omitempty"`
	Destination  string                 `json:"destination,omitempty"`
	Payouts      []toschain.ActorPayout `json:"payouts,omitempty"`
}

// ReceiptReport is a Receipt file checked against the request.
type ReceiptReport struct {
	SHA256          string `json:"file_sha256"`
	ResponseHash    string `json:"cell_hash"`
	QuoteCommitment string `json:"quote_commitment"`
	ExecutionID     string `json:"execution_id"`
	InputDigest     string `json:"input_digest"`
	SourceDigest    string `json:"source_digest"`
	ToolchainDigest string `json:"toolchain_digest"`
	SandboxDigest   string `json:"sandbox_digest"`
	ProviderAgentID string `json:"provider_agent_id"`
	ChargedNanoTOS  string `json:"charged_nanotos"`
	ResultDigest    string `json:"result_digest"`
	ArtifactDigest  string `json:"artifact_digest"`
	ReportDigest    string `json:"report_digest"`
	CompletedAtUnix uint64 `json:"completed_at_unix"`
	ExitCode        int32  `json:"exit_code"`
}

// ArtifactReport is an artifact file checked against its Receipt.
type ArtifactReport struct {
	SHA256  string       `json:"file_sha256"`
	Bytes   int          `json:"bytes"`
	Members []FileDigest `json:"members"`
}

// Check is one named check and its outcome.
type Check struct {
	ID      string `json:"id"`
	Subject string `json:"subject,omitempty"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
}

// notClaimed is what a pass does not establish.
var notClaimed = []string{
	"operator independence of the endpoints: agreeing endpoints run by one operator are one source",
	"computation correctness: a Receipt is the provider's attested statement of the digests it binds",
	"the identity or independence of the buyer, the provider or the verifier",
	"anything after the checkpoint, or about a request the verification did not select",
}

// NoBundleNotClaimed is added to not_claimed when no evidence bundle is
// given: a request is then tied to its caller wallet and nothing more. A
// record must bind each request's caller to the buyer's declared wallet.
const NoBundleNotClaimed = "without an evidence bundle, only the caller wallet of each request is proven: " +
	"not its Quote, its Capability binding or whose purchase it is; bind the reported caller to the buyer's declared wallet"

type verification struct {
	ctx     context.Context
	session Session
	input   Input
	verdict *Verdict
	failed  bool
	// history is the actor's complete finalized history, newest first.
	history []toschain.ActorTransaction
	// receiptBinding and manifest come from a bundle's validated Quote.
	receiptBinding *railwork.ReceiptBinding
	manifest       []byte
}

func (v *verification) pass(id, subject, detail string) {
	v.verdict.Checks = append(v.verdict.Checks, Check{ID: id, Subject: subject, OK: true, Detail: detail})
}

func (v *verification) fail(id, subject, format string, arguments ...any) {
	v.failed = true
	v.verdict.Checks = append(v.verdict.Checks, Check{ID: id, Subject: subject, OK: false, Detail: fmt.Sprintf(format, arguments...)})
}

// NewVerdict returns an empty failing verdict for network, for a caller that
// fails before a verification runs.
func NewVerdict(network *nativev1.NetworkDomain) *Verdict {
	verdict := &Verdict{Schema: VerdictSchema, Result: ResultFail, Requests: []RequestReport{}, Checks: []Check{},
		NotClaimed: append([]string(nil), notClaimed...)}
	if network != nil {
		verdict.Network = NetworkTuple{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
			GenesisFileHash: network.GenesisFileHash}
	}
	return verdict
}

// Fail records a failing check on a verdict; the verdict fails.
func (d *Verdict) Fail(id, detail string) {
	d.Result = ResultFail
	d.Checks = append(d.Checks, Check{ID: id, OK: false, Detail: detail})
}

// Verify runs one verification in session. It never returns a partial pass:
// a read it cannot make is a failing check, and the verdict passes only when
// every check passed.
func Verify(ctx context.Context, session Session, input Input) *Verdict {
	v := &verification{ctx: ctx, session: session, input: input, verdict: NewVerdict(input.Network)}
	if input.Bundle == nil {
		v.verdict.NotClaimed = append(v.verdict.NotClaimed, NoBundleNotClaimed)
	}
	v.run()
	if v.failed {
		v.verdict.Result = ResultFail
	} else {
		v.verdict.Result = ResultPass
	}
	return v.verdict
}

func (v *verification) run() {
	if err := v.checkInput(); err != nil {
		v.fail("input", "", "%v", err)
		return
	}
	if v.ctx == nil || v.session == nil {
		v.fail("input", "", "no finalized session")
		return
	}
	v.verdict.Checkpoint = &Checkpoint{Seqno: v.session.Checkpoint(), ChainTime: v.session.ChainTime().Unix()}
	defer func() {
		root, file := v.session.BlockHashes()
		v.verdict.Checkpoint.BlockRoot, v.verdict.Checkpoint.BlockFile = root, file
	}()
	account, requests, ok := v.readActor()
	if !ok {
		return
	}
	selected, refused, ok := v.selectRequests(requests)
	if !ok {
		return
	}
	reports := make([]RequestReport, 0, len(selected)+len(refused))
	for _, request := range selected {
		if !v.crossCheckGetters(request, account.Data) {
			return
		}
		reports = append(reports, reportOf(request, v.session.ChainTime()))
	}
	for _, call := range refused {
		reports = append(reports, refusedReport(call))
	}
	v.verdict.Requests = reports
	var receipt *nativecore.SoftwareWorkReceiptV1
	if v.input.Bundle != nil {
		v.checkBundle(account, selected, refused)
	}
	if v.input.Receipt != nil {
		receipt = v.checkReceipt(selected, refused)
	}
	if v.input.Artifact != nil && receipt != nil {
		v.checkArtifact(receipt)
	}
}

func (v *verification) checkInput() error {
	input := v.input
	if input.Network == nil || input.Network.NetworkId == "" || input.Network.GenesisRootHash == "" ||
		input.Network.GenesisFileHash == "" {
		return errors.New("the network tuple is required")
	}
	if _, err := digest32(input.ActorCodeHash, "tvm-cell-sha256:"); err != nil {
		return errors.New("the pinned actor code hash must be tvm-cell-sha256:<64 hex>")
	}
	if canonical, err := toschain.CanonicalAddress(input.Actor); err != nil || !strings.HasPrefix(canonical, "0:") {
		return errors.New("the actor must be a raw workchain 0 address")
	}
	if len(input.RequestIDs)+len(input.RequestHashes) == 0 {
		return errors.New("no request is selected: name a request ID, a request_hash or an evidence bundle")
	}
	if len(input.RequestIDs)+len(input.RequestHashes) > MaxSelected {
		return fmt.Errorf("at most %d requests are selected at once", MaxSelected)
	}
	for _, hash := range input.RequestHashes {
		if _, err := hex32(hash); err != nil {
			return fmt.Errorf("request_hash %q is not 64 lowercase hex", hash)
		}
	}
	if (input.Receipt != nil || input.Artifact != nil) && len(input.RequestIDs)+len(input.RequestHashes) != 1 {
		return errors.New("a Receipt or artifact file is checked against exactly one selected request")
	}
	if input.Artifact != nil && input.Receipt == nil {
		return errors.New("an artifact is checked against its Receipt: give the Receipt file too")
	}
	if input.Bundle != nil && (len(input.RequestIDs) != 0 || len(input.RequestHashes) != 1 ||
		input.RequestHashes[0] != input.Bundle.Request.RequestHash) {
		return errors.New("an evidence bundle selects exactly its own request_hash")
	}
	return nil
}

// readActor reads the actor, its complete history and the replayed
// requests at the checkpoint.
func (v *verification) readActor() (*toschain.ActorAccount, map[uint64]*serviceactor.Request, bool) {
	account, found, err := v.session.ReadActor(v.ctx, v.input.Actor)
	if err != nil {
		v.fail("actor-account", v.input.Actor, "the actor account does not read at the checkpoint with the pinned code: %v", err)
		return nil, nil, false
	}
	if !found || account == nil || account.Data == nil {
		v.fail("actor-account", v.input.Actor, "the actor account is not active at the checkpoint")
		return nil, nil, false
	}
	v.verdict.Actor = &ActorReport{Address: account.Address, CodeHash: account.CodeHash, PinnedCodeHash: v.input.ActorCodeHash,
		CodeHashMatches: account.CodeHash == v.input.ActorCodeHash, Owner: account.Data.Owner.Text(), Active: account.Data.Active,
		BalanceNanoTOS: strconv.FormatUint(account.BalanceNano, 10), PolicyVersion: account.Data.Policy.PolicyVersion,
		NextRequestID: account.Data.NextRequestID, PendingCount: account.Data.PendingCount, LiveCount: account.Data.LiveCount,
		LastTransaction: account.LastTransaction}
	if account.Address != v.input.Actor || account.CodeHash != v.input.ActorCodeHash {
		v.fail("actor-code-hash", v.input.Actor, "the actor runs %s, not the pinned release %s", account.CodeHash, v.input.ActorCodeHash)
		return nil, nil, false
	}
	v.pass("actor-code-hash", v.input.Actor, "the actor runs the pinned release code")
	history, err := v.session.History(v.ctx, v.input.Actor, nil)
	if err != nil {
		v.fail("actor-history", v.input.Actor, "the actor history does not read completely: %v", err)
		return nil, nil, false
	}
	if history.Result != toschain.HistoryComplete || history.Head != account.LastTransaction {
		v.fail("actor-history", v.input.Actor, "the actor history is not complete up to the account's last transaction")
		return nil, nil, false
	}
	v.verdict.Actor.HistoryLength = len(history.Transactions)
	v.pass("actor-history", v.input.Actor, fmt.Sprintf("%d transactions back to the first", len(history.Transactions)))
	requests, err := serviceactor.Replay(history.Transactions, account.Data)
	if err != nil {
		v.fail("actor-replay", v.input.Actor, "the history does not reconcile with the actor state: %v", err)
		return nil, nil, false
	}
	v.pass("actor-replay", v.input.Actor, fmt.Sprintf("%d requests replayed and reconciled", len(requests)))
	v.history = history.Transactions
	return account, requests, true
}

// selectRequests resolves the selectors. A request_hash that no successful
// call carries may name aborted calls, which are reported as refused.
func (v *verification) selectRequests(requests map[uint64]*serviceactor.Request) ([]*serviceactor.Request, []toschain.ActorTransaction, bool) {
	var selected []*serviceactor.Request
	var refused []toschain.ActorTransaction
	seen := map[uint64]bool{}
	for _, id := range v.input.RequestIDs {
		subject := strconv.FormatUint(id, 10)
		request := requests[id]
		if request == nil {
			v.fail("request-selected", subject, "no request has this ID at the checkpoint")
			return nil, nil, false
		}
		if seen[id] {
			v.fail("request-selected", subject, "the request is selected twice")
			return nil, nil, false
		}
		seen[id] = true
		selected = append(selected, request)
		v.pass("request-selected", subject, "request "+subject)
	}
	for _, hash := range v.input.RequestHashes {
		var matches []*serviceactor.Request
		for _, request := range requests {
			if hex.EncodeToString(request.Snapshot.RequestHash[:]) == hash && v.bundleSelects(request.Call) {
				matches = append(matches, request)
			}
		}
		var failed []toschain.ActorTransaction
		for _, transaction := range v.history {
			if transaction.Kind == toschain.ActorTxFailed && transaction.Call != nil && transaction.Call.RequestHash == hash &&
				v.bundleSelects(transaction) {
				failed = append(failed, transaction)
			}
		}
		switch {
		case len(matches) > 1 || len(matches)+len(failed) > 1:
			v.fail("request-selected", hash, "%d calls carry this request_hash; select it by request ID", len(matches)+len(failed))
			return nil, nil, false
		case len(matches) == 1:
			id := matches[0].Snapshot.RequestID
			if seen[id] {
				v.fail("request-selected", hash, "the request is selected twice")
				return nil, nil, false
			}
			seen[id] = true
			selected = append(selected, matches[0])
			v.pass("request-selected", hash, "request "+strconv.FormatUint(id, 10))
		case len(failed) == 1:
			refused = append(refused, failed[0])
			v.pass("request-selected", hash, "an aborted call")
		default:
			v.fail("request-selected", hash, "no finalized call carries this request_hash")
			return nil, nil, false
		}
	}
	sort.Slice(selected, func(a, b int) bool { return selected[a].Snapshot.RequestID < selected[b].Snapshot.RequestID })
	return selected, refused, true
}

// bundleSelects reports whether a call is the bundle's: from its buyer
// wallet with its journaled query_id. Without a bundle every call is.
func (v *verification) bundleSelects(call toschain.ActorTransaction) bool {
	bundle := v.input.Bundle
	if bundle == nil {
		return true
	}
	return call.Sender == bundle.BuyerWallet && call.Call != nil && strconv.FormatUint(call.Call.QueryID, 10) == bundle.Journal.QueryID
}

// crossCheckGetters requires get_request and get_refund to agree with the
// decoded state for the request.
func (v *verification) crossCheckGetters(request *serviceactor.Request, data *nativecore.ServiceActorDataV1) bool {
	id := request.Snapshot.RequestID
	subject := strconv.FormatUint(id, 10)
	pending, err := v.session.GetRequest(v.ctx, v.input.Actor, id)
	if err != nil {
		v.fail("request-getters", subject, "get_request does not read: %v", err)
		return false
	}
	refund, err := v.session.GetRefund(v.ctx, v.input.Actor, id)
	if err != nil {
		v.fail("request-getters", subject, "get_refund does not read: %v", err)
		return false
	}
	switch request.State {
	case serviceactor.StatePending:
		if refund != nil || !nativecore.SameRequestView(data.Pending[id], pending) {
			v.fail("request-getters", subject, "get_request differs from the decoded pending entry")
			return false
		}
	case serviceactor.StateExpired:
		if pending != nil || !nativecore.SameRefundView(data.Refunds[id], refund) {
			v.fail("request-getters", subject, "get_refund differs from the decoded refund entry")
			return false
		}
	default:
		if pending != nil || refund != nil {
			v.fail("request-getters", subject, "a resolved request is still live in the getters")
			return false
		}
	}
	v.pass("request-getters", subject, "get_request and get_refund agree with the actor state")
	return true
}

func txReport(transaction toschain.ActorTransaction) TxReport {
	report := TxReport{LT: transaction.LT, Hash: transaction.Hash, Now: transaction.Now, Sender: transaction.Sender,
		ValueNanoTOS: transaction.ValueNano, ExitCode: transaction.ExitCode, Destination: transaction.Destination,
		Payouts: append([]toschain.ActorPayout(nil), transaction.Payouts...)}
	if transaction.Call != nil {
		report.QueryID = strconv.FormatUint(transaction.Call.QueryID, 10)
	} else if transaction.QueryID != 0 {
		report.QueryID = strconv.FormatUint(transaction.QueryID, 10)
	}
	return report
}

func reportOf(request *serviceactor.Request, chainTime time.Time) RequestReport {
	snapshot, terms := request.Snapshot, request.Snapshot.Terms
	id := snapshot.RequestID
	report := RequestReport{RequestID: &id, RequestHash: hex.EncodeToString(snapshot.RequestHash[:]), State: string(request.State),
		Status: string(request.StatusAt(chainTime)), Caller: snapshot.Caller.Text(), PriceNanoTOS: terms.PricePerCall.String(),
		StorageFeeNanoTOS: terms.StorageFee.String(), CleanupBountyNanoTOS: terms.CleanupBounty.String(),
		TermsHash: hex.EncodeToString(snapshot.TermsHash[:]), PolicyVersion: terms.PolicyVersion,
		ResponseDeadline: snapshot.ResponseDeadline, RefundClaimDeadline: snapshot.RefundClaimDeadline,
		Call: txReport(request.Call)}
	if terms.HasAttestor {
		report.AttestorKeyID = "mldsa44:" + hex.EncodeToString(terms.AttestorKeyID[:])
	}
	if request.Expiration != nil {
		expire := txReport(*request.Expiration)
		report.Expire = &expire
	}
	if terminal := request.Terminal; terminal != nil {
		outcome := txReport(*terminal)
		switch terminal.Kind {
		case toschain.ActorTxRespond:
			report.Respond, report.ProviderWallet, report.ResponseHash = &outcome, terminal.Sender, terminal.ResponseHash
		case toschain.ActorTxClaim:
			report.ClaimRefund = &outcome
		case toschain.ActorTxSweep:
			report.Sweep = &outcome
		}
	}
	return report
}

func refusedReport(call toschain.ActorTransaction) RequestReport {
	report := RequestReport{State: StateRefused, Caller: call.Sender, Call: txReport(call)}
	if call.Call != nil {
		report.RequestHash, report.TermsHash = call.Call.RequestHash, call.Call.ExpectedTermsHash
	}
	return report
}

// checkReceipt checks a Receipt file against the one selected request: it
// is canonical, it hashes to the finalized response_hash, and its own Quote
// commitment, execution ID and input digest rebuild the request_hash the
// call carried, so it binds exactly this request. It returns the decoded
// Receipt when every check passed.
func (v *verification) checkReceipt(selected []*serviceactor.Request, refused []toschain.ActorTransaction) *nativecore.SoftwareWorkReceiptV1 {
	if len(selected) != 1 || len(refused) != 0 {
		v.fail("receipt-response-hash", "", "a Receipt needs a responded request")
		return nil
	}
	request := selected[0]
	subject := strconv.FormatUint(request.Snapshot.RequestID, 10)
	receipt, hash, err := railwork.DecodeReceipt(v.input.Receipt)
	if err != nil {
		v.fail("receipt-canonical", subject, "the Receipt is not a canonical software-work Receipt: %v", err)
		return nil
	}
	v.pass("receipt-canonical", subject, "")
	report := &v.verdict.Requests[0]
	report.Receipt = &ReceiptReport{SHA256: sha256Text(v.input.Receipt), ResponseHash: hex.EncodeToString(hash[:]),
		QuoteCommitment: receipt.QuoteCommitment, ExecutionID: receipt.ExecutionID, InputDigest: receipt.InputDigest,
		SourceDigest: receipt.SourceDigest, ToolchainDigest: receipt.ToolchainDigest, SandboxDigest: receipt.SandboxDigest,
		ProviderAgentID: receipt.ProviderAgentID, ChargedNanoTOS: receipt.ChargedAtomicAmount, ResultDigest: receipt.ResultDigest,
		ArtifactDigest: receipt.ArtifactDigest, ReportDigest: receipt.ReportDigest, CompletedAtUnix: receipt.CompletedAt,
		ExitCode: receipt.ExitCode}
	if request.State != serviceactor.StateResponded || request.Terminal == nil {
		v.fail("receipt-response-hash", subject, "the request is %s, not responded: no finalized response_hash to match", request.State)
		return nil
	}
	if hex.EncodeToString(hash[:]) != request.Terminal.ResponseHash {
		v.fail("receipt-response-hash", subject, "the Receipt cell hash is not the finalized response_hash")
		return nil
	}
	v.pass("receipt-response-hash", subject, "the Receipt hashes to the finalized response_hash")
	quote, errQuote := digest32(receipt.QuoteCommitment, "tvm-cell-sha256:")
	execution, errExecution := digest32(receipt.ExecutionID, "sha256:")
	input, errInput := digest32(receipt.InputDigest, "sha256:")
	if errQuote != nil || errExecution != nil || errInput != nil {
		v.fail("receipt-request-hash", subject, "the Receipt's Quote commitment, execution ID or input digest is malformed")
		return nil
	}
	rebuilt, err := railwork.RequestHash(quote, execution, input)
	if err != nil || rebuilt != request.Snapshot.RequestHash {
		v.fail("receipt-request-hash", subject, "the Receipt's Quote, execution and input do not rebuild the call's request_hash")
		return nil
	}
	v.pass("receipt-request-hash", subject, "the Receipt binds the call's request_hash")
	if receipt.ChargedAtomicAmount != request.Snapshot.Terms.PricePerCall.String() || receipt.ExitCode != 0 || receipt.CompletedAt == 0 {
		v.fail("receipt-terms", subject, "the Receipt does not charge the snapshotted price for a successful completed execution")
		return nil
	}
	v.pass("receipt-terms", subject, "the Receipt charges the snapshotted price, exit code 0")
	if v.receiptBinding != nil {
		if err := railwork.CheckReceiptBinding(receipt, *v.receiptBinding); err != nil {
			v.fail("receipt-binding", subject, "the Receipt does not bind the bundle's Quote: %v", err)
			return nil
		}
		v.pass("receipt-binding", subject, "the Receipt binds the Quote's provider, source, toolchain and manifest")
	}
	return &receipt
}

// checkArtifact checks an artifact against its Receipt: the file digest and
// the digests of its two members.
func (v *verification) checkArtifact(receipt *nativecore.SoftwareWorkReceiptV1) {
	subject := v.verdict.Requests[0].RequestHash
	report := &ArtifactReport{SHA256: sha256Text(v.input.Artifact), Bytes: len(v.input.Artifact)}
	v.verdict.Requests[0].Artifact = report
	if report.SHA256 != receipt.ArtifactDigest {
		v.fail("artifact-digest", subject, "the artifact is not the one the Receipt binds")
		return
	}
	v.pass("artifact-digest", subject, "the artifact matches the Receipt's artifact_digest")
	output, testReport, err := railwork.ArtifactMembers(v.input.Artifact)
	if err != nil {
		v.fail("artifact-members", subject, "the artifact is not the two-member software-work tar: %v", err)
		return
	}
	report.Members = []FileDigest{{Name: "output.log", SHA256: sha256Text(output), Bytes: len(output)},
		{Name: "report.json", SHA256: sha256Text(testReport), Bytes: len(testReport)}}
	if report.Members[0].SHA256 != receipt.ResultDigest || report.Members[1].SHA256 != receipt.ReportDigest {
		v.fail("artifact-members", subject, "the artifact's output or report differs from the Receipt")
		return
	}
	v.pass("artifact-members", subject, "output.log and report.json match the Receipt")
}

// checkBundle checks an evidence bundle: its pins equal the verifier's, its
// Quote rebuilds its commitments and request_hash, the request's Capability
// and terms verify at the call, and its journal and finalized claims equal
// finalized state.
func (v *verification) checkBundle(account *toschain.ActorAccount, selected []*serviceactor.Request, refused []toschain.ActorTransaction) {
	bundle := v.input.Bundle
	subject := bundle.Request.RequestHash
	network := v.input.Network
	if bundle.Network != (NetworkTuple{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
		GenesisFileHash: network.GenesisFileHash}) || bundle.ActorCodeHash != v.input.ActorCodeHash || bundle.Actor != v.input.Actor {
		v.fail("bundle-pins", subject, "the bundle names another network, actor or actor release than the verifier pins")
		return
	}
	v.pass("bundle-pins", subject, "the bundle names the pinned network, actor and release")
	validated, ok := v.checkBundleQuote(bundle)
	if !ok {
		return
	}
	var call toschain.ActorTransaction
	var request *serviceactor.Request
	switch {
	case len(selected) == 1:
		request = selected[0]
		call = request.Call
	case len(refused) == 1:
		call = refused[0]
	default:
		v.fail("bundle-journal", subject, "the bundle's request is not selected")
		return
	}
	journal := bundle.Journal
	if journal.CallTransaction != nil && *journal.CallTransaction != (toschain.ActorTxID{LT: call.LT, Hash: call.Hash}) {
		v.fail("bundle-journal", subject, "the journaled call transaction is not the finalized call")
		return
	}
	if request != nil && journal.RequestID != nil && *journal.RequestID != request.Snapshot.RequestID {
		v.fail("bundle-journal", subject, "the journaled request ID is not the finalized one")
		return
	}
	if request == nil && journal.RequestID != nil {
		v.fail("bundle-journal", subject, "the journal records a request ID for an aborted call")
		return
	}
	v.pass("bundle-journal", subject, "the journal names the finalized call from the bundle's buyer wallet")
	if request == nil {
		v.pass("bundle-binding", subject, "an aborted call admitted no request; no binding to verify")
		return
	}
	if !v.checkBundleBinding(bundle, validated, request) {
		return
	}
	v.checkBundleFinalized(bundle, request)
	v.checkBundleResult(bundle, request)
}

// checkBundleQuote rebuilds the bundle's Quote commitments and request
// commitment, and the Receipt binding they define.
func (v *verification) checkBundleQuote(bundle *Bundle) (*quoteexchange.Validated, bool) {
	subject := bundle.Request.RequestHash
	raw, err := base64.StdEncoding.Strict().DecodeString(bundle.Quote.PackageBase64)
	value := &nativev1.QuoteProposalPackageV1{}
	if err != nil || proto.Unmarshal(raw, value) != nil {
		v.fail("bundle-quote", subject, "the bundle's Quote package does not decode")
		return nil, false
	}
	validated, err := quoteexchange.ValidatePortable(v.input.Network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: bundle.Offer.CapabilityID, CapabilityVersion: bundle.Offer.CapabilityVersion,
		BuyerAddress: bundle.Quote.RequestBuyerAddress}, value)
	if err != nil {
		v.fail("bundle-quote", subject, "the bundle's Quote package does not validate: %v", err)
		return nil, false
	}
	quote, commitment, err := nativecore.BuildAcceptedQuoteCommitment(v.input.Network, validated.Proposal)
	if err != nil || commitment != bundle.Quote.QuoteCommitment ||
		base64.StdEncoding.EncodeToString(quote.ToBOCWithOptions(cell.BOCSerializeOptions{})) != bundle.Quote.AcceptedQuoteBOC {
		v.fail("bundle-quote", subject, "the bundle's Accepted Quote does not rebuild from its package")
		return nil, false
	}
	rail := validated.Rail
	if rail.Actor != v.input.Actor || hex.EncodeToString(rail.TermsHash[:]) != bundle.Quote.TermsHash ||
		rail.Price.String() != bundle.Quote.PriceNanoTOS || rail.StorageFee.String() != bundle.Quote.StorageFeeNanoTOS ||
		rail.PolicyVersion != bundle.Quote.PolicyVersion || validated.Proposal.ProviderAgentId != bundle.Offer.ProviderAgentID ||
		validated.Proposal.ManifestDigest != bundle.Offer.ManifestDigest || validated.Manifest.ToolchainDigest != bundle.Offer.ToolchainDigest {
		v.fail("bundle-quote", subject, "the bundle's offer and terms differ from its Quote package")
		return nil, false
	}
	v.pass("bundle-quote", subject, "the Quote package validates and rebuilds the Accepted Quote commitment")
	var quoteHash [32]byte
	copy(quoteHash[:], quote.Hash())
	execution, errExecution := hex32(bundle.Request.ExecutionID)
	input, errInput := hex32(bundle.Request.InputDigest)
	source, errSource := digest32(bundle.Request.SourceDigest, "sha256:")
	if errExecution != nil || errInput != nil || errSource != nil {
		v.fail("bundle-request-hash", subject, "the bundle's execution ID, input digest or source digest is malformed")
		return nil, false
	}
	if railwork.InputDigest(source) != input {
		v.fail("bundle-request-hash", subject, "the bundle's input digest is not the commitment to its source digest")
		return nil, false
	}
	rebuilt, err := railwork.RequestHash(quoteHash, execution, input)
	if err != nil || hex.EncodeToString(rebuilt[:]) != bundle.Request.RequestHash {
		v.fail("bundle-request-hash", subject, "the bundle's Quote, execution ID and input do not rebuild its request_hash")
		return nil, false
	}
	v.pass("bundle-request-hash", subject, "the request_hash commits to the Quote, the execution and the source digest")
	v.receiptBinding = &railwork.ReceiptBinding{QuoteCommitment: commitment, ExecutionID: execution, InputDigest: input,
		SourceDigest: bundle.Request.SourceDigest, Price: new(big.Int).Set(rail.Price), ProviderAgentID: validated.Proposal.ProviderAgentId,
		ToolchainDigest: validated.Manifest.ToolchainDigest, SandboxDigest: validated.Proposal.ManifestDigest}
	v.manifest = value.CanonicalManifestCbor
	return validated, true
}

// packageManifest serves the manifest bytes the Quote package carries; the
// gathering step checks them against the finalized digest.
type packageManifest struct {
	digest string
	raw    []byte
}

func (p packageManifest) Manifest(_ context.Context, digest string) ([]byte, error) {
	if digest != p.digest || len(p.raw) == 0 {
		return nil, errors.New("the Quote package carries no manifest with this digest")
	}
	return append([]byte(nil), p.raw...), nil
}

// checkBundleBinding runs the existing-request verification of the
// settlement design (section 2.4) at the checkpoint: the Capability, its
// version and manifest, the owner Agent and the actor binding, with the
// Capability's liveness judged at the call, then the call and its request
// snapshot against the Quote.
func (v *verification) checkBundleBinding(bundle *Bundle, validated *quoteexchange.Validated, request *serviceactor.Request) bool {
	subject := bundle.Request.RequestHash
	evidence, err := serviceactor.Gather(v.ctx, v.session, v.input.Network,
		packageManifest{digest: validated.Proposal.ManifestDigest, raw: v.manifest}, bundle.Offer.CapabilityID, bundle.Offer.CapabilityVersion)
	if err != nil {
		v.fail("bundle-binding", subject, "the Capability binding does not gather: %v", err)
		return false
	}
	if evidence.Actor == nil || evidence.Actor.Address != v.input.Actor {
		v.fail("bundle-binding", subject, "the Capability's manifest names another actor or an inactive one")
		return false
	}
	acceptance, err := serviceactor.ProveAcceptance(v.ctx, v.session, evidence, request.Call)
	if err != nil {
		v.fail("bundle-binding", subject, "the Capability's liveness at the call does not read: %v", err)
		return false
	}
	codeHash, err := digest32(v.input.ActorCodeHash, "tvm-cell-sha256:")
	if err != nil {
		v.fail("bundle-binding", subject, "the pinned code hash is malformed")
		return false
	}
	if _, err := serviceactor.VerifyExistingRequest(evidence, codeHash, &validated.Rail, validated.Proposal, v.input.Actor,
		request.Call, bundle.BuyerWallet, request.Snapshot.RequestHash, acceptance); err != nil {
		v.fail("bundle-binding", subject, "the request does not verify against the Capability and the Quote: %v", err)
		return false
	}
	v.pass("bundle-binding", subject, "the Capability, manifest, actor and terms bind the call from the buyer wallet")
	return true
}

// checkBundleFinalized requires every outcome the bundle claims to be the
// finalized one. An outcome finalized since the export is not a mismatch.
func (v *verification) checkBundleFinalized(bundle *Bundle, request *serviceactor.Request) {
	subject := bundle.Request.RequestHash
	if bundle.Finalized == nil {
		return
	}
	claimed, actual := bundle.Finalized.Request, reportOf(request, v.session.ChainTime())
	same := func(claim, finalized *TxReport) bool {
		return claim == nil || finalized != nil && claim.LT == finalized.LT && claim.Hash == finalized.Hash
	}
	if claimed.RequestID == nil || *claimed.RequestID != *actual.RequestID || claimed.RequestHash != actual.RequestHash ||
		claimed.Call.LT != actual.Call.LT || claimed.Call.Hash != actual.Call.Hash || !same(claimed.Respond, actual.Respond) ||
		!same(claimed.Expire, actual.Expire) || !same(claimed.ClaimRefund, actual.ClaimRefund) || !same(claimed.Sweep, actual.Sweep) ||
		claimed.ResponseHash != "" && claimed.ResponseHash != actual.ResponseHash {
		v.fail("bundle-finalized", subject, "the bundle's finalized outcome is not the finalized state")
		return
	}
	if bundle.Finalized.Checkpoint.Seqno > v.session.Checkpoint() {
		v.fail("bundle-finalized", subject, "the bundle claims a checkpoint after the verifier's")
		return
	}
	v.pass("bundle-finalized", subject, "the bundle's call and outcome transactions are the finalized ones")
}

// checkBundleResult requires an accepted result's response hash to be the
// finalized one and its file digests to be the files given.
func (v *verification) checkBundleResult(bundle *Bundle, request *serviceactor.Request) {
	subject := bundle.Request.RequestHash
	result := bundle.Result
	if !result.Accepted {
		return
	}
	if request.State != serviceactor.StateResponded || request.Terminal == nil || result.ResponseHash != request.Terminal.ResponseHash {
		v.fail("bundle-result", subject, "the bundle's accepted result is not the finalized response")
		return
	}
	if v.input.Receipt != nil && (result.Receipt == nil || result.Receipt.SHA256 != sha256Text(v.input.Receipt)) {
		v.fail("bundle-result", subject, "the Receipt file given is not the bundle's")
		return
	}
	if v.input.Artifact != nil && (result.Artifact == nil || result.Artifact.SHA256 != sha256Text(v.input.Artifact)) {
		v.fail("bundle-result", subject, "the artifact file given is not the bundle's")
		return
	}
	v.pass("bundle-result", subject, "the accepted result is the finalized response")
}

func sha256Text(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hex32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value || bytes.Equal(raw, make([]byte, 32)) {
		return out, errors.New("expected 64 lowercase hex digits, not all zero")
	}
	copy(out[:], raw)
	return out, nil
}

func digest32(value, prefix string) ([32]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return [32]byte{}, errors.New("invalid digest prefix")
	}
	return hex32(strings.TrimPrefix(value, prefix))
}
