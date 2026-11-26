package buyeragent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"google.golang.org/protobuf/proto"
)

// Buyer is the chain side the agent drives: buyersdk.ServiceActorBuyer.
type Buyer interface {
	Prepare(ctx context.Context, request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1,
		executionID, inputDigest [32]byte) (buyersdk.CallRecord, error)
	Call(ctx context.Context, requestHash string) (buyersdk.CallRecord, error)
	Withdraw(requestHash string) (buyersdk.CallRecord, error)
	Resolve(ctx context.Context, requestHash string) (*buyersdk.RequestReport, error)
	SendLifecycle(ctx context.Context, requestHash, operation string) (buyersdk.CallRecord, error)
	Journal() *buyersdk.ServiceActorJournal
	Limits() buyersdk.ServiceActorLimits
}

// CarriageChecker decides whether a prepared purchase can be carried to its
// provider and its result brought back (MCP_BUYER_ADAPTER_V1 section 7.1).
// It runs before a purchase is kept and again before its call is sent; an
// error refuses the purchase. The provider key card it needs may come from
// any source, but must be verified against finalized state before use.
type CarriageChecker interface {
	CheckCarriage(ctx context.Context, record buyersdk.CallRecord, archive []byte) error
}

// Config wires an agent.
type Config struct {
	// StateDir is the agent's owner-private (0700) state directory.
	StateDir string
	// BuyerAgentID is the Agent results return to; it is committed in each
	// execution ID.
	BuyerAgentID string
	Network      *nativev1.NetworkDomain
	Buyer        Buyer
	Carriage     CarriageChecker
	// Delivery carries the task of each admitted, pending purchase; nil
	// delivers nothing (an agent wired without a carrier).
	Delivery TaskDeliverer
	// Results accepts the result of each responded purchase; nil accepts
	// none.
	Results ResultReceiver
	// Accepted reads accepted results for the result method; nil reports
	// none.
	Accepted AcceptedResults
	// Offers serves search and quote; nil refuses both.
	Offers *Offers
	// MaxLifecycleSends bounds the expire, claim_refund and sweep sends in
	// one budget window. Zero means 2 * MaxCalls + 8 (section 6).
	MaxLifecycleSends int
	Now               func() time.Time
	Random            func([]byte) error
}

// Agent is the custody-side core. Its methods are what the socket server
// exposes; the server decides which role may call which.
type Agent struct {
	config  Config
	store   store
	release func()
	mutex   sync.Mutex
	changed chan struct{}
	// duties serializes the refund duties, so the background loop and a
	// client's refund request never send the same operation twice.
	duties sync.Mutex
}

// Open checks the state directory, takes the single-instance lock and
// prepares the store. A second agent on the same state directory is
// refused.
func Open(config Config) (*Agent, error) {
	if config.Buyer == nil || config.Carriage == nil || config.Network == nil ||
		!agentIDPattern.MatchString(config.BuyerAgentID) {
		return nil, errors.New("invalid buyer agent configuration")
	}
	if !filepath.IsAbs(config.StateDir) || filepath.Clean(config.StateDir) != config.StateDir {
		return nil, errors.New("the agent state directory must be absolute and clean")
	}
	if err := checkPrivateDir(config.StateDir); err != nil {
		return nil, err
	}
	limits := config.Buyer.Limits()
	if !limits.Valid() || limits.MaxPrepared == 0 {
		return nil, errors.New("the buyer limits must be valid and bound the prepared calls")
	}
	if config.MaxLifecycleSends == 0 {
		config.MaxLifecycleSends = 2*limits.MaxCalls + 8
	}
	if config.MaxLifecycleSends < 0 {
		return nil, errors.New("the lifecycle send bound must not be negative")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = func(value []byte) error { _, err := rand.Read(value); return err }
	}
	config.Network = proto.Clone(config.Network).(*nativev1.NetworkDomain)
	release, acquired, err := osguard.TryExclusiveFileLock(filepath.Join(config.StateDir, "agent.lock"), 0o600)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, errors.New("another buyer agent holds this state directory")
	}
	agent := &Agent{config: config, store: store{root: config.StateDir}, release: release, changed: make(chan struct{})}
	if err := agent.store.ensure(); err != nil {
		release()
		return nil, err
	}
	return agent, nil
}

// Close releases the single-instance lock.
func (a *Agent) Close() {
	if a != nil && a.release != nil {
		a.release()
		a.release = nil
	}
}

// notify wakes every waiter after a decision or a phase change.
func (a *Agent) notifyLocked() {
	close(a.changed)
	a.changed = make(chan struct{})
}

func (a *Agent) now() time.Time { return a.config.Now() }

// StoreQuote keeps a validated Quote for a later prepare and returns its
// quote ID, the SHA-256 of the package's deterministic encoding. The terms
// the confirmer shows are not taken from here: they come from the
// admission at prepare, bound by the terms hash the call pins.
func (a *Agent) StoreQuote(request *nativev1.RequestQuoteProposalRequest, value *nativev1.QuoteProposalPackageV1) (string, error) {
	if request == nil || value == nil {
		return "", refusal(CodeBadInput, "no Quote was given", nil)
	}
	if _, err := validatePortableQuote(a.config.Network, request, value); err != nil {
		return "", refusal(CodeOfferInvalid, "the Quote does not validate", err)
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	id := hex.EncodeToString(sum[:])
	record := quoteRecord{Schema: quoteSchema, QuoteID: id, CapabilityID: request.CapabilityId,
		CapabilityVersion: request.CapabilityVersion, BuyerAddress: request.BuyerAddress,
		PackageBase64: base64.StdEncoding.EncodeToString(raw)}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if err := writeJSON(a.store.quotePath(id), record, true); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return id, nil
}

func (a *Agent) loadQuote(id string) (*nativev1.RequestQuoteProposalRequest, *nativev1.QuoteProposalPackageV1, error) {
	record, err := a.store.readQuote(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, refusal(CodeNotFound, "no Quote has this quote ID", err)
	}
	if err != nil {
		return nil, nil, err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil {
		return nil, nil, errors.New("a stored Quote does not decode")
	}
	value := &nativev1.QuoteProposalPackageV1{}
	if err := proto.Unmarshal(raw, value); err != nil {
		return nil, nil, errors.New("a stored Quote does not decode")
	}
	request := &nativev1.RequestQuoteProposalRequest{CapabilityId: record.CapabilityID,
		CapabilityVersion: record.CapabilityVersion, BuyerAddress: record.BuyerAddress}
	return request, value, nil
}

// PrepareParams is a client's prepare request.
type PrepareParams struct {
	QuoteID        string `json:"quote_id"`
	IdempotencyKey string `json:"idempotency_key"`
	ArchiveBase64  string `json:"archive_base64"`
}

// maxArchiveBase64 is the Base64 length of the largest archive.
var maxArchiveBase64 = base64.StdEncoding.EncodedLen(MaxArchiveBytes)

func (p PrepareParams) check() ([]byte, error) {
	if !hex64Pattern.MatchString(p.QuoteID) {
		return nil, refusal(CodeBadInput, "quote_id must be 64 lowercase hex digits", nil)
	}
	if !idempotencyKeyPattern.MatchString(p.IdempotencyKey) {
		return nil, refusal(CodeBadInput, "idempotency_key must be 16 to 64 characters of [A-Za-z0-9_-]", nil)
	}
	if len(p.ArchiveBase64) == 0 || len(p.ArchiveBase64) > maxArchiveBase64 {
		return nil, refusal(CodeBadInput, "archive_base64 is empty or longer than the archive bound", nil)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(p.ArchiveBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != p.ArchiveBase64 {
		return nil, refusal(CodeBadInput, "archive_base64 is not canonical standard Base64", err)
	}
	return raw, nil
}

// Prepare re-validates a client's prepare request, journals the call as
// prepared and keeps the purchase. It pays nothing. A retry with the same
// idempotency key, Quote and source returns the same purchase; the same key
// with anything else is refused.
func (a *Agent) Prepare(ctx context.Context, params PrepareParams) (PurchaseView, error) {
	archive, err := params.check()
	if err != nil {
		return PurchaseView{}, err
	}
	request, value, err := a.loadQuote(params.QuoteID)
	if err != nil {
		return PurchaseView{}, err
	}
	now := a.now()
	validated, err := validateQuote(a.config.Network, request, value, now)
	if err != nil {
		if value.GetProposal().GetExpiresAtUnixSeconds() <= uint64(now.Unix()) {
			return PurchaseView{}, refusal(CodeQuoteExpired, "the Quote has expired", err)
		}
		return PurchaseView{}, refusal(CodeOfferInvalid, "the Quote does not validate", err)
	}
	bound := MaxArchiveBytes
	if limit := int(validated.TransportBinding.MaxRequestBytes); limit < bound {
		bound = limit
	}
	checked, err := CheckSourceArchive(archive, bound)
	if err != nil {
		return PurchaseView{}, refusal(CodeBadInput, "the source archive breaks the archive rules", err)
	}
	sourceDigest := checked.SourceDigest()

	a.mutex.Lock()
	defer a.mutex.Unlock()
	key, found, err := a.store.readKey(params.IdempotencyKey)
	if err != nil {
		return PurchaseView{}, err
	}
	if found && (key.QuoteID != params.QuoteID || key.SourceDigest != sourceDigest) {
		return PurchaseView{}, refusal(CodeConflict, "this idempotency key was used for another Quote or source", nil)
	}
	var nonce [32]byte
	if found {
		raw, decodeErr := hex.DecodeString(key.ExecutionNonce)
		if decodeErr != nil || len(raw) != 32 {
			return PurchaseView{}, errors.New("a stored execution nonce is invalid")
		}
		copy(nonce[:], raw)
	} else if nonce, err = a.drawNonzero(); err != nil {
		return PurchaseView{}, err
	}
	executionID, err := railwork.ExecutionID(a.config.BuyerAgentID, nonce)
	if err != nil {
		return PurchaseView{}, err
	}
	inputDigest := railwork.InputDigest(checked.Digest)
	quoteHash, _, err := railwork.QuoteCommitment(a.config.Network, validated.Proposal)
	if err != nil {
		return PurchaseView{}, refusal(CodeOfferInvalid, "the Quote does not validate", err)
	}
	expected, err := railwork.RequestHash(quoteHash, executionID, inputDigest)
	if err != nil {
		return PurchaseView{}, err
	}
	requestHash := hex.EncodeToString(expected[:])
	if found && key.RequestHash != requestHash {
		return PurchaseView{}, errors.New("a stored idempotency record derives another request hash")
	}
	if !found {
		key = keyRecord{Schema: keySchema, IdempotencyKey: params.IdempotencyKey, QuoteID: params.QuoteID,
			SourceDigest: sourceDigest, ExecutionNonce: hex.EncodeToString(nonce[:]), RequestHash: requestHash}
		if err := writeJSON(a.store.keyPath(params.IdempotencyKey), key, true); err != nil {
			return PurchaseView{}, err
		}
	}

	record, err := a.config.Buyer.Journal().Read(requestHash)
	if errors.Is(err, os.ErrNotExist) {
		record, err = a.config.Buyer.Prepare(ctx, request, value, executionID, inputDigest)
		if err != nil {
			return PurchaseView{}, prepareRefusal(err)
		}
	}
	if err != nil {
		return PurchaseView{}, err
	}
	if record.RequestHash != requestHash || record.ExecutionID != hex.EncodeToString(executionID[:]) ||
		record.InputDigest != hex.EncodeToString(inputDigest[:]) {
		return PurchaseView{}, errors.New("the journal holds another call under this request hash")
	}
	purchase, err := a.store.readPurchase(requestHash)
	if err == nil {
		switch purchase.Outcome {
		case outcomeNotCarriable:
			return PurchaseView{}, refusal(CodeNotCarriable, "the purchase cannot be carried to its provider", nil)
		case outcomeCardWindow:
			return PurchaseView{}, carriageRefusal(ErrCardWindowTooLong)
		}
		return a.viewOf(record, purchase), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return PurchaseView{}, err
	}
	purchase = PurchaseRecord{RequestHash: requestHash, QuoteID: params.QuoteID, IdempotencyKey: params.IdempotencyKey,
		SourceDigest: sourceDigest, ExecutionNonce: key.ExecutionNonce, ArchiveBytes: len(archive),
		Members: checked.Members, CreatedUnix: now.Unix(), ProviderAgentID: validated.Proposal.ProviderAgentId,
		ManifestDigest: validated.Proposal.ManifestDigest, ToolchainDigest: validated.Manifest.ToolchainDigest,
		ProviderName: validated.Manifest.Name, ProviderDescription: validated.Manifest.Description,
		RetentionSeconds: validated.Manifest.RetentionSeconds}
	if record.Phase == buyersdk.PhasePrepared {
		if carriageErr := a.config.Carriage.CheckCarriage(ctx, record, archive); carriageErr != nil {
			if record, err = a.config.Buyer.Withdraw(requestHash); err != nil {
				return PurchaseView{}, err
			}
			purchase.Outcome = outcomeNotCarriable
			if errors.Is(carriageErr, ErrCardWindowTooLong) {
				purchase.Outcome = outcomeCardWindow
			}
			if err := a.store.writePurchase(purchase); err != nil {
				return PurchaseView{}, err
			}
			return PurchaseView{}, carriageRefusal(carriageErr)
		}
	}
	if err := writePrivate(a.store.archivePath(requestHash), archive, false); err != nil {
		return PurchaseView{}, err
	}
	if err := a.store.writePurchase(purchase); err != nil {
		return PurchaseView{}, err
	}
	return a.viewOf(record, purchase), nil
}

func (a *Agent) drawNonzero() ([32]byte, error) {
	var nonce [32]byte
	for {
		if err := a.config.Random(nonce[:]); err != nil {
			return nonce, err
		}
		if nonce != [32]byte{} {
			return nonce, nil
		}
	}
}

func prepareRefusal(err error) error {
	switch {
	case errors.Is(err, buyersdk.ErrTooManyPrepared):
		return refusal(CodeOverBudget, "too many purchases are waiting for a decision", err)
	case errors.Is(err, buyersdk.ErrOverBudget):
		return refusal(CodeOverBudget, "the purchase is over the budget", err)
	case errors.Is(err, buyersdk.ErrQuoteExpired):
		return refusal(CodeQuoteExpired, "the Quote has expired", err)
	case errors.Is(err, railwork.ErrQuoteNotCarriable):
		return refusal(CodeNotCarriable, "the purchase cannot be carried to its provider", err)
	}
	return refusal(CodeOfferInvalid, "finalized state does not verify the offer or the Quote", err)
}

// Purchase outcomes recorded when a purchase leaves prepared unsent.
const (
	outcomeDeclined     = "declined"
	outcomeWithdrawn    = "withdrawn"
	outcomeCodeFailures = "code-failures"
	outcomeNotCarriable = "not-carriable"
	outcomeCardWindow   = "card-window-too-long"
)

// Decision states a client sees (MCP_BUYER_ADAPTER_V1 section 4.6).
const (
	StateAwaitingConfirmation = "awaiting_confirmation"
	StateDeclined             = "declined"
	StateWithdrawn            = "withdrawn"
	StateExpired              = "expired"
	StateSubmitted            = "submitted"
	StateAdmitted             = "admitted"
	StateRefused              = "refused"
	StateFundingSurplus       = "funding_surplus"
	StateAmbiguous            = "ambiguous"
)

// PurchaseView is what a client may see of a purchase. It never carries the
// confirmation code or its nonce.
type PurchaseView struct {
	TokenFunding      *TokenFundingView `json:"token_funding,omitempty"`
	RequestHash       string            `json:"request_hash"`
	Reference         string            `json:"purchase_reference"`
	State             string            `json:"state"`
	Phase             string            `json:"journal_phase"`
	CapabilityID      string            `json:"capability_id"`
	CapabilityVersion string            `json:"capability_version"`
	Actor             string            `json:"actor"`
	AttestorKeyID     string            `json:"attestor_key_id"`
	PriceNanoTOS      string            `json:"price_nanotos"`
	StorageFeeNanoTOS string            `json:"storage_fee_nanotos"`
	PaymentNanoTOS    string            `json:"payment_nanotos"`
	TermsHash         string            `json:"terms_hash"`
	QuoteCommitment   string            `json:"quote_commitment"`
	QuoteExpiresUnix  uint64            `json:"quote_expires_at_unix"`
	SourceDigest      string            `json:"source_digest"`
	ArchiveBytes      int               `json:"archive_bytes"`
	Members           []Member          `json:"members"`
	Requested         bool              `json:"payment_requested"`
	// The preview of section 4.5: the provider, the manifest and its text,
	// and the terms the deadlines and refunds follow. The text is the
	// provider's own and untrusted.
	ProviderAgentID          string `json:"provider_agent_id"`
	ManifestDigest           string `json:"manifest_digest"`
	ProviderName             string `json:"untrusted_provider_name"`
	ProviderDescription      string `json:"untrusted_provider_description"`
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	RetentionSeconds         uint64 `json:"retention_seconds"`
}

func stateOf(record buyersdk.CallRecord, purchase PurchaseRecord, now time.Time) string {
	switch record.Phase {
	case buyersdk.PhasePrepared:
		if uint64(now.Unix()) >= record.ExpiresAtUnix {
			return StateExpired
		}
		return StateAwaitingConfirmation
	case buyersdk.PhaseWithdrawn:
		if purchase.Outcome == outcomeDeclined {
			return StateDeclined
		}
		return StateWithdrawn
	case buyersdk.PhaseSending, buyersdk.PhaseSubmitted:
		return StateSubmitted
	case buyersdk.PhaseAdmitted:
		return StateAdmitted
	case buyersdk.PhaseRefused:
		return StateRefused
	case buyersdk.PhaseFundingSurplus:
		return StateFundingSurplus
	case buyersdk.PhaseAmbiguous:
		return StateAmbiguous
	}
	return StateAmbiguous
}

func (a *Agent) viewOf(record buyersdk.CallRecord, purchase PurchaseRecord) PurchaseView {
	return PurchaseView{TokenFunding: tokenFunding(record), RequestHash: record.RequestHash, Reference: PurchaseReference(record.RequestHash),
		State: stateOf(record, purchase, a.now()), Phase: string(record.Phase), CapabilityID: record.CapabilityID,
		CapabilityVersion: record.CapabilityVersion, Actor: record.Actor, AttestorKeyID: record.AttestorKeyID,
		PriceNanoTOS: record.PriceNanoTOS, StorageFeeNanoTOS: record.StorageFeeNanoTOS,
		PaymentNanoTOS: record.PaymentNanoTOS, TermsHash: record.TermsHash, QuoteCommitment: record.QuoteCommitment,
		QuoteExpiresUnix: record.ExpiresAtUnix, SourceDigest: purchase.SourceDigest, ArchiveBytes: purchase.ArchiveBytes,
		Members: append([]Member(nil), purchase.Members...), Requested: purchase.RequestedUnix != 0,
		ProviderAgentID: purchase.ProviderAgentID, ManifestDigest: purchase.ManifestDigest,
		ProviderName: purchase.ProviderName, ProviderDescription: purchase.ProviderDescription,
		ResponseSLASeconds: record.ResponseSLASeconds, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,
		CleanupBountyNanoTOS: record.CleanupBountyNanoTOS, RetentionSeconds: purchase.RetentionSeconds}
}

// RequestHashParams names one purchase.
type RequestHashParams struct {
	RequestHash string `json:"request_hash"`
}

func checkRequestHash(value string) error {
	if !hex64Pattern.MatchString(value) {
		return refusal(CodeBadInput, "request_hash must be 64 lowercase hex digits", nil)
	}
	return nil
}

// load reads a purchase the agent prepared: both its journal record and its
// purchase record must exist.
func (a *Agent) loadLocked(requestHash string) (buyersdk.CallRecord, PurchaseRecord, error) {
	if err := checkRequestHash(requestHash); err != nil {
		return buyersdk.CallRecord{}, PurchaseRecord{}, err
	}
	purchase, err := a.store.readPurchase(requestHash)
	if errors.Is(err, os.ErrNotExist) {
		return buyersdk.CallRecord{}, PurchaseRecord{}, refusal(CodeNotFound, "no purchase has this request hash", err)
	}
	if err != nil {
		return buyersdk.CallRecord{}, PurchaseRecord{}, err
	}
	record, err := a.config.Buyer.Journal().Read(requestHash)
	if err != nil {
		return buyersdk.CallRecord{}, PurchaseRecord{}, err
	}
	return record, purchase, nil
}

// Status returns one purchase as a client may see it.
func (a *Agent) Status(requestHash string) (PurchaseView, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	record, purchase, err := a.loadLocked(requestHash)
	if err != nil {
		return PurchaseView{}, err
	}
	return a.viewOf(record, purchase), nil
}

// Withdraw withdraws a purchase that is still prepared.
func (a *Agent) Withdraw(requestHash string) (PurchaseView, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.withdrawLocked(requestHash, outcomeWithdrawn)
}

func (a *Agent) withdrawLocked(requestHash, outcome string) (PurchaseView, error) {
	record, purchase, err := a.loadLocked(requestHash)
	if err != nil {
		return PurchaseView{}, err
	}
	if record.Phase != buyersdk.PhasePrepared {
		return a.viewOf(record, purchase), refusal(CodeConflict, "the purchase is no longer waiting for a decision", nil)
	}
	if record, err = a.config.Buyer.Withdraw(requestHash); err != nil {
		return PurchaseView{}, refusal(CodeConflict, "the purchase is no longer waiting for a decision", err)
	}
	purchase.Outcome, purchase.ConfirmationNonce, purchase.PresentedUnix = outcome, "", 0
	if err := a.store.writePurchase(purchase); err != nil {
		return PurchaseView{}, err
	}
	a.notifyLocked()
	return a.viewOf(record, purchase), nil
}

// RequestPaymentParams asks for the human's decision.
type RequestPaymentParams struct {
	RequestHash string `json:"request_hash"`
	WaitSeconds int    `json:"wait_seconds"`
}

// MaxWaitSeconds bounds how long a client waits for one decision.
const MaxWaitSeconds = 300

// RequestPayment makes a prepared purchase visible to the confirmer and
// waits up to WaitSeconds for the human's decision. It draws no code and
// pays nothing.
func (a *Agent) RequestPayment(ctx context.Context, params RequestPaymentParams) (PurchaseView, error) {
	if params.WaitSeconds < 0 || params.WaitSeconds > MaxWaitSeconds {
		return PurchaseView{}, refusal(CodeBadInput, "wait_seconds must be 0 to 300", nil)
	}
	var record buyersdk.CallRecord
	var purchase PurchaseRecord
	var err error
	a.withLock(func() {
		record, purchase, err = a.loadLocked(params.RequestHash)
		if err == nil && record.Phase == buyersdk.PhasePrepared && purchase.RequestedUnix == 0 {
			purchase.RequestedUnix = a.now().Unix()
			err = a.store.writePurchase(purchase)
			a.notifyLocked()
		}
	})
	if err != nil {
		return PurchaseView{}, err
	}
	timer := time.NewTimer(time.Duration(params.WaitSeconds) * time.Second)
	defer timer.Stop()
	for {
		var changed chan struct{}
		a.withLock(func() {
			record, purchase, err = a.loadLocked(params.RequestHash)
			changed = a.changed
		})
		if err != nil {
			return PurchaseView{}, err
		}
		view := a.viewOf(record, purchase)
		if view.State != StateAwaitingConfirmation {
			return view, nil
		}
		select {
		case <-changed:
		case <-timer.C:
			return view, nil
		case <-ctx.Done():
			return view, nil
		}
	}
}

// BudgetView is the budget in use.
type BudgetView struct {
	TokenAssets       []TokenBudgetView `json:"token_assets,omitempty"`
	WindowSeconds     int64             `json:"window_seconds"`
	MaxCalls          int               `json:"max_calls"`
	MaxPrepared       int               `json:"max_prepared"`
	MaxPerCallNanoTOS string            `json:"max_per_call_nanotos"`
	MaxWindowNanoTOS  string            `json:"max_window_nanotos"`
	ReservedNanoTOS   string            `json:"reserved_nanotos"`
	ReservedCalls     int               `json:"reserved_calls"`
}

func (a *Agent) budget() (BudgetView, error) {
	limits := a.config.Buyer.Limits()
	total, calls, err := a.config.Buyer.Journal().Reserved(limits, a.now())
	if err != nil {
		return BudgetView{}, err
	}
	tokens, err := a.tokenBudgets(limits)
	if err != nil {
		return BudgetView{}, err
	}
	return BudgetView{TokenAssets: tokens, WindowSeconds: int64(limits.Window / time.Second), MaxCalls: limits.MaxCalls,
		MaxPrepared: limits.MaxPrepared, MaxPerCallNanoTOS: limits.MaxPerCallNanoTOS.String(),
		MaxWindowNanoTOS: limits.MaxWindowNanoTOS.String(), ReservedNanoTOS: total.String(), ReservedCalls: calls}, nil
}

// PurchasesParams pages through the purchases in request-hash order.
type PurchasesParams struct {
	PageSize int    `json:"page_size"`
	After    string `json:"after,omitempty"`
}

// PurchasesView is one page of purchases and the budget.
type PurchasesView struct {
	Purchases []PurchaseView `json:"purchases"`
	Next      string         `json:"next,omitempty"`
	Budget    BudgetView     `json:"budget"`
}

// Purchases lists the agent's purchases.
func (a *Agent) Purchases(params PurchasesParams) (PurchasesView, error) {
	if params.PageSize < 1 || params.PageSize > 100 {
		return PurchasesView{}, refusal(CodeBadInput, "page_size must be 1 to 100", nil)
	}
	if params.After != "" {
		if err := checkRequestHash(params.After); err != nil {
			return PurchasesView{}, err
		}
	}
	return a.list(params.PageSize, params.After, func(PurchaseView) bool { return true })
}

func (a *Agent) list(pageSize int, after string, keep func(PurchaseView) bool) (PurchasesView, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	records, err := a.config.Buyer.Journal().Records()
	if err != nil {
		return PurchasesView{}, err
	}
	sort.Slice(records, func(i, j int) bool { return records[i].RequestHash < records[j].RequestHash })
	view := PurchasesView{Purchases: []PurchaseView{}}
	for _, record := range records {
		if record.RequestHash <= after {
			continue
		}
		purchase, err := a.store.readPurchase(record.RequestHash)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return PurchasesView{}, err
		}
		item := a.viewOf(record, purchase)
		if !keep(item) {
			continue
		}
		if len(view.Purchases) == pageSize {
			view.Next = view.Purchases[pageSize-1].RequestHash
			break
		}
		view.Purchases = append(view.Purchases, item)
	}
	if view.Budget, err = a.budget(); err != nil {
		return PurchasesView{}, err
	}
	return view, nil
}

// Pending lists the purchases a client asked the human to decide.
func (a *Agent) Pending() (PurchasesView, error) {
	return a.list(100, "", func(view PurchaseView) bool {
		return view.Requested && view.State == StateAwaitingConfirmation
	})
}

// Presentation is what the confirmer shows for one purchase. It is sent
// only to the custody account.
type Presentation struct {
	Purchase    PurchaseView `json:"purchase"`
	NetworkID   string       `json:"network_id"`
	BuyerWallet string       `json:"buyer_wallet"`
	Budget      BudgetView   `json:"budget"`
	// ProviderAgentID and ManifestDigest come from the validated Quote.
	ProviderAgentID string `json:"provider_agent_id"`
	ManifestDigest  string `json:"manifest_digest"`
	// ProviderName and ProviderDescription are the manifest's
	// human-readable fields: text the provider wrote, which the confirmer
	// renders as untrusted.
	ProviderName        string `json:"untrusted_provider_name"`
	ProviderDescription string `json:"untrusted_provider_description"`
	// The terms the deadlines and the refund follow.
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	RetentionSeconds         uint64 `json:"retention_seconds"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	AllowanceNanoTOS         string `json:"execution_allowance_nanotos"`
	// NowUnix is the agent's clock when it presented, so deadlines are
	// computed from one instant.
	NowUnix        int64  `json:"now_unix"`
	Code           string `json:"confirmation_code"`
	ValidUntilUnix int64  `json:"code_valid_until_unix"`
}

// Present draws the presentation's nonce, unless the current one is still
// valid, and returns the code with the purchase. Only the confirmer's
// fetch draws a nonce, so a client can never rotate or learn the code.
func (a *Agent) Present(requestHash string) (Presentation, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	record, purchase, err := a.loadLocked(requestHash)
	if err != nil {
		return Presentation{}, err
	}
	now := a.now()
	if record.Phase != buyersdk.PhasePrepared || purchase.RequestedUnix == 0 {
		return Presentation{}, refusal(CodeConflict, "the purchase is not waiting for a decision", nil)
	}
	// The terms shown come from the journal record, which Prepare filled
	// from the admitted policy. A record without them cannot be shown
	// honestly, so it is never presented.
	if record.ResponseSLASeconds == 0 || record.RefundClaimWindowSeconds == 0 || record.CleanupBountyNanoTOS == "" {
		return Presentation{}, refusal(CodeOfferInvalid, "the purchase record lacks its admitted terms", nil)
	}
	if purchase.ConfirmationNonce == "" || !now.Before(time.Unix(purchase.PresentedUnix, 0).Add(ConfirmationLifetime)) {
		var nonce [ConfirmationNonceBytes]byte
		if err := a.config.Random(nonce[:]); err != nil {
			return Presentation{}, err
		}
		purchase.ConfirmationNonce, purchase.PresentedUnix = hex.EncodeToString(nonce[:]), now.Unix()
		if err := a.store.writePurchase(purchase); err != nil {
			return Presentation{}, err
		}
	}
	nonce, err := parseNonce(purchase.ConfirmationNonce)
	if err != nil {
		return Presentation{}, err
	}
	budget, err := a.budget()
	if err != nil {
		return Presentation{}, err
	}
	request, value, err := a.loadQuote(purchase.QuoteID)
	if err != nil {
		return Presentation{}, err
	}
	validated, err := validatePortableQuote(a.config.Network, request, value)
	if err != nil {
		return Presentation{}, refusal(CodeOfferInvalid, "the stored Quote no longer validates", err)
	}
	fields, err := fieldsOf(record, purchase)
	if err != nil {
		return Presentation{}, err
	}
	return Presentation{Purchase: a.viewOf(record, purchase), NetworkID: record.NetworkID, BuyerWallet: record.BuyerWallet,
		Budget: budget, ProviderAgentID: validated.Proposal.ProviderAgentId, ManifestDigest: validated.Proposal.ManifestDigest,
		ProviderName: validated.Manifest.Name, ProviderDescription: validated.Manifest.Description,
		ResponseSLASeconds: record.ResponseSLASeconds, RefundClaimWindowSeconds: record.RefundClaimWindowSeconds,
		RetentionSeconds: validated.Manifest.RetentionSeconds, CleanupBountyNanoTOS: record.CleanupBountyNanoTOS,
		AllowanceNanoTOS: strconv.Itoa(nativecore.ServiceActorAdmissionGasAllowance), NowUnix: now.Unix(),
		Code:           ConfirmationCode(nonce, fields),
		ValidUntilUnix: time.Unix(purchase.PresentedUnix, 0).Add(ConfirmationLifetime).Unix()}, nil
}

// DecideParams is the confirmer's decision.
type DecideParams struct {
	RequestHash string `json:"request_hash"`
	Decision    string `json:"decision"`
	Code        string `json:"code,omitempty"`
}

// Decisions.
const (
	DecisionConfirm = "confirm"
	DecisionDecline = "decline"
)

// Decide applies the human's decision. A confirmation pays only when the
// typed code equals the code the agent recomputes from its own records and
// the stored nonce; the comparison is constant time. Three wrong codes
// withdraw the purchase. A matching code is spent at once, so it confirms
// at most one send.
func (a *Agent) Decide(ctx context.Context, params DecideParams) (PurchaseView, error) {
	if params.Decision != DecisionConfirm && params.Decision != DecisionDecline {
		return PurchaseView{}, refusal(CodeBadInput, "decision must be confirm or decline", nil)
	}
	if len(params.Code) > 64 || (params.Decision == DecisionDecline && params.Code != "") {
		return PurchaseView{}, refusal(CodeBadInput, "code is longer than 64 characters or given with a decline", nil)
	}
	var record buyersdk.CallRecord
	var purchase PurchaseRecord
	var view PurchaseView
	var err error
	confirmed := false
	a.withLock(func() {
		record, purchase, view, confirmed, err = a.decideLocked(params)
	})
	if !confirmed {
		return view, err
	}
	return a.pay(ctx, record, purchase)
}

// decideLocked applies a decision under the agent's lock. It reports
// confirmed only for a matching code, which it has already spent; the send
// then runs outside the lock.
func (a *Agent) decideLocked(params DecideParams) (buyersdk.CallRecord, PurchaseRecord, PurchaseView, bool, error) {
	record, purchase, err := a.loadLocked(params.RequestHash)
	if err != nil {
		return record, purchase, PurchaseView{}, false, err
	}
	now := a.now()
	if record.Phase != buyersdk.PhasePrepared || purchase.RequestedUnix == 0 || purchase.ConfirmationNonce == "" {
		return record, purchase, a.viewOf(record, purchase), false,
			refusal(CodeConflict, "the purchase has no current presentation", nil)
	}
	if !now.Before(time.Unix(purchase.PresentedUnix, 0).Add(ConfirmationLifetime)) {
		purchase.ConfirmationNonce, purchase.PresentedUnix = "", 0
		if err := a.store.writePurchase(purchase); err != nil {
			return record, purchase, PurchaseView{}, false, err
		}
		return record, purchase, a.viewOf(record, purchase), false,
			refusal(CodeConflict, "the confirmation code expired; present the purchase again", nil)
	}
	if params.Decision == DecisionDecline {
		view, err := a.withdrawLocked(params.RequestHash, outcomeDeclined)
		return record, purchase, view, false, err
	}
	nonce, err := parseNonce(purchase.ConfirmationNonce)
	if err != nil {
		return record, purchase, PurchaseView{}, false, err
	}
	fields, err := fieldsOf(record, purchase)
	if err != nil {
		return record, purchase, PurchaseView{}, false, err
	}
	if !codesMatch(ConfirmationCode(nonce, fields), params.Code) {
		purchase.CodeFailures++
		if err := a.store.writePurchase(purchase); err != nil {
			return record, purchase, PurchaseView{}, false, err
		}
		if purchase.CodeFailures >= MaxCodeFailures {
			view, err := a.withdrawLocked(params.RequestHash, outcomeCodeFailures)
			if err != nil {
				return record, purchase, view, false, err
			}
			return record, purchase, view, false, refusal(CodeDeclined, "too many wrong codes; the purchase was withdrawn", nil)
		}
		return record, purchase, a.viewOf(record, purchase), false, refusal(CodeBadInput, "the code does not match", nil)
	}
	purchase.ConfirmationNonce, purchase.PresentedUnix = "", 0
	if err := a.store.writePurchase(purchase); err != nil {
		return record, purchase, PurchaseView{}, false, err
	}
	return record, purchase, PurchaseView{}, true, nil
}

// withLock runs fn holding the agent's lock, and releases the lock even
// if fn panics, so a recovered panic never leaves the agent stuck.
func (a *Agent) withLock(fn func()) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	fn()
}

// pay repeats the carriage check on the stored archive and hands the call
// to the buyer, which re-verifies at a fresh checkpoint and sends at most
// once.
func (a *Agent) pay(ctx context.Context, record buyersdk.CallRecord, purchase PurchaseRecord) (PurchaseView, error) {
	archive, err := readPrivate(a.store.archivePath(record.RequestHash))
	if err != nil {
		return PurchaseView{}, err
	}
	if sum := sha256.Sum256(archive); "sha256:"+hex.EncodeToString(sum[:]) != purchase.SourceDigest {
		return PurchaseView{}, errors.New("the stored source archive does not match its digest")
	}
	if err := a.config.Carriage.CheckCarriage(ctx, record, archive); err != nil {
		return a.viewOf(record, purchase), carriageRefusal(err)
	}
	called, callErr := a.config.Buyer.Call(ctx, record.RequestHash)
	a.withLock(a.notifyLocked)
	view := a.viewOf(called, purchase)
	if called.RequestHash == "" {
		view = a.viewOf(record, purchase)
	}
	if callErr == nil {
		return view, nil
	}
	switch {
	case called.Phase == buyersdk.PhaseAmbiguous:
		return view, refusal(CodeAmbiguous, "the call may have been submitted; it is resolved from finalized history", callErr)
	case errors.Is(callErr, buyersdk.ErrQuoteExpired):
		return view, refusal(CodeQuoteExpired, "the Quote has expired", callErr)
	case errors.Is(callErr, buyersdk.ErrOverBudget):
		return view, refusal(CodeOverBudget, "the purchase is over the budget", callErr)
	case called.Phase == buyersdk.PhasePrepared:
		return view, refusal(CodeDependencyUnavailable, "the call was not sent; nothing was paid", callErr)
	}
	return view, refusal(CodeInternal, fmt.Sprintf("the call ended in phase %s", called.Phase), callErr)
}
