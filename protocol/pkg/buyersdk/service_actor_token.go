package buyersdk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"

	"github.com/tosnetwork/ai/protocol/pkg/mldsa44"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const TokenPreparedMessageVersion = "tosctl.service-actor-token.prepared-message.v1"

// TokenReadAt identifies the single finalized checkpoint of every field in a build snapshot.
type TokenReadAt struct {
	Seqno    uint32 `json:"seqno"`
	RootHash string `json:"root_hash"`
	GenUtime uint32 `json:"gen_utime"`
}

// TokenAssetPin is client policy, independent of the recognition record returned by a node.
type TokenAssetPin struct {
	Master         string
	WalletCodeHash [32]byte
	Decimals       uint8
}
type TokenRecognizedAsset struct {
	Status               uint8
	WalletCodeHash       [32]byte
	Decimals             uint8
	MaxLiabilityPerActor *big.Int
}
type TokenWalletTerms struct{ GasConsumption, MinimumStorage *big.Int }
type TokenForwardPrices struct {
	LumpPrice, BitPrice, CellPrice uint64
	FirstFraction                  uint16
}

// TokenBuildSnapshot contains corroborated data from one finalized read session.
// It performs no chain reads; callers must not combine fields from different sessions.
type TokenBuildSnapshot struct {
	Actor                                string
	CodeProfile                          string
	ReadAt                               TokenReadAt
	Balance                              *big.Int
	Data                                 *nativecore.ServiceActorTokenDataV1
	TermsHash                            [32]byte
	FundingPrices                        [6]*big.Int
	AcceptingTokens                      bool
	CurrentAttestorKeyStored             bool
	AssetPin                             *TokenAssetPin
	Asset                                *TokenRecognizedAsset
	WalletTerms                          *TokenWalletTerms
	ForwardPrices                        *TokenForwardPrices
	SenderTokenBalance, OwnWalletBalance *big.Int
	OwnWallet                            string
	OwnWalletDeployed                    bool
	CallerLive, CallerReturned           uint32
	Request                              *nativecore.ServiceActorRequestViewV1
	Refund                               *nativecore.ServiceActorRefundV1
	Returned                             *nativecore.ServiceActorTokenReturnedV1
	Payout                               *nativecore.ServiceActorTokenPayoutV1
	RequestAttestorKey                   []byte
	GlobalID                             *int32
	// VerifyResponse verifies the snapshotted key, signature and SRP2 digest.
	VerifyResponse func(publicKey, signature []byte, digest [32]byte) error
}

// TokenPolicyChange contains only fields the policy operation may replace.
type TokenPolicyChange struct {
	PricePerCall, StorageFee, CleanupBounty, MaxTokenLiability *big.Int
	ResponseSLA, RefundClaimWindow, RateLimitPerDay            *uint32
	Active, OpenAccess                                         *bool
	AuthorizedCaller                                           *string
	ClearAuthorizedCaller                                      bool
	MetadataHash, ProofSchemeHash                              *[32]byte
}

// TokenBuildRequest is an unsigned action; private keys are never accepted.
type TokenBuildRequest struct {
	Operation, Sender                                      string
	QueryID, ID                                            uint64
	Destination                                            string
	RequestHash, ExpectedTermsHash, ResponseHash           [32]byte
	ForwardTOS, WalletValue, Value, TOSAmount, TokenAmount *big.Int
	PolicyChange                                           *TokenPolicyChange
	PublicKey, Signature                                   []byte
}

// TokenPreparedMessage is the exact ordered unsigned message document.
type TokenPreparedMessage struct {
	Version      string            `json:"version"`
	Operation    string            `json:"operation"`
	Rail         string            `json:"rail"`
	CodeProfile  string            `json:"code_profile"`
	Actor        string            `json:"actor"`
	ReadAt       TokenReadAt       `json:"read_at"`
	Sender       string            `json:"sender"`
	Destination  string            `json:"destination"`
	ValueNanotos string            `json:"value_nanotos"`
	Bounce       bool              `json:"bounce"`
	BodyBOC      string            `json:"body_boc"`
	BodyHash     string            `json:"body_hash"`
	Details      map[string]string `json:"details"`
	Warnings     []string          `json:"-"`
}

// Pretty emits the deterministic build-only document, including its final newline.
func (p TokenPreparedMessage) Pretty() ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(p); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func tokenRaw(text string, basechain bool) (nativecore.MsgAddressV1, error) {
	a, err := nativecore.StandardAddress(text)
	if err != nil {
		return a, err
	}
	raw, ok := a.RawStandard()
	if !ok || raw != text || (basechain && a.Workchain != 0) {
		return a, errors.New("address is not canonical for the token rail")
	}
	return a, nil
}
func tokenCoins(v *big.Int) bool { return v != nil && v.Sign() >= 0 && v.BitLen() <= 120 }
func tokenAmount(v *big.Int) (*big.Int, error) {
	if !tokenCoins(v) {
		return nil, errors.New("token amount is outside Coins range")
	}
	return new(big.Int).Set(v), nil
}
func tokenZero(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}
func tokenSum(vs ...*big.Int) (*big.Int, error) {
	r := new(big.Int)
	for _, v := range vs {
		if !tokenCoins(v) {
			return nil, errors.New("amount is outside Coins range")
		}
		r.Add(r, v)
		if r.BitLen() > 120 {
			return nil, errors.New("amount sum exceeds Coins range")
		}
	}
	return r, nil
}
func tokenFunded(minimum, explicit *big.Int) (*big.Int, error) {
	if !tokenCoins(minimum) {
		return nil, errors.New("invalid minimum message value")
	}
	v := explicit
	if v == nil {
		var err error
		v, err = tokenSum(minimum, minimum)
		if err != nil {
			return nil, err
		}
	}
	if !tokenCoins(v) || v.Sign() == 0 || v.Cmp(minimum) < 0 || !v.IsUint64() {
		return nil, errors.New("message value does not cover its minimum or exceeds 64 bits (1929)")
	}
	return new(big.Int).Set(v), nil
}
func tokenRefusal(code uint32, text string) error {
	return fmt.Errorf("%s (refused with %d)", text, code)
}

// tokenRecheckQueryTTL is the contract's RECHECK_QUERY_TTL in seconds.
const tokenRecheckQueryTTL = 3600

// tokenBalanceQueryIdle mirrors the supersede rule of section 8.5:
// recover_surplus, recheck_payout and abandon_payout throw 1943 while a
// balance query younger than RECHECK_QUERY_TTL is pending; an older one is
// replaced or cleared.
func tokenBalanceQueryIdle(q nativecore.ServiceActorTokenBalanceQueryV1, now uint64) error {
	if !q.Active {
		return nil
	}
	free := uint64(q.CreatedAt) + tokenRecheckQueryTTL
	if now < free {
		return tokenRefusal(1943, fmt.Sprintf("balance query %d is pending until %d", q.QueryID, free))
	}
	return nil
}
func tokenFreeBacking(s TokenBuildSnapshot, code uint32) (*big.Int, error) {
	locks, err := tokenSum(s.Data.Accounting.LockedStorageFees, s.Data.Accounting.LockedOutcomeFees, big.NewInt(nativecore.ServiceActorMinimumOperatingReserve))
	if err != nil {
		return nil, err
	}
	if !tokenCoins(s.Balance) || s.Balance.Cmp(locks) < 0 {
		return nil, tokenRefusal(code, "actor balance does not cover its locks and reserve")
	}
	return new(big.Int).Sub(s.Balance, locks), nil
}

// TokenWalletNeed prices the body as a referenced cell, a conservative wallet envelope bound.
func TokenWalletNeed(forward *big.Int, terms TokenWalletTerms, prices TokenForwardPrices, body *cell.Cell) (*big.Int, error) {
	if !tokenCoins(forward) || !tokenCoins(terms.GasConsumption) || !tokenCoins(terms.MinimumStorage) || body == nil {
		return nil, errors.New("wallet pricing input is missing or invalid")
	}
	seen := map[string]bool{}
	pending := []*cell.Cell{body}
	var bits, cells uint64
	for len(pending) > 0 {
		v := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if v == nil || v.IsSpecial() {
			return nil, errors.New("wallet body has a missing or exotic cell")
		}
		key := string(v.Hash())
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(seen) > 4096 {
			return nil, errors.New("wallet body exceeds the cell bound")
		}
		bits += uint64(v.BitsSize())
		cells++
		for n := uint(0); n < v.RefsNum(); n++ {
			r, err := v.PeekRef(int(n))
			if err != nil {
				return nil, err
			}
			pending = append(pending, r)
		}
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(prices.BitPrice), new(big.Int).SetUint64(bits))
	fee.Add(fee, new(big.Int).Mul(new(big.Int).SetUint64(prices.CellPrice), new(big.Int).SetUint64(cells)))
	fee.Add(fee, big.NewInt(65535))
	fee.Rsh(fee, 16)
	fee.Add(fee, new(big.Int).SetUint64(prices.LumpPrice))
	first := new(big.Int).Mul(fee, new(big.Int).SetUint64(uint64(prices.FirstFraction)))
	first.Rsh(first, 16)
	remaining := new(big.Int).Sub(fee, first)
	remaining.Mul(remaining, big.NewInt(3))
	remaining.Div(remaining, big.NewInt(2))
	if forward.Sign() > 0 {
		remaining.Mul(remaining, big.NewInt(2))
	}
	gas, err := tokenSum(terms.GasConsumption, terms.GasConsumption)
	if err != nil {
		return nil, err
	}
	return tokenSum(forward, remaining, gas, terms.MinimumStorage)
}

// PrepareTokenMessage plans one action without signing or reading mutable state.
func PrepareTokenMessage(s TokenBuildSnapshot, r TokenBuildRequest) (*TokenPreparedMessage, error) {
	if err := validateTokenBuildRequest(r); err != nil {
		return nil, err
	}
	if s.Data == nil {
		return nil, errors.New("missing finalized token build snapshot")
	}
	if len(s.ReadAt.RootHash) != 64 {
		return nil, errors.New("invalid finalized root hash")
	}
	root, err := hex.DecodeString(s.ReadAt.RootHash)
	if err != nil || hex.EncodeToString(root) != s.ReadAt.RootHash {
		return nil, errors.New("non-canonical finalized root hash")
	}
	if s.CodeProfile != "release" && s.CodeProfile != "test" {
		return nil, errors.New("unknown token actor code profile")
	}
	if _, err := tokenRaw(s.Actor, true); err != nil {
		return nil, err
	}
	if _, err := tokenRaw(r.Sender, false); err != nil {
		return nil, err
	}
	if !tokenCoins(s.Balance) || !s.Balance.IsUint64() {
		return nil, errors.New("actor balance is invalid")
	}
	p := s.Data.Policy
	a := s.Data.Accounting
	l := a.Ledger
	for _, v := range []*big.Int{p.PricePerCall, p.StorageFee, p.CleanupBounty, p.MaxTokenLiability, a.WithdrawableTOSRevenue, a.LockedStorageFees, a.LockedOutcomeFees, l.PendingLiability, l.RefundableLiability, l.ReturnedLiability, l.InFlight, l.WithdrawableTokenRevenue} {
		if !tokenCoins(v) {
			return nil, errors.New("token snapshot contains an invalid ledger amount")
		}
	}
	if s.Request != nil && !tokenCoins(s.Request.Price) || s.Refund != nil && !tokenCoins(s.Refund.Price) || s.Returned != nil && !tokenCoins(s.Returned.Amount) || s.Payout != nil && !tokenCoins(s.Payout.Amount) {
		return nil, errors.New("token snapshot contains an invalid lifecycle amount")
	}
	for _, v := range s.FundingPrices {
		if !tokenCoins(v) {
			return nil, errors.New("token funding prices are invalid")
		}
	}
	if r.Value != nil && (!tokenCoins(r.Value) || r.Value.Sign() == 0 || !r.Value.IsUint64()) {
		return nil, errors.New("message value must be a positive 64-bit amount")
	}
	if r.Operation == "call" {
		return prepareTokenCall(s, r)
	}
	details := map[string]string{"query_id": strconv.FormatUint(r.QueryID, 10)}
	destination := s.Actor
	value := r.Value
	if value == nil {
		value = big.NewInt(10_000_000)
	} else {
		value = new(big.Int).Set(value)
	}
	var body *cell.Cell
	var warnings []string
	owner, ok := s.Data.Owner.RawStandard()
	if !ok {
		return nil, errors.New("owner is not a canonical standard address")
	}
	switch r.Operation {
	case "respond", "update-policy", "rotate-attestor-key", "revoke-attestor", "withdraw-revenue", "recover-surplus", "abandon-payout":
		if r.Sender != owner {
			return nil, tokenRefusal(1900, "operation is owner-only")
		}
	}
	id := strconv.FormatUint(r.ID, 10)
	now := uint64(s.ReadAt.GenUtime)
	funding := s.FundingPrices[5]
	switch r.Operation {
	case "respond":
		q := s.Request
		if q == nil {
			return nil, tokenRefusal(1913, "request is not pending")
		}
		if now >= q.ResponseDeadline {
			return nil, tokenRefusal(1912, "response window closed")
		}
		if q.HasAttestor {
			if len(r.Signature) != mldsa44.SignatureSize || s.GlobalID == nil || s.VerifyResponse == nil {
				return nil, tokenRefusal(1911, "response needs a verified attestor signature")
			}
			kid, e := mldsa44.KeyID(s.RequestAttestorKey)
			if e != nil || kid != q.AttestorKeyID {
				return nil, tokenRefusal(1911, "request attestor key does not match")
			}
			snap := nativecore.ServiceActorRequestSnapshotV1{RequestID: r.ID, Caller: q.Caller, RequestHash: q.RequestHash, ResponseDeadline: q.ResponseDeadline, RefundClaimDeadline: q.RefundClaimDeadline, TermsHash: q.TermsHash, Terms: nativecore.ServiceActorTermsV1{PricePerCall: q.Price}}
			domain, e := nativecore.ServiceActorResponseDomainHash(*s.GlobalID, s.Actor, snap, r.ResponseHash)
			if e != nil {
				return nil, e
			}
			if e = s.VerifyResponse(s.RequestAttestorKey, r.Signature, domain); e != nil {
				return nil, tokenRefusal(1911, "attestor signature verification failed")
			}
		} else if len(r.Signature) != 0 {
			return nil, errors.New("an unattested request carries no signature")
		}
		body, err = nativecore.BuildServiceActorTokenRespondBody(r.QueryID, r.ID, r.ResponseHash, r.Signature)
		details["request_id"] = id
		details["response_hash"] = hex.EncodeToString(r.ResponseHash[:])
	case "expire":
		q := s.Request
		if q == nil {
			return nil, tokenRefusal(1913, "request is not pending")
		}
		if now >= q.RefundClaimDeadline {
			return nil, tokenRefusal(1915, "refund window closed")
		}
		if now < q.ResponseDeadline {
			warnings = append(warnings, "request is not yet expirable (1914)")
		}
		body, err = nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenExpireOpcode, r.QueryID, r.ID)
		details["request_id"] = id
	case "claim-refund":
		if _, err = tokenRaw(r.Sender, true); err != nil {
			return nil, tokenRefusal(1934, "claimer must be canonical on workchain 0")
		}
		q := s.Refund
		if q == nil {
			return nil, tokenRefusal(1917, "refund not found")
		}
		if q.Caller.Text() != r.Sender {
			return nil, tokenRefusal(1918, "refund belongs to another caller")
		}
		if now >= q.RefundClaimDeadline {
			return nil, tokenRefusal(1916, "refund claim expired")
		}
		if err = tokenClaimDestination(r.Destination, s.Actor); err != nil {
			return nil, err
		}
		if err = tokenNextPayout(s, 1); err != nil {
			return nil, err
		}
		body, err = nativecore.BuildServiceActorTokenClaimBody(nativecore.ServiceActorTokenClaimRefundOpcode, r.QueryID, r.ID, r.Destination)
		value, err = tokenFunded(funding, r.Value)
		details["request_id"] = id
		details["destination"] = r.Destination
		details["token_amount"] = q.Price.String()
		details["payout_funding"] = funding.String()
	case "sweep-expired-request":
		var amount *big.Int
		var caller string
		var deadline uint64
		if q := s.Request; q != nil {
			amount, caller, deadline = q.Price, q.Caller.Text(), q.RefundClaimDeadline
		} else if q := s.Refund; q != nil {
			amount, caller, deadline = q.Price, q.Caller.Text(), q.RefundClaimDeadline
		} else {
			return nil, tokenRefusal(1920, "request is not live")
		}
		if now < deadline {
			warnings = append(warnings, "request is not yet sweepable (1919)")
		}
		if err = tokenNextPayout(s, 1); err != nil {
			return nil, err
		}
		body, err = nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenSweepOpcode, r.QueryID, r.ID)
		value, err = tokenFunded(funding, r.Value)
		details["request_id"] = id
		details["recipient"] = caller
		details["token_amount"] = amount.String()
		details["payout_funding"] = funding.String()
	case "claim-returned", "sweep-returned":
		q := s.Returned
		if q == nil {
			return nil, tokenRefusal(1931, "returned entry not found")
		}
		if q.Paying != 0 {
			return nil, tokenRefusal(1930, "returned entry is paying")
		}
		if err = tokenNextPayout(s, 1); err != nil {
			return nil, err
		}
		details["id"] = id
		details["token_amount"] = q.Amount.String()
		details["payout_funding"] = funding.String()
		if r.Operation == "claim-returned" {
			if _, e := tokenRaw(r.Sender, true); e != nil {
				return nil, tokenRefusal(1934, "claimer must be canonical on workchain 0")
			}
			if q.Caller.Text() != r.Sender {
				return nil, tokenRefusal(1918, "returned entry belongs to another caller")
			}
			if err = tokenClaimDestination(r.Destination, s.Actor); err != nil {
				return nil, err
			}
			body, err = nativecore.BuildServiceActorTokenClaimBody(nativecore.ServiceActorTokenClaimReturnedOpcode, r.QueryID, r.ID, r.Destination)
			details["destination"] = r.Destination
		} else {
			if now < q.ReturnDeadline {
				warnings = append(warnings, "returned entry is not yet sweepable (1919)")
			}
			body, err = nativecore.BuildServiceActorTokenIDBody(nativecore.ServiceActorTokenSweepReturnedOpcode, r.QueryID, r.ID)
			details["recipient"] = q.Caller.Text()
			details["return_deadline"] = strconv.FormatUint(q.ReturnDeadline, 10)
		}
		value, err = tokenFunded(funding, r.Value)
	case "revoke-attestor":
		body, err = nativecore.BuildServiceActorTokenRevokeBody(r.QueryID)
	case "rotate-attestor-key":
		if a.AttestorKeyCount >= 4 {
			return nil, tokenRefusal(1944, "attestor key store is full")
		}
		kid, e := mldsa44.KeyID(r.PublicKey)
		if e != nil {
			return nil, e
		}
		body, err = nativecore.BuildServiceActorTokenRotateBody(r.QueryID, r.PublicKey)
		details["attestor_key_id"] = mldsa44.KeyIDText(kid)
	case "update-policy":
		next, active, e := tokenUpdatedPolicy(s, r.PolicyChange)
		if e != nil {
			return nil, e
		}
		body, err = nativecore.BuildServiceActorTokenPolicyBody(r.QueryID, next, active, owner)
		details["price_per_call"] = next.PricePerCall.String()
		details["storage_fee"] = next.StorageFee.String()
		details["cleanup_bounty"] = next.CleanupBounty.String()
		details["response_sla"] = strconv.FormatUint(uint64(next.ResponseSLA), 10)
		details["refund_claim_window"] = strconv.FormatUint(uint64(next.RefundClaimWindow), 10)
		details["active"] = strconv.FormatBool(active)
		details["open_access"] = strconv.FormatBool(next.OpenAccess)
		details["authorized_caller"] = ""
		if next.HasAuthorizedCaller {
			details["authorized_caller"] = next.AuthorizedCaller.Text()
		}
		details["rate_limit_per_day"] = strconv.FormatUint(uint64(next.RateLimitPerDay), 10)
		details["max_token_liability"] = next.MaxTokenLiability.String()
		details["metadata_hash"] = hex.EncodeToString(next.MetadataHash[:])
		details["proof_scheme_hash"] = hex.EncodeToString(next.ProofSchemeHash[:])
	case "withdraw-revenue":
		tokens, tos := tokenZero(r.TokenAmount), tokenZero(r.TOSAmount)
		if !tokenCoins(tokens) || !tokenCoins(tos) || !tos.IsUint64() || tokens.Sign() == 0 && tos.Sign() == 0 {
			return nil, errors.New("withdrawal needs a positive bounded amount")
		}
		free, e := tokenFreeBacking(s, 1922)
		if e != nil {
			return nil, e
		}
		if free.Cmp(a.WithdrawableTOSRevenue) > 0 {
			free = new(big.Int).Set(a.WithdrawableTOSRevenue)
		}
		if tokens.Cmp(l.WithdrawableTokenRevenue) > 0 || tos.Cmp(free) > 0 {
			return nil, tokenRefusal(1922, "withdrawal exceeds revenue")
		}
		minimum := big.NewInt(200_000_000)
		if tokens.Sign() > 0 {
			if a.RevenuePayoutsInFlight >= 4 {
				return nil, tokenRefusal(1930, "revenue payouts are full")
			}
			if _, e := tokenRaw(owner, true); e != nil {
				return nil, tokenRefusal(1934, "token recipient owner must be canonical on workchain 0")
			}
			if e = tokenNextPayout(s, 1); e != nil {
				return nil, e
			}
			minimum = funding
		}
		body, err = nativecore.BuildServiceActorTokenWithdrawBody(r.QueryID, tokens, tos)
		value, err = tokenFunded(minimum, r.Value)
		details["token_amount"] = tokens.String()
		details["tos_amount"] = tos.String()
		details["minimum_value"] = minimum.String()
	case "recover-surplus":
		amount, e := tokenAmount(r.TokenAmount)
		if e != nil || amount.Sign() == 0 {
			return nil, tokenRefusal(1936, "recovery amount must be positive")
		}
		if a.SurplusPayoutsInFlight >= 4 {
			return nil, tokenRefusal(1930, "surplus payouts are full")
		}
		if _, e := tokenRaw(owner, true); e != nil {
			return nil, tokenRefusal(1934, "owner must be canonical on workchain 0")
		}
		if err = tokenBalanceQueryIdle(a.BalanceQuery, now); err != nil {
			return nil, err
		}
		if err = tokenNextPayout(s, 2); err != nil {
			return nil, err
		}
		attributed, e := tokenSum(l.PendingLiability, l.RefundableLiability, l.ReturnedLiability, l.InFlight, l.WithdrawableTokenRevenue)
		if e != nil {
			return nil, e
		}
		if !tokenCoins(s.OwnWalletBalance) {
			return nil, errors.New("own token wallet balance was not read")
		}
		// surplus_at_read is the actor's own computation at the read: the
		// wallet balance less everything attributed, in_flight included. While
		// a payout is in transit S has already debited it, so the true
		// unattributed balance can be larger (section 4.3); the value is then a
		// lower bound, as the actor's own answer will be.
		surplus := new(big.Int).Sub(s.OwnWalletBalance, attributed)
		if surplus.Sign() < 0 {
			surplus.SetInt64(0)
		}
		if l.InFlight.Sign() > 0 || len(s.Data.Payouts) > 0 {
			warnings = append(warnings, "payouts are in flight: surplus_at_read is a lower bound, since a payout in transit is already debited at the actor's wallet and still counted in in_flight")
		}
		if amount.Cmp(surplus) > 0 {
			return nil, tokenRefusal(1936, "recovery exceeds surplus")
		}
		minimum, e := tokenSum(big.NewInt(200_000_000), funding)
		if e != nil {
			return nil, e
		}
		body, err = nativecore.BuildServiceActorTokenRecoverBody(r.QueryID, amount)
		value, err = tokenFunded(minimum, r.Value)
		details["token_amount"] = amount.String()
		details["surplus_at_read"] = surplus.String()
		details["minimum_value"] = minimum.String()
	case "abandon-payout", "recheck-payout":
		q := s.Payout
		if q == nil {
			return nil, tokenRefusal(1940, "payout not found")
		}
		ownerPayout := q.Kind == 3 || q.Kind == 6
		if (r.Operation == "abandon-payout") != ownerPayout {
			return nil, tokenRefusal(1941, "payout kind does not support this operation")
		}
		if now < uint64(q.CreatedAt)+2_592_000 {
			warnings = append(warnings, "payout age threshold has not yet passed")
		}
		// recheck_payout and abandon_payout both refuse a younger pending query.
		if err = tokenBalanceQueryIdle(a.BalanceQuery, now); err != nil {
			return nil, err
		}
		op := nativecore.ServiceActorTokenAbandonOpcode
		if r.Operation == "recheck-payout" {
			op = nativecore.ServiceActorTokenRecheckOpcode
			if err = tokenNextPayout(s, 1); err != nil {
				return nil, err
			}
			minimum := big.NewInt(200_000_000)
			value, err = tokenFunded(minimum, r.Value)
			if err != nil {
				return nil, err
			}
			details["minimum_value"] = minimum.String()
		}
		body, err = nativecore.BuildServiceActorTokenIDBody(op, r.QueryID, r.ID)
		details["id"] = id
		details["kind"] = strconv.FormatUint(uint64(q.Kind), 10)
		details["created_at"] = strconv.FormatUint(uint64(q.CreatedAt), 10)
	case "top-up-actor", "top-up-wallet":
		if r.Value == nil || r.Value.Sign() <= 0 {
			return nil, errors.New("top-up needs a positive amount")
		}
		details = map[string]string{"actor_balance": s.Balance.String()}
		if r.Operation == "top-up-wallet" {
			if !s.OwnWalletDeployed {
				return nil, errors.New("own token wallet is not deployed")
			}
			destination, err = nativecore.DeriveServiceActorTokenWallet(s.Actor, s.Data.Route)
			if err != nil {
				return nil, err
			}
			if destination != s.OwnWallet {
				return nil, errors.New("own wallet differs from the route-derived address")
			}
			if _, err = tokenRaw(destination, true); err != nil {
				return nil, err
			}
		}
		body = cell.BeginCell().EndCell()
	default:
		return nil, errors.New("unknown token actor operation")
	}
	if err != nil {
		return nil, err
	}
	return newTokenPrepared(s, r, destination, value, body, details, warnings)
}

func tokenNextPayout(s TokenBuildSnapshot, used uint64) error {
	if s.Data.NextPayoutID >= math.MaxUint64-used {
		return tokenRefusal(1909, "no payout id remains")
	}
	return nil
}
func tokenClaimDestination(destination, actor string) error {
	if _, err := tokenRaw(destination, true); err != nil || destination == actor {
		return tokenRefusal(1934, "destination must be canonical on workchain 0 and different from actor")
	}
	return nil
}
func newTokenPrepared(s TokenBuildSnapshot, r TokenBuildRequest, destination string, value *big.Int, body *cell.Cell, details map[string]string, warnings []string) (*TokenPreparedMessage, error) {
	if body == nil || value == nil || value.Sign() <= 0 || !value.IsUint64() {
		return nil, errors.New("invalid prepared token message")
	}
	return &TokenPreparedMessage{Version: TokenPreparedMessageVersion, Operation: r.Operation, Rail: "tos.service.service-actor-token.v1", CodeProfile: s.CodeProfile, Actor: s.Actor, ReadAt: s.ReadAt, Sender: r.Sender, Destination: destination, ValueNanotos: value.String(), Bounce: true, BodyBOC: base64.StdEncoding.EncodeToString(body.ToBOCWithFlags(false)), BodyHash: hex.EncodeToString(body.Hash()), Details: details, Warnings: warnings}, nil
}

func prepareTokenCall(s TokenBuildSnapshot, r TokenBuildRequest) (*TokenPreparedMessage, error) {
	if r.RequestHash == ([32]byte{}) {
		return nil, errors.New("a token buyer request hash must be nonzero")
	}
	d := s.Data
	p := d.Policy
	a := d.Accounting
	l := a.Ledger
	if !d.Active {
		return nil, tokenRefusal(1901, "actor is inactive")
	}
	if p.HasAttestor && !s.CurrentAttestorKeyStored && a.AttestorKeyCount >= 4 {
		return nil, tokenRefusal(1944, "attestor key store is full")
	}
	master, ok := d.Route.Master.RawStandard()
	if !ok || d.Route.Master.Workchain != 0 || d.Route.WalletCode == nil {
		return nil, tokenRefusal(1932, "invalid asset route")
	}
	switch d.Route.BridgeConfigParam {
	case 79, 81, 82, 83:
	default:
		return nil, tokenRefusal(1932, "invalid token bridge parameter")
	}
	pin, asset := s.AssetPin, s.Asset
	walletHash := d.Route.WalletCode.Hash()
	if pin == nil || asset == nil || pin.Master != master || pin.WalletCodeHash != d.Route.WalletCodeHash || !bytes.Equal(walletHash, d.Route.WalletCodeHash[:]) || asset.Status != 1 || asset.WalletCodeHash != pin.WalletCodeHash || asset.Decimals != pin.Decimals || !tokenCoins(asset.MaxLiabilityPerActor) || asset.MaxLiabilityPerActor.Sign() == 0 {
		return nil, tokenRefusal(1933, "asset master, wallet code, decimals or status differs from the client pin")
	}
	if _, err := tokenRaw(r.Sender, true); err != nil {
		return nil, tokenRefusal(1934, "sender must be canonical on workchain 0")
	}
	if !p.OpenAccess && (!p.HasAuthorizedCaller || p.AuthorizedCaller.Text() != r.Sender) {
		return nil, tokenRefusal(1923, "sender is not the authorized caller")
	}
	if !s.AcceptingTokens {
		return nil, tokenRefusal(1935, "actor is not accepting tokens")
	}
	minimum, err := tokenSum(p.StorageFee, s.FundingPrices[0])
	if err != nil {
		return nil, err
	}
	forward := r.ForwardTOS
	if forward == nil {
		forward, err = tokenSum(minimum, minimum)
		if err != nil {
			return nil, err
		}
	}
	if !tokenCoins(forward) || forward.Cmp(minimum) < 0 {
		return nil, tokenRefusal(1929, "forward value does not cover funding budget")
	}
	body, err := nativecore.BuildServiceActorTokenFundingTransfer(r.QueryID, p.PricePerCall, s.Actor, r.Sender, forward, r.RequestHash, r.ExpectedTermsHash)
	if err != nil {
		return nil, err
	}
	if _, err = tokenSum(l.PendingLiability, p.PricePerCall); err != nil {
		return nil, tokenRefusal(1927, "pending token liability overflows")
	}
	if _, err = tokenSum(a.LockedStorageFees, p.StorageFee); err != nil {
		return nil, tokenRefusal(1927, "locked storage fees overflow")
	}
	if _, err = tokenSum(s.Balance, p.StorageFee); err != nil {
		return nil, tokenRefusal(1927, "actor balance overflows")
	}
	if d.LiveCount >= 1500 {
		return nil, tokenRefusal(1907, "live request capacity is full")
	}
	if s.CallerLive >= 1000 {
		return nil, tokenRefusal(1908, "caller live request capacity is full")
	}
	if d.NextRequestID == math.MaxUint64 {
		return nil, tokenRefusal(1909, "request ids are exhausted")
	}
	var warnings []string
	today := s.ReadAt.GenUtime / 86400
	if p.RateLimitPerDay > 0 && a.CallDay == today && a.CallsToday >= p.RateLimitPerDay {
		dayEnd := (uint64(today) + 1) * 86400
		if dayEnd-uint64(s.ReadAt.GenUtime) > 600 {
			return nil, tokenRefusal(1924, "daily rate limit is reached")
		}
		warnings = append(warnings, "daily rate limit is reached until the next chain day (1924)")
	}
	if a.ReturnedCount >= 1500 || s.CallerReturned >= 16 {
		return nil, tokenRefusal(1935, "returned entry capacity is full")
	}
	exposure, err := tokenSum(l.PendingLiability, l.RefundableLiability, l.ReturnedLiability, l.InFlight, p.PricePerCall)
	if err != nil {
		return nil, err
	}
	if exposure.Cmp(p.MaxTokenLiability) > 0 || exposure.Cmp(asset.MaxLiabilityPerActor) > 0 {
		return nil, tokenRefusal(1937, "token liability exceeds its cap")
	}
	if r.ExpectedTermsHash != s.TermsHash {
		return nil, tokenRefusal(1926, "quoted terms differ from finalized terms")
	}
	if _, err = tokenFreeBacking(s, 1928); err != nil {
		return nil, err
	}
	if !tokenCoins(s.SenderTokenBalance) || s.SenderTokenBalance.Cmp(p.PricePerCall) < 0 {
		return nil, errors.New("sender token wallet balance is missing or below the price")
	}
	if s.WalletTerms == nil || s.ForwardPrices == nil {
		return nil, errors.New("bridge wallet terms and forward prices must be present")
	}
	need, err := TokenWalletNeed(forward, *s.WalletTerms, *s.ForwardPrices, body)
	if err != nil {
		return nil, err
	}
	value := r.WalletValue
	if value == nil {
		value, err = tokenSum(need, big.NewInt(50_000_000))
		if err != nil {
			return nil, err
		}
	}
	if !tokenCoins(value) || !value.IsUint64() || value.Cmp(need) <= 0 {
		return nil, errors.New("wallet message value must exceed its need and fit 64 bits")
	}
	destination, err := nativecore.DeriveServiceActorTokenWallet(r.Sender, d.Route)
	if err != nil {
		return nil, err
	}
	details := map[string]string{"token_amount": p.PricePerCall.String(), "forward_tos_amount": forward.String(), "minimum_forward": minimum.String(), "storage_fee": p.StorageFee.String(), "min_funding_value": s.FundingPrices[0].String(), "accepting_tokens": strconv.FormatBool(s.AcceptingTokens), "query_id": strconv.FormatUint(r.QueryID, 10), "request_hash": hex.EncodeToString(r.RequestHash[:]), "expected_terms_hash": hex.EncodeToString(r.ExpectedTermsHash[:]), "asset_master": master, "asset_decimals": strconv.FormatUint(uint64(asset.Decimals), 10), "token_wallet": destination, "wallet_need": need.String()}
	return newTokenPrepared(s, r, destination, value, body, details, warnings)
}

func tokenUpdatedPolicy(s TokenBuildSnapshot, c *TokenPolicyChange) (nativecore.ServiceActorTokenPolicyV1, bool, error) {
	p := s.Data.Policy
	active := s.Data.Active
	if c == nil {
		c = &TokenPolicyChange{}
	}
	if s.Data.Policy.PolicyVersion == math.MaxUint32 {
		return p, active, errors.New("policy version is exhausted")
	}
	for _, pair := range []struct {
		change *big.Int
		target **big.Int
	}{{c.PricePerCall, &p.PricePerCall}, {c.StorageFee, &p.StorageFee}, {c.CleanupBounty, &p.CleanupBounty}, {c.MaxTokenLiability, &p.MaxTokenLiability}} {
		if pair.change != nil {
			v, err := tokenAmount(pair.change)
			if err != nil {
				return p, active, err
			}
			*pair.target = v
		}
	}
	if c.ResponseSLA != nil {
		p.ResponseSLA = *c.ResponseSLA
	}
	if c.RefundClaimWindow != nil {
		p.RefundClaimWindow = *c.RefundClaimWindow
	}
	if c.RateLimitPerDay != nil {
		p.RateLimitPerDay = *c.RateLimitPerDay
	}
	if c.Active != nil {
		active = *c.Active
	}
	if c.OpenAccess != nil {
		p.OpenAccess = *c.OpenAccess
	}
	if c.MetadataHash != nil {
		p.MetadataHash = *c.MetadataHash
	}
	if c.ProofSchemeHash != nil {
		p.ProofSchemeHash = *c.ProofSchemeHash
	}
	if c.ClearAuthorizedCaller && c.AuthorizedCaller != nil {
		return p, active, errors.New("caller cannot be set and cleared together")
	}
	if c.ClearAuthorizedCaller {
		p.HasAuthorizedCaller = false
	}
	if c.AuthorizedCaller != nil {
		caller, err := tokenRaw(*c.AuthorizedCaller, true)
		if err != nil {
			return p, active, err
		}
		p.HasAuthorizedCaller = true
		p.AuthorizedCaller = caller
	}
	minimumWindow := uint32(3600)
	if s.CodeProfile == "test" {
		minimumWindow = 600
	}
	if p.ResponseSLA < minimumWindow || p.ResponseSLA > 2_592_000 {
		return p, active, tokenRefusal(1903, "invalid response SLA")
	}
	if p.RefundClaimWindow < minimumWindow || p.RefundClaimWindow > 2_592_000 {
		return p, active, tokenRefusal(1904, "invalid refund window")
	}
	if p.CleanupBounty.Cmp(big.NewInt(100_000_000)) < 0 || p.CleanupBounty.Cmp(big.NewInt(1_000_000_000)) > 0 {
		return p, active, tokenRefusal(1905, "invalid cleanup bounty")
	}
	least, err := tokenSum(big.NewInt(100_000_000), p.CleanupBounty)
	if err != nil {
		return p, active, err
	}
	if p.StorageFee.Cmp(least) < 0 {
		return p, active, tokenRefusal(1906, "storage fee below its minimum")
	}
	if p.PricePerCall.Sign() <= 0 {
		return p, active, tokenRefusal(1902, "price must be positive")
	}
	if p.MaxTokenLiability.Sign() <= 0 {
		return p, active, tokenRefusal(1937, "liability cap must be positive")
	}
	return p, active, nil
}

// Reject unused action fields rather than silently discarding a caller's limit or destination.
func validateTokenBuildRequest(r TokenBuildRequest) error {
	allowed := map[string]bool{"value": r.Operation != "call"}
	switch r.Operation {
	case "call":
		for _, key := range []string{"request_hash", "terms_hash", "forward", "wallet_value"} {
			allowed[key] = true
		}
	case "respond":
		allowed["id"] = true
		allowed["response_hash"] = true
		allowed["signature"] = true
	case "expire", "sweep-expired-request", "sweep-returned", "abandon-payout", "recheck-payout":
		allowed["id"] = true
	case "claim-refund", "claim-returned":
		allowed["id"] = true
		allowed["destination"] = true
	case "update-policy":
		allowed["policy"] = true
	case "rotate-attestor-key":
		allowed["public_key"] = true
	case "withdraw-revenue":
		allowed["tokens"] = true
		allowed["tos"] = true
	case "recover-surplus":
		allowed["tokens"] = true
	case "revoke-attestor", "top-up-actor", "top-up-wallet":
	default:
		return errors.New("unknown token actor operation")
	}
	fields := []struct {
		name    string
		present bool
	}{{"value", r.Value != nil}, {"wallet_value", r.WalletValue != nil}, {"forward", r.ForwardTOS != nil}, {"tokens", r.TokenAmount != nil}, {"tos", r.TOSAmount != nil}, {"destination", r.Destination != ""}, {"id", r.ID != 0}, {"request_hash", r.RequestHash != ([32]byte{})}, {"terms_hash", r.ExpectedTermsHash != ([32]byte{})}, {"response_hash", r.ResponseHash != ([32]byte{})}, {"policy", r.PolicyChange != nil}, {"public_key", len(r.PublicKey) != 0}, {"signature", len(r.Signature) != 0}}
	for _, field := range fields {
		if field.present && !allowed[field.name] {
			return fmt.Errorf("%s does not accept %s", r.Operation, field.name)
		}
	}
	return nil
}
