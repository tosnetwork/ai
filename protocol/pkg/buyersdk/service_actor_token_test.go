package buyersdk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const tokenCLIFixtureSHA = "bb388496634a6901d03c8db01ae92de70c831bd8"
const tokenCLIFixtureDir = "tosctl/src/node-control/commands/src/commands/nodectl/fixtures/service_actor_token/"

type tokenFixture map[string]json.RawMessage

func fixtureObject(t *testing.T, raw json.RawMessage) tokenFixture {
	t.Helper()
	var m tokenFixture
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func fixtureText(t *testing.T, m tokenFixture, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return s
}
func fixtureUint(t *testing.T, m tokenFixture, key string) uint64 {
	t.Helper()
	if len(m[key]) == 0 {
		return 0
	}
	var n uint64
	if err := json.Unmarshal(m[key], &n); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return n
}
func fixtureBool(t *testing.T, m tokenFixture, key string) bool {
	t.Helper()
	if len(m[key]) == 0 {
		return false
	}
	var n bool
	if err := json.Unmarshal(m[key], &n); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return n
}
func fixtureCoin(t *testing.T, m tokenFixture, key string) *big.Int {
	t.Helper()
	if len(m[key]) == 0 {
		return nil
	}
	n, ok := new(big.Int).SetString(fixtureText(t, m, key), 10)
	if !ok {
		t.Fatalf("%s: invalid coin", key)
	}
	return n
}
func fixtureAddress(t *testing.T, text string) nativecore.MsgAddressV1 {
	t.Helper()
	a, err := nativecore.StandardAddress(text)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func fixtureHash(t *testing.T, text string) (h [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		t.Fatalf("invalid fixture hash %q", text)
	}
	copy(h[:], b)
	return h
}
func fixtureOptionalHash(t *testing.T, m tokenFixture, key string) *[32]byte {
	t.Helper()
	if len(m[key]) == 0 || string(m[key]) == "null" {
		return nil
	}
	v := fixtureHash(t, fixtureText(t, m, key))
	return &v
}
func fixtureRead(t *testing.T, repo, path string) []byte {
	t.Helper()
	b, err := exec.Command("git", "-C", repo, "show", tokenCLIFixtureSHA+":"+path).CombinedOutput()
	if err != nil {
		t.Fatalf("pinned fixture unavailable: %v: %s", err, b)
	}
	return b
}
func tokenFixtureRepo(t *testing.T) string {
	t.Helper()
	repo := os.Getenv("TOS_SERVICE_TOKEN_CLI_REPO")
	if repo == "" {
		repo = filepath.Clean(filepath.Join("..", "..", "..", "..", "tos"))
	}
	return repo
}

func tokenFixtureInputs(t *testing.T, raw []byte) (TokenBuildSnapshot, TokenBuildRequest) {
	t.Helper()
	var f tokenFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	state := fixtureObject(t, f["state"])
	reads := fixtureObject(t, f["reads"])
	data := fixtureObject(t, state["get_service_data"])
	ledger := fixtureObject(t, state["get_native_ledger"])
	route := fixtureObject(t, state["get_asset_route"])
	anchor := fixtureObject(t, state["read_at"])
	args := fixtureObject(t, f["arguments"])
	d := &nativecore.ServiceActorTokenDataV1{Owner: fixtureAddress(t, fixtureText(t, data, "owner")), Active: fixtureBool(t, data, "active"), NextRequestID: fixtureUint(t, data, "next_request_id"), PendingCount: uint32(fixtureUint(t, data, "pending_count")), LiveCount: uint32(fixtureUint(t, data, "live_count")), NextPayoutID: fixtureUint(t, data, "next_payout_id")}
	p := &d.Policy
	p.PolicyVersion = uint32(fixtureUint(t, data, "policy_version"))
	p.PricePerCall = fixtureCoin(t, data, "price_per_call")
	p.StorageFee = fixtureCoin(t, data, "storage_fee")
	p.CleanupBounty = fixtureCoin(t, data, "cleanup_bounty")
	p.ResponseSLA = uint32(fixtureUint(t, data, "response_sla"))
	p.RefundClaimWindow = uint32(fixtureUint(t, data, "refund_claim_window"))
	p.OpenAccess = fixtureBool(t, data, "open_access")
	p.RateLimitPerDay = uint32(fixtureUint(t, data, "rate_limit_per_day"))
	p.MaxTokenLiability = fixtureCoin(t, data, "max_token_liability")
	p.MetadataHash = fixtureHash(t, fixtureText(t, data, "metadata_hash"))
	p.ProofSchemeHash = fixtureHash(t, fixtureText(t, data, "proof_scheme_hash"))
	if string(data["authorized_caller"]) != "null" {
		p.HasAuthorizedCaller = true
		p.AuthorizedCaller = fixtureAddress(t, fixtureText(t, data, "authorized_caller"))
	}
	a := &d.Accounting
	a.WithdrawableTOSRevenue = fixtureCoin(t, ledger, "withdrawable_revenue")
	a.LockedStorageFees = fixtureCoin(t, ledger, "locked_storage_fees")
	a.LockedOutcomeFees = fixtureCoin(t, ledger, "locked_outcome_fees")
	a.CallDay = uint32(fixtureUint(t, ledger, "call_day"))
	a.CallsToday = uint32(fixtureUint(t, ledger, "calls_today"))
	a.RevenuePayoutsInFlight = uint8(fixtureUint(t, ledger, "revenue_payouts_in_flight"))
	a.ReturnedCount = uint32(fixtureUint(t, ledger, "returned_count"))
	a.ReturnsInFlight = uint16(fixtureUint(t, ledger, "returns_in_flight"))
	a.SurplusPayoutsInFlight = uint8(fixtureUint(t, ledger, "surplus_payouts_in_flight"))
	a.AttestorKeyCount = uint8(fixtureUint(t, state, "get_attestor_key_count"))
	var tokenValues []string
	if err := json.Unmarshal(state["get_token_ledger"], &tokenValues); err != nil || len(tokenValues) != 5 {
		t.Fatal("invalid token ledger fixture")
	}
	ls := []**big.Int{&a.Ledger.PendingLiability, &a.Ledger.RefundableLiability, &a.Ledger.ReturnedLiability, &a.Ledger.InFlight, &a.Ledger.WithdrawableTokenRevenue}
	for n, text := range tokenValues {
		v, ok := new(big.Int).SetString(text, 10)
		if !ok {
			t.Fatal("invalid token ledger amount")
		}
		*ls[n] = v
	}
	codeBytes, err := base64.StdEncoding.DecodeString(fixtureText(t, route, "wallet_code_boc"))
	if err != nil {
		t.Fatal(err)
	}
	code, err := cell.FromBOC(codeBytes)
	if err != nil {
		t.Fatal(err)
	}
	var codeHash [32]byte
	copy(codeHash[:], code.Hash())
	master := fixtureText(t, route, "master")
	d.Route = nativecore.ServiceActorTokenAssetRouteV1{Master: fixtureAddress(t, master), WalletCode: code, WalletCodeHash: codeHash, BridgeConfigParam: uint32(fixtureUint(t, route, "bridge_config_param"))}
	s := TokenBuildSnapshot{Actor: fixtureText(t, state, "actor"), CodeProfile: fixtureText(t, state, "code_profile"), ReadAt: TokenReadAt{Seqno: uint32(fixtureUint(t, anchor, "seqno")), RootHash: fixtureText(t, anchor, "root_hash"), GenUtime: uint32(fixtureUint(t, anchor, "gen_utime"))}, Balance: fixtureCoin(t, state, "balance"), Data: d, TermsHash: fixtureHash(t, fixtureText(t, state, "get_terms_hash")), AcceptingTokens: fixtureBool(t, state, "get_accepting_tokens"), CurrentAttestorKeyStored: fixtureBool(t, state, "current_attestor_key_stored"), OwnWallet: fixtureText(t, state, "get_own_wallet"), OwnWalletDeployed: fixtureBool(t, reads, "own_wallet_deployed"), SenderTokenBalance: fixtureCoin(t, reads, "sender_token_wallet_balance"), OwnWalletBalance: fixtureCoin(t, reads, "own_wallet_balance"), CallerLive: uint32(fixtureUint(t, reads, "get_caller_live_count")), CallerReturned: uint32(fixtureUint(t, reads, "get_caller_returned_count"))}
	var prices []string
	if err := json.Unmarshal(state["get_funding_prices"], &prices); err != nil || len(prices) != 6 {
		t.Fatal("invalid funding price fixture")
	}
	for n, text := range prices {
		v, ok := new(big.Int).SetString(text, 10)
		if !ok {
			t.Fatal("invalid funding price")
		}
		s.FundingPrices[n] = v
	}
	if raw := reads["config_param_84_entry"]; len(raw) > 0 {
		v := fixtureObject(t, raw)
		s.Asset = &TokenRecognizedAsset{Status: uint8(fixtureUint(t, v, "status")), Decimals: uint8(fixtureUint(t, v, "decimals")), WalletCodeHash: fixtureHash(t, fixtureText(t, v, "wallet_code_hash")), MaxLiabilityPerActor: fixtureCoin(t, v, "max_liability_per_actor")}
		s.AssetPin = &TokenAssetPin{Master: master, WalletCodeHash: codeHash, Decimals: s.Asset.Decimals}
	}
	if raw := reads["bridge_wallet_terms"]; len(raw) > 0 {
		v := fixtureObject(t, raw)
		s.WalletTerms = &TokenWalletTerms{GasConsumption: fixtureCoin(t, v, "wallet_gas_consumption"), MinimumStorage: fixtureCoin(t, v, "wallet_min_tos_for_storage")}
	}
	if raw := reads["config_param_25"]; len(raw) > 0 {
		v := fixtureObject(t, raw)
		s.ForwardPrices = &TokenForwardPrices{LumpPrice: fixtureUint(t, v, "lump_price"), BitPrice: fixtureUint(t, v, "bit_price"), CellPrice: fixtureUint(t, v, "cell_price"), FirstFraction: uint16(fixtureUint(t, v, "first_frac"))}
	}
	if raw := reads["get_refund"]; len(raw) > 0 && string(raw) != "null" {
		v := fixtureObject(t, raw)
		s.Refund = &nativecore.ServiceActorRefundV1{Caller: fixtureAddress(t, fixtureText(t, v, "caller")), Price: fixtureCoin(t, v, "price"), StorageFee: fixtureCoin(t, v, "storage_fee"), CleanupBounty: fixtureCoin(t, v, "cleanup_bounty"), RefundClaimDeadline: fixtureUint(t, v, "refund_claim_deadline")}
	}
	if raw := reads["get_request"]; len(raw) > 0 && string(raw) != "null" {
		v := fixtureObject(t, raw)
		s.Request = &nativecore.ServiceActorRequestViewV1{Caller: fixtureAddress(t, fixtureText(t, v, "caller")), Price: fixtureCoin(t, v, "price"), StorageFee: fixtureCoin(t, v, "storage_fee"), CleanupBounty: fixtureCoin(t, v, "cleanup_bounty"), ResponseDeadline: fixtureUint(t, v, "response_deadline"), RefundClaimDeadline: fixtureUint(t, v, "refund_claim_deadline"), PolicyVersion: uint32(fixtureUint(t, v, "policy_version")), RequestHash: fixtureHash(t, fixtureText(t, v, "request_hash")), TermsHash: fixtureHash(t, fixtureText(t, v, "terms_hash"))}
	}
	if raw := reads["get_returned"]; len(raw) > 0 && string(raw) != "null" {
		v := fixtureObject(t, raw)
		s.Returned = &nativecore.ServiceActorTokenReturnedV1{Caller: fixtureAddress(t, fixtureText(t, v, "caller")), Amount: fixtureCoin(t, v, "amount"), Paying: fixtureUint(t, v, "paying"), ReturnDeadline: fixtureUint(t, v, "return_deadline")}
	}
	if raw := reads["get_payout"]; len(raw) > 0 && string(raw) != "null" {
		v := fixtureObject(t, raw)
		s.Payout = &nativecore.ServiceActorTokenPayoutV1{Kind: uint8(fixtureUint(t, v, "kind")), RequestID: fixtureUint(t, v, "request_id"), Recipient: fixtureAddress(t, fixtureText(t, v, "recipient")), Requester: fixtureAddress(t, fixtureText(t, v, "requester")), Amount: fixtureCoin(t, v, "amount"), CreatedAt: uint32(fixtureUint(t, v, "created_at")), RecipientWallet: fixtureAddress(t, fixtureText(t, v, "recipient_wallet")), OwnWallet: fixtureAddress(t, fixtureText(t, v, "own_wallet")), OutcomeFeeLock: fixtureCoin(t, v, "outcome_fee_lock")}
	}
	r := TokenBuildRequest{Operation: fixtureText(t, f, "operation"), Sender: fixtureText(t, f, "sender"), QueryID: fixtureUint(t, f, "query_id"), Value: fixtureCoin(t, args, "amount_nanotos"), TokenAmount: fixtureCoin(t, args, "token_amount"), TOSAmount: fixtureCoin(t, args, "tos_amount_nanotos"), ForwardTOS: fixtureCoin(t, args, "forward_tos_nanotos"), WalletValue: fixtureCoin(t, args, "wallet_value_nanotos")}
	if len(args["request_id"]) > 0 {
		r.ID = fixtureUint(t, args, "request_id")
	}
	if len(args["id"]) > 0 {
		r.ID = fixtureUint(t, args, "id")
	}
	if len(args["destination"]) > 0 {
		r.Destination = fixtureText(t, args, "destination")
	}
	if h := fixtureOptionalHash(t, args, "request_hash"); h != nil {
		r.RequestHash = *h
	}
	if h := fixtureOptionalHash(t, args, "expected_terms_hash"); h != nil {
		r.ExpectedTermsHash = *h
	}
	if h := fixtureOptionalHash(t, args, "response_hash"); h != nil {
		r.ResponseHash = *h
	}
	if len(args["new_attestor_pubkey"]) > 0 {
		r.PublicKey, err = hex.DecodeString(fixtureText(t, args, "new_attestor_pubkey"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if r.Operation == "update-policy" {
		c := &TokenPolicyChange{PricePerCall: fixtureCoin(t, args, "price_per_call_units"), StorageFee: fixtureCoin(t, args, "storage_fee_nanotos"), CleanupBounty: fixtureCoin(t, args, "cleanup_bounty_nanotos"), MaxTokenLiability: fixtureCoin(t, args, "max_token_liability"), MetadataHash: fixtureOptionalHash(t, args, "metadata_hash"), ProofSchemeHash: fixtureOptionalHash(t, args, "proof_scheme_hash"), ClearAuthorizedCaller: fixtureBool(t, args, "clear_authorized_caller")}
		if len(args["response_sla"]) > 0 {
			n := uint32(fixtureUint(t, args, "response_sla"))
			c.ResponseSLA = &n
		}
		if len(args["refund_claim_window"]) > 0 {
			n := uint32(fixtureUint(t, args, "refund_claim_window"))
			c.RefundClaimWindow = &n
		}
		if len(args["rate_limit_per_day"]) > 0 {
			n := uint32(fixtureUint(t, args, "rate_limit_per_day"))
			c.RateLimitPerDay = &n
		}
		if len(args["open_access"]) > 0 {
			b := fixtureBool(t, args, "open_access")
			c.OpenAccess = &b
		}
		if len(args["active"]) > 0 {
			b := fixtureBool(t, args, "active")
			c.Active = &b
		}
		if len(args["authorized_caller"]) > 0 {
			v := fixtureText(t, args, "authorized_caller")
			c.AuthorizedCaller = &v
		}
		r.PolicyChange = c
	}
	return s, r
}

func TestTokenPreparedMessagesMatchPinnedCLI(t *testing.T) {
	repo := tokenFixtureRepo(t)
	listing, err := exec.Command("git", "-C", repo, "ls-tree", "-r", "--name-only", tokenCLIFixtureSHA, tokenCLIFixtureDir).CombinedOutput()
	if err != nil {
		t.Fatalf("set TOS_SERVICE_TOKEN_CLI_REPO to the pinned source checkout: %v: %s", err, listing)
	}
	count := 0
	for _, path := range strings.Split(strings.TrimSpace(string(listing)), "\n") {
		if !strings.HasSuffix(path, ".inputs.json") {
			continue
		}
		count++
		name := strings.TrimSuffix(filepath.Base(path), ".inputs.json")
		t.Run(name, func(t *testing.T) {
			s, r := tokenFixtureInputs(t, fixtureRead(t, repo, path))
			got, err := PrepareTokenMessage(s, r)
			if err != nil {
				t.Fatal(err)
			}
			verifyTokenPreparedBody(t, s, r, got)
			pretty, err := got.Pretty()
			if err != nil {
				t.Fatal(err)
			}
			want := fixtureRead(t, repo, strings.TrimSuffix(path, ".inputs.json")+".out.json")
			if !bytes.Equal(pretty, want) {
				t.Fatalf("build-only bytes differ\nGOT:\n%s\nWANT:\n%s", pretty, want)
			}
		})
	}
	if count != 17 {
		t.Fatalf("ran %d pinned CLI fixtures, want 17", count)
	}
}

func loadTokenFixture(t *testing.T, name string) (TokenBuildSnapshot, TokenBuildRequest) {
	t.Helper()
	return tokenFixtureInputs(t, fixtureRead(t, tokenFixtureRepo(t), tokenCLIFixtureDir+name+".inputs.json"))
}

func TestTokenCallRejectsRecognitionPinMismatch(t *testing.T) {
	for _, name := range []string{"master", "wallet-code", "decimals", "status", "missing-pin"} {
		t.Run(name, func(t *testing.T) {
			s, r := loadTokenFixture(t, "call")
			if _, err := PrepareTokenMessage(s, r); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			switch name {
			case "master":
				s.AssetPin.Master = r.Sender
			case "wallet-code":
				s.Asset.WalletCodeHash[0] ^= 1
			case "decimals":
				s.Asset.Decimals++
			case "status":
				s.Asset.Status = 2
			case "missing-pin":
				s.AssetPin = nil
			}
			if _, err := PrepareTokenMessage(s, r); err == nil || !strings.Contains(err.Error(), "1933") {
				t.Fatalf("pin mismatch was not refused: %v", err)
			}
		})
	}
}
func TestTokenBuilderRefusesVisibleOperationFailures(t *testing.T) {
	cases := []struct {
		name, fixture string
		change        func(*TokenBuildSnapshot, *TokenBuildRequest)
		code          string
	}{
		{"underfunded claim", "claim-refund", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { r.Value = big.NewInt(1) }, "1929"},
		{"wrong owner", "respond", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { r.Sender = s.Actor }, "1900"},
		{"self destination", "claim-returned", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { r.Destination = s.Actor }, "1934"},
		{"paying returned entry", "claim-returned", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { s.Returned.Paying = 12 }, "1930"},
		{"expired refund", "claim-refund", func(s *TokenBuildSnapshot, r *TokenBuildRequest) {
			s.Refund.RefundClaimDeadline = uint64(s.ReadAt.GenUtime)
		}, "1916"},
		{"closed response", "respond", func(s *TokenBuildSnapshot, r *TokenBuildRequest) {
			s.Request.ResponseDeadline = uint64(s.ReadAt.GenUtime)
		}, "1912"},
		{"changed terms", "call", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { r.ExpectedTermsHash[0] ^= 1 }, "1926"},
		{"not accepting", "call", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { s.AcceptingTokens = false }, "1935"},
		{"liability full", "call", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { s.Data.Policy.MaxTokenLiability = big.NewInt(1) }, "1937"},
		{"payout id exhausted", "claim-returned", func(s *TokenBuildSnapshot, r *TokenBuildRequest) { s.Data.NextPayoutID = ^uint64(0) - 1 }, "1909"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, r := loadTokenFixture(t, tc.fixture)
			if _, err := PrepareTokenMessage(s, r); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			tc.change(&s, &r)
			if _, err := PrepareTokenMessage(s, r); err == nil || !strings.Contains(err.Error(), tc.code) {
				t.Fatalf("want %s refusal, got %v", tc.code, err)
			}
		})
	}
}
func TestTokenPayoutDoesNotConsultRecognition(t *testing.T) {
	s, r := loadTokenFixture(t, "claim-returned")
	s.Asset, s.AssetPin = nil, nil
	p, err := PrepareTokenMessage(s, r)
	if err != nil {
		t.Fatal(err)
	}
	if p.Operation != "claim-returned" {
		t.Fatal("wrong operation")
	}
}
func TestTokenPolicyPlanningLeavesItsSnapshotUnchanged(t *testing.T) {
	s, r := loadTokenFixture(t, "update-policy")
	old := s.Data.Policy.PricePerCall.String()
	p, err := PrepareTokenMessage(s, r)
	if err != nil {
		t.Fatal(err)
	}
	if p.Details["price_per_call"] == old || s.Data.Policy.PricePerCall.String() != old {
		t.Fatal("policy plan mutated or ignored the snapshot")
	}
}
func TestTokenWalletFeeCountsTheTransferBodyAsAReference(t *testing.T) {
	s, r := loadTokenFixture(t, "call")
	p, err := PrepareTokenMessage(s, r)
	if err != nil {
		t.Fatal(err)
	}
	want := fixtureObject(t, fixtureRead(t, tokenFixtureRepo(t), tokenCLIFixtureDir+"call.out.json"))
	details := fixtureObject(t, want["details"])
	if p.Details["wallet_need"] != fixtureText(t, details, "wallet_need") {
		t.Fatal("wallet need does not match the reference implementation")
	}
	b, err := base64.StdEncoding.DecodeString(p.BodyBOC)
	if err != nil || len(b) < 5 || b[4] != 1 {
		t.Fatal("body must use no-index no-CRC serialization")
	}
	need, err := TokenWalletNeed(s.FundingPrices[0], *s.WalletTerms, *s.ForwardPrices, cell.BeginCell().EndCell())
	if err != nil || need.Sign() <= 0 {
		t.Fatal("fee instrument did not produce a positive bound", err)
	}
}

func TestTokenBuilderRefusesUnusedArgumentsAndZeroRequestHash(t *testing.T) {
	cases := []struct {
		name, fixture string
		change        func(*TokenBuildRequest)
	}{
		{"call value", "call", func(r *TokenBuildRequest) { r.Value = big.NewInt(1) }},
		{"claim token amount", "claim-refund", func(r *TokenBuildRequest) { r.TokenAmount = big.NewInt(1) }},
		{"withdraw destination", "withdraw-revenue", func(r *TokenBuildRequest) { r.Destination = r.Sender }},
		{"zero request hash", "call", func(r *TokenBuildRequest) { r.RequestHash = [32]byte{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, r := loadTokenFixture(t, tc.fixture)
			if _, err := PrepareTokenMessage(s, r); err != nil {
				t.Fatal("positive control:", err)
			}
			tc.change(&r)
			if _, err := PrepareTokenMessage(s, r); err == nil {
				t.Fatal("ignored unsupported action data")
			}
		})
	}
}

// The independent pinned documents are also accepted by the production wire decoders.
func verifyTokenPreparedBody(t *testing.T, s TokenBuildSnapshot, r TokenBuildRequest, p *TokenPreparedMessage) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(p.BodyBOC)
	if err != nil {
		t.Fatal(err)
	}
	body, err := cell.FromBOC(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.Operation == "call" {
		decoded, err := nativecore.DecodeServiceActorTokenFundingTransfer(body)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.QueryID != r.QueryID || decoded.Amount.Cmp(s.Data.Policy.PricePerCall) != 0 || decoded.Destination.Text() != s.Actor || decoded.ResponseDestination.Text() != r.Sender || decoded.Payload.RequestHash != r.RequestHash || decoded.Payload.ExpectedTermsHash != r.ExpectedTermsHash {
			t.Fatal("funding wire fields differ")
		}
		return
	}
	if strings.HasPrefix(r.Operation, "top-up-") {
		if body.BitsSize() != 0 || body.RefsNum() != 0 {
			t.Fatal("top-up body is not empty")
		}
		return
	}
	decoded, err := nativecore.DecodeServiceActorTokenInbound(body)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.QueryID != r.QueryID {
		t.Fatal("message query id differs")
	}
	ops := map[string]uint32{"respond": 0x53544302, "expire": 0x53544303, "claim-refund": 0x53544304, "sweep-expired-request": 0x53544305, "update-policy": 0x53544306, "rotate-attestor-key": 0x53544307, "revoke-attestor": 0x53544308, "withdraw-revenue": 0x53544309, "claim-returned": 0x5354430a, "recover-surplus": 0x5354430b, "abandon-payout": 0x5354430c, "sweep-returned": 0x5354430d, "recheck-payout": 0x5354430f}
	if decoded.Opcode != ops[r.Operation] {
		t.Fatal("message opcode differs")
	}
}

func TestTokenWalletTopUpDerivesItsDestination(t *testing.T) {
	s, r := loadTokenFixture(t, "top-up-wallet")
	if _, err := PrepareTokenMessage(s, r); err != nil {
		t.Fatal("positive control:", err)
	}
	s.OwnWallet = r.Sender
	if _, err := PrepareTokenMessage(s, r); err == nil {
		t.Fatal("accepted a wallet outside the stored route")
	}
}
