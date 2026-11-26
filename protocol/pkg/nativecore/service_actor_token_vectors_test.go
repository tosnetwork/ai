package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenVectorJSON(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("../../../spec/test-vectors", name))
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func tokenVectorCell(t *testing.T, b64 string) *cell.Cell {
	t.Helper()
	raw, e := base64.StdEncoding.DecodeString(b64)
	if e != nil {
		t.Fatal(e)
	}
	c, e := cell.FromBOC(raw)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func tokenCorpusHash(t *testing.T, text string) [32]byte {
	t.Helper()
	v, e := hex.DecodeString(strings.TrimPrefix(text, "tvm-cell-sha256:"))
	if e != nil || len(v) != 32 {
		t.Fatalf("invalid vector hash %q", text)
	}
	var h [32]byte
	copy(h[:], v)
	return h
}
func tokenSameCell(t *testing.T, want, got *cell.Cell) {
	t.Helper()
	if !bytes.Equal(want.Hash(), got.Hash()) {
		t.Fatalf("cell hash differs: want %x got %x", want.Hash(), got.Hash())
	}
}
func tokenLogRebuild(t *testing.T, tag string, value *cell.Cell) {
	t.Helper()
	var rebuilt *cell.Cell
	var e error
	switch tag {
	case "sat1":
		p, err := DecodeServiceActorTokenRequestSnapshot(value)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, e = BuildServiceActorTokenRequestSnapshot(p)
	case "saf1":
		p, err := DecodeServiceActorTokenFundingLog(value)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, e = BuildServiceActorTokenFundingLog(p)
	case "sao1":
		p, err := DecodeServiceActorTokenOutcomeLog(value)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, e = BuildServiceActorTokenOutcomeLog(p)
	case "sab1":
		p, err := DecodeServiceActorTokenBalanceLog(value)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, e = BuildServiceActorTokenBalanceLog(p)
	case "terms":
		p, err := DecodeServiceActorTokenTerms(value)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, e = BuildServiceActorTokenTerms(p)
	default:
		t.Fatal("unknown test tag")
	}
	if e != nil {
		t.Fatal(e)
	}
	tokenSameCell(t, value, rebuilt)
}
func TestServiceActorTokenFrozenVectors(t *testing.T) {
	v := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	code := tokenVectorCell(t, v["contract_code_boc_base64"].(string))
	codeHash := tokenCorpusHash(t, v["contract_code_hash"].(string))
	if !bytes.Equal(code.Hash(), codeHash[:]) || codeHash != ServiceActorTokenReleaseCodeHash {
		t.Fatal("release code identity differs")
	}
	checkState := func(t *testing.T, dv map[string]any, actor string) {
		dataCell := tokenVectorCell(t, dv["deploy_data_boc_base64"].(string))
		data, e := DecodeServiceActorTokenData(dataCell)
		if e != nil {
			t.Fatal(e)
		}
		if e = ValidateServiceActorTokenLiveState(data); e != nil {
			t.Fatal(e)
		}
		rebuilt, e := BuildServiceActorTokenInitialData(data.Owner.Text(), data.Policy, data.Route)
		if e != nil {
			t.Fatal(e)
		}

		if !bytes.Equal(dataCell.Hash(), rebuilt.Hash()) {
			var compare func(*cell.Cell, *cell.Cell, string)
			compare = func(a, b *cell.Cell, label string) {
				as, bs := a.MustBeginParse(), b.MustBeginParse()
				if !bytes.Equal(a.Hash(), b.Hash()) {
					t.Logf("%s bits %d/%d refs %d/%d", label, as.BitsLeft(), bs.BitsLeft(), as.RefsNum(), bs.RefsNum())
					for i := 0; as.RefsNum() > 0 && bs.RefsNum() > 0; i++ {
						ar, _ := as.LoadRefCell()
						br, _ := bs.LoadRefCell()
						compare(ar, br, fmt.Sprintf("%s.%d", label, i))
					}
				}
			}
			compare(dataCell, rebuilt, "root")
		}
		tokenSameCell(t, dataCell, rebuilt)
		init := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).MustStoreBoolBit(true).MustStoreRef(code).MustStoreBoolBit(true).MustStoreRef(rebuilt).MustStoreBoolBit(false).EndCell()
		if got := fmt.Sprintf("0:%x", init.Hash()); got != actor {
			t.Fatalf("actor: %s != %s", got, actor)
		}
		terms := TokenTermsOfPolicy(data.Policy, data.Route)
		tc, e := BuildServiceActorTokenTerms(terms)
		if e != nil {
			t.Fatal(e)
		}
		want := tokenVectorCell(t, dv["terms_cell_boc_base64"].(string))
		tokenSameCell(t, want, tc)
		if fmt.Sprintf("%x", tc.Hash()) != dv["terms_hash"] {
			t.Fatal("terms hash differs")
		}
		tokenLogRebuild(t, "terms", want)
		for _, item := range dv["sat1"].([]any) {
			tokenLogRebuild(t, "sat1", tokenVectorCell(t, item.(string)))
		}
		if data.Policy.HasAttestor {
			pubHash := sha256.Sum256(data.Policy.AttestorKey)
			if fmt.Sprintf("%x", pubHash) != dv["attestor_public_key_sha256"] {
				t.Fatal("attestor public key hash differs")
			}
			if fmt.Sprintf("%x", data.Policy.AttestorKeyID) != dv["attestor_key_id"] {
				t.Fatal("attestor key id differs")
			}
			rs := dv["respond"].(map[string]any)
			snapshot, e := DecodeServiceActorTokenRequestSnapshot(tokenVectorCell(t, dv["sat1"].([]any)[0].(string)))
			if e != nil {
				t.Fatal(e)
			}
			domain, e := ServiceActorTokenResponseDomainHash(int32(rs["global_id"].(float64)), actor, snapshot, tokenCorpusHash(t, rs["response_hash"].(string)))
			if e != nil {
				t.Fatal(e)
			}
			if fmt.Sprintf("%x", domain) != rs["domain_hash"] {
				t.Fatal("attested response domain differs")
			}
		} else {
			ownWallet, e := DeriveServiceActorTokenWallet(actor, data.Route)
			if e != nil || ownWallet != v["actor_wallet"] {
				t.Fatalf("wallet identity differs %s %v", ownWallet, e)
			}
			if data.Route.Master.Text() != v["master"] {
				t.Fatal("master differs")
			}
			if fmt.Sprintf("%x", data.Route.WalletCodeHash) != v["wallet_code_hash"] {
				t.Fatal("wallet code hash differs")
			}
			input := v["init"].(map[string]any)
			if data.Owner.Text() != input["owner"] || data.Policy.PricePerCall.String() != input["price_per_call"] || data.Policy.StorageFee.String() != input["storage_fee"] || data.Policy.CleanupBounty.String() != input["cleanup_bounty"] || uint32(input["response_sla"].(float64)) != data.Policy.ResponseSLA || uint32(input["refund_claim_window"].(float64)) != data.Policy.RefundClaimWindow || data.Policy.MaxTokenLiability.String() != input["max_token_liability"] {
				t.Fatal("deploy inputs differ")
			}
		}
	}
	t.Run("plain", func(t *testing.T) { checkState(t, v, v["actor"].(string)) })
	a := v["attested"].(map[string]any)
	t.Run("attested", func(t *testing.T) { checkState(t, a, a["actor"].(string)) })
	for _, tag := range []string{"saf1_refused_amount", "saf1_underfunded", "sab1_surplus"} {
		for i, item := range v[tag].([]any) {
			t.Run(fmt.Sprintf("%s_%d", tag, i), func(t *testing.T) {
				kind := "saf1"
				if tag == "sab1_surplus" {
					kind = "sab1"
				}
				tokenLogRebuild(t, kind, tokenVectorCell(t, item.(string)))
			})
		}
	}
	for name, items := range v["sao1"].(map[string]any) {
		for i, item := range items.([]any) {
			t.Run(fmt.Sprintf("%s_%d", name, i), func(t *testing.T) { tokenLogRebuild(t, "sao1", tokenVectorCell(t, item.(string))) })
		}
	}
	funding := tokenVectorCell(t, v["funding_transfer_body_boc_base64"].(string))
	parsed, e := DecodeServiceActorTokenFundingTransfer(funding)
	if e != nil {
		t.Fatal(e)
	}
	rebuilt, e := BuildServiceActorTokenFundingTransfer(parsed.QueryID, parsed.Amount, parsed.Destination.Text(), parsed.ResponseDestination.Text(), parsed.ForwardTOSAmount, parsed.Payload.RequestHash, parsed.Payload.ExpectedTermsHash)
	if e != nil {
		t.Fatal(e)
	}
	tokenSameCell(t, funding, rebuilt)
}
func tokenNegativeDecode(object string, value *cell.Cell) error {
	switch object {
	case "sat1":
		_, e := DecodeServiceActorTokenRequestSnapshot(value)
		return e
	case "saf1":
		_, e := DecodeServiceActorTokenFundingLog(value)
		return e
	case "sao1":
		_, e := DecodeServiceActorTokenOutcomeLog(value)
		return e
	case "sab1":
		_, e := DecodeServiceActorTokenBalanceLog(value)
		return e
	case "terms":
		_, e := DecodeServiceActorTokenTerms(value)
		return e
	}
	return errors.New("unknown corpus object")
}
func tokenNegativeBase(t *testing.T, v map[string]any, base string) *cell.Cell {
	t.Helper()
	switch {
	case base == "terms_cell":
		return tokenVectorCell(t, v["terms_cell_boc_base64"].(string))
	case strings.HasPrefix(base, "sao1."):
		return tokenVectorCell(t, v["sao1"].(map[string]any)[strings.TrimPrefix(base, "sao1.")].([]any)[0].(string))
	default:
		return tokenVectorCell(t, v[base].([]any)[0].(string))
	}
}
func tokenRuleMatches(rule string, err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch rule {
	case "tag":
		return strings.Contains(s, "tag")
	case "trailing_data":
		return strings.Contains(s, "trailing")
	case "missing_field":
		return strings.Contains(s, "missing") || strings.Contains(s, "not enough")
	case "address_required":
		return strings.Contains(s, "not an internal")
	case "deadlines_disagree":
		return strings.Contains(s, "deadlines disagree")
	case "attestor_flag_disagrees":
		return strings.Contains(s, "attestor flag")
	case "terms_not_canonical":
		return strings.Contains(s, "non-minimal") || strings.Contains(s, "not canonical")
	case "kind_range":
		return strings.Contains(s, "kind outside")
	case "outcome_range":
		return strings.Contains(s, "outcome outside")
	case "resolver_reason_outside_set":
		return strings.Contains(s, "reason is outside")
	case "resolver_underfunded_with_payout":
		return strings.Contains(s, "underfunded")
	case "resolver_result_outside_set":
		return strings.Contains(s, "result outside")
	case "resolver_result_disagrees_with_payout":
		return strings.Contains(s, "result and payout id disagree")
	case "resolver_surplus_with_target":
		return strings.Contains(s, "surplus balance log carries a target")
	}
	return false
}
func TestServiceActorTokenNegativeCorpus(t *testing.T) {
	corpus := tokenVectorJSON(t, "service-actor-token-negative-v1.json")
	positive := tokenVectorJSON(t, "service-actor-token-conformance-vectors.json")
	negatives := corpus["decoder_negatives"].([]any)
	if len(negatives) != 38 {
		t.Fatal("decoder corpus count changed")
	}
	for _, r := range negatives {
		row := r.(map[string]any)
		t.Run(row["name"].(string), func(t *testing.T) {
			object := row["object"].(string)
			if e := tokenNegativeDecode(object, tokenNegativeBase(t, positive, row["base"].(string))); e != nil {
				t.Fatalf("unmutated base refused: %v", e)
			}
			err := tokenNegativeDecode(object, tokenVectorCell(t, row["boc_base64"].(string)))
			if !tokenRuleMatches(row["rule"].(string), err) {
				t.Fatalf("wrong refusal for rule %s: %v", row["rule"], err)
			}
		})
	}
	good := corpus["payload_positives"].([]any)
	for _, r := range good {
		row := r.(map[string]any)
		if _, e := DecodeServiceActorTokenForwardPayload(tokenVectorCell(t, row["boc_base64"].(string))); e != nil {
			t.Fatalf("payload positive %s: %v", row["name"], e)
		}
	}
	bad := corpus["payload_negatives"].([]any)
	if len(bad) != 6 {
		t.Fatal("payload corpus count changed")
	}
	for _, r := range bad {
		row := r.(map[string]any)
		_, e := DecodeServiceActorTokenForwardPayload(tokenVectorCell(t, row["boc_base64"].(string)))
		var failure ServiceActorTokenRefusalV1
		if !errors.As(e, &failure) || int(failure.Code) != int(row["expected_reason"].(float64)) {
			t.Fatalf("payload refusal reason differs for %s: %v", row["name"], e)
		}
		text := e.Error()
		name := row["name"].(string)
		if name == "another_tag" && !strings.Contains(text, "tag mismatch") || name == "too_short" && !strings.Contains(text, "truncated") || (name == "trailing_bits" || name == "trailing_reference" || name == "reference_and_trailing_bit") && !strings.Contains(text, "trailing") {
			t.Fatalf("payload refused for a different rule: %s: %v", name, e)
		}
	}
	codes := corpus["refusal_codes"].([]any)
	if len(codes) != 48 {
		t.Fatal("refusal corpus count changed")
	}
	for _, r := range codes {
		row := r.(map[string]any)
		code := int64(row["code"].(float64))
		err := DecodeServiceActorTokenRefusalCode(code)
		var failure ServiceActorTokenRefusalV1
		if !errors.As(err, &failure) || failure.Code != uint16(code) || failure.Name != row["name"] {
			t.Fatalf("wrong typed refusal for %d: %v", code, err)
		}
		path := row["path"].(string)
		// Both directions: every path the record names is set, and no flag is
		// set that the record does not name.
		if strings.Contains(path, "reason") != failure.Reason || strings.Contains(path, "throw") != failure.Throw || strings.Contains(path, "result") != failure.Result {
			t.Fatalf("wrong refusal paths for %d: %s %+v", code, path, failure)
		}
	}
}
