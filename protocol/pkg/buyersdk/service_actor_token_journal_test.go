package buyersdk

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenJournalFixture(t *testing.T) (*ServiceActorJournal, ServiceActorLimits, CallRecord) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := OpenServiceActorJournal(dir, saNow)
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultLimits()
	key := TokenAssetBudgetKey(saOwner, saCodeHash, 6)
	limits.TokenAssets = map[string]TokenAssetLimits{key: {MaxPerCallAtomic: big.NewInt(10), MaxWindowAtomic: big.NewInt(15)}}
	record := CallRecord{Schema: tokenCallRecordSchema, Rail: nativecore.ServiceActorTokenRail, AssetMaster: saOwner, AssetWalletCodeHash: saCodeHash, AssetDecimals: 6, PriceAtomic: "10", PreparedTokenMessage: &TokenPreparedMessage{ValueNanotos: "100"}, PaymentNanoTOS: "100", RequestHash: strings.Repeat("a1", 32), QueryID: 1, Phase: PhasePrepared, ExpiresAtUnix: uint64(saNow.Unix() + 600)}
	return j, limits, record
}

func TestTokenJournalSeparatesPrincipalAndNativeFunding(t *testing.T) {
	j, limits, r := tokenJournalFixture(t)
	if err := j.Create(r, limits, saNow); err != nil {
		t.Fatal(err)
	}
	principal, err := j.ReservedToken(limits, saNow)
	if err != nil || principal[TokenAssetBudgetKey(saOwner, saCodeHash, 6)].String() != "10" {
		t.Fatalf("principal=%v err=%v", principal, err)
	}
	native, count, err := j.Reserved(limits, saNow)
	if err != nil || native.String() != "100" || count != 1 {
		t.Fatalf("native=%v count=%d err=%v", native, count, err)
	}
	r.RequestHash = strings.Repeat("b2", 32)
	r.QueryID = 2
	r.PriceAtomic = "6"
	if err = j.Create(r, limits, saNow); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("window bypass: %v", err)
	}
	r.PriceAtomic = "11"
	if err = j.Create(r, limits, saNow); !errors.Is(err, ErrOverBudget) {
		t.Fatalf("per-call bypass: %v", err)
	}
	r.PriceAtomic = "5"
	if err = j.Create(r, limits, saNow); err != nil {
		t.Fatal(err)
	}
	if _, err = j.BeginSend(r.RequestHash, limits, saNow); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenServiceActorJournal(j.directory, saNow)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Read(r.RequestHash)
	if err != nil || pending.Phase != PhaseAmbiguous {
		t.Fatalf("restart lost reservation: %#v %v", pending, err)
	}
	principal, err = reopened.ReservedToken(limits, saNow)
	if err != nil || principal[TokenAssetBudgetKey(saOwner, saCodeHash, 6)].String() != "15" {
		t.Fatal("ambiguous principal released", principal, err)
	}
}

func TestTokenJournalIdentityNeverSharesABudgetByMasterAlone(t *testing.T) {
	for _, change := range []func(*CallRecord){func(r *CallRecord) { r.AssetWalletCodeHash = saCodeHash + "0" }, func(r *CallRecord) { r.AssetDecimals++ }, func(r *CallRecord) { r.AssetMaster = saBuyer }} {
		j, limits, r := tokenJournalFixture(t)
		change(&r)
		if err := j.Create(r, limits, saNow); !errors.Is(err, ErrOverBudget) {
			t.Fatalf("unlisted asset budget accepted: %v", err)
		}
	}
	j, limits, r := tokenJournalFixture(t)
	limits.TokenAssets[TokenAssetBudgetKey(r.AssetMaster, r.AssetWalletCodeHash, r.AssetDecimals)] = TokenAssetLimits{MaxPerCallAtomic: big.NewInt(0), MaxWindowAtomic: big.NewInt(10)}
	if limits.Valid() || j.Create(r, limits, saNow) == nil {
		t.Fatal("invalid token limits accepted")
	}
}

func TestTokenCustodyCarriesTheExactMessageAndChecksBindings(t *testing.T) {
	body := cell.BeginCell().MustStoreUInt(7, 32).EndCell()
	p := &TokenPreparedMessage{Version: TokenPreparedMessageVersion, Operation: "call", Sender: saBuyer, Destination: saOwner, ValueNanotos: "100", Bounce: true, BodyBOC: base64.StdEncoding.EncodeToString(body.ToBOCWithOptions(cell.BOCSerializeOptions{})), BodyHash: hex.EncodeToString(body.Hash())}
	output, _ := json.Marshal(map[string]any{"version": "tosctl.wallet-prepared-send.v2", "valid_until": 2000000120, "wallet": "buyer", "payer": saBuyer, "destination": saOwner, "amount_nanotos": 100, "body_hash": cellHash(body), "state_init_hash": "", "message_boc_base64": "te6c"})
	endpoints := vetter{endpoints: []string{"https://a.example/jsonRPC", "https://b.example/jsonRPC", "https://c.example/jsonRPC"}}
	sender, calls := testSender(t, validConfig, endpoints, output)
	if err := sender.PreflightToken(context.Background(), p, 2000000120); err != nil {
		t.Fatal(err)
	}
	sender.runWithPath = func(_ context.Context, args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		return []byte("OK Transfer sent"), nil
	}
	if err := sender.SendToken(context.Background(), p, 2000000120); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join((*calls)[0], " "), " --bounce --valid-until 2000000120 --build-only") {
		t.Fatal("preflight omitted bounce")
	}
	argv := strings.Join((*calls)[1], " ")
	if !strings.Contains(argv, "--to "+p.Destination+" --amount-nanotos 100 --body-boc "+p.BodyBOC+" --bounce --valid-until 2000000120 --yes") {
		t.Fatal("token body rebuilt", argv)
	}
	before := len(*calls)
	if sender.PreflightToken(context.Background(), p, 0) == nil || !errors.Is(sender.SendToken(context.Background(), p, 0), ErrCallNotStarted) || len(*calls) != before {
		t.Fatal("missing expiry reached custody")
	}
	p.BodyHash = strings.Repeat("00", 32)
	if sender.PreflightToken(context.Background(), p, 2000000120) == nil || !errors.Is(sender.SendToken(context.Background(), p, 2000000120), ErrCallNotStarted) {
		t.Fatal("tampered body accepted")
	}
}

func TestTokenConfirmedFundingCannotChangeSilently(t *testing.T) {
	a := &TokenPreparedMessage{BodyBOC: "same", BodyHash: "hash", ValueNanotos: "5", Destination: saActor}
	b := *a
	b.ReadAt.Seqno++
	if !sameTokenMessage(a, &b) {
		t.Fatal("checkpoint alone changes exact message")
	}
	for _, change := range []func(*TokenPreparedMessage){func(p *TokenPreparedMessage) { p.ValueNanotos = "6" }, func(p *TokenPreparedMessage) { p.BodyBOC = "other" }, func(p *TokenPreparedMessage) { p.Destination = saBuyer }, func(p *TokenPreparedMessage) { p.Bounce = true }} {
		b := *a
		change(&b)
		if sameTokenMessage(a, &b) {
			t.Fatal("confirmed message changed")
		}
	}
}

func TestTokenJournalTwoAssetsHaveIndependentPrincipalAndSharedFunding(t *testing.T) {
	j, limits, a := tokenJournalFixture(t)
	b := a
	b.RequestHash = strings.Repeat("b2", 32)
	b.QueryID = 2
	b.AssetMaster = saBuyer
	keyA := TokenAssetBudgetKey(a.AssetMaster, a.AssetWalletCodeHash, a.AssetDecimals)
	keyB := TokenAssetBudgetKey(b.AssetMaster, b.AssetWalletCodeHash, b.AssetDecimals)
	limits.TokenAssets[keyB] = TokenAssetLimits{MaxPerCallAtomic: big.NewInt(10), MaxWindowAtomic: big.NewInt(10)}
	if err := j.Create(a, limits, saNow); err != nil {
		t.Fatal(err)
	}
	if err := j.Create(b, limits, saNow); err != nil {
		t.Fatal("second asset blocked by first asset", err)
	}
	c := a
	c.QueryID = 3
	c.RequestHash = strings.Repeat("c3", 32)
	c.PriceAtomic = "6"
	if !errors.Is(j.Create(c, limits, saNow), ErrOverBudget) {
		t.Fatal("asset A exceeded window")
	}
	reserved, err := j.ReservedToken(limits, saNow)
	if err != nil || reserved[keyA].String() != "10" || reserved[keyB].String() != "10" {
		t.Fatal("mixed principal units", reserved, err)
	}
	limits.MaxWindowNanoTOS = big.NewInt(200)
	limits.MaxPerCallNanoTOS = big.NewInt(100)
	c.PriceAtomic = "5"
	if !errors.Is(j.Create(c, limits, saNow), ErrOverBudget) {
		t.Fatal("native funding did not share a window")
	}
}

func TestTokenLifecycleFundingIsReservedDurablyAgainstNativeCaps(t *testing.T) {
	j, limits, r := tokenJournalFixture(t)
	limits.MaxPerCallNanoTOS = big.NewInt(200)
	limits.MaxWindowNanoTOS = big.NewInt(300)
	if err := j.Create(r, limits, saNow); err != nil {
		t.Fatal(err)
	}
	send := LifecycleSend{Operation: "claim-returned", QueryID: 2, Phase: PhaseSending, SentUnix: saNow.Unix(), PreparedTokenMessage: &TokenPreparedMessage{ValueNanotos: "200"}}
	updated, err := j.beginTokenLifecycle(r, send, limits, saNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Lifecycle) != 1 {
		t.Fatal("funding not persisted")
	}
	total, _, err := j.Reserved(limits, saNow)
	if err != nil || total.String() != "300" {
		t.Fatal("funding invisible", total, err)
	}
	send.QueryID = 3
	send.PreparedTokenMessage = &TokenPreparedMessage{ValueNanotos: "1"}
	if _, err = j.beginTokenLifecycle(updated, send, limits, saNow); !errors.Is(err, ErrOverBudget) {
		t.Fatal("second lifecycle funding bypassed cap", err)
	}
	if _, err = j.beginTokenLifecycle(r, send, limits, saNow); !errors.Is(err, ErrLifecycleUnsettled) {
		t.Fatal("concurrent lifecycle write was not detected", err)
	}
}

func TestTokenPrincipalLimitsAreAtMost120Bits(t *testing.T) {
	_, limits, r := tokenJournalFixture(t)
	key := TokenAssetBudgetKey(r.AssetMaster, r.AssetWalletCodeHash, r.AssetDecimals)
	huge := new(big.Int).Lsh(big.NewInt(1), 120)
	limits.TokenAssets[key] = TokenAssetLimits{MaxPerCallAtomic: big.NewInt(1), MaxWindowAtomic: huge}
	if limits.Valid() {
		t.Fatal("window principal cap exceeds 120 bits")
	}
	limits.TokenAssets[key] = TokenAssetLimits{MaxPerCallAtomic: huge, MaxWindowAtomic: huge}
	if limits.Valid() {
		t.Fatal("per-call principal cap exceeds 120 bits")
	}
}
