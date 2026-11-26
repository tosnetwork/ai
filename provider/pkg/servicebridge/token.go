package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type TokenSession interface {
	buyersdk.TokenBuildSession
	serviceactor.TokenSession
	TokenHistory(context.Context, string, *toschain.ActorTxID) (*toschain.TokenActorHistory, error)
	WalletSeqno(context.Context, string) (uint32, error)
	WalletLastTransaction(context.Context, string) (toschain.ActorTxID, error)
	WalletHistory(context.Context, string, toschain.ActorTxID) (*toschain.WalletHistory, error)
}

type tokenVerifiedSession struct {
	*toschain.ServiceActorSession
	source *toschain.ServiceActorReader
}

func (s *tokenVerifiedSession) Endpoints() []string { return s.source.Endpoints() }
func (s *tokenVerifiedSession) CheckEndpointGenesis(ctx context.Context, endpoint string) error {
	return s.source.CheckEndpointGenesis(ctx, endpoint)
}

type TokenEnv struct {
	SetupEnv
	Begin        func(context.Context, NodeConfig, TokenActorConfig) (TokenSession, error)
	CheckCustody func(context.Context, NodeConfig, TokenSession) error
}

func (e *TokenEnv) fill() {
	e.SetupEnv.fill()
	if e.CheckCustody == nil {
		e.CheckCustody = func(ctx context.Context, c NodeConfig, session TokenSession) error {
			raw, err := readPrivateFile(c.TOSCTL.ConfigPath, 1<<20)
			if err != nil {
				return err
			}

			vetter, ok := session.(buyersdk.EndpointVetter)
			if !ok {
				return errors.New("missing custody endpoint verifier")
			}
			return buyersdk.CheckSubmissionEndpoints(ctx, raw, vetter)
		}
	}

	if e.Begin == nil {
		e.Begin = func(ctx context.Context, c NodeConfig, a TokenActorConfig) (TokenSession, error) {
			c.ActorCodeHash = a.CodeHash
			dir := tokenStateDir(c, a.Address)
			if err := ensurePrivateDirectory(dir); err != nil {
				return nil, err
			}
			reader, err := openServiceActorReader(c, networkOf(c), dir)
			if err != nil {
				return nil, err
			}
			session, err := reader.Begin(ctx)
			if err != nil {
				return nil, err
			}
			return &tokenVerifiedSession{ServiceActorSession: session, source: reader}, nil
		}
	}
}

type TokenPolicyInput struct {
	PriceAtomic          string `json:"price_atomic"`
	StorageFeeNanoTOS    string `json:"storage_fee_nanotos"`
	CleanupBountyNanoTOS string `json:"cleanup_bounty_nanotos"`
	MaxLiabilityAtomic   string `json:"max_liability_atomic"`
	ResponseSLA          uint32 `json:"response_sla_seconds"`
	RefundClaimWindow    uint32 `json:"refund_claim_window_seconds"`
}
type TokenActionInput struct {
	Actor          string            `json:"actor"`
	Operation      string            `json:"operation"`
	TokenAmount    string            `json:"token_amount,omitempty"`
	TOSAmount      string            `json:"tos_amount_nanotos,omitempty"`
	AllTokens      bool              `json:"all_tokens,omitempty"`
	AllTOS         bool              `json:"all_tos,omitempty"`
	ID             uint64            `json:"id,omitempty"`
	Policy         *TokenPolicyInput `json:"policy,omitempty"`
	IdempotencyKey string            `json:"idempotency_key"`
}
type TokenPayoutTarget struct {
	Kind       uint8  `json:"kind"`
	ReturnedID uint64 `json:"returned_id"`
	Recipient  string `json:"recipient"`
	Requester  string `json:"requester"`
	Amount     string `json:"amount"`
}
type TokenPreview struct {
	Warnings       []string                       `json:"warnings,omitempty"`
	Recheck        *TokenPayoutTarget             `json:"recheck,omitempty"`
	Network        NetworkConfig                  `json:"network"`
	Actor          string                         `json:"actor"`
	AssetID        string                         `json:"asset_id"`
	Master         string                         `json:"master"`
	Decimals       uint8                          `json:"decimals"`
	Digest         string                         `json:"digest"`
	Checkpoint     uint64                         `json:"checkpoint"`
	PolicyVersion  uint32                         `json:"policy_version"`
	ActorFloorMet  bool                           `json:"actor_floor_met"`
	WalletFloorMet bool                           `json:"wallet_floor_met"`
	TokenRevenue   string                         `json:"token_revenue_atomic"`
	TOSRevenue     string                         `json:"tos_revenue_nanotos"`
	Message        *buyersdk.TokenPreparedMessage `json:"message"`
}

// TokenActionRecord is durable before custody can sign. An unknown operation
// is only observed, never automatically signed or submitted for a second time.
type TokenActionRecord struct {
	Call               *toschain.TokenActorTransaction `json:"call,omitempty"`
	Delivery           *TokenDelivery                  `json:"delivery,omitempty"`
	PreviousDeliveries []TokenDelivery                 `json:"previous_deliveries,omitempty"`
	Failure            string                          `json:"failure,omitempty"`
	Network            NetworkConfig                   `json:"network"`
	Schema             string                          `json:"schema"`
	Input              TokenActionInput                `json:"input"`
	InputHash          string                          `json:"input_hash"`
	Preview            TokenPreview                    `json:"preview"`
	Anchor             toschain.ActorTxID              `json:"anchor"`
	QueryID            uint64                          `json:"query_id"`
	BodyHash           string                          `json:"body_hash"`
	State              string                          `json:"state"`
	PayoutID           uint64                          `json:"payout_id,omitempty"`
	Transaction        *toschain.ActorTxID             `json:"transaction,omitempty"`
}

func tokenInputHash(in TokenActionInput) (string, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func tokenRecordPath(c NodeConfig, key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(c.StateDir, "token-actions", hex.EncodeToString(hash[:])+".json")
}
func tokenTerminal(state string) bool {
	return state == "never_sent" || state == "expired" || state == "refused" || state == "superseded" || state == "delivered" || state == "finalized" || state == "failed" || state == "abandoned" || state == "returned"
}
func checkTokenInput(in TokenActionInput) error {
	canonical, err := toschain.CanonicalAddress(in.Actor)
	if err != nil || canonical != in.Actor || !strings.HasPrefix(in.Actor, "0:") {
		return errors.New("invalid token actor address")
	}
	for _, v := range []string{in.TokenAmount, in.TOSAmount} {
		if v != "" {
			if _, err = tokenUnits(v, false); err != nil {
				return err
			}
		}
	}
	if !regexpTokenKey(in.IdempotencyKey) {
		return errors.New("idempotency key must contain 16 to 64 letters, digits, hyphens or underscores")
	}
	switch in.Operation {
	case "withdraw-revenue", "recover-surplus", "recheck-payout", "abandon-payout", "update-policy", "pause", "resume":
	default:
		return errors.New("unsupported provider token operation")
	}
	if in.Operation != "withdraw-revenue" && (in.TokenAmount != "" && in.Operation != "recover-surplus" || in.TOSAmount != "" || in.AllTokens || in.AllTOS) {
		return errors.New("unused token withdrawal fields")
	}
	if in.Policy != nil && in.Operation != "update-policy" || in.Operation == "update-policy" && in.Policy == nil {
		return errors.New("policy is required only for update-policy")
	}
	if in.Operation != "recheck-payout" && in.Operation != "abandon-payout" && in.ID != 0 {
		return errors.New("unused payout id")
	}
	if in.Operation == "withdraw-revenue" && (in.AllTokens && in.TokenAmount != "" || in.AllTOS && in.TOSAmount != "") {
		return errors.New("amount and all are mutually exclusive")
	}
	return nil
}
func regexpTokenKey(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func tokenBounds(a TokenActorConfig, p *TokenPolicyInput) (*buyersdk.TokenPolicyChange, error) {
	if p == nil {
		return nil, errors.New("missing token policy")
	}
	price, err := tokenUnits(p.PriceAtomic, true)
	if err != nil {
		return nil, err
	}
	min, _ := tokenUnits(a.MinPriceAtomic, true)
	max, _ := tokenUnits(a.MaxPriceAtomic, true)
	if price.Cmp(min) < 0 || price.Cmp(max) > 0 {
		return nil, errors.New("token price outside operator bounds")
	}
	storage, err := tokenUnits(p.StorageFeeNanoTOS, true)
	if err != nil {
		return nil, err
	}
	bounty, err := tokenUnits(p.CleanupBountyNanoTOS, true)
	if err != nil {
		return nil, err
	}
	liability, err := tokenUnits(p.MaxLiabilityAtomic, true)
	if err != nil {
		return nil, err
	}
	for _, pair := range [][2]*big.Int{{storage, mustTokenUnits(a.MaxStorageFeeNanoTOS)}, {bounty, mustTokenUnits(a.MaxCleanupBountyNanoTOS)}, {liability, mustTokenUnits(a.MaxLiabilityAtomic)}} {
		if pair[0].Cmp(pair[1]) > 0 {
			return nil, errors.New("token policy exceeds operator amount bounds")
		}
	}
	return &buyersdk.TokenPolicyChange{PricePerCall: price, StorageFee: storage, CleanupBounty: bounty, MaxTokenLiability: liability, ResponseSLA: &p.ResponseSLA, RefundClaimWindow: &p.RefundClaimWindow}, nil
}
func mustTokenUnits(s string) *big.Int { n, _ := tokenUnits(s, true); return n }

func prepareToken(ctx context.Context, c NodeConfig, a TokenActorConfig, s TokenSession, in TokenActionInput) (*TokenPreview, *toschain.TokenActorAccount, error) {
	resolved, err := s.ResolveTokenActor(ctx, a.Address, c.Token.Pins, false)
	if err != nil {
		return nil, nil, err
	}
	if resolved == nil || resolved.Account == nil || resolved.Account.Data == nil {
		return nil, nil, errors.New("token actor is not deployed")
	}
	account := resolved.Account
	d := account.Data
	if account.CodeHash != a.CodeHash || d.Owner.Text() != c.WalletAddress || d.Route.Master.Text() != a.Master {
		return nil, nil, errors.New("token actor owner, release or master differs from operator configuration")
	}
	var pin *toschain.TokenAssetPin
	for i := range c.Token.Pins {
		if c.Token.Pins[i].Master == a.Master {
			pin = &c.Token.Pins[i]
		}
	}
	if pin == nil {
		return nil, nil, errors.New("token asset is not pinned")
	}
	if in.Operation != "pause" {
		if _, err = toschain.MatchTokenAssetPin(d.Route, pin.Decimals, c.Token.Pins); err != nil {
			return nil, nil, err
		}
	}
	var actorFloor, walletFloor bool
	if in.Operation != "pause" {
		actorFloor, walletFloor, err = tokenFloors(ctx, c, a, s)
		if err != nil {
			return nil, nil, err
		}
	}
	floor := new(big.Int).Add(d.Accounting.LockedStorageFees, d.Accounting.LockedOutcomeFees)
	floor.Add(floor, big.NewInt(nativecore.ServiceActorMinimumOperatingReserve))
	floor.Add(floor, mustTokenUnits(a.MinActorFreeNanoTOS))
	hash, err := tokenInputHash(in)
	if err != nil {
		return nil, nil, err
	}
	h, _ := hex.DecodeString(hash)
	query := binary.BigEndian.Uint64(h[:8])
	if query == 0 {
		query = 1
	}
	request := buyersdk.TokenBuildRequest{Operation: in.Operation, Sender: c.WalletAddress, QueryID: query, ID: in.ID}
	if in.TokenAmount != "" {
		request.TokenAmount, err = tokenUnits(in.TokenAmount, false)
		if err != nil {
			return nil, nil, err
		}
	}
	if in.TOSAmount != "" {
		request.TOSAmount, err = tokenUnits(in.TOSAmount, false)
		if err != nil {
			return nil, nil, err
		}
	}
	if in.AllTokens {
		request.TokenAmount = new(big.Int).Set(d.Accounting.Ledger.WithdrawableTokenRevenue)
	}
	if in.AllTOS {
		request.TOSAmount = new(big.Int).Set(d.Accounting.WithdrawableTOSRevenue)
	}
	if in.Operation == "update-policy" {
		request.PolicyChange, err = tokenBounds(a, in.Policy)
		if err != nil {
			return nil, nil, err
		}
	}
	if in.Operation == "pause" || in.Operation == "resume" {
		active := in.Operation == "resume"
		request.Operation = "update-policy"
		request.PolicyChange = &buyersdk.TokenPolicyChange{Active: &active}
	}
	if in.Operation == "resume" || in.Operation == "update-policy" && d.Active {
		if err = tokenAdmissionClear(c, s, a.AssetID); err != nil {
			return nil, nil, err
		}
		if !actorFloor || !walletFloor {
			return nil, nil, errors.New("token actor or wallet TOS floor not met")
		}
		if _, err = s.ReadTokenAsset(ctx, a.Master, c.Token.Pins); err != nil {
			return nil, nil, err
		}
	}
	prepared, err := buyersdk.PrepareTokenAtSession(ctx, s, a.Address, c.Token.Pins, request, nil)
	if err != nil {
		return nil, nil, err
	}
	if request.TOSAmount != nil && request.TOSAmount.Sign() > 0 {
		remaining := new(big.Int).Sub(new(big.Int).SetUint64(account.BalanceNano), request.TOSAmount)
		if remaining.Cmp(floor) < 0 {
			return nil, nil, errors.New("withdrawal would breach actor TOS floor")
		}
	}
	p := &TokenPreview{Warnings: append([]string(nil), prepared.Warnings...), Network: c.Network, Actor: a.Address, AssetID: a.AssetID, Master: a.Master, Decimals: pin.Decimals, Checkpoint: s.Checkpoint(), PolicyVersion: d.Policy.PolicyVersion, ActorFloorMet: actorFloor, WalletFloorMet: walletFloor, TokenRevenue: d.Accounting.Ledger.WithdrawableTokenRevenue.String(), TOSRevenue: d.Accounting.WithdrawableTOSRevenue.String(), Message: prepared}
	if in.Operation == "recheck-payout" {
		target := d.Payouts[in.ID]
		returnedID := in.ID
		if target.Kind == 5 || target.Kind == 7 {
			returnedID = target.RequestID
		}
		p.Recheck = &TokenPayoutTarget{Kind: target.Kind, ReturnedID: returnedID, Recipient: target.Recipient.Text(), Requester: target.Requester.Text(), Amount: target.Amount.String()}
	}

	// Checkpoints may advance; the human confirms semantics, balances and policy,
	// not a block label. A changed amount, envelope, policy or floor still expires.
	clone := *p
	clone.Checkpoint = 0
	msg := *prepared
	msg.ReadAt = buyersdk.TokenReadAt{}
	clone.Message = &msg
	raw, err := json.Marshal(clone)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	p.Digest = hex.EncodeToString(sum[:])
	return p, account, nil
}

// RunTokenAction is the common pre-sign boundary for direct commands and MCP.
// A preview is always required; yes alone cannot approve a different envelope.
func RunTokenAction(ctx context.Context, c NodeConfig, in TokenActionInput, yes bool, confirmed string, env TokenEnv) (*TokenActionRecord, error) {
	env.fill()
	if c.Token == nil {
		return nil, errors.New("no token provider configured")
	}
	if err := checkTokenInput(in); err != nil {
		return nil, err
	}
	a, err := c.Token.Actor(in.Actor)
	if err != nil {
		return nil, err
	}
	release, err := lockSetup(c.StateDir)
	if err != nil {
		return nil, err
	}
	defer release()
	inputHash, err := tokenInputHash(in)
	if err != nil {
		return nil, err
	}
	path := tokenRecordPath(c, in.IdempotencyKey)
	if err = ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	var prior TokenActionRecord
	err = readJSON(path, 1<<20, &prior)
	existing := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if existing {
		storedHash, hashErr := tokenInputHash(prior.Input)
		if hashErr != nil || storedHash != inputHash || prior.Schema != "tos.service.provider-token-action.v1" || prior.InputHash != inputHash || prior.Network != c.Network || prior.Preview.Message == nil {
			return nil, errors.New("idempotency key belongs to another token action")
		}
		if prior.State == "building" || prior.State == "signed" || prior.State == "never_sent" {
			prior.State = "never_sent"
			if err = writeJSON(path, prior, false); err != nil {
				return &prior, err
			}
			if in.Operation != "pause" || !yes {
				return &prior, nil
			}
		}
	}
	session, err := env.Begin(ctx, c, a)
	if err != nil {
		if existing {
			return &prior, err
		}
		return nil, err
	}
	if existing {
		if err = resolveTokenAction(ctx, session, c, &prior); err != nil {
			return &prior, err
		}
		if err = writeJSON(path, prior, false); err != nil {
			return &prior, err
		}
		if in.Operation != "pause" || !yes || (prior.State != "never_sent" && prior.State != "expired") {
			return &prior, nil
		}
	}

	if in.Operation == "pause" {
		if err = tokenPolicyBarrier(ctx, c, in, session); err != nil {
			return nil, err
		}
	}
	preview, account, err := prepareToken(ctx, c, a, session, in)
	if err != nil {
		if existing {
			return &prior, err
		}
		return nil, err
	}
	record := &TokenActionRecord{Network: c.Network, Schema: "tos.service.provider-token-action.v1", Input: in, InputHash: inputHash, Preview: *preview, State: "preview", Anchor: account.LastTransaction}
	if !yes {
		return record, ErrConfirmationRequired
	}
	if confirmed != preview.Digest {
		return record, errors.New("token preview changed; nothing signed or sent")
	}
	if in.Operation != "pause" && in.Operation != "abandon-payout" && in.Operation != "recheck-payout" {
		if err = tokenNoOpenAction(ctx, c, in.Actor, session); err != nil {
			return record, err
		}
	}
	body, err := decodeCellBOCText(preview.Message.BodyBOC)
	if err != nil {
		return record, err
	}
	record.BodyHash = hex.EncodeToString(body.Hash())
	parsed, err := nativecore.DecodeServiceActorTokenInbound(body)
	if err != nil {
		return record, err
	}
	record.QueryID = parsed.QueryID
	if existing {
		record.PreviousDeliveries = append(record.PreviousDeliveries, prior.PreviousDeliveries...)
		if prior.Delivery != nil {
			record.PreviousDeliveries = append(record.PreviousDeliveries, *prior.Delivery)
		}
		if len(record.PreviousDeliveries) > 32 {
			return &prior, errors.New("pause retry journal needs operator archival")
		}
	}
	runner, err := env.Runner(c.TOSCTL, env.vaultURL(c.TOSCTL))
	if err != nil {
		record.State = "never_sent"
		return record, err
	}
	defer closeRunner(runner)
	wallet, err := (tosctlOps{runner: runner}).wallet(ctx, c.WalletName)
	if err != nil {
		record.State = "never_sent"
		return record, err
	}
	if wallet.Address != c.WalletAddress {
		record.State = "never_sent"
		return record, errors.New("custody wallet identity changed")
	}
	// A building record cannot have reached the broadcaster. A crash or a
	// preparation error is therefore provably not sent, even if signing began.
	record.State = "building"
	if err = writeJSON(path, record, !existing); err != nil {
		return record, err
	}
	delivery, err := prepareTokenDelivery(ctx, c, session, record, runner, env)
	if err != nil {
		record.State = "never_sent"
		if saveErr := writeJSON(path, record, false); saveErr != nil {
			return record, errors.Join(err, saveErr)
		}
		return record, err
	}
	record.Delivery = delivery
	record.State = "submitted"
	if err = writeJSON(path, record, false); err != nil {
		return record, err
	}
	if err = broadcastTokenDelivery(ctx, runner, delivery); err != nil {
		return record, err
	}
	return record, nil
}

// The contract replaces the entire policy. A pause must wait for an earlier
// policy send to resolve or expire, then use the post-update finalized policy.
func tokenPolicyBarrier(ctx context.Context, c NodeConfig, in TokenActionInput, s TokenSession) error {
	entries, err := os.ReadDir(filepath.Join(c.StateDir, "token-actions"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 4096 {
		return errors.New("token action journal needs archival")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stateUpdatePrefix) {
			continue
		}
		var r TokenActionRecord
		if err = readJSON(filepath.Join(c.StateDir, "token-actions", entry.Name()), 1<<20, &r); err != nil {
			return err
		}
		if r.Input.Actor != in.Actor || r.Input.IdempotencyKey == in.IdempotencyKey || tokenTerminal(r.State) {
			continue
		}
		switch r.Input.Operation {
		case "update-policy", "resume", "pause":
		default:
			continue
		}
		if err = resolveTokenAction(ctx, s, c, &r); err != nil {
			return err
		}
		if err = writeJSON(filepath.Join(c.StateDir, "token-actions", entry.Name()), r, false); err != nil {
			return err
		}
		if !tokenTerminal(r.State) {
			if r.Delivery != nil && s.ChainTime().Unix() > int64(r.Delivery.ValidUntil) {
				return errors.New("alarm: policy delivery unresolved past wallet TTL; pause held for operator, no stale policy may be signed")
			}
			return errors.New("alarm: pause waits for an in-flight policy update; no stale policy may be signed")
		}
	}
	return nil
}

func tokenNoOpenAction(ctx context.Context, c NodeConfig, actor string, session TokenSession) error {
	dir := filepath.Join(c.StateDir, "token-actions")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 4096 {
		return errors.New("token action journal needs archival")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stateUpdatePrefix) {
			continue
		}
		if !entry.Type().IsRegular() {
			return errors.New("unexpected token action journal entry")
		}
		var r TokenActionRecord
		if err = readJSON(filepath.Join(dir, entry.Name()), 1<<20, &r); err != nil {
			return err
		}
		if r.Input.Actor == actor && !tokenTerminal(r.State) {
			if err := resolveTokenAction(ctx, session, c, &r); err != nil {
				return err
			}
			if err := writeJSON(filepath.Join(dir, entry.Name()), r, false); err != nil {
				return err
			}
			if !tokenTerminal(r.State) {
				return errors.New("an earlier token action is unresolved; reconcile it before signing")
			}
		}
	}
	return nil
}
func closeRunner(r TOSCTLRunner) {
	if closer, ok := r.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

// TokenOffer uses one finalized registry/actor/recognition view; it never
// publishes a token offer by relabelling a native price.
func TokenOffer(ctx context.Context, c NodeConfig, address string, env TokenEnv) (*serviceactor.TokenAdmission, error) {
	env.fill()
	if c.Token == nil {
		return nil, errors.New("no token provider")
	}
	a, err := c.Token.Actor(address)
	if err != nil {
		return nil, err
	}
	s, err := env.Begin(ctx, c, a)
	if err != nil {
		return nil, err
	}
	return tokenOfferAtSession(ctx, c, a, s)
}
func tokenOfferAtSession(ctx context.Context, c NodeConfig, a TokenActorConfig, s TokenSession, ignoreLocalPause ...bool) (*serviceactor.TokenAdmission, error) {
	var err error
	if len(ignoreLocalPause) > 0 && ignoreLocalPause[0] {
		err = tokenAlarmClear(c, s, a.AssetID)
	} else {
		err = tokenAdmissionClear(c, s, a.AssetID)
	}
	if err != nil {
		return nil, err
	}
	source := tokenManifestFile{path: a.ManifestFile}
	e, err := serviceactor.GatherTokenEvidence(ctx, s, networkOf(c), source, a.CapabilityID, a.Version, c.Token.Pins, true)
	if err != nil {
		return nil, err
	}
	if e.Capability.GetCapability().OwnerAgentId != c.AgentID {
		return nil, errors.New("token offer belongs to another provider Agent")
	}
	actorFloor, walletFloor, err := tokenFloors(ctx, c, a, s)
	if err != nil {
		return nil, err
	}
	if !actorFloor || !walletFloor {
		return nil, errors.New("token offer TOS floor not met")
	}
	if e.Actor.Address != a.Address || e.Actor.Data.Owner.Text() != c.WalletAddress || e.Actor.Data.Route.Master.Text() != a.Master {
		return nil, errors.New("token offer actor does not belong to this provider")
	}
	bytes, err := hex.DecodeString(a.CodeHash[len("tvm-cell-sha256:"):])
	if err != nil {
		return nil, err
	}
	var code [32]byte
	copy(code[:], bytes)
	admission, err := serviceactor.VerifyTokenAdmission(e, code, nil, nil, "")
	if err != nil {
		return nil, err
	}
	p := admission.Policy
	if _, err = tokenBounds(a, &TokenPolicyInput{PriceAtomic: p.PricePerCall.String(), StorageFeeNanoTOS: p.StorageFee.String(), CleanupBountyNanoTOS: p.CleanupBounty.String(), MaxLiabilityAtomic: p.MaxTokenLiability.String(), ResponseSLA: p.ResponseSLA, RefundClaimWindow: p.RefundClaimWindow}); err != nil {
		return nil, err
	}
	return admission, nil
}

type tokenManifestFile struct{ path string }

func (f tokenManifestFile) Manifest(_ context.Context, digest string) ([]byte, error) {
	info, err := os.Lstat(f.path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("invalid token manifest file")
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("token manifest digest mismatch")
	}
	return raw, nil
}

func ValidateTokenActionInput(in TokenActionInput) error { return checkTokenInput(in) }
