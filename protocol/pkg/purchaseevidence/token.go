package purchaseevidence

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactor"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const TokenBundleSchema = "tos.service.purchase-evidence.token.v1"
const TokenVerdictSchema = "tos.service.purchase-verdict.token.v1"

// TokenFundingHop names a transaction, not a trusted RPC summary. The verifier
// finds it in a hash-linked finalized history and links exact message hashes.
type TokenFundingHop struct {
	Account     string             `json:"account"`
	Transaction toschain.ActorTxID `json:"transaction"`
}

type TokenBundle struct {
	Schema             string       `json:"schema"`
	Network            NetworkTuple `json:"network"`
	Actor              string       `json:"actor"`
	ActorCodeHash      string       `json:"actor_code_hash"`
	BuyerWallet        string       `json:"buyer_wallet"`
	QuotePackageBase64 string       `json:"quote_package_base64"`
	AcceptedQuoteBOC   string       `json:"accepted_quote_boc"`
	ServiceRequestBOC  string       `json:"service_request_boc"`
	SourceDigest       string       `json:"source_digest"`
	// Funding is exactly payer wallet, sender token wallet, actor token wallet.
	Funding []TokenFundingHop  `json:"funding"`
	Call    toschain.ActorTxID `json:"call"`
}

func DecodeTokenBundle(raw []byte) (*TokenBundle, error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return nil, errors.New("token evidence outside bounds")
	}
	var b TokenBundle
	if err := jsonstrict.Decode(raw, &b); err != nil {
		return nil, err
	}
	if b.Schema != TokenBundleSchema || len(b.Funding) != 3 {
		return nil, errors.New("token evidence needs its schema and three funding hops")
	}
	return &b, nil
}

type TokenSession interface {
	serviceactor.TokenLifecycleSession
	serviceactor.TokenSession
	serviceactor.TransitionSession
	BlockHashes() (string, string)
	ReadTokenWallet(context.Context, string, nativecore.ServiceActorTokenAssetRouteV1) (*toschain.TokenWalletAccount, bool, error)
	// TokenWalletTransaction proves one named wallet transaction at the
	// session's checkpoint by an anchored walk from the wallet's finalized head.
	TokenWalletTransaction(context.Context, string, toschain.ActorTxID) (*toschain.TokenActorTransaction, error)
}

// The verifier's chain reader is asserted to be a token session at run time;
// keep that a compile-time fact.
var _ TokenSession = (*toschain.ServiceActorSession)(nil)

type TokenInput struct {
	Network              *nativev1.NetworkDomain
	Actor, ActorCodeHash string
	Pins                 []toschain.TokenAssetPin
	RequestIDs           []uint64
	RequestHashes        []string
	Bundle               *TokenBundle
	Receipt, Artifact    []byte
}

type TokenRequestReport struct {
	RequestID    uint64              `json:"request_id"`
	RequestHash  string              `json:"request_hash"`
	Caller       string              `json:"caller"`
	State        serviceactor.Status `json:"state"`
	PriceAtomic  string              `json:"price_atomic"`
	PayoutID     uint64              `json:"payout_id,omitempty"`
	ReturnedID   uint64              `json:"returned_id,omitempty"`
	Destination  string              `json:"destination,omitempty"`
	Call         toschain.ActorTxID  `json:"call"`
	ResponseHash string              `json:"response_hash,omitempty"`
	NextAction   string              `json:"next_action,omitempty"`
}

type TokenVerdict struct {
	Schema          string                             `json:"schema"`
	Result          string                             `json:"result"`
	Network         NetworkTuple                       `json:"network"`
	Checkpoint      Checkpoint                         `json:"checkpoint"`
	Requests        []TokenRequestReport               `json:"requests"`
	FundingRefusals []serviceactor.TokenFundingRefusal `json:"funding_refusals"`
	Checks          []Check                            `json:"checks"`
	NotClaimed      []string                           `json:"not_claimed"`
	Reads           *Reads                             `json:"reads,omitempty"`
	Tool            *Tool                              `json:"tool,omitempty"`
	Inputs          []FileDigest                       `json:"inputs,omitempty"`
}

// VerifyToken reads one current checkpoint. A pinned, executed SAT1 proves the
// contract's admission predicates; it does not invent a historical CP84 hash
// from a later view. Suspensions cannot invalidate an already admitted payout.
func VerifyToken(ctx context.Context, session TokenSession, in TokenInput) *TokenVerdict {
	v := &TokenVerdict{Schema: TokenVerdictSchema, Result: ResultFail, Requests: []TokenRequestReport{}, FundingRefusals: []serviceactor.TokenFundingRefusal{}, Checks: []Check{}, NotClaimed: append([]string(nil), notClaimed...)}
	fail := func(id string, err error) *TokenVerdict {
		v.Checks = append(v.Checks, Check{ID: id, Detail: err.Error()})
		return v
	}
	pass := func(id, detail string) { v.Checks = append(v.Checks, Check{ID: id, OK: true, Detail: detail}) }
	if in.Network == nil || session == nil || ctx == nil {
		return fail("input", errors.New("missing network or finalized token session"))
	}
	v.Network = NetworkTuple{in.Network.NetworkId, in.Network.GenesisRootHash, in.Network.GenesisFileHash}
	v.Checkpoint = Checkpoint{Seqno: session.Checkpoint(), ChainTime: session.ChainTime().Unix()}
	defer func() {
		v.Checkpoint.BlockRoot, v.Checkpoint.BlockFile = session.BlockHashes()
		if session.Checkpoint() != v.Checkpoint.Seqno || session.ChainTime().Unix() != v.Checkpoint.ChainTime {
			fail("checkpoint", errors.New("token verification changed checkpoint"))
			v.Result = ResultFail
		}
	}()
	if canonical, err := toschain.CanonicalAddress(in.Actor); err != nil || canonical != in.Actor || !strings.HasPrefix(in.Actor, "0:") {
		return fail("input", errors.New("token actor must be canonical workchain 0"))
	}
	if in.ActorCodeHash != "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]) && in.ActorCodeHash != "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenTestProfileCodeHash[:]) {
		return fail("input", errors.New("unsupported token release"))
	}
	if len(in.RequestIDs)+len(in.RequestHashes) > MaxSelected || (len(in.RequestIDs)+len(in.RequestHashes) == 0 && in.Bundle == nil) {
		return fail("input", errors.New("select between one and 64 token requests"))
	}
	account, found, err := session.ReadTokenActor(ctx, in.Actor)
	if err != nil {
		return fail("actor", err)
	}
	if !found || account == nil || account.Data == nil || account.Address != in.Actor || account.CodeHash != in.ActorCodeHash {
		return fail("actor", errors.New("token actor differs from pinned release"))
	}
	history, err := session.TokenHistory(ctx, in.Actor, nil)
	if err != nil {
		return fail("history", err)
	}
	requests, err := serviceactor.ReplayTokenRequests(account, history, session.ChainTime())
	if err != nil {
		return fail("history", err)
	}
	refusals, err := serviceactor.ResolveTokenFundingRefusals(account, history)
	if err != nil {
		return fail("funding-refusals", err)
	}
	selectedRefusals := map[int]bool{}
	pass("finalized-state", "complete actor history and typed pending, refund, payout and returned cells agree")
	selected := map[uint64]*serviceactor.TokenRequest{}
	for _, id := range in.RequestIDs {
		r := requests[id]
		if r == nil {
			return fail("selection", fmt.Errorf("request %d not found", id))
		}
		selected[id] = r
	}
	for _, text := range in.RequestHashes {
		if _, err := hex32(text); err != nil {
			return fail("selection", err)
		}
		matched := false
		for id, r := range requests {
			if hex.EncodeToString(r.Snapshot.RequestHash[:]) == text {
				selected[id] = r
				matched = true
			}
		}
		if !matched {
			for index, f := range refusals {
				if f.Call.Notification != nil && f.Call.Notification.Payload != nil && hex.EncodeToString(f.Call.Notification.Payload.RequestHash[:]) == text {
					selectedRefusals[index] = true
					matched = true
				}
			}
		}
		if !matched {
			return fail("selection", errors.New("request hash not found in admission or authenticated refusal"))
		}

	}
	var quote *quoteexchange.ValidatedToken
	var request *serviceactor.TokenRequest
	if in.Bundle != nil {
		b := in.Bundle
		if len(b.QuotePackageBase64) > 3<<20 || len(b.AcceptedQuoteBOC) > 2<<20 || len(b.ServiceRequestBOC) > 2<<20 {
			return fail("bundle-bounds", errors.New("token evidence exceeds cell bounds"))
		}
		if b.Schema != TokenBundleSchema || b.Network != v.Network || b.Actor != in.Actor || b.ActorCodeHash != in.ActorCodeHash || len(b.Funding) != 3 {
			return fail("bundle-pins", errors.New("token bundle differs from verifier pins"))
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(b.QuotePackageBase64)
		if err != nil || len(raw) > quoteexchange.MaxPackageBytes {
			return fail("bundle-quote", errors.New("bad Quote package"))
		}
		pkg := &nativev1.QuoteProposalPackageV1{}
		if err = proto.Unmarshal(raw, pkg); err != nil || pkg.Proposal == nil {
			return fail("bundle-quote", errors.New("bad Quote proposal"))
		}
		quote, err = quoteexchange.ValidateTokenPortable(in.Network, &nativev1.RequestQuoteProposalRequest{CapabilityId: pkg.Proposal.CapabilityId, CapabilityVersion: pkg.Proposal.CapabilityVersion, BuyerAddress: b.BuyerWallet}, pkg)
		if err != nil {
			return fail("bundle-quote", err)
		}
		q, _, err := nativecore.BuildAcceptedTokenQuoteCommitment(in.Network, quote.Proposal)
		if err != nil {
			return fail("bundle-quote", err)
		}
		if base64.StdEncoding.EncodeToString(q.ToBOCWithOptions(cell.BOCSerializeOptions{})) != b.AcceptedQuoteBOC {
			return fail("bundle-quote", errors.New("Accepted Quote bytes differ"))
		}
		reqCell, err := tokenEvidenceCell(b.ServiceRequestBOC)
		if err != nil {
			return fail("bundle-request", err)
		}
		req, err := nativecore.DecodeServiceRequestCellV1(reqCell)
		if err != nil {
			return fail("bundle-request", err)
		}
		if !bytes.Equal(req.QuoteCommitment[:], q.Hash()) {
			return fail("bundle-request", errors.New("request names another Quote"))
		}
		source, err := digest32(b.SourceDigest, "sha256:")
		if err != nil || railwork.InputDigest(source) != req.InputDigest {
			return fail("bundle-request", errors.New("source digest does not bind input"))
		}
		var requestHash [32]byte
		copy(requestHash[:], reqCell.Hash())
		for id, r := range requests {
			if r.Snapshot.RequestHash == requestHash {
				if request != nil {
					return fail("bundle-request", errors.New("request hash has more than one admission"))
				}
				request = r
				selected[id] = r
			}
		}
		if request == nil || b.Call != (toschain.ActorTxID{LT: request.Call.LT, Hash: request.Call.Hash}) {
			return fail("bundle-request", errors.New("bundle call does not identify its admitted request"))
		}
		if len(selected) != 1 {
			return fail("selection", errors.New("bundle must select exactly one request"))
		}
		e, err := serviceactor.GatherTokenEvidence(ctx, session, in.Network, packageManifest{digest: quote.Proposal.ManifestDigest, raw: pkg.CanonicalManifestCbor}, quote.Proposal.CapabilityId, quote.Proposal.CapabilityVersion, nil, false)
		if err != nil {
			return fail("bundle-binding", err)
		}
		acceptance, err := serviceactor.ProveAcceptance(ctx, session, &e.Evidence, toschain.ActorTransaction{LT: request.Call.LT, Hash: request.Call.Hash})
		if err != nil {
			return fail("bundle-binding", err)
		}
		code, err := digest32(in.ActorCodeHash, "tvm-cell-sha256:")
		if err != nil {
			return fail("bundle-binding", err)
		}
		if err = tokenQuotePin(quote.Rail.Asset, account.Data.Route, in.Pins); err != nil {
			return fail("asset-pins", err)
		}
		if _, err = serviceactor.VerifyTokenExistingRequest(e, code, &quote.Rail, quote.Proposal, request.Call, b.BuyerWallet, requestHash, acceptance); err != nil {
			return fail("bundle-binding", err)
		}
		if err = verifyTokenFunding(ctx, session, account, b, request); err != nil {
			return fail("funding-chain", err)
		}
		pass("bundle-binding", "Quote, manifest, registry, immutable SAT1 and three funding hops bind the request")
		if in.Receipt != nil {
			root, err := tokenEvidenceBytes(in.Receipt)
			if err != nil {
				return fail("receipt", err)
			}
			if !bytes.Equal(root.ToBOC(), in.Receipt) {
				return fail("receipt", errors.New("Receipt BOC is not its canonical encoding"))
			}
			receipt, err := nativecore.DecodeSoftwareWorkTokenReceiptCellV1(root)
			if err != nil {
				return fail("receipt", err)
			}
			if request.Status != serviceactor.StatusResponded || hex.EncodeToString(root.Hash()) != request.ResponseHash {
				return fail("receipt", errors.New("Receipt is not the finalized response"))
			}
			if err = nativecore.TokenReceiptMatchesQuote(receipt, &nativecore.AcceptedQuoteTermsV1{Network: in.Network, Proposal: quote.Proposal}); err != nil {
				return fail("receipt", err)
			}
			if err = railwork.CheckReceiptBinding(receipt.SoftwareWorkReceiptV1, railwork.ReceiptBinding{QuoteCommitment: "tvm-cell-sha256:" + hex.EncodeToString(q.Hash()), ExecutionID: req.ExecutionID, InputDigest: req.InputDigest, SourceDigest: b.SourceDigest, Price: quote.Rail.PriceAtomic, ProviderAgentID: quote.Proposal.ProviderAgentId, ToolchainDigest: quote.Manifest.ToolchainDigest, SandboxDigest: quote.Proposal.ManifestDigest}); err != nil {
				return fail("receipt", err)
			}
			if receipt.CompletedAt > uint64(request.Terminal.Now) || receipt.CompletedAt >= request.Snapshot.ResponseDeadline {
				return fail("receipt", errors.New("Receipt completion time differs from finalized response"))
			}
			if in.Artifact != nil {
				if len(in.Artifact) > railwork.MaxResultBytes || sha256Text(in.Artifact) != receipt.ArtifactDigest {
					return fail("artifact", errors.New("artifact digest differs"))
				}
				output, report, err := railwork.ArtifactMembers(in.Artifact)
				if err != nil {
					return fail("artifact", err)
				}
				if sha256Text(output) != receipt.ResultDigest || sha256Text(report) != receipt.ReportDigest {
					return fail("artifact", errors.New("artifact members differ"))
				}
			}
			pass("receipt", "schema 2 Receipt and supplied artifact agree with the exact finalized response")
		}
	} else {
		v.NotClaimed = append(v.NotClaimed, NoBundleNotClaimed, "without a token bundle, no asset-recognition or funding-chain claim is made")
		if in.Receipt != nil || in.Artifact != nil {
			return fail("input", errors.New("token Receipt or artifact needs its bundle"))
		}
	}
	if in.Artifact != nil && in.Receipt == nil {
		return fail("input", errors.New("artifact needs Receipt"))
	}
	ids := make([]uint64, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sortTokenIDs(ids)
	for _, id := range ids {
		r := selected[id]
		v.Requests = append(v.Requests, TokenRequestReport{RequestID: id, RequestHash: hex.EncodeToString(r.Snapshot.RequestHash[:]), Caller: r.Snapshot.Caller.Text(), State: r.Status, PriceAtomic: r.Snapshot.Terms.PricePerCall.String(), PayoutID: r.PayoutID, ReturnedID: r.ReturnedID, Destination: r.Destination, Call: toschain.ActorTxID{LT: r.Call.LT, Hash: r.Call.Hash}, ResponseHash: r.ResponseHash, NextAction: serviceactor.TokenRequestAction(r.Status)})
	}
	for index, f := range refusals {
		if selectedRefusals[index] {
			v.FundingRefusals = append(v.FundingRefusals, f)
		}
	}
	v.Result = ResultPass
	return v
}

func tokenQuotePin(asset *nativev1.TOSAssetIdentityV1, route nativecore.ServiceActorTokenAssetRouteV1, pins []toschain.TokenAssetPin) error {
	if err := nativecore.ValidateTokenAssetIdentity(asset); err != nil {
		return err
	}

	pin, err := toschain.MatchTokenAssetPin(route, uint8(asset.Decimals), pins)
	if err != nil {
		return err
	}
	if pin.Master != "0:"+hex.EncodeToString(asset.Master.AccountId) || pin.MinterCodeHash != asset.Master.CodeHash || pin.WalletCodeHash != asset.WalletCodeHash {
		return errors.New("Quote asset differs from client release pin")
	}
	return nil
}
func tokenEvidenceCell(text string) (*cell.Cell, error) {
	if len(text) > 2<<20 {
		return nil, errors.New("evidence BOC text outside bounds")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, err
	}
	return tokenEvidenceBytes(raw)
}
func tokenEvidenceBytes(raw []byte) (*cell.Cell, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("evidence cell outside bounds")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || roots[0] == nil {
		return nil, errors.New("evidence needs one cell root")
	}
	return roots[0], nil
}
func sortTokenIDs(ids []uint64) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}
