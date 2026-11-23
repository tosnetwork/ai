package provideragent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// Time bounds of one method (section 7): a chain read ends after 20
// seconds, and every method answers within 30.
const (
	chainReadTimeout = 20 * time.Second
	preflightTimeout = 25 * time.Second
	// maxRecordsAnswer caps one records answer; the page is shortened to fit.
	maxRecordsAnswer  = 256 << 10
	servingReportTail = 16
)

// StatusView is the status answer (section 4.4).
type StatusView struct {
	Offered bool `json:"offered"`
	// Report is the node's status report with its request list replaced by
	// RequestCounts; it is absent before the offer.
	Report        *servicebridge.ProviderStatus `json:"report,omitempty"`
	RequestCounts map[string]int                `json:"request_counts"`
	Admission     servicebridge.AdmissionStatus `json:"admission"`
	// PauseRecordedAs says whether the agent wrote the current marker for
	// the model or for the wallet floor; empty for any other pause.
	PauseRecordedAs string     `json:"pause_recorded_as,omitempty"`
	Bounds          BoundsView `json:"bounds"`
	Serving         bool       `json:"serving"`
	ServingReport   []string   `json:"untrusted_serving_report"`
}

// BoundsView is the autonomous bounds with today's values.
type BoundsView struct {
	MaxAdmissionsPerDay       uint64                       `json:"max_admissions_per_day"`
	AdmissionsLastDay         uint64                       `json:"admissions_last_24h"`
	MinWalletNanoTOS          string                       `json:"min_wallet_nanotos"`
	Wallet                    *servicebridge.WalletBalance `json:"wallet,omitempty"`
	WalletBelowFloor          bool                         `json:"wallet_below_floor"`
	WalletError               string                       `json:"untrusted_wallet_error,omitempty"`
	MaxWithdrawPreviewsPerDay int                          `json:"max_withdraw_previews_per_day"`
	WithdrawPreviewsLastDay   int                          `json:"withdraw_previews_last_24h"`
}

// chainRefusal maps a failed chain read or library call that sent nothing.
func chainRefusal(err error) error {
	if errors.Is(err, errNotOffered) {
		return agentapi.Refusal(agentapi.CodeNotOffered, "the node has no published offer yet", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return agentapi.Refusal(agentapi.CodeDependencyUnavailable, "the finalized read did not finish within 20 seconds", err)
	}
	return agentapi.Refusal(agentapi.CodeDependencyUnavailable, "finalized state could not be read; nothing was sent", err)
}

// Status is the status method.
func (a *Agent) Status(ctx context.Context, role agentsocket.Role) (any, error) {
	if err := a.limit(role, rateRead, false); err != nil {
		return nil, err
	}
	view := StatusView{RequestCounts: map[string]int{}, ServingReport: a.ring.last(servingReportTail),
		Serving: a.serving.Load()}
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	defer cancel()
	report, err := a.lib.Status(readCtx, a.now())
	switch {
	case errors.Is(err, errNotOffered):
	case err != nil:
		return nil, chainRefusal(err)
	default:
		view.Offered = true
		for _, request := range report.Requests {
			view.RequestCounts[request.OperatorState]++
		}
		report.Requests = nil
		view.Report = report
	}
	if pause, marker, pauseErr := servicebridge.ReadAdmissionPauseMarker(a.rail.StateDir); pauseErr != nil {
		view.Admission = servicebridge.AdmissionStatus{Paused: true, Error: pauseErr.Error()}
	} else if pause != nil {
		view.Admission = servicebridge.AdmissionStatus{Paused: true, PausedUnix: pause.PausedUnix,
			Reason: pause.Reason, Origin: pause.Origin, Stamp: pause.Stamp}
		a.withLock(func() {
			if origin, originErr := a.store.readOrigin(); originErr == nil && origin != nil &&
				string(origin.Marker) == string(marker) {
				view.PauseRecordedAs = origin.Why
			}
		})
	}
	view.Bounds = a.bounds(readCtx)
	return a.out(role, view)
}

// bounds reads today's admission count and the wallet against the floor.
func (a *Agent) bounds(ctx context.Context) BoundsView {
	now := a.now()
	view := BoundsView{MaxAdmissionsPerDay: a.config.MaxAdmissionsPerDay,
		MinWalletNanoTOS:          strconv.FormatUint(a.config.minWallet, 10),
		MaxWithdrawPreviewsPerDay: a.config.MaxWithdrawPreviewsPerDay,
		WithdrawPreviewsLastDay:   a.rates.withdrawalsToday(now)}
	if records, err := a.lib.ProviderRecords(); err == nil {
		view.AdmissionsLastDay = servicebridge.AdmissionsInLastDay(records, now)
	}
	balance, err := a.lib.WalletBalance(ctx)
	if err != nil {
		view.WalletError = err.Error()
		return view
	}
	view.Wallet = &balance
	view.WalletBelowFloor = balance.BalanceNano < a.config.minWallet
	return view
}

var (
	pageTokenPattern = regexp.MustCompile(`^[1-9][0-9]{0,5}$`)
	operatorStates   = map[string]bool{
		servicebridge.OperatorAdmitted: true, servicebridge.OperatorExecuting: true,
		servicebridge.OperatorResultAvailable: true, servicebridge.OperatorResponded: true,
		servicebridge.OperatorRefunded: true, servicebridge.OperatorSwept: true,
		servicebridge.OperatorOutcomeUnknown: true,
	}
)

// RecordsView is a page of the provider's requests, newest first.
type RecordsView struct {
	Records       []json.RawMessage `json:"records"`
	NextPageToken string            `json:"next_page_token,omitempty"`
}

// Records is the records method (section 4.5).
func (a *Agent) Records(ctx context.Context, role agentsocket.Role, params agentapi.RecordsParams) (any, error) {
	if params.OperatorState != "" && !operatorStates[params.OperatorState] {
		return nil, agentapi.Refusal(agentapi.CodeBadInput, "operator_state is not one of the node's operator states", nil)
	}
	if params.PageSize == 0 {
		params.PageSize = agentapi.DefaultRecordsPage
	}
	if params.PageSize < 1 || params.PageSize > agentapi.MaxRecordsPage {
		return nil, agentapi.Refusal(agentapi.CodeBadInput, "page_size must be 1 to 100", nil)
	}
	offset := 0
	if params.PageToken != "" {
		if !pageTokenPattern.MatchString(params.PageToken) {
			return nil, agentapi.Refusal(agentapi.CodeBadInput, "page_token is not a token this agent issued", nil)
		}
		offset, _ = strconv.Atoi(params.PageToken)
	}
	if err := a.limit(role, rateRead, false); err != nil {
		return nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	defer cancel()
	report, err := a.lib.Status(readCtx, a.now())
	if err != nil {
		return nil, chainRefusal(err)
	}
	requests := make([]servicebridge.RequestStatus, 0, len(report.Requests))
	for _, request := range report.Requests {
		if params.OperatorState == "" || request.OperatorState == params.OperatorState {
			requests = append(requests, request)
		}
	}
	sort.SliceStable(requests, func(i, j int) bool {
		if requests[i].UpdatedUnix != requests[j].UpdatedUnix {
			return requests[i].UpdatedUnix > requests[j].UpdatedUnix
		}
		return requests[i].RequestHash < requests[j].RequestHash
	})
	view := RecordsView{Records: []json.RawMessage{}}
	if offset >= len(requests) {
		return view, nil
	}
	size := 0
	for index := offset; index < len(requests) && len(view.Records) < params.PageSize; index++ {
		rendered, err := a.out(role, requests[index])
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(rendered)
		if err != nil {
			return nil, err
		}
		if size+len(encoded) > maxRecordsAnswer && len(view.Records) > 0 {
			break
		}
		size += len(encoded)
		view.Records = append(view.Records, encoded)
	}
	if next := offset + len(view.Records); next < len(requests) {
		view.NextPageToken = strconv.Itoa(next)
	}
	return view, nil
}

// Preflight is the preflight method (section 4.6). A failed check is a
// report with ok false, not a refusal.
func (a *Agent) Preflight(ctx context.Context, role agentsocket.Role) (any, error) {
	if err := a.limit(role, ratePreflight, false); err != nil {
		return nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	return a.out(role, a.lib.Preflight(readCtx))
}

// OfferDescribe is the offer_describe method (section 4.7).
func (a *Agent) OfferDescribe(ctx context.Context, role agentsocket.Role) (any, error) {
	if err := a.limit(role, rateDescribe, false); err != nil {
		return nil, err
	}
	description, err := a.describe(ctx)
	if err != nil {
		return nil, err
	}
	return a.out(role, description)
}

func (a *Agent) describe(ctx context.Context) (*OfferDescription, error) {
	readCtx, cancel := context.WithTimeout(ctx, chainReadTimeout)
	defer cancel()
	description, err := a.lib.DescribeOffer(readCtx, a.config.Offer.OfferPath)
	if errors.Is(err, servicebridge.ErrOfferMismatch) {
		return nil, agentapi.Refusal(agentapi.CodeNotReady, "the offer file does not match finalized state", err)
	}
	if err != nil {
		return nil, chainRefusal(err)
	}
	return description, nil
}

// ExportOffer is the export_offer method (section 4.8): the offer file's
// bytes after the checks of offer_describe. The offer file is public by
// design; the MCP server writes it in the developer account.
func (a *Agent) ExportOffer(ctx context.Context, role agentsocket.Role) (any, error) {
	if err := a.limit(role, rateDescribe, false); err != nil {
		return nil, err
	}
	description, err := a.describe(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := a.lib.OfferFile(a.config.Offer.OfferPath)
	if err != nil {
		return nil, chainRefusal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != description.OfferFileSHA256 {
		return nil, agentapi.Refusal(agentapi.CodeConflict, "the offer file changed while it was checked; ask again", nil)
	}
	// The offer file is returned as it is: it is public and carries no
	// custody path, so the client's view does not rewrite its bytes.
	return agentapi.ExportView{CapabilityID: description.CapabilityID, CapabilityVersion: description.CapabilityVersion,
		SHA256: description.OfferFileSHA256, Bytes: len(raw), OfferBase64: base64.StdEncoding.EncodeToString(raw)}, nil
}
