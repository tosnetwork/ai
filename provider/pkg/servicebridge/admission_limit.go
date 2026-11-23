package servicebridge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// ErrAdmissionLimited reports a task that was not admitted because an
// admission limiter refused one more admission now. It wraps
// ErrAdmissionPaused, so the dispatcher holds the task exactly as it holds
// one while admission is paused: never counted as a failed handling, and
// admitted once the limiter allows it if the request is still admissible.
var ErrAdmissionLimited = fmt.Errorf("%w: an admission limit is reached", ErrAdmissionPaused)

// AdmissionLimiter decides whether one more request may be admitted now.
// The provider asks it right after the pause check, before the executor's
// readiness and the gate, with every provider record it holds; nothing of
// the task is claimed, verified or spent before it answers. A nil answer
// admits; any error holds the task (the provider wraps it in
// ErrAdmissionLimited).
type AdmissionLimiter interface {
	AllowAdmission(now time.Time, records []ProviderRecord) error
}

// AdmissionDay is the interval a daily admission cap counts over.
const AdmissionDay = 24 * time.Hour

// AdmissionsInLastDay counts the records whose admission time
// (ProviderRecord.AdmissionTime) lies within AdmissionDay before now. A
// record dated after now, which a clock set back produces, is counted: the
// count errs toward holding work, never toward admitting more.
func AdmissionsInLastDay(records []ProviderRecord, now time.Time) uint64 {
	since := now.Add(-AdmissionDay).Unix()
	var count uint64
	for _, record := range records {
		if record.AdmissionTime() > since {
			count++
		}
	}
	return count
}

// DailyAdmissionCap admits at most Max requests within any AdmissionDay,
// counted from the provider records' admission times. At the cap a task is
// held, and it is admitted once an admission leaves the interval.
type DailyAdmissionCap struct {
	Max uint64
}

// AllowAdmission implements AdmissionLimiter.
func (c DailyAdmissionCap) AllowAdmission(now time.Time, records []ProviderRecord) error {
	if c.Max == 0 {
		return errors.New("servicebridge: the daily admission cap must be at least 1")
	}
	if count := AdmissionsInLastDay(records, now); count >= c.Max {
		return fmt.Errorf("%w: %d of at most %d admissions in the last 24 hours", ErrAdmissionLimited, count, c.Max)
	}
	return nil
}

// WalletFloorReason is the fixed reason of the pause the wallet floor writes.
const WalletFloorReason = "wallet below the configured floor"

// AccountSession is the part of a finalized reader session the wallet floor
// reads: toschain's ServiceActorSession is one.
type AccountSession interface {
	Checkpoint() uint64
	Account(ctx context.Context, account string) (toschain.FinalizedAccount, error)
}

// The finalized reader's session is what the floor reads in production.
var _ AccountSession = (*toschain.ServiceActorSession)(nil)

// WalletBalance is a wallet's finalized balance at a checkpoint.
type WalletBalance struct {
	Wallet      string `json:"wallet"`
	State       string `json:"state"`
	BalanceNano uint64 `json:"balance_nanotos"`
	Checkpoint  uint64 `json:"checkpoint"`
}

// ReadWalletBalance reads the wallet's state and balance by quorum at the
// session's checkpoint.
func ReadWalletBalance(ctx context.Context, session AccountSession, wallet string) (WalletBalance, error) {
	if ctx == nil || session == nil {
		return WalletBalance{}, errors.New("servicebridge: the wallet balance needs a finalized session")
	}
	if wallet == "" {
		return WalletBalance{}, errors.New("servicebridge: the wallet balance needs the owner wallet's address")
	}
	account, err := session.Account(ctx, wallet)
	if err != nil {
		return WalletBalance{}, fmt.Errorf("servicebridge: read the owner wallet's finalized balance: %w", err)
	}
	return WalletBalance{Wallet: wallet, State: account.State, BalanceNano: account.BalanceNano,
		Checkpoint: session.Checkpoint()}, nil
}

// What a wallet floor check did.
const (
	// WalletFloorPaused: below the floor with no marker; an agent marker was
	// written, whose bytes the caller keeps to lift it later.
	WalletFloorPaused = "paused"
	// WalletFloorHeld: below the floor and already paused, by the floor's
	// own marker or another one; nothing changed.
	WalletFloorHeld = "held"
	// WalletFloorLifted: at or above the floor, and the floor's own marker,
	// still byte for byte as written, was removed.
	WalletFloorLifted = "lifted"
	// WalletFloorKept: at or above the floor, but the marker is no longer the
	// floor's own (re-stamped or replaced); it stays. A marker that cannot
	// be read at all is an error, and stays too.
	WalletFloorKept = "kept"
	// WalletFloorClear: at or above the floor and no floor marker to lift.
	WalletFloorClear = "clear"
)

// WalletFloorOutcome is the result of one wallet floor check.
type WalletFloorOutcome struct {
	Action    string
	Balance   WalletBalance
	FloorNano uint64
	// Pause and Marker are the marker written when Action is
	// WalletFloorPaused, or the marker found when it is WalletFloorHeld.
	Pause  *AdmissionPause
	Marker []byte
}

// ApplyWalletFloor pauses admission while the owner wallet's finalized
// balance is below floorNano, and lifts only its own pause once the balance
// is at or above it.
//
// Below the floor it writes an agent marker with WalletFloorReason when no
// marker exists, and changes nothing when one exists. At or above the floor
// it removes the marker only when floorMarker names the bytes of the marker
// this check wrote earlier and the file still holds exactly them
// (ResumeAdmissionIf): a marker the operator re-stamped, or any other
// marker, is never lifted. The caller passes floorMarker only while its own
// record still holds that pause as the floor's; a pause the caller has since
// given another reason, such as a model's pause over the floor's, is passed
// as nil and so stays until it is resumed for that reason.
func ApplyWalletFloor(
	stateDir string,
	balance WalletBalance,
	floorNano uint64,
	floorMarker []byte,
	now time.Time,
) (WalletFloorOutcome, error) {
	// A zero floor would never pause, so a floor check configured with one
	// is a mistake, not a disabled floor.
	if floorNano == 0 {
		return WalletFloorOutcome{}, errors.New("servicebridge: the wallet floor must be at least 1 nanoTOS")
	}
	outcome := WalletFloorOutcome{Balance: balance, FloorNano: floorNano}
	if balance.BalanceNano < floorNano {
		result, err := PauseAdmissionAs(stateDir, PauseOriginAgent, WalletFloorReason, now)
		if err != nil {
			return WalletFloorOutcome{}, err
		}
		outcome.Pause, outcome.Marker = result.Pause, result.Marker
		outcome.Action = WalletFloorPaused
		if result.Already {
			outcome.Action = WalletFloorHeld
		}
		return outcome, nil
	}
	if len(floorMarker) == 0 {
		outcome.Action = WalletFloorClear
		return outcome, nil
	}
	removed, err := ResumeAdmissionIf(stateDir, floorMarker)
	switch {
	case errors.Is(err, ErrPauseMarkerChanged):
		outcome.Action = WalletFloorKept
		return outcome, nil
	case err != nil:
		return WalletFloorOutcome{}, err
	case removed:
		outcome.Action = WalletFloorLifted
	default:
		// The marker is already gone: someone resumed; nothing to lift.
		outcome.Action = WalletFloorClear
	}
	return outcome, nil
}
