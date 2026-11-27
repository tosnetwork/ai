package servicebridge

import (
	"errors"
	"time"
)

type tokenWorkCheckpoint interface {
	Checkpoint() uint64
	ChainTime() time.Time
}

// tokenWorkSafety is evaluated at the execution gate and again before
// responding. A stale local monitor cannot authorize new paid execution.
func tokenWorkSafety(c NodeConfig, asset string, s tokenWorkCheckpoint, now time.Time) error {
	if c.Token == nil || s == nil || now.IsZero() {
		return errors.New("servicebridge: token execution has no safety context")
	}
	if pause, err := ReadAdmissionPause(c.StateDir); err != nil || pause != nil {
		return errors.New("servicebridge: token execution is locally paused")
	}
	if now.Before(s.ChainTime()) {
		now = s.ChainTime()
	}
	alerts, err := readTokenMonitor(c, s.Checkpoint(), now.Unix())
	if err != nil {
		return err
	}
	if alerts[asset] {
		return errors.New("servicebridge: asset alarm refuses token execution")
	}
	return nil
}
