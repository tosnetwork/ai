package buyerinit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

// chainStep drives one chain message. Finalized state is read first, so a
// message that landed is never sent again; a message that may still be in
// flight is waited on until it lands or its window passes on finalized chain
// time; only then is a message sent, after the step is durably marked as
// sending. A plan reports what it would send and stops there.
func (r *run) chainStep(id, what string, step *ChainStep, valueNano uint64, effect func(Session) (bool, error),
	send func(ctx context.Context) error) error {
	session, err := r.begin()
	if err != nil {
		return err
	}
	done, err := effect(session)
	if err != nil {
		return err
	}
	if done {
		return r.finalize(id, what, step, session, StatusAlready)
	}
	if step.State == stepSending {
		expiry := time.Unix(step.StartedUnix, 0).Add(sendResolutionWindow)
		if !session.ChainTime().After(expiry) {
			done, session, err = r.await(effect, expiry)
			if err != nil {
				return err
			}
			if done {
				return r.finalize(id, what, step, session, StatusDone)
			}
			if !session.ChainTime().After(expiry) {
				return fmt.Errorf("%w: %s was sent at %s and is neither finalized nor past its window; nothing was "+
					"re-sent, run init apply again later", ErrOutcomeUnknown, what,
					time.Unix(step.StartedUnix, 0).UTC().Format(time.RFC3339))
			}
		}
		r.env.Report(id + ": the earlier send is past its window on finalized chain time and absent, so it can no " +
			"longer land")
	}
	if !r.apply {
		if valueNano > 0 {
			r.note(id, StatusPlanned, "%s will be sent, attaching %d nanoTOS", what, valueNano)
		} else {
			r.note(id, StatusPlanned, "%s will be sent", what)
		}
		return nil
	}
	if !r.env.Yes {
		prompt := fmt.Sprintf("Send %s", what)
		if valueNano > 0 {
			prompt += fmt.Sprintf(", attaching %d nanoTOS", valueNano)
		}
		confirmed := false
		if r.env.Confirm != nil {
			if confirmed, err = r.env.Confirm(prompt + "?"); err != nil {
				return err
			}
		}
		if !confirmed {
			return ErrConfirmationRequired
		}
	}
	// The send's deadline starts before the stamp, so tosctl cannot sign
	// later than maxSendTime after it (sendResolutionWindow). The stamp and
	// tosctl's own expiry both come from this host's clock, so a host clock
	// off the chain's moves both alike.
	sendCtx, cancel := context.WithTimeout(r.ctx, maxSendTime)
	defer cancel()
	// The record says a message may be in flight before tosctl runs.
	step.State, step.StartedUnix = stepSending, r.env.Now().Unix()
	step.Attempts++
	if err := r.save(); err != nil {
		return err
	}
	if err := send(sendCtx); err != nil {
		if errors.Is(err, buyersdk.ErrCallNotStarted) {
			step.State = stepPending
			return errors.Join(err, r.save())
		}
		r.env.Report(fmt.Sprintf("%s: %v; the message may still have been broadcast, waiting for finalized state", id, err))
	}
	done, session, err = r.await(effect, time.Time{})
	if err != nil {
		return err
	}
	if !done {
		return fmt.Errorf("%w: %s was sent and is not in finalized state yet; nothing will be re-sent, run init "+
			"apply again to resume", ErrOutcomeUnknown, what)
	}
	return r.finalize(id, what, step, session, StatusDone)
}

func (r *run) finalize(id, what string, step *ChainStep, session Session, status string) error {
	if step.State == stepSending {
		status = StatusDone
	}
	step.State, step.Checkpoint = stepFinalized, session.Checkpoint()
	if err := r.save(); err != nil {
		return err
	}
	r.note(id, status, "%s is in finalized state at checkpoint %d", what, session.Checkpoint())
	return nil
}

// await polls finalized state until the effect is present, the chain time
// passes stopAfter (when set), or the wait budget ends. It returns the last
// session it read.
func (r *run) await(effect func(Session) (bool, error), stopAfter time.Time) (bool, Session, error) {
	deadline := r.env.Now().Add(r.env.WaitBudget)
	var last Session
	for {
		session, err := r.begin()
		if err == nil {
			last = session
			done, effectErr := effect(session)
			if effectErr != nil {
				return false, session, effectErr
			}
			if done || (!stopAfter.IsZero() && session.ChainTime().After(stopAfter)) {
				return done, session, nil
			}
		}
		if !r.env.Now().Before(deadline) {
			if last == nil {
				return false, nil, err
			}
			return false, last, nil
		}
		if err := r.env.Sleep(r.ctx, r.env.PollInterval); err != nil {
			return false, last, err
		}
	}
}
