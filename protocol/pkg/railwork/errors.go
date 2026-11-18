package railwork

import (
	"errors"
)

// Refusal is a stable local refusal label (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1
// section 12). Refusals are never sent on the wire: a receiver drops the
// frame or message and the counterparty learns the outcome from finalized
// actor state.
type Refusal string

// Refusal labels of section 12.
const (
	RefusalPacketInvalid        Refusal = "packet-invalid"
	RefusalNotARailFrame        Refusal = "not-a-rail-frame"
	RefusalFrameInvalid         Refusal = "frame-invalid"
	RefusalFrameConflict        Refusal = "frame-conflict"
	RefusalJoinInvalid          Refusal = "join-invalid"
	RefusalInboxFull            Refusal = "inbox-full"
	RefusalMessageInvalid       Refusal = "message-invalid"
	RefusalTaskNotAdmitted      Refusal = "task-not-admitted"
	RefusalAdmissionPaused      Refusal = "admission-paused"
	RefusalSlotTaken            Refusal = "slot-taken"
	RefusalResultNotAccepted    Refusal = "result-not-accepted"
	RefusalResultRequestRefused Refusal = "result-request-refused"
	RefusalAckUnmatched         Refusal = "ack-unmatched"
)

// Error is a refusal with its reason. errors.Is matches an *Error by its
// label when the target carries no reason, so callers test
// errors.Is(err, railwork.ErrFrameInvalid).
type Error struct {
	Refusal Refusal
	Reason  string
	// Err is the underlying cause, when another package refused first.
	Err error
}

func (e *Error) Error() string {
	if e == nil {
		return "railwork: <nil>"
	}
	text := "railwork: " + string(e.Refusal)
	if e.Reason != "" {
		text += ": " + e.Reason
	}
	if e.Err != nil {
		text += ": " + e.Err.Error()
	}
	return text
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Is matches a reason-less *Error target of the same label.
func (e *Error) Is(target error) bool {
	var other *Error
	if e == nil || !errors.As(target, &other) || other == nil {
		return false
	}
	return other.Reason == "" && other.Err == nil && other.Refusal == e.Refusal
}

// Label sentinels for errors.Is.
var (
	ErrPacketInvalid        = &Error{Refusal: RefusalPacketInvalid}
	ErrNotARailFrame        = &Error{Refusal: RefusalNotARailFrame}
	ErrFrameInvalid         = &Error{Refusal: RefusalFrameInvalid}
	ErrFrameConflict        = &Error{Refusal: RefusalFrameConflict}
	ErrJoinInvalid          = &Error{Refusal: RefusalJoinInvalid}
	ErrInboxFull            = &Error{Refusal: RefusalInboxFull}
	ErrMessageInvalid       = &Error{Refusal: RefusalMessageInvalid}
	ErrTaskNotAdmitted      = &Error{Refusal: RefusalTaskNotAdmitted}
	ErrAdmissionPaused      = &Error{Refusal: RefusalAdmissionPaused}
	ErrSlotTaken            = &Error{Refusal: RefusalSlotTaken}
	ErrResultNotAccepted    = &Error{Refusal: RefusalResultNotAccepted}
	ErrResultRequestRefused = &Error{Refusal: RefusalResultRequestRefused}
	ErrAckUnmatched         = &Error{Refusal: RefusalAckUnmatched}
)

// RefusalOf returns the label of a refusal this package produced.
func RefusalOf(err error) (Refusal, bool) {
	var refusal *Error
	if !errors.As(err, &refusal) || refusal == nil {
		return "", false
	}
	return refusal.Refusal, true
}

func refuse(label Refusal, reason string) error {
	return &Error{Refusal: label, Reason: reason}
}

func refuseWith(label Refusal, reason string, cause error) error {
	return &Error{Refusal: label, Reason: reason, Err: cause}
}
