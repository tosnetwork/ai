package quoteprovider

import "errors"

// Error is a Quote Proposal construction that could not read the finalized
// state it needs. Its class is one of the fixed failure texts; its cause is
// the underlying read error, when there is one, so a local caller (a buyer
// building its own Quote) learns why: an unavailable quorum, a checkpoint
// fence, or the object being absent.
//
// A cause can name configured endpoints, whose URLs may carry access
// tokens. A caller that answers remote parties must report only Class
// (PublicError does that) and never Error.
type Error struct {
	class string
	cause error
}

func readError(class string, cause error) error { return &Error{class: class, cause: cause} }

// Error returns the class followed by the cause.
func (e *Error) Error() string {
	if e.cause == nil {
		return e.class
	}
	return e.class + ": " + e.cause.Error()
}

// Unwrap returns the underlying read error, nil when there is none.
func (e *Error) Unwrap() error { return e.cause }

// Class returns the fixed failure text alone.
func (e *Error) Class() string { return e.class }

// PublicError returns err with the cause of any Error in it removed: the
// fixed class alone when err is or wraps an Error, err itself otherwise.
func PublicError(err error) error {
	var quoteErr *Error
	if errors.As(err, &quoteErr) {
		return errors.New(quoteErr.class)
	}
	return err
}
