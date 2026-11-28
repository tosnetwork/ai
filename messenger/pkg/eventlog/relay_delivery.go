package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

// ErrAckMismatch reports a delivery ack that names another copy than the one
// on record.
var ErrAckMismatch = errors.New("delivery ack does not match the carried copy")

func (d Delivery) dueAt() uint64 {
	if d.State == StateCarried {
		return d.NextRedepositAtUnix
	}
	return d.NextAttemptAtUnix
}

// Carried records that a relay accepted deposit generation gen of a sealed
// copy. Only the attempt holding the delivery may record it. The same
// generation may be recorded again, which is what a retry after a crash
// between the carrier's answer and this write does; a generation that skips
// ahead is refused. redepositAt at or past the copy's own expiry means no
// further deposit is scheduled.
func (j *Journal) Carried(deliveryID, attemptID string, gen RelayGeneration, redepositAt, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if !validDeliveryID(deliveryID) {
		return Delivery{}, errors.New("invalid delivery identifier")
	}
	if now.IsZero() || now.Unix() < 0 || redepositAt.Unix() <= now.Unix() {
		return Delivery{}, errors.New("invalid relay carriage time")
	}
	if gen.Generation == 0 || !canon.ValidDigest(gen.DescriptorDigest) || gen.DescriptorIssuedAtUnix == 0 ||
		gen.CardDigest != "" && !canon.ValidDigest(gen.CardDigest) ||
		gen.CredentialDigest != "" && !canon.ValidDigest(gen.CredentialDigest) {
		return Delivery{}, errors.New("invalid relay generation")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.deliveryPath(deliveryID)
	delivery, err := readDelivery(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Delivery{}, ErrUnknown
		}
		return Delivery{}, err
	}
	if delivery.State != StatePending && delivery.State != StateCarried {
		return Delivery{}, ErrNotPending
	}
	if err := holdsAttempt(delivery, attemptID); err != nil {
		return Delivery{}, err
	}
	if delivery.CiphertextBase64 == "" {
		return Delivery{}, errors.New("an unsealed copy cannot be carried")
	}
	if gen.Generation != delivery.Generation && gen.Generation != delivery.Generation+1 {
		return Delivery{}, errors.New("relay generation does not follow the recorded one")
	}
	seconds := uint64(now.Unix())
	gen.DepositedAtUnix = seconds
	delivery.State = StateCarried
	delivery.Generation = gen.Generation
	delivery.LastDepositAtUnix = seconds
	delivery.NextAttemptAtUnix = 0
	delivery.LastCode = ""
	delivery.AttemptID = ""
	delivery.AttemptExpiresAt = 0
	delivery.NextRedepositAtUnix = uint64(redepositAt.Unix())
	if delivery.NextRedepositAtUnix >= delivery.ExpiresAtUnix {
		delivery.NextRedepositAtUnix = 0
	}
	replaced := false
	for index := range delivery.Generations {
		if delivery.Generations[index].Generation == gen.Generation {
			delivery.Generations[index] = gen
			replaced = true
		}
	}
	if !replaced {
		delivery.Generations = append(delivery.Generations, gen)
	}
	if extra := len(delivery.Generations) - MaxRelayGenerations; extra > 0 {
		delivery.Generations = append([]RelayGeneration(nil), delivery.Generations[extra:]...)
	}
	return j.commitDelivery(path, delivery)
}

// RelayAckMatch is what a verified delivery ack names about a copy.
type RelayAckMatch struct {
	SessionID        string
	DeviceID         string
	CiphertextDigest string
}

// DeliveredByAck settles a carried copy on a verified Endpoint-signed ack
// whose session, device and ciphertext digest are those on record. It needs
// no attempt lease, since the ack arrives on its own schedule. A copy already
// delivered reports changed=false.
func (j *Journal) DeliveredByAck(deliveryID string, match RelayAckMatch, now time.Time) (Delivery, bool, error) {
	delivery, path, err := j.lockedRelayAckTarget(deliveryID, match, now)
	if err != nil {
		return Delivery{}, false, err
	}
	defer j.mutex.Unlock()
	if delivery.State == StateDelivered {
		return delivery, false, nil
	}
	// A sealed pending copy is accepted too: the carrier may have deposited it
	// and its ack arrived before Carried was recorded, or the process died in
	// between. The signed ack binds the ciphertext digest, which exists only
	// once the copy is sealed, so this settles nothing that was not sent.
	if delivery.State != StateCarried && delivery.State != StatePending {
		return Delivery{}, false, ErrNotPending
	}
	delivery.State = StateDelivered
	delivery.NextAttemptAtUnix = 0
	delivery.NextRedepositAtUnix = 0
	delivery.AttemptID = ""
	delivery.AttemptExpiresAt = 0
	delivery.LastCode = ""
	delivery.SettledAtUnix = uint64(now.Unix())
	settled, err := j.commitDelivery(path, delivery)
	return settled, err == nil, err
}

// RelayRejected applies a verified rejected ack. descriptor-expired keeps the
// copy pending, records the own descriptor that was refused and schedules the
// next deposit at retryAt, which the caller derived from the single "newer"
// rule; any other code takes the code's own disposition.
func (j *Journal) RelayRejected(deliveryID string, match RelayAckMatch, code fault.Code,
	rejectedDescriptor string, retryAt, now time.Time) (Delivery, error) {
	if !fault.Known(code) {
		return Delivery{}, errors.New("invalid relay rejection code")
	}
	if code == fault.CodeDescriptorExpired && (!canon.ValidDigest(rejectedDescriptor) || retryAt.Before(now)) {
		return Delivery{}, errors.New("descriptor-expired needs the refused descriptor and a retry time")
	}
	delivery, path, err := j.lockedRelayAckTarget(deliveryID, match, now)
	if err != nil {
		return Delivery{}, err
	}
	defer j.mutex.Unlock()
	// A sealed pending copy is accepted too: the carrier may have deposited it
	// and its ack arrived before Carried was recorded, or the process died in
	// between. The signed ack binds the ciphertext digest, which exists only
	// once the copy is sealed, so this settles nothing that was not sent.
	if delivery.State != StateCarried && delivery.State != StatePending {
		return Delivery{}, ErrNotPending
	}
	delivery.AttemptID = ""
	delivery.AttemptExpiresAt = 0
	seconds := uint64(now.Unix())
	if code != fault.CodeDescriptorExpired {
		return j.commitDelivery(path, applyFailure(delivery, code, seconds))
	}
	if delivery.Attempts < ^uint32(0) {
		delivery.Attempts++
	}
	delivery.State = StatePending
	delivery.LastCode = code
	delivery.RejectedDescriptorDigest = rejectedDescriptor
	delivery.NextRedepositAtUnix = 0
	next := uint64(retryAt.Unix())
	if next >= delivery.ExpiresAtUnix {
		// Its own lifetime ends before a retry: a relay held it and no
		// device accepted it, which the owner surface reports as such.
		delivery.State = StateAbandoned
		delivery.LastCode = fault.CodeRetentionExceeded
		delivery.NextAttemptAtUnix = 0
		delivery.SettledAtUnix = seconds
	} else {
		delivery.NextAttemptAtUnix = next
	}
	return j.commitDelivery(path, delivery)
}

// lockedRelayAckTarget reads and matches the delivery an ack names and
// returns with the journal mutex held on success.
func (j *Journal) lockedRelayAckTarget(deliveryID string, match RelayAckMatch, now time.Time) (Delivery, string, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, "", err
	}
	if !deliveryCopyPattern.MatchString(deliveryID) || !sessionPattern.MatchString(match.SessionID) ||
		!ids.Device.MatchString(match.DeviceID) || !canon.ValidDigest(match.CiphertextDigest) {
		return Delivery{}, "", errors.New("invalid relay delivery ack target")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Delivery{}, "", errors.New("invalid relay delivery ack time")
	}
	j.mutex.Lock()
	path := j.deliveryPath(deliveryID)
	delivery, err := readDelivery(path)
	if err != nil {
		j.mutex.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			return Delivery{}, "", ErrUnknown
		}
		return Delivery{}, "", err
	}
	if delivery.SessionID != match.SessionID || delivery.RecipientDeviceID != match.DeviceID ||
		delivery.CiphertextBase64 == "" || delivery.CiphertextDigest != match.CiphertextDigest {
		j.mutex.Unlock()
		return Delivery{}, "", ErrAckMismatch
	}
	return delivery, path, nil
}

// Defer releases an attempt without counting it: the copy was not sealed or
// not deposited because a precondition outside the sender's control failed,
// such as the recipient's stored evidence. A carried copy returns to pending
// and keeps its ciphertext and generation; a sealed copy is not re-deposited
// while it is deferred.
func (j *Journal) Defer(deliveryID, attemptID string, code fault.Code, nextAt, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if !validDeliveryID(deliveryID) || !fault.Known(code) {
		return Delivery{}, errors.New("invalid delivery deferral")
	}
	if now.IsZero() || now.Unix() < 0 || !nextAt.After(now) {
		return Delivery{}, errors.New("invalid delivery deferral time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.deliveryPath(deliveryID)
	delivery, err := readDelivery(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Delivery{}, ErrUnknown
		}
		return Delivery{}, err
	}
	if delivery.State != StatePending && delivery.State != StateCarried {
		return Delivery{}, ErrNotPending
	}
	if err := holdsAttempt(delivery, attemptID); err != nil {
		return Delivery{}, err
	}
	delivery.AttemptID = ""
	delivery.AttemptExpiresAt = 0
	delivery.State = StatePending
	delivery.LastCode = code
	delivery.NextRedepositAtUnix = 0
	delivery.NextAttemptAtUnix = uint64(nextAt.Unix())
	return j.commitDelivery(path, delivery)
}

// WakeDeliveries makes the named pending copies due now. It is used once
// fresher evidence for their recipient has been committed. A copy that is no
// longer pending, or is held by an attempt, is left alone.
func (j *Journal) WakeDeliveries(deliveryIDs []string, now time.Time) (int, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return 0, errors.New("invalid delivery wake")
	}
	for _, deliveryID := range deliveryIDs {
		if !validDeliveryID(deliveryID) {
			return 0, errors.New("invalid delivery identifier")
		}
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	seconds := uint64(now.Unix())
	woken := 0
	for _, deliveryID := range deliveryIDs {
		path := j.deliveryPath(deliveryID)
		delivery, err := readDelivery(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return woken, err
		}
		if delivery.State != StatePending || delivery.NextAttemptAtUnix <= seconds || delivery.AttemptExpiresAt > seconds {
			continue
		}
		delivery.NextAttemptAtUnix = seconds
		if _, err := j.commitDelivery(path, delivery); err != nil {
			return woken, err
		}
		woken++
	}
	return woken, nil
}

// OpenDeliveries returns every delivery not yet settled: pending, held or
// carried. Unreadable records are skipped, as in Due.
func (j *Journal) OpenDeliveries() ([]Delivery, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	entries, err := os.ReadDir(j.outboundRoot())
	if err != nil {
		return nil, errors.New("read delivery journal")
	}
	var open []Delivery
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		delivery, err := readDelivery(j.deliveryPathForFile(entry.Name()))
		if err != nil {
			continue
		}
		switch delivery.State {
		case StatePending, StateHeld, StateCarried:
			open = append(open, delivery)
		}
	}
	return open, nil
}

// previousDeliverySchema is the delivery record schema before relay
// carriage.
const previousDeliverySchema = "tos.messaging.delivery-journal.v1"

// ErrPreRelayDeliveryJournal reports a state directory written before the
// delivery schema gained relay carriage. The project is pre-launch and does
// not migrate: the state is reset rather than read as something it is not.
var ErrPreRelayDeliveryJournal = errors.New("pre-relay delivery journal; reset state")

// refusePreRelayDeliveries refuses a store holding any v1 delivery record.
// Such records would otherwise be skipped as unreadable, and their events
// silently never sent.
func refusePreRelayDeliveries(outbound string) error {
	entries, err := os.ReadDir(outbound)
	if err != nil {
		return errors.New("read delivery journal")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := readRecordBytes(filepath.Join(outbound, entry.Name()))
		if err != nil {
			continue
		}
		var header struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &header) == nil && header.Schema == previousDeliverySchema {
			return ErrPreRelayDeliveryJournal
		}
	}
	return nil
}
