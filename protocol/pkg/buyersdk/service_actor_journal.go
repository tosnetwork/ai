package buyersdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

// CallPhase is a Service Actor call's position in the buyer journal.
type CallPhase string

const (
	// PhasePrepared: verified and reserved, not yet handed to custody.
	PhasePrepared CallPhase = "prepared"
	// PhaseSending: durably recorded before custody starts; a record found
	// here at startup is ambiguous.
	PhaseSending CallPhase = "sending"
	// PhaseSubmitted: custody reported the call submitted.
	PhaseSubmitted CallPhase = "submitted"
	// PhaseAmbiguous: custody may or may not have submitted the call; it is
	// never sent again and is resolved only from finalized history.
	PhaseAmbiguous CallPhase = "ambiguous"
	// PhaseAdmitted: the finalized call transaction admitted the request.
	PhaseAdmitted CallPhase = "admitted"
	// PhaseRefused: the finalized call transaction aborted.
	PhaseRefused CallPhase = "refused"
	// PhaseWithdrawn: withdrawn while still prepared. It was never handed to
	// custody, holds no reservation and is never sent.
	PhaseWithdrawn CallPhase = "withdrawn"
)

const callRecordSchema = "tos.service.service-actor-call.v1"

// CallRecord is the durable record of one Service Actor purchase. It holds
// every input the call and its later resolution need.
type CallRecord struct {
	Schema             string    `json:"schema"`
	RequestHash        string    `json:"request_hash"`
	QueryID            uint64    `json:"query_id"`
	NetworkID          string    `json:"network_id"`
	GenesisRootHash    string    `json:"genesis_root_hash"`
	GenesisFileHash    string    `json:"genesis_file_hash"`
	BuyerWallet        string    `json:"buyer_wallet"`
	Actor              string    `json:"actor"`
	ActorCodeHash      string    `json:"actor_code_hash"`
	CapabilityID       string    `json:"capability_id"`
	CapabilityVersion  string    `json:"capability_version"`
	PackageBase64      string    `json:"package_base64"`
	BuyerAddressInReq  string    `json:"request_buyer_address"`
	AcceptedQuoteBOC   string    `json:"accepted_quote_boc"`
	QuoteCommitment    string    `json:"quote_commitment"`
	ExecutionID        string    `json:"execution_id"`
	InputDigest        string    `json:"input_digest"`
	TermsHash          string    `json:"terms_hash"`
	PolicyVersion      uint32    `json:"policy_version"`
	PriceNanoTOS       string    `json:"price_nanotos"`
	StorageFeeNanoTOS  string    `json:"storage_fee_nanotos"`
	AttestorKeyID      string    `json:"attestor_key_id"`
	PaymentNanoTOS     string    `json:"payment_nanotos"`
	ExpiresAtUnix      uint64    `json:"expires_at_unix_seconds"`
	Phase              CallPhase `json:"phase"`
	CreatedUnix        int64     `json:"created_unix"`
	UpdatedUnix        int64     `json:"updated_unix"`
	SentUnix           int64     `json:"sent_unix,omitempty"`
	RequestID          *uint64   `json:"request_id,omitempty"`
	CallTransactionLT  uint64    `json:"call_transaction_lt,omitempty"`
	CallTransactionHex string    `json:"call_transaction_hash,omitempty"`
	ExitCode           int32     `json:"exit_code,omitempty"`
	// The admitted policy's response SLA, refund claim window and cleanup
	// bounty. They are fields of the terms whose hash the call pins, so
	// they are exactly the terms the call is admitted under.
	ResponseSLASeconds       uint32 `json:"response_sla_seconds,omitempty"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds,omitempty"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos,omitempty"`
	// Lifecycle holds the expire, claim_refund and sweep sends for the
	// admitted request, oldest first.
	Lifecycle []LifecycleSend `json:"lifecycle,omitempty"`
}

// ServiceActorLimits bounds what the buyer may reserve.
type ServiceActorLimits struct {
	Window            time.Duration
	MaxCalls          int
	MaxPerCallNanoTOS *big.Int
	MaxWindowNanoTOS  *big.Int
	// MaxPrepared bounds the unexpired prepared records, which wait for a
	// decision and reserve budget meanwhile. Zero means no bound beyond
	// MaxCalls; when set it is at most MaxCalls.
	MaxPrepared int
}

func (l ServiceActorLimits) valid() bool {
	return l.Window > 0 && l.Window <= 31*24*time.Hour && l.MaxCalls > 0 && l.MaxCalls <= 100_000 &&
		l.MaxPerCallNanoTOS != nil && l.MaxPerCallNanoTOS.Sign() > 0 && l.MaxWindowNanoTOS != nil &&
		l.MaxWindowNanoTOS.Cmp(l.MaxPerCallNanoTOS) >= 0 && l.MaxPrepared >= 0 && l.MaxPrepared <= l.MaxCalls
}

// Valid reports whether the limits are bounded and consistent.
func (l ServiceActorLimits) Valid() bool { return l.valid() }

// ErrTooManyPrepared reports that the unexpired prepared records already
// reach MaxPrepared.
var ErrTooManyPrepared = errors.New("too many prepared calls are waiting for a decision")

// ErrOverBudget is what every per-call and window budget refusal is.
var ErrOverBudget = errors.New("the call is over the buyer's budget")

// ErrQuoteExpired reports a Quote past its expiry.
var ErrQuoteExpired = errors.New("the Quote has expired")

type budgetError string

func (e budgetError) Error() string { return string(e) }

func (e budgetError) Is(target error) bool { return target == ErrOverBudget }

// ServiceActorJournal is an owner-private directory of call records. Every
// read-modify-write holds one exclusive file lock across processes, and every
// write is an atomic, synced replacement.
type ServiceActorJournal struct{ directory string }

// OpenServiceActorJournal opens the journal and recovers every record left
// in the sending phase as ambiguous.
func OpenServiceActorJournal(directory string, now time.Time) (*ServiceActorJournal, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("buyer journal directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return nil, errors.New("buyer journal directory must be owner-private")
	}
	journal := &ServiceActorJournal{directory: directory}
	err = journal.withLock(func() error {
		records, err := journal.recordsUnlocked()
		if err != nil {
			return err
		}
		for _, record := range records {
			changed := false
			if record.Phase == PhaseSending {
				record.Phase, changed = PhaseAmbiguous, true
			}
			for index := range record.Lifecycle {
				if record.Lifecycle[index].Phase == PhaseSending {
					record.Lifecycle[index].Phase, changed = PhaseAmbiguous, true
				}
			}
			if changed {
				record.UpdatedUnix = now.Unix()
				if err := journal.writeUnlocked(record); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return journal, nil
}

// ReadServiceActorCallRecord reads one record of the journal in directory
// without opening the journal: unlike OpenServiceActorJournal it recovers
// nothing and writes no record, so it is safe while the agent that owns the
// journal runs. It holds the journal lock for the read, so it never sees a
// record half way through a transition.
func ReadServiceActorCallRecord(directory, requestHash string) (CallRecord, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return CallRecord{}, errors.New("buyer journal directory must be absolute and clean")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return CallRecord{}, errors.New("buyer journal directory must be owner-private")
	}
	return (&ServiceActorJournal{directory: directory}).Read(requestHash)
}

func (j *ServiceActorJournal) withLock(fn func() error) error {
	return osguard.WithExclusiveFileLock(filepath.Join(j.directory, "journal.lock"), 0o600, fn)
}

func (j *ServiceActorJournal) path(requestHash string) string {
	return filepath.Join(j.directory, "call-"+requestHash+".json")
}

func validHex64(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value && !bytes.Equal(raw, make([]byte, 32))
}

// reservation reports what a record holds against the budget at now: an
// outstanding call (prepared and unexpired, sending, submitted or
// ambiguous) holds its payment whatever its age; an admitted call counts
// while its send time is inside the window; a refused call holds nothing.
func (r CallRecord) reservation(now time.Time, window time.Duration) bool {
	switch r.Phase {
	case PhaseRefused, PhaseWithdrawn:
		return false
	case PhasePrepared:
		return uint64(now.Unix()) < r.ExpiresAtUnix
	case PhaseAdmitted:
		return r.SentUnix > now.Add(-window).Unix()
	default:
		return true
	}
}

// fitsBudget checks the limits with candidate counted once, in addition to
// every other record's reservation.
func fitsBudget(records []CallRecord, candidate CallRecord, limits ServiceActorLimits, now time.Time) error {
	payment, ok := new(big.Int).SetString(candidate.PaymentNanoTOS, 10)
	if !ok || payment.Sign() <= 0 || payment.Cmp(limits.MaxPerCallNanoTOS) > 0 {
		return budgetError("the call payment exceeds the per-call limit")
	}
	total, calls := new(big.Int).Set(payment), 1
	for _, existing := range records {
		if existing.RequestHash == candidate.RequestHash || !existing.reservation(now, limits.Window) {
			continue
		}
		amount, ok := new(big.Int).SetString(existing.PaymentNanoTOS, 10)
		if !ok {
			return errors.New("a journal record carries an invalid payment")
		}
		total.Add(total, amount)
		calls++
	}
	if calls > limits.MaxCalls || total.Cmp(limits.MaxWindowNanoTOS) > 0 {
		return budgetError("the call exceeds the buyer's window budget")
	}
	return nil
}

// Create stores a new prepared record after checking that its request hash
// and query id were never used and that its reservation fits the limits.
func (j *ServiceActorJournal) Create(record CallRecord, limits ServiceActorLimits, now time.Time) error {
	if record.Schema != callRecordSchema || record.Phase != PhasePrepared || !validHex64(record.RequestHash) || record.QueryID == 0 {
		return errors.New("invalid Service Actor call record")
	}
	if !limits.valid() {
		return errors.New("invalid buyer limits")
	}
	return j.withLock(func() error {
		records, err := j.recordsUnlocked()
		if err != nil {
			return err
		}
		for _, existing := range records {
			if existing.RequestHash == record.RequestHash {
				return errors.New("this request_hash was already used; a request_hash is never reused")
			}
			if existing.QueryID == record.QueryID {
				return errors.New("this query_id was already used")
			}
		}
		if err := fitsBudget(records, record, limits, now); err != nil {
			return err
		}
		if limits.MaxPrepared > 0 && waitingPrepared(records, now) >= limits.MaxPrepared {
			return ErrTooManyPrepared
		}
		return j.writeUnlocked(record)
	})
}

// waitingPrepared counts the prepared records whose Quote has not expired.
func waitingPrepared(records []CallRecord, now time.Time) int {
	count := 0
	for _, record := range records {
		if record.Phase == PhasePrepared && uint64(now.Unix()) < record.ExpiresAtUnix {
			count++
		}
	}
	return count
}

// Withdraw moves a prepared record to withdrawn under the lock. A record in
// any other phase is refused with its phase, so a call that custody may
// already hold is never withdrawn.
func (j *ServiceActorJournal) Withdraw(requestHash string, now time.Time) (CallRecord, error) {
	return j.Transition(requestHash, []CallPhase{PhasePrepared}, func(r *CallRecord) error {
		r.Phase, r.UpdatedUnix = PhaseWithdrawn, now.Unix()
		return nil
	})
}

// Records returns every record, ordered by request hash.
func (j *ServiceActorJournal) Records() ([]CallRecord, error) {
	var result []CallRecord
	err := j.withLock(func() error {
		records, err := j.recordsUnlocked()
		result = records
		return err
	})
	return result, err
}

// Reserved returns the payment total and the call count that the limits'
// window currently holds, counted as the budget check counts them.
func (j *ServiceActorJournal) Reserved(limits ServiceActorLimits, now time.Time) (*big.Int, int, error) {
	if !limits.valid() {
		return nil, 0, errors.New("invalid buyer limits")
	}
	total, calls := new(big.Int), 0
	err := j.withLock(func() error {
		records, err := j.recordsUnlocked()
		if err != nil {
			return err
		}
		for _, record := range records {
			if !record.reservation(now, limits.Window) {
				continue
			}
			amount, ok := new(big.Int).SetString(record.PaymentNanoTOS, 10)
			if !ok {
				return errors.New("a journal record carries an invalid payment")
			}
			total.Add(total, amount)
			calls++
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return total, calls, nil
}

// BeginSend moves a prepared record to sending under the lock, after
// rechecking at that instant that its Quote is unexpired and that its
// reservation still fits the limits.
func (j *ServiceActorJournal) BeginSend(requestHash string, limits ServiceActorLimits, now time.Time) (CallRecord, error) {
	var result CallRecord
	if !limits.valid() {
		return result, errors.New("invalid buyer limits")
	}
	err := j.withLock(func() error {
		records, err := j.recordsUnlocked()
		if err != nil {
			return err
		}
		record, err := j.readUnlocked(requestHash)
		if err != nil {
			return err
		}
		if record.Phase != PhasePrepared {
			return fmt.Errorf("call %s is %s and is never sent again", requestHash, record.Phase)
		}
		if uint64(now.Unix()) >= record.ExpiresAtUnix {
			return ErrQuoteExpired
		}
		if err := fitsBudget(records, record, limits, now); err != nil {
			return err
		}
		record.Phase, record.UpdatedUnix, record.SentUnix = PhaseSending, now.Unix(), now.Unix()
		if err := j.writeUnlocked(record); err != nil {
			return err
		}
		result = record
		return nil
	})
	return result, err
}

// Transition moves a record from one phase to the next under the lock, so
// that two processes never both start the same call.
func (j *ServiceActorJournal) Transition(requestHash string, from []CallPhase, update func(*CallRecord) error) (CallRecord, error) {
	var result CallRecord
	err := j.withLock(func() error {
		record, err := j.readUnlocked(requestHash)
		if err != nil {
			return err
		}
		allowed := false
		for _, phase := range from {
			allowed = allowed || record.Phase == phase
		}
		if !allowed {
			return fmt.Errorf("call %s is %s", requestHash, record.Phase)
		}
		if err := update(&record); err != nil {
			return err
		}
		if err := j.writeUnlocked(record); err != nil {
			return err
		}
		result = record
		return nil
	})
	return result, err
}

// Read returns one record.
func (j *ServiceActorJournal) Read(requestHash string) (CallRecord, error) {
	var result CallRecord
	err := j.withLock(func() error {
		record, err := j.readUnlocked(requestHash)
		result = record
		return err
	})
	return result, err
}

func (j *ServiceActorJournal) recordsUnlocked() ([]CallRecord, error) {
	entries, err := os.ReadDir(j.directory)
	if err != nil {
		return nil, err
	}
	var records []CallRecord
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "call-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		record, err := j.readUnlocked(strings.TrimSuffix(strings.TrimPrefix(name, "call-"), ".json"))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(a, b int) bool { return records[a].RequestHash < records[b].RequestHash })
	return records, nil
}

func (j *ServiceActorJournal) readUnlocked(requestHash string) (CallRecord, error) {
	var record CallRecord
	if !validHex64(requestHash) {
		return record, errors.New("invalid request_hash")
	}
	path := j.path(requestHash)
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) || info.Size() > maxCallRecordBytes {
		return record, errors.New("journal record is not an owner-private regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("journal record %s does not decode: %w", requestHash, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return record, errors.New("journal record has trailing data")
	}
	if record.Schema != callRecordSchema || record.RequestHash != requestHash {
		return record, errors.New("journal record names another call")
	}
	return record, nil
}

// maxCallRecordBytes bounds one journal record file. The writer enforces it
// before publishing, so a record the reader would refuse is never written:
// startup and budget checks read every record, and one unreadable record
// would make the whole journal unusable.
const maxCallRecordBytes = 1 << 20

func (j *ServiceActorJournal) writeUnlocked(record CallRecord) error {
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if len(raw)+1 > maxCallRecordBytes {
		return fmt.Errorf("journal record is %d bytes, above the %d-byte limit", len(raw)+1, maxCallRecordBytes)
	}
	file, err := os.CreateTemp(j.directory, ".call-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, j.path(record.RequestHash)); err != nil {
		return err
	}
	directory, err := os.Open(j.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
