package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

type agentDigest = [agentpacketseal.AgentDigestSize]byte

// Limits are the operator's resource bounds. Every field is required: there
// is no unlimited default, and no value may exceed the V1 ceiling.
type Limits struct {
	// PerRecipientMaxEnvelopes is at most MaxPerRecipientEnvelopes.
	PerRecipientMaxEnvelopes int
	// PerRecipientMaxBytes is at most MaxPerRecipientBytes.
	PerRecipientMaxBytes int64
	// PerClientRecipientMaxEnvelopes is at most
	// MaxPerClientRecipientEnvelopes.
	PerClientRecipientMaxEnvelopes int
	// GlobalMaxEntries bounds stored envelopes plus held tombstones.
	GlobalMaxEntries int
	// GlobalMaxBytes bounds the stored envelope bytes.
	GlobalMaxBytes int64
	// TTL is the retention after receipt, at most MaxTTL.
	TTL time.Duration
}

// DefaultLimits returns the V1 ceilings with the given global bounds.
func DefaultLimits(globalMaxEntries int, globalMaxBytes int64) Limits {
	return Limits{
		PerRecipientMaxEnvelopes: MaxPerRecipientEnvelopes, PerRecipientMaxBytes: MaxPerRecipientBytes,
		PerClientRecipientMaxEnvelopes: MaxPerClientRecipientEnvelopes,
		GlobalMaxEntries:               globalMaxEntries, GlobalMaxBytes: globalMaxBytes, TTL: MaxTTL,
	}
}

// Validate checks every bound.
func (l Limits) Validate() error {
	switch {
	case l.PerRecipientMaxEnvelopes <= 0 || l.PerRecipientMaxEnvelopes > MaxPerRecipientEnvelopes:
		return fmt.Errorf("per-recipient envelope limit must be in 1..%d", MaxPerRecipientEnvelopes)
	case l.PerRecipientMaxBytes < MaxEnvelopeBytes || l.PerRecipientMaxBytes > MaxPerRecipientBytes:
		return fmt.Errorf("per-recipient byte limit must be in %d..%d", MaxEnvelopeBytes, MaxPerRecipientBytes)
	case l.PerClientRecipientMaxEnvelopes <= 0 || l.PerClientRecipientMaxEnvelopes > MaxPerClientRecipientEnvelopes:
		return fmt.Errorf("per-(client, recipient) envelope limit must be in 1..%d", MaxPerClientRecipientEnvelopes)
	case l.GlobalMaxEntries <= 0:
		return errors.New("a global entry limit is required")
	case l.GlobalMaxBytes < MaxEnvelopeBytes:
		return fmt.Errorf("a global byte limit of at least %d is required", MaxEnvelopeBytes)
	case l.TTL < time.Second || l.TTL > MaxTTL || l.TTL%time.Second != 0:
		return fmt.Errorf("TTL must be whole seconds in 1s..%s", MaxTTL)
	}
	return nil
}

// Store outcomes.
var (
	// ErrStoreUnavailable is a persistence failure or a closed store.
	ErrStoreUnavailable = errors.New("agentpacketrelay: store unavailable")
	errStoreCorrupt     = errors.New("agentpacketrelay: store state is corrupt")
)

// depositStatus is the store's answer to a deposit.
type depositStatus int

const (
	depositCreated depositStatus = iota + 1
	depositDuplicate
	depositGone
	depositConflict
	depositQuota
)

// ackStatus is the store's answer to an acknowledgement.
type ackStatus int

const (
	ackDeleted ackStatus = iota + 1
	ackTombstone
	ackNotFound
)

// record is the index entry of one stored envelope.
type record struct {
	agent    agentDigest
	keyID    [agentpacketseal.KeyIDSize]byte
	id       [32]byte
	size     int64
	received uint64
	expires  uint64
	client   netip.Addr
	sum      [32]byte
	// committed is false while the envelope is being written.
	committed bool
}

type tombstone struct {
	agent   agentDigest
	expires uint64
}

type recipientUsage struct {
	ids      map[[32]byte]struct{}
	bytes    int64
	byClient map[netip.Addr]int
}

// backend persists records. Every method is called for one ID at a time:
// the store never runs two operations on the same ID concurrently.
type backend interface {
	putEnvelope(rec record, envelope []byte) error
	getEnvelope(id [32]byte) ([]byte, error)
	putTombstone(id [32]byte, stone tombstone) error
	deleteEnvelope(id [32]byte) error
	deleteTombstone(id [32]byte) error
	close() error
}

// Store is the relay's bounded envelope store: a durable backend behind an
// in-memory index that enforces the quotas atomically.
type Store struct {
	mu         sync.Mutex
	limits     Limits
	backend    backend
	envelopes  map[[32]byte]*record
	tombstones map[[32]byte]tombstone
	recipients map[agentDigest]*recipientUsage
	entries    int
	bytes      int64
	// busy holds the IDs with a persistence operation in flight; the
	// channel closes when it ends.
	busy   map[[32]byte]chan struct{}
	closed bool
}

func newStore(limits Limits, b backend) (*Store, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &Store{limits: limits, backend: b, envelopes: map[[32]byte]*record{}, tombstones: map[[32]byte]tombstone{},
		recipients: map[agentDigest]*recipientUsage{}, busy: map[[32]byte]chan struct{}{}}, nil
}

// NewMemoryStore returns a store that keeps everything in memory. It is for
// tests; it does not survive a restart.
func NewMemoryStore(limits Limits) (*Store, error) {
	return newStore(limits, newMemoryBackend())
}

// Limits returns the store's bounds.
func (s *Store) Limits() Limits { return s.limits }

// Close stops the store; in-flight operations finish first.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for len(s.busy) > 0 {
		var wait chan struct{}
		for _, ch := range s.busy {
			wait = ch
			break
		}
		s.mu.Unlock()
		<-wait
		s.mu.Lock()
	}
	s.mu.Unlock()
	return s.backend.close()
}

// lockID waits until no operation runs on id and returns with s.mu held, or
// returns an error without the lock.
func (s *Store) lockID(ctx context.Context, id [32]byte) error {
	s.mu.Lock()
	for {
		if s.closed {
			s.mu.Unlock()
			return ErrStoreUnavailable
		}
		wait, ok := s.busy[id]
		if !ok {
			return nil
		}
		s.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
	}
}

// markBusy claims id for a persistence operation; s.mu must be held.
func (s *Store) markBusy(id [32]byte) chan struct{} {
	ch := make(chan struct{})
	s.busy[id] = ch
	return ch
}

// release ends a persistence operation; s.mu must be held.
func (s *Store) release(id [32]byte, ch chan struct{}) {
	delete(s.busy, id)
	close(ch)
}

func (s *Store) usage(agent agentDigest) *recipientUsage {
	usage := s.recipients[agent]
	if usage == nil {
		usage = &recipientUsage{ids: map[[32]byte]struct{}{}, byClient: map[netip.Addr]int{}}
		s.recipients[agent] = usage
	}
	return usage
}

// addRecord indexes rec and charges its quotas; s.mu must be held.
func (s *Store) addRecord(rec *record) {
	s.envelopes[rec.id] = rec
	usage := s.usage(rec.agent)
	usage.ids[rec.id] = struct{}{}
	usage.bytes += rec.size
	usage.byClient[rec.client]++
	s.entries++
	s.bytes += rec.size
}

// dropRecord removes rec from the index and refunds its quotas; s.mu must be
// held.
func (s *Store) dropRecord(rec *record) {
	delete(s.envelopes, rec.id)
	if usage := s.recipients[rec.agent]; usage != nil {
		delete(usage.ids, rec.id)
		usage.bytes -= rec.size
		if usage.byClient[rec.client]--; usage.byClient[rec.client] <= 0 {
			delete(usage.byClient, rec.client)
		}
		if len(usage.ids) == 0 {
			delete(s.recipients, rec.agent)
		}
	}
	s.entries--
	s.bytes -= rec.size
}

func (s *Store) addTombstone(id [32]byte, stone tombstone) {
	s.tombstones[id] = stone
	s.entries++
}

func (s *Store) dropTombstone(id [32]byte) {
	delete(s.tombstones, id)
	s.entries--
}

// depositInput is one envelope the server has already checked: it parses,
// matches its path, and its effective expiry is in bounds.
type depositInput struct {
	header   agentpacketseal.Header
	envelope []byte
	client   netip.Addr
	now      uint64
	expires  uint64
}

// deposit stores one envelope, or reports why not.
func (s *Store) deposit(ctx context.Context, in depositInput) (depositStatus, error) {
	agent, err := agentpacketseal.AgentDigest(in.header.RecipientAgentID)
	if err != nil {
		return 0, fmt.Errorf("agentpacketrelay: deposit recipient: %w", err)
	}
	id := in.header.EnvelopeID
	sum := sha256.Sum256(in.envelope)
	if err := s.lockID(ctx, id); err != nil {
		return 0, err
	}
	// s.mu is held from here until the persistence step.
	var cleanupTombstone bool
	if existing, ok := s.envelopes[id]; ok {
		if existing.expires > in.now {
			s.mu.Unlock()
			if existing.sum == sum && existing.agent == agent {
				return depositDuplicate, nil
			}
			return depositConflict, nil
		}
		// An expired envelope the sweep has not reached yet is gone; the
		// new write replaces its file.
		s.dropRecord(existing)
	}
	if stone, ok := s.tombstones[id]; ok {
		if stone.expires > in.now {
			s.mu.Unlock()
			return depositGone, nil
		}
		s.dropTombstone(id)
		cleanupTombstone = true
	}
	usage := s.recipients[agent]
	count, used, fromClient := 0, int64(0), 0
	if usage != nil {
		count, used, fromClient = len(usage.ids), usage.bytes, usage.byClient[in.client]
	}
	size := int64(len(in.envelope))
	if count+1 > s.limits.PerRecipientMaxEnvelopes || used+size > s.limits.PerRecipientMaxBytes ||
		fromClient+1 > s.limits.PerClientRecipientMaxEnvelopes ||
		s.entries+1 > s.limits.GlobalMaxEntries || s.bytes+size > s.limits.GlobalMaxBytes {
		if cleanupTombstone {
			// The expired tombstone is already out of the index; its file
			// must go before any later envelope under this ID is written.
			ch := s.markBusy(id)
			s.mu.Unlock()
			removeErr := s.backend.deleteTombstone(id)
			s.mu.Lock()
			s.release(id, ch)
			s.mu.Unlock()
			if removeErr != nil {
				return 0, fmt.Errorf("%w: %v", ErrStoreUnavailable, removeErr)
			}
			return depositQuota, nil
		}
		s.mu.Unlock()
		return depositQuota, nil
	}
	rec := &record{agent: agent, keyID: in.header.RecipientKeyID, id: id, size: size, received: in.now,
		expires: in.expires, client: in.client, sum: sum}
	s.addRecord(rec)
	ch := s.markBusy(id)
	s.mu.Unlock()

	var writeErr error
	if cleanupTombstone {
		writeErr = s.backend.deleteTombstone(id)
	}
	if writeErr == nil {
		writeErr = s.backend.putEnvelope(*rec, in.envelope)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.release(id, ch)
	if writeErr != nil {
		s.dropRecord(rec)
		return 0, fmt.Errorf("%w: %v", ErrStoreUnavailable, writeErr)
	}
	rec.committed = true
	return depositCreated, nil
}

// list returns a snapshot of one mailbox under one lock, in V1 order.
func (s *Store) list(agent agentDigest, now uint64) ([]MailboxEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreUnavailable
	}
	out := []MailboxEntry{}
	if usage := s.recipients[agent]; usage != nil {
		for id := range usage.ids {
			rec := s.envelopes[id]
			if rec == nil || !rec.committed || rec.expires <= now {
				continue
			}
			out = append(out, MailboxEntry{EnvelopeID: rec.id, RecipientKeyID: rec.keyID, Size: uint32(rec.size),
				ReceivedAtUnix: rec.received, ExpiresAtUnix: rec.expires})
		}
	}
	slices.SortFunc(out, func(a, b MailboxEntry) int {
		if a.ReceivedAtUnix != b.ReceivedAtUnix {
			if a.ReceivedAtUnix < b.ReceivedAtUnix {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.EnvelopeID[:], b.EnvelopeID[:])
	})
	return out, nil
}

// errEnvelopeAbsent is a download of an absent, expired or uncommitted
// envelope.
var errEnvelopeAbsent = errors.New("agentpacketrelay: envelope absent")

// get returns the stored bytes of one live envelope.
func (s *Store) get(agent agentDigest, id [32]byte, now uint64) ([]byte, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStoreUnavailable
	}
	rec := s.envelopes[id]
	if rec == nil || !rec.committed || rec.agent != agent || rec.expires <= now {
		s.mu.Unlock()
		return nil, errEnvelopeAbsent
	}
	sum := rec.sum
	s.mu.Unlock()
	// The read runs outside the lock. Files are replaced only by rename, so
	// it sees one whole version; the checksum decides whether that version
	// is still the indexed one.
	raw, err := s.backend.getEnvelope(id)
	if err == nil && sha256.Sum256(raw) == sum {
		return raw, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.envelopes[id]; current == nil || current.sum != sum || current.expires <= now {
		return nil, errEnvelopeAbsent
	}
	if err == nil {
		err = errStoreCorrupt
	}
	return nil, fmt.Errorf("%w: read envelope: %v", ErrStoreUnavailable, err)
}

// ack deletes one envelope whose secret the caller has already checked
// against id, leaving a tombstone until its effective expiry.
func (s *Store) ack(ctx context.Context, agent agentDigest, id [32]byte, now uint64) (ackStatus, error) {
	if err := s.lockID(ctx, id); err != nil {
		return 0, err
	}
	if stone, ok := s.tombstones[id]; ok && stone.agent == agent && stone.expires > now {
		s.mu.Unlock()
		return ackTombstone, nil
	}
	rec := s.envelopes[id]
	if rec == nil || !rec.committed || rec.agent != agent || rec.expires <= now {
		s.mu.Unlock()
		return ackNotFound, nil
	}
	stone := tombstone{agent: agent, expires: rec.expires}
	ch := s.markBusy(id)
	s.mu.Unlock()

	// The tombstone is durable before the envelope goes: a crash between
	// the two leaves both on disk, and reopening keeps the tombstone and
	// removes the envelope.
	putErr := s.backend.putTombstone(id, stone)
	var deleteErr error
	if putErr == nil {
		deleteErr = s.backend.deleteEnvelope(id)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.release(id, ch)
	if putErr != nil {
		return 0, fmt.Errorf("%w: write tombstone: %v", ErrStoreUnavailable, putErr)
	}
	// With the tombstone durable the envelope is acknowledged whatever the
	// delete did: reopening removes a leftover envelope file.
	s.dropRecord(rec)
	s.addTombstone(id, stone)
	if deleteErr != nil {
		return 0, fmt.Errorf("%w: delete acknowledged envelope: %v", ErrStoreUnavailable, deleteErr)
	}
	return ackDeleted, nil
}

// Sweep removes every envelope and tombstone whose effective expiry has
// passed. Expired entries are already invisible; the sweep frees their
// quota and their files.
func (s *Store) Sweep(now time.Time) error {
	unix := uint64(max(now.Unix(), 0))
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStoreUnavailable
	}
	type job struct {
		id       [32]byte
		envelope bool
		ch       chan struct{}
	}
	var jobs []job
	for id, rec := range s.envelopes {
		if _, busy := s.busy[id]; busy || !rec.committed || rec.expires > unix {
			continue
		}
		s.dropRecord(rec)
		jobs = append(jobs, job{id: id, envelope: true, ch: s.markBusy(id)})
	}
	for id, stone := range s.tombstones {
		if _, busy := s.busy[id]; busy || stone.expires > unix {
			continue
		}
		s.dropTombstone(id)
		jobs = append(jobs, job{id: id, ch: s.markBusy(id)})
	}
	s.mu.Unlock()
	var errs []error
	for _, j := range jobs {
		var err error
		if j.envelope {
			err = s.backend.deleteEnvelope(j.id)
		} else {
			err = s.backend.deleteTombstone(j.id)
		}
		if err != nil {
			errs = append(errs, err)
		}
		s.mu.Lock()
		s.release(j.id, j.ch)
		s.mu.Unlock()
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: sweep: %v", ErrStoreUnavailable, errors.Join(errs...))
	}
	return nil
}

// RunSweeper sweeps every interval until ctx ends, reporting failures to
// onError (which may be nil).
func (s *Store) RunSweeper(ctx context.Context, interval time.Duration, now func() time.Time, onError func(error)) {
	if interval <= 0 || now == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Sweep(now()); err != nil && onError != nil && !errors.Is(err, context.Canceled) {
				onError(err)
			}
		}
	}
}

// Usage is a snapshot of the store's accounting.
type Usage struct {
	Envelopes  int
	Tombstones int
	Bytes      int64
}

// Usage returns the current accounting under one lock.
func (s *Store) Usage() Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Usage{Envelopes: len(s.envelopes), Tombstones: len(s.tombstones), Bytes: s.bytes}
}
