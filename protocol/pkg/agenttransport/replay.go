package agenttransport

import (
	"container/heap"
	"errors"
	"fmt"
	"sync"
)

// Replay table bounds of section 5.4. The durable record of the high-water
// mark (checksummed, atomically replaced, start refusal) is the relay's; this
// type is the in-memory admission logic it restores and advances.
const (
	DefaultReplayEntries   = 262144
	MaxReplayPerCredential = 64
	// MarkLeadSeconds is how far ahead of the clock a recorded mark reaches.
	MarkLeadSeconds = 140
	// MarkIntervalSeconds is how often the relay records the mark.
	MarkIntervalSeconds = 10
)

var (
	// ErrReplayTableFull is 503 replay_table_full; retryable.
	ErrReplayTableFull = errors.New("replay_table_full")
	// ErrReplayCredentialFull is the 429 answer: 64 live entries for one
	// issued credential (chain_1), however many blocks its holders appended.
	ErrReplayCredentialFull = errors.New("replay table holds the per-credential maximum")
	// ErrProofFloor is 503 proof_floor: the proof is at or below the floor.
	ErrProofFloor = errors.New("proof_floor")
	// ErrProofMark refuses a proof at or above the last recorded high-water
	// mark: the relay has not durably bounded it, so it fails closed. It is
	// answered as 503 replay_table_full and wraps ErrReplayTableFull.
	ErrProofMark = fmt.Errorf("%w: proof time is not below the recorded high-water mark", ErrReplayTableFull)
)

type replayKey struct {
	credential [32]byte
	nonce      [32]byte
}

type replayEntry struct {
	key      replayKey
	group    [32]byte
	issuedAt uint64
}

// ReplayIdentity keys a request in the replay table. CredentialID with the
// nonce makes a proof unique; IssuerChain (chain_1) bounds a holder, because a
// holder mints a new CredentialID with every block it appends but cannot
// change the issuer's block 0.
type ReplayIdentity struct {
	CredentialID [32]byte
	IssuerChain  [32]byte
}

type replayHeap []replayEntry

func (h replayHeap) Len() int           { return len(h) }
func (h replayHeap) Less(i, j int) bool { return h[i].issuedAt < h[j].issuedAt }
func (h replayHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *replayHeap) Push(x any) {
	if e, ok := x.(replayEntry); ok {
		*h = append(*h, e)
	}
}
func (h *replayHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// ReplayConfig bounds the table; zero values take the defaults.
type ReplayConfig struct {
	Entries       int
	PerCredential int
}

// ReplayTable claims (credential_id, nonce) pairs, at most PerCredential live
// entries per issued credential (chain_1). It fails closed when full and
// never evicts an entry whose issued_at_unix is inside the window.
type ReplayTable struct {
	mu     sync.Mutex
	config ReplayConfig
	live   map[replayKey]struct{}
	counts map[[32]byte]int
	byTime replayHeap
	floor  uint64
	mark   uint64
}

func newReplayTable(c ReplayConfig) (*ReplayTable, error) {
	if c.Entries == 0 {
		c.Entries = DefaultReplayEntries
	}
	if c.PerCredential == 0 {
		c.PerCredential = MaxReplayPerCredential
	}
	if c.Entries < 1 || c.PerCredential < 1 || c.PerCredential > MaxReplayPerCredential {
		return nil, fmt.Errorf("invalid replay table bounds: %d entries, %d per credential", c.Entries, c.PerCredential)
	}
	return &ReplayTable{config: c, live: make(map[replayKey]struct{}), counts: make(map[[32]byte]int)}, nil
}

// NewReplayTable is the table of a relay whose V2 store is empty. It admits
// nothing until the first MarkRecorded.
func NewReplayTable(c ReplayConfig) (*ReplayTable, error) { return newReplayTable(c) }

// RestoreReplayTable is the table after a restart: the floor starts at the
// recorded mark, so every proof admitted before the restart stays refused.
func RestoreReplayTable(c ReplayConfig, recordedMark uint64) (*ReplayTable, error) {
	if recordedMark == 0 {
		return nil, errors.New("a used replay table needs its recorded high-water mark")
	}
	t, err := newReplayTable(c)
	if err != nil {
		return nil, err
	}
	t.floor, t.mark = recordedMark, recordedMark
	return t, nil
}

// NextMark is the mark to record durably now: max(recorded, now + 140).
// It never decreases, whatever the clock does.
func (t *ReplayTable) NextMark(now uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	lead := now + MarkLeadSeconds
	if lead < now {
		lead = ^uint64(0)
	}
	return max(t.mark, lead)
}

// MarkRecorded reports that mark was durably recorded. A decrease is refused.
func (t *ReplayTable) MarkRecorded(mark uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if mark < t.mark || mark == 0 {
		return fmt.Errorf("high-water mark %d would decrease from %d", mark, t.mark)
	}
	t.mark = mark
	return nil
}

// Claim admits a proof's nonce once. It runs after VerifyProof.
func (t *ReplayTable) Claim(k ReplayIdentity, p Proof, now uint64) error {
	if err := CheckProofWindow(p.IssuedAt, now); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Drop only entries strictly older than the window, raising the floor.
	for len(t.byTime) > 0 && now > t.byTime[0].issuedAt && now-t.byTime[0].issuedAt > ProofWindowSeconds {
		e, ok := heap.Pop(&t.byTime).(replayEntry)
		if !ok {
			return errors.New("replay table order corrupted")
		}
		delete(t.live, e.key)
		if t.counts[e.group]--; t.counts[e.group] <= 0 {
			delete(t.counts, e.group)
		}
		t.floor = max(t.floor, e.issuedAt)
	}
	if p.IssuedAt <= t.floor {
		return fmt.Errorf("%w: issued at %d, floor %d", ErrProofFloor, p.IssuedAt, t.floor)
	}
	if p.IssuedAt >= t.mark {
		return fmt.Errorf("%w: issued at %d, mark %d", ErrProofMark, p.IssuedAt, t.mark)
	}
	key := replayKey{credential: k.CredentialID, nonce: p.Nonce}
	group := k.IssuerChain
	if _, seen := t.live[key]; seen {
		return invalid("request proof nonce replayed")
	}
	if len(t.live) >= t.config.Entries {
		return ErrReplayTableFull
	}
	if t.counts[group] >= t.config.PerCredential {
		return ErrReplayCredentialFull
	}
	t.live[key] = struct{}{}
	t.counts[group]++
	heap.Push(&t.byTime, replayEntry{key: key, group: group, issuedAt: p.IssuedAt})
	return nil
}

// RetryAfter is how many seconds until a fresh proof signed at now can pass
// the floor; 0 when it already can.
func (t *ReplayTable) RetryAfter(now uint64) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.floor < now {
		return 0
	}
	if wait := t.floor - now; wait < ^uint64(0) {
		return wait + 1
	}
	return ^uint64(0)
}

// Floor, Mark and Len are one snapshot under the table lock.
func (t *ReplayTable) State() (floor, mark uint64, entries int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.floor, t.mark, len(t.live)
}
