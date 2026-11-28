package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

// V2Limits reserves independent shares: strangers never borrow the contact
// count/byte budget. Zero stranger bounds close stranger admission.
type V2Limits struct {
	Base                  Limits
	StrangerMaxEnvelopes  int
	StrangerMaxBytes      int64
	StrangerGlobalPercent int
}

func DefaultV2Limits(entries int, size int64) V2Limits {
	return V2Limits{DefaultLimits(entries, size), 32, 2 << 20, 25}
}
func (l V2Limits) Validate() error {
	if err := l.Base.Validate(); err != nil {
		return err
	}
	if l.StrangerMaxEnvelopes < 0 || l.StrangerMaxEnvelopes > 64 || l.StrangerMaxBytes < 0 || l.StrangerMaxBytes > 4<<20 || l.StrangerGlobalPercent < 0 || l.StrangerGlobalPercent > 25 {
		return errors.New("invalid V2 stranger limits")
	}
	return nil
}
func shareInt(n, p int) int           { return n/100*p + (n%100)*p/100 }
func shareBytes(n int64, p int) int64 { return n/100*int64(p) + (n%100)*int64(p)/100 }

// Lane tags are part of equality and persistence, never inferred from padding.
// In particular a 16-byte lane and a zero-suffixed issuer hash cannot alias.
type v2LaneKey struct {
	Tag   uint8    `json:"tag"`
	Value [32]byte `json:"value"`
}

const (
	v2ExplicitLane = 1
	v2DefaultLane  = 2
)

func checkedV2Lane(checked agenttransport.CheckedRequest) (v2LaneKey, error) {
	identity, err := checkedReplayIdentity(checked)
	if err != nil {
		return v2LaneKey{}, err
	}
	lane, explicit, err := checked.Credential.Lane()
	if err != nil {
		return v2LaneKey{}, err
	}
	if explicit {
		blocks, err := checked.Credential.Blocks()
		if err != nil {
			return v2LaneKey{}, err
		}
		firstExplicit := false
		for _, caveat := range blocks[0].Caveats {
			if caveat.Type == agenttransport.CaveatLane {
				firstExplicit = true
			}
		}
		// The implicit issuer-chain lane is already a lane choice. A holder
		// may repeat a block-0 lane, but cannot replace a default lane.
		if !firstExplicit {
			return v2LaneKey{}, agenttransport.ErrCredentialScope
		}
		var key v2LaneKey
		key.Tag = v2ExplicitLane
		copy(key.Value[:16], lane[:])
		return key, nil
	}
	return v2LaneKey{v2DefaultLane, identity.IssuerChain}, nil
}
func (k v2LaneKey) valid(contact bool) bool {
	if !contact {
		return k == (v2LaneKey{})
	}
	if k.Tag == v2DefaultLane {
		return true
	}
	if k.Tag != v2ExplicitLane {
		return false
	}
	for _, v := range k.Value[16:] {
		if v != 0 {
			return false
		}
	}
	return true
}

type v2Record struct {
	Version   string                          `json:"version"`
	Agent     string                          `json:"agent"`
	ID        [32]byte                        `json:"id"`
	KeyID     [agentpacketseal.KeyIDSize]byte `json:"key_id"`
	Size      int64                           `json:"size"`
	Sum       [32]byte                        `json:"envelope_sha256"`
	Received  uint64                          `json:"received"`
	Expires   uint64                          `json:"expires"`
	Client    netip.Addr                      `json:"client"`
	Contact   bool                            `json:"contact"`
	Lane      v2LaneKey                       `json:"lane"`
	Tombstone bool                            `json:"tombstone"`
	Body      []byte                          `json:"body"`
}
type v2Usage struct {
	Count int
	Bytes int64
}
type v2MailboxUsage struct {
	IDs map[[32]byte]struct{}
	v2Usage
	Stranger        v2Usage
	Clients         map[netip.Addr]int
	StrangerClients map[netip.Addr]int
}
type v2LaneSlot struct {
	Agent agentDigest
	Lane  v2LaneKey
}

// V2Store is deliberately not a Store: a V1 handler cannot receive it. The
// durable format is also disjoint. All index mutations follow a synced record.
type V2Store struct {
	mu                v2Gate
	disk              *v2Disk
	replay            *V2Replay
	limits            V2Limits
	records           map[entryKey]v2Record
	memory            map[entryKey][]byte
	mailboxes         map[agentDigest]*v2MailboxUsage
	lanes             map[v2LaneSlot]v2Usage
	strangers         map[netip.Addr]int
	sites             map[netip.Addr]int
	stranger, contact v2Usage
	closed, poisoned  bool
}

type V2OpenOptions struct {
	Replay        agenttransport.ReplayConfig
	RecoveryFloor *uint64
	// Required for explicit recovery. The callback logs only the public floor,
	// never a credential, proof, lane, secret or mailbox identifier.
	RecoveryAudit func(uint64) error
}

func OpenV2Store(path string, limits V2Limits, now time.Time, options V2OpenOptions) (*V2Store, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if _, err := agenttransport.NewReplayTable(options.Replay); err != nil {
		return nil, err
	}
	if now.Unix() <= 0 {
		return nil, errors.New("invalid V2 store clock")
	}
	d, fresh, err := openV2Disk(path)
	if err != nil {
		return nil, err
	}
	if fresh && options.RecoveryFloor != nil {
		d.release()
		return nil, errors.New("cannot recover an unused V2 store")
	}
	if err = d.prepare(fresh); err != nil {
		d.release()
		return nil, err
	}
	replay, err := openV2Replay(d, fresh, options.Replay, unixNow(now), options.RecoveryFloor, options.RecoveryAudit)
	if err != nil {
		d.release()
		return nil, err
	}
	if fresh {
		if err = d.write("FORMAT", []byte(v2Format)); err != nil {
			d.release()
			return nil, err
		}
	}
	s := newV2Store(limits)
	s.disk, s.replay = d, replay
	if err = d.clearTemp(); err != nil {
		d.release()
		return nil, err
	}
	// Control records are introduced by the HTTP/policy layer in its own change.
	controls, err := boundedV2Dir(filepath.Join(path, "controls"), 1)
	if err != nil || len(controls) != 0 {
		d.release()
		return nil, errors.New("unknown V2 control record")
	}
	entries, err := boundedV2Dir(filepath.Join(path, "records"), limits.Base.GlobalMaxEntries)
	if err != nil {
		d.release()
		return nil, err
	}
	for _, entry := range entries {
		rec, err := s.readRecordFile(entry.Name())
		if err != nil {
			d.release()
			return nil, err
		}
		key, err := rec.key()
		if err != nil || entry.Name() != keyFileName(key) {
			d.release()
			return nil, errors.New("V2 record name mismatch")
		}
		if rec.Expires <= unixNow(now) {
			if err = d.remove("records/" + entry.Name()); err != nil {
				d.release()
				return nil, err
			}
			continue
		}
		if err = s.loadFits(key, rec); err != nil {
			d.release()
			return nil, err
		}
		s.add(key, rec)
	}
	return s, nil
}
func newV2Store(limits V2Limits) *V2Store {
	return &V2Store{mu: v2Gate{make(chan struct{}, 1)}, limits: limits, records: map[entryKey]v2Record{}, memory: map[entryKey][]byte{}, mailboxes: map[agentDigest]*v2MailboxUsage{}, lanes: map[v2LaneSlot]v2Usage{}, strangers: map[netip.Addr]int{}, sites: map[netip.Addr]int{}}
}
func boundedV2Dir(path string, limit int) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []os.DirEntry
	for {
		entries, err := f.ReadDir(1)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if len(out) >= limit {
			return nil, errors.New("V2 directory exceeds its entry bound")
		}
		if !entries[0].Type().IsRegular() {
			return nil, errors.New("invalid V2 record entry")
		}
		out = append(out, entries[0])
	}
}
func (r v2Record) key() (entryKey, error) {
	agent, ok := parseAgentText(r.Agent)
	if !ok || r.ID == [32]byte{} {
		return entryKey{}, errors.New("invalid V2 record identity")
	}
	return entryKey{agent, r.ID}, nil
}
func v2Client(addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, errors.New("invalid V2 client")
	}
	addr = addr.Unmap()
	if addr.Is6() {
		addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}
	return addr, nil
}
func (s *V2Store) readRecordFile(name string) (v2Record, error) {
	var rec v2Record
	if len(name) != 129 || name[64] != '-' || strings.ContainsAny(name, "/\\") {
		return rec, errors.New("invalid V2 record name")
	}
	if _, err := hex.DecodeString(name[:64] + name[65:]); err != nil || strings.ToLower(name) != name {
		return rec, errors.New("invalid V2 record name")
	}
	raw, err := readV2File(filepath.Join(s.disk.root, "records", name), maxV2RecordBytes)
	if err != nil {
		return rec, err
	}
	if err = decodeV2(raw, &rec); err != nil {
		return rec, err
	}
	if err = rec.validate(); err != nil {
		return rec, err
	}
	return rec, nil
}
func (r v2Record) validate() error {
	if _, err := r.key(); err != nil {
		return err
	}
	client, err := v2Client(r.Client)
	if err != nil || client != r.Client || r.Version != "tos.service.relay-envelope.v2" || !r.Lane.valid(r.Contact) || r.Received == 0 || r.Expires <= r.Received || r.Expires-r.Received > uint64(MaxTTL/time.Second) {
		return errors.New("invalid V2 record metadata")
	}
	if r.Tombstone {
		if r.Size != 0 || len(r.Body) != 0 {
			return errors.New("V2 tombstone retains a body")
		}
		return nil
	}
	header, err := agentpacketseal.ParseEnvelope(r.Body)
	if r.Size != int64(len(r.Body)) || sha256.Sum256(r.Body) != r.Sum || err != nil || header.EnvelopeID != r.ID || header.RecipientAgentID != r.Agent || header.RecipientKeyID != r.KeyID || header.ExpiresAtUnix < r.Expires {
		return errors.New("V2 record envelope mismatch")
	}
	return nil
}
func (s *V2Store) persist(key entryKey, rec v2Record) error {
	if s.disk == nil {
		if rec.Tombstone {
			delete(s.memory, key)
		} else {
			s.memory[key] = bytes.Clone(rec.Body)
		}
		return nil
	}
	raw, err := encodeV2(rec)
	if err != nil {
		return err
	}
	if len(raw) > maxV2RecordBytes {
		return errors.New("V2 record exceeds its bound")
	}
	if err = s.disk.write("records/"+keyFileName(key), raw); err != nil {
		s.poisoned = true
		return ErrStoreUnavailable
	}
	return nil
}
func (s *V2Store) forget(key entryKey) error {
	if s.disk != nil {
		if err := s.disk.remove("records/" + keyFileName(key)); err != nil {
			s.poisoned = true
			return ErrStoreUnavailable
		}
	}
	s.drop(key)
	delete(s.memory, key)
	return nil
}
func (s *V2Store) available() error {
	if s.closed || s.poisoned {
		return ErrStoreUnavailable
	}
	return nil
}
func (s *V2Store) add(key entryKey, rec v2Record) {
	bodySize := rec.Size
	rec.Body = nil
	s.records[key] = rec
	usage := &s.stranger
	if rec.Contact {
		usage = &s.contact
	}
	usage.Count++
	if !rec.Contact {
		s.strangers[rec.Client]++
		if site, ok := site48(rec.Client); ok {
			s.sites[site]++
		}
	}
	if rec.Tombstone {
		return
	}
	usage.Bytes += bodySize
	box := s.mailboxes[key.agent]
	if box == nil {
		box = &v2MailboxUsage{IDs: map[[32]byte]struct{}{}, Clients: map[netip.Addr]int{}, StrangerClients: map[netip.Addr]int{}}
		s.mailboxes[key.agent] = box
	}
	box.IDs[key.id] = struct{}{}
	box.Count++
	box.Bytes += bodySize
	box.Clients[rec.Client]++
	if rec.Contact {
		slot := v2LaneSlot{key.agent, rec.Lane}
		lane := s.lanes[slot]
		lane.Count++
		lane.Bytes += bodySize
		s.lanes[slot] = lane
	} else {
		box.Stranger.Count++
		box.Stranger.Bytes += bodySize
		box.StrangerClients[rec.Client]++
	}
}
func (s *V2Store) drop(key entryKey) {
	rec, ok := s.records[key]
	if !ok {
		return
	}
	delete(s.records, key)
	usage := &s.stranger
	if rec.Contact {
		usage = &s.contact
	}
	usage.Count--
	if !rec.Contact {
		decrementV2(s.strangers, rec.Client)
		if site, ok := site48(rec.Client); ok {
			decrementV2(s.sites, site)
		}
	}
	if rec.Tombstone {
		return
	}
	usage.Bytes -= rec.Size
	box := s.mailboxes[key.agent]
	delete(box.IDs, key.id)
	box.Count--
	box.Bytes -= rec.Size
	decrementV2(box.Clients, rec.Client)
	if rec.Contact {
		slot := v2LaneSlot{key.agent, rec.Lane}
		lane := s.lanes[slot]
		lane.Count--
		lane.Bytes -= rec.Size
		if lane.Count == 0 {
			delete(s.lanes, slot)
		} else {
			s.lanes[slot] = lane
		}
	} else {
		box.Stranger.Count--
		box.Stranger.Bytes -= rec.Size
		decrementV2(box.StrangerClients, rec.Client)
	}
	if box.Count == 0 {
		delete(s.mailboxes, key.agent)
	}
}
func decrementV2(m map[netip.Addr]int, key netip.Addr) {
	if m[key] <= 1 {
		delete(m, key)
	} else {
		m[key]--
	}
}
func (s *V2Store) shareFits(rec v2Record) bool {
	countLimit := shareInt(s.limits.Base.GlobalMaxEntries, s.limits.StrangerGlobalPercent)
	byteLimit := shareBytes(s.limits.Base.GlobalMaxBytes, s.limits.StrangerGlobalPercent)
	usage := s.stranger
	if rec.Contact {
		countLimit = s.limits.Base.GlobalMaxEntries - countLimit
		byteLimit = s.limits.Base.GlobalMaxBytes - byteLimit
		usage = s.contact
	}
	if usage.Count >= countLimit || rec.Size > byteLimit || usage.Bytes > byteLimit-rec.Size {
		return false
	}
	if !rec.Contact {
		if s.strangers[rec.Client] >= 64 {
			return false
		}
		if site, ok := site48(rec.Client); ok && s.sites[site] >= 256 {
			return false
		}
	}
	return true
}
func (s *V2Store) mailboxFits(key entryKey, rec v2Record, stranger v2Usage, checked *agenttransport.CheckedRequest) bool {
	box := s.mailboxes[key.agent]
	var count, client, fromStranger int
	var used int64
	var usedStranger v2Usage
	if box != nil {
		count, used, client, fromStranger, usedStranger = box.Count, box.Bytes, box.Clients[rec.Client], box.StrangerClients[rec.Client], box.Stranger
	}
	if count >= s.limits.Base.PerRecipientMaxEnvelopes || rec.Size > s.limits.Base.PerRecipientMaxBytes || used > s.limits.Base.PerRecipientMaxBytes-rec.Size || client >= s.limits.Base.PerClientRecipientMaxEnvelopes {
		return false
	}
	if !rec.Contact {
		stranger.Count = min(stranger.Count, s.limits.StrangerMaxEnvelopes)
		stranger.Bytes = min(stranger.Bytes, s.limits.StrangerMaxBytes)
		return usedStranger.Count < stranger.Count && rec.Size <= stranger.Bytes && usedStranger.Bytes <= stranger.Bytes-rec.Size && fromStranger < 8
	}
	lane := s.lanes[v2LaneSlot{key.agent, rec.Lane}]
	if lane.Count >= 64 {
		return false
	}
	if checked == nil {
		return false
	}
	return checked.Credential.CheckDeposit(agenttransport.LaneUsage{StoredEnvelopes: uint64(lane.Count), StoredBytes: uint64(lane.Bytes), EnvelopeBytes: uint64(rec.Size)}) == nil
}
func (s *V2Store) loadFits(key entryKey, rec v2Record) error {
	if !s.shareFits(rec) {
		return errors.New("V2 retained records exceed a configured share or address cap")
	}
	if rec.Tombstone {
		return nil
	}
	box := s.mailboxes[key.agent]
	if box != nil && (box.Count >= s.limits.Base.PerRecipientMaxEnvelopes || rec.Size > s.limits.Base.PerRecipientMaxBytes || box.Bytes > s.limits.Base.PerRecipientMaxBytes-rec.Size || box.Clients[rec.Client] >= s.limits.Base.PerClientRecipientMaxEnvelopes) {
		return errors.New("V2 retained mailbox exceeds its bound")
	}
	if !rec.Contact && box != nil && (box.Stranger.Count >= 64 || rec.Size > 4<<20 || box.Stranger.Bytes > (4<<20)-rec.Size || box.StrangerClients[rec.Client] >= 8) {
		return errors.New("V2 retained stranger lane exceeds its hard bound")
	}
	if rec.Contact && s.lanes[v2LaneSlot{key.agent, rec.Lane}].Count >= 64 {
		return errors.New("V2 retained contact lane exceeds its hard bound")
	}
	return nil
}
func (s *V2Store) deposit(ctx context.Context, in depositInput, checked *agenttransport.CheckedRequest, stranger v2Usage) (depositStatus, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	client, err := v2Client(in.client)
	if err != nil {
		return 0, err
	}
	header, err := agentpacketseal.ParseEnvelope(in.envelope)
	if err != nil || header != in.header {
		return 0, errors.New("invalid V2 deposit envelope")
	}
	if in.now == 0 || in.expires <= in.now || in.expires > header.ExpiresAtUnix || in.expires-in.now > uint64(s.limits.Base.TTL/time.Second) {
		return 0, errors.New("invalid V2 deposit expiry")
	}
	agent, ok := parseAgentText(header.RecipientAgentID)
	if !ok {
		return 0, errors.New("invalid V2 recipient")
	}
	key := entryKey{agent, header.EnvelopeID}
	rec := v2Record{Version: "tos.service.relay-envelope.v2", Agent: header.RecipientAgentID, ID: key.id, KeyID: header.RecipientKeyID, Received: in.now, Expires: in.expires, Client: client, Size: int64(len(in.envelope)), Sum: sha256.Sum256(in.envelope), Body: in.envelope}
	if checked != nil {
		rec.Lane, err = checkedV2Lane(*checked)
		if err != nil {
			return 0, err
		}
		d, err := checked.Credential.Delegation()
		if err != nil || d.AgentID() != header.RecipientAgentID {
			return 0, agenttransport.ErrCredentialScope
		}
		rec.Contact = true
		if err = checked.Credential.CheckDeposit(agenttransport.LaneUsage{EnvelopeBytes: uint64(rec.Size)}); err != nil {
			return 0, err
		}
	}
	if err := s.mu.lock(ctx); err != nil {
		return 0, err
	}
	defer s.mu.Unlock()
	if err = s.available(); err != nil {
		return 0, err
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if old, ok := s.records[key]; ok {
		if old.Expires > in.now {
			if old.Tombstone {
				return depositGone, nil
			}
			if old.Sum == rec.Sum {
				return depositDuplicate, nil
			}
			return depositConflict, nil
		}
		if err = s.forget(key); err != nil {
			return 0, err
		}
	}
	if !s.shareFits(rec) || !s.mailboxFits(key, rec, stranger, checked) {
		return depositQuota, nil
	}
	if err = s.persist(key, rec); err != nil {
		return 0, err
	}
	s.add(key, rec)
	return depositCreated, nil
}
func (s *V2Store) ack(ctx context.Context, agent agentDigest, id [32]byte, now uint64) (ackStatus, error) {
	if err := s.mu.lock(ctx); err != nil {
		return 0, err
	}
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	key := entryKey{agent, id}
	rec, ok := s.records[key]
	if !ok || rec.Expires <= now {
		return ackNotFound, nil
	}
	if rec.Tombstone {
		return ackTombstone, nil
	}
	stone := rec
	stone.Tombstone = true
	stone.Body = nil
	stone.Size = 0
	if err := s.persist(key, stone); err != nil {
		return 0, err
	}
	s.drop(key)
	s.add(key, stone)
	return ackDeleted, nil
}

type V2MailboxEntry struct {
	EnvelopeID                    [32]byte
	RecipientKeyID                [agentpacketseal.KeyIDSize]byte
	Size                          uint32
	ReceivedAtUnix, ExpiresAtUnix uint64
	Lane                          string
}

func (s *V2Store) list(ctx context.Context, agent agentDigest, now uint64) ([]V2MailboxEntry, error) {
	if err := s.mu.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]V2MailboxEntry, 0)
	box := s.mailboxes[agent]
	if box == nil {
		return out, nil
	}
	// The index is bounded globally; a mailbox has at most 256 active records.
	for id := range box.IDs {
		rec := s.records[entryKey{agent, id}]
		if rec.Tombstone || rec.Expires <= now {
			continue
		}
		class := "stranger"
		if rec.Contact {
			class = "contact"
		}
		out = append(out, V2MailboxEntry{EnvelopeID: rec.ID, RecipientKeyID: rec.KeyID, Size: uint32(rec.Size), ReceivedAtUnix: rec.Received, ExpiresAtUnix: rec.Expires, Lane: class})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].EnvelopeID[:], out[j].EnvelopeID[:]) < 0 })
	return out, nil
}
func (s *V2Store) get(ctx context.Context, agent agentDigest, id [32]byte, now uint64) ([]byte, error) {
	if err := s.mu.lock(ctx); err != nil {
		return nil, err
	}
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := entryKey{agent, id}
	rec, ok := s.records[key]
	if !ok || rec.Tombstone || rec.Expires <= now {
		return nil, errEnvelopeAbsent
	}
	if s.disk == nil {
		return bytes.Clone(s.memory[key]), nil
	}
	disk, err := s.readRecordFile(keyFileName(key))
	if err != nil {
		s.poisoned = true
		return nil, ErrStoreUnavailable
	}
	if disk.Sum != rec.Sum || disk.Expires != rec.Expires || disk.Tombstone {
		s.poisoned = true
		return nil, ErrStoreUnavailable
	}
	return disk.Body, nil
}
func (s *V2Store) Sweep(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	for key, rec := range s.records {
		if rec.Expires <= unixNow(now) {
			if err := s.forget(key); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *V2Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.replay != nil {
		s.replay.close()
	}
	if s.disk != nil {
		s.disk.release()
	}
	return nil
}
func (s *V2Store) Replay() *V2Replay { return s.replay }

type V2Usage struct {
	StrangerEntries, ContactEntries int
	StrangerBytes, ContactBytes     int64
	Mailboxes, Lanes                int
}

func (s *V2Store) Usage() V2Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return V2Usage{s.stranger.Count, s.contact.Count, s.stranger.Bytes, s.contact.Bytes, len(s.mailboxes), len(s.lanes)}
}

// v2Gate makes request-side lock contention cancellable. Close drains the
// current writer before relinquishing the exclusive directory lock.
type v2Gate struct{ gate chan struct{} }

func (g *v2Gate) lock(ctx context.Context) error {
	select {
	case g.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (g *v2Gate) Lock()   { g.gate <- struct{}{} }
func (g *v2Gate) Unlock() { <-g.gate }
