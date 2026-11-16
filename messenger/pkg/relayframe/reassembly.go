package relayframe

// Reassembler holds the parts of split kind-3 objects until each object is
// complete and its digest matches. Its bounds are what keep a sender, or a
// few, from filling a receiver with incomplete objects:
//
//   - parts are held only from senders the caller admits: before part 0 any
//     current member of a room this node belongs to or the authority of a room
//     it asked to join, and from part 0 on (when the room is known) a sender
//     admitted in that room, checked again at completion;
//   - one object is at most MaxRoomObjectBytes of part bytes;
//   - a sender holds at most 4 incomplete objects and 4 MiB of part bytes,
//     and all senders together at most 16 MiB, so filling the global cap takes
//     at least four admitted senders;
//   - a part with another part count, or a repeated index with other bytes,
//     drops the whole object, and so does a digest mismatch on completion;
//   - an incomplete object is dropped 24 h 5 min after its first part.
//
// Every refusal is answered by the caller with a relay ack and nothing else.
// The Reassembler holds parts in memory; a caller that needs them across a
// restart stores each accepted part and adds them again on start with their
// arrival times, which rebuilds the same state.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

// Reassembly refusals.
var (
	ErrReassemblyNotAdmitted    = errors.New("room part sender is not admitted")
	ErrReassemblyObjectTooLarge = errors.New("room object parts exceed the object bound")
	ErrReassemblyPeerObjects    = errors.New("sender holds the most incomplete room objects")
	ErrReassemblyPeerBytes      = errors.New("sender holds the most incomplete room part bytes")
	ErrReassemblyTotalBytes     = errors.New("incomplete room part bytes reached the global bound")
	ErrReassemblyInconsistent   = errors.New("room parts are inconsistent; the object is dropped")
	ErrReassemblyDigest         = errors.New("reassembled room object does not match its digest; the object is dropped")
	ErrReassemblyCut            = errors.New("room part is not cut by the fixed rule")
)

// ReassemblyLimits are the reassembly bounds.
type ReassemblyLimits struct {
	MaxObjectBytes int
	MaxPeerObjects int
	MaxPeerBytes   int
	MaxTotalBytes  int
	Lifetime       time.Duration
	// PartBytes is the cut: 0 for the production cut, or the test part size
	// P every part of a handshake object is cut at.
	PartBytes int
}

// DefaultReassemblyLimits are the production bounds of section 4.
func DefaultReassemblyLimits() ReassemblyLimits {
	return ReassemblyLimits{
		MaxObjectBytes: MaxRoomObjectBytes, MaxPeerObjects: 4, MaxPeerBytes: 4 << 20,
		MaxTotalBytes: 16 << 20, Lifetime: 24*time.Hour + 5*time.Minute,
	}
}

func (l ReassemblyLimits) validate() error {
	if l.MaxObjectBytes <= 0 || l.MaxObjectBytes > MaxRoomObjectBytes || l.MaxPeerObjects <= 0 ||
		l.MaxPeerBytes < l.MaxObjectBytes || l.MaxTotalBytes < l.MaxPeerBytes || l.Lifetime <= 0 {
		return errors.New("invalid reassembly limits")
	}
	if l.PartBytes != 0 && (l.PartBytes < MinTestPartBytes || l.PartBytes > MaxTestPartBytes) {
		return ErrRoomPartSize
	}
	return nil
}

// SenderSet answers who may hold parts. MayHold is asked before an object's
// room is known; MayHoldInRoom once part 0 names it, and again at completion.
type SenderSet interface {
	MayHold(sender string) bool
	MayHoldInRoom(sender, roomID string) bool
}

// PartStatus is what Add did with an accepted part.
type PartStatus int

const (
	// PartStored means the part is held and the object is still incomplete.
	PartStored PartStatus = iota + 1
	// PartDuplicate means the exact part was already held.
	PartDuplicate
	// PartComplete means the object is complete, its digest matched, and it
	// is released in the result; nothing of it is held any more.
	PartComplete
)

// PartResult is the outcome of an accepted part.
type PartResult struct {
	Status PartStatus
	// RoomID and ObjectType are set once part 0 is known.
	RoomID     string
	ObjectType uint8
	// Card and Evidence are part 0's, once it is known.
	Card     []byte
	Evidence []byte
	// Object is the complete object, for PartComplete.
	Object []byte
}

type reassemblyKey struct {
	sender string
	digest [sha256.Size]byte
}

type incompleteObject struct {
	count    uint8
	parts    map[uint8][]byte
	bytes    int
	first    time.Time
	roomID   string
	kind     uint8
	card     []byte
	evidence []byte
}

// Reassembler is safe for concurrent use.
type Reassembler struct {
	limits    ReassemblyLimits
	senders   SenderSet
	mutex     sync.Mutex
	objects   map[reassemblyKey]*incompleteObject
	peerBytes map[string]int
	peerCount map[string]int
	total     int
}

// NewReassembler returns an empty reassembler under the given limits.
func NewReassembler(limits ReassemblyLimits, senders SenderSet) (*Reassembler, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if senders == nil {
		return nil, errors.New("reassembly needs a sender set")
	}
	return &Reassembler{limits: limits, senders: senders, objects: map[reassemblyKey]*incompleteObject{},
		peerBytes: map[string]int{}, peerCount: map[string]int{}}, nil
}

// Add offers one decoded kind-3 frame from an authenticated packet sender,
// received at now.
func (r *Reassembler) Add(sender string, frame Frame, now time.Time) (PartResult, error) {
	if !ids.Agent.MatchString(sender) || frame.Kind != KindRoom || now.IsZero() {
		return PartResult{}, ErrFrameMalformed
	}
	if err := validateShape(frame.Kind, frame.PartIndex, frame.PartCount); err != nil {
		return PartResult{}, err
	}
	if err := validateFields(frame.Kind, frame.PartIndex, frame.Card, frame.Evidence, frame.Part); err != nil {
		return PartResult{}, err
	}
	if !r.senders.MayHold(sender) {
		return PartResult{}, ErrReassemblyNotAdmitted
	}
	if frame.PartCount == 1 {
		return r.single(sender, frame)
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	// Expired objects never count against the caps a new part is judged by.
	r.expire(now)
	key := reassemblyKey{sender: sender, digest: frame.ObjectDigest}
	object, held := r.objects[key]
	// A part that contradicts a held object drops the whole object, whatever
	// its size: the object can no longer complete honestly.
	if held {
		if object.count != frame.PartCount {
			r.drop(key)
			return PartResult{}, ErrReassemblyInconsistent
		}
		if existing, found := object.parts[frame.PartIndex]; found {
			if !bytes.Equal(existing, frame.Part) {
				r.drop(key)
				return PartResult{}, ErrReassemblyInconsistent
			}
			return object.result(PartDuplicate), nil
		}
	}
	// Only a new part is judged against the fixed cut.
	if err := r.checkCut(frame); err != nil {
		return PartResult{}, err
	}
	if !held && r.peerCount[sender] >= r.limits.MaxPeerObjects {
		return PartResult{}, ErrReassemblyPeerObjects
	}
	accumulated := len(frame.Part)
	if held {
		accumulated += object.bytes
	}
	if accumulated > r.limits.MaxObjectBytes {
		return PartResult{}, ErrReassemblyObjectTooLarge
	}
	if r.peerBytes[sender]+len(frame.Part) > r.limits.MaxPeerBytes {
		return PartResult{}, ErrReassemblyPeerBytes
	}
	if r.total+len(frame.Part) > r.limits.MaxTotalBytes {
		return PartResult{}, ErrReassemblyTotalBytes
	}
	var roomID string
	var kind uint8
	if frame.PartIndex == 0 {
		var err error
		roomID, kind, err = roomPrefix(frame.Part)
		if err != nil || kind == RoomApplication {
			if held {
				r.drop(key)
			}
			return PartResult{}, ErrReassemblyInconsistent
		}
		if !r.senders.MayHoldInRoom(sender, roomID) {
			return PartResult{}, ErrReassemblyNotAdmitted
		}
	}
	if !held {
		object = &incompleteObject{count: frame.PartCount, parts: map[uint8][]byte{}, first: now}
		r.objects[key] = object
		r.peerCount[sender]++
	}
	object.parts[frame.PartIndex] = append([]byte(nil), frame.Part...)
	object.bytes = accumulated
	r.peerBytes[sender] += len(frame.Part)
	r.total += len(frame.Part)
	if frame.PartIndex == 0 {
		object.roomID, object.kind = roomID, kind
		object.card = append([]byte(nil), frame.Card...)
		object.evidence = append([]byte(nil), frame.Evidence...)
	}
	if len(object.parts) < int(object.count) {
		return object.result(PartStored), nil
	}
	return r.complete(key, object)
}

// single handles an unsplit object, which the frame decoder already checked
// against its digest. Nothing is held.
func (r *Reassembler) single(sender string, frame Frame) (PartResult, error) {
	roomID, kind, err := roomPrefix(frame.Part)
	if err != nil {
		return PartResult{}, ErrReassemblyInconsistent
	}
	if len(frame.Part) > r.limits.MaxObjectBytes {
		return PartResult{}, ErrReassemblyObjectTooLarge
	}
	// An unsplit object must be one the cut leaves in one part.
	if sizes, err := RoomCut(kind, len(frame.Part), r.cutFor(kind)); err != nil || len(sizes) != 1 {
		return PartResult{}, ErrReassemblyCut
	}
	if ObjectDigest(frame.Part) != frame.ObjectDigest {
		return PartResult{}, ErrFrameDigest
	}
	if !r.senders.MayHoldInRoom(sender, roomID) {
		return PartResult{}, ErrReassemblyNotAdmitted
	}
	return PartResult{Status: PartComplete, RoomID: roomID, ObjectType: kind,
		Card: append([]byte(nil), frame.Card...), Evidence: append([]byte(nil), frame.Evidence...),
		Object: append([]byte(nil), frame.Part...)}, nil
}

func (r *Reassembler) cutFor(kind uint8) int {
	if kind == RoomApplication {
		return 0
	}
	return r.limits.PartBytes
}

// checkCut refuses a part of a split object that the fixed cut could not have
// produced: every part but the last is exactly the cut size, and the last is
// at most it. A split object is always a handshake object, so the test part
// size, when set, applies to every part.
func (r *Reassembler) checkCut(frame Frame) error {
	first, later := FirstPartBytes, LaterPartBytes
	if r.limits.PartBytes != 0 {
		first, later = r.limits.PartBytes, r.limits.PartBytes
	}
	// The smallest object this part count can describe must fit the bound.
	minimum := first + (int(frame.PartCount)-2)*later + 1
	if minimum > r.limits.MaxObjectBytes {
		return ErrReassemblyObjectTooLarge
	}
	size := later
	if frame.PartIndex == 0 {
		size = first
	}
	last := frame.PartIndex == frame.PartCount-1
	if (!last && len(frame.Part) != size) || (last && len(frame.Part) > size) {
		return ErrReassemblyCut
	}
	return nil
}

// complete releases a complete object whose digest matches, dropping it in
// either case. The mutex is held.
func (r *Reassembler) complete(key reassemblyKey, object *incompleteObject) (PartResult, error) {
	assembled := make([]byte, 0, object.bytes)
	for index := uint8(0); index < object.count; index++ {
		assembled = append(assembled, object.parts[index]...)
	}
	result := object.result(PartComplete)
	r.drop(key)
	if ObjectDigest(assembled) != key.digest {
		return PartResult{}, ErrReassemblyDigest
	}
	if !r.senders.MayHoldInRoom(key.sender, result.RoomID) {
		return PartResult{}, ErrReassemblyNotAdmitted
	}
	result.Object = assembled
	return result, nil
}

func (o *incompleteObject) result(status PartStatus) PartResult {
	return PartResult{Status: status, RoomID: o.roomID, ObjectType: o.kind,
		Card: append([]byte(nil), o.card...), Evidence: append([]byte(nil), o.evidence...)}
}

// ReplaceFirstPartEvidence keeps newer evidence (and card) for part 0 of an
// incomplete object, when a later generation delivered the same part 0 with
// evidence the caller judged newer. The part bytes are unchanged.
func (r *Reassembler) ReplaceFirstPartEvidence(sender string, digest [sha256.Size]byte, card, evidence []byte) error {
	if len(card) > MaxCardBytes || len(evidence) == 0 || len(evidence) > MaxEvidenceBytes {
		return ErrFrameMalformed
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	object, held := r.objects[reassemblyKey{sender: sender, digest: digest}]
	if !held || object.parts[0] == nil {
		return errors.New("no incomplete room object holds part 0")
	}
	object.card = append([]byte(nil), card...)
	object.evidence = append([]byte(nil), evidence...)
	return nil
}

// Sweep drops every incomplete object older than the lifetime and returns
// how many it dropped. Add also expires objects before judging a part; Sweep
// frees memory between parts, on the maintenance pass.
func (r *Reassembler) Sweep(now time.Time) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.expire(now)
}

// expire drops every incomplete object older than the lifetime. The mutex is
// held.
func (r *Reassembler) expire(now time.Time) int {
	var expired []reassemblyKey
	for key, object := range r.objects {
		if now.Sub(object.first) >= r.limits.Lifetime {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		r.drop(key)
	}
	return len(expired)
}

// DropSender drops every incomplete object of a sender, for example a member
// that was removed.
func (r *Reassembler) DropSender(sender string) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	var keys []reassemblyKey
	for key := range r.objects {
		if key.sender == sender {
			keys = append(keys, key)
		}
	}
	for _, key := range keys {
		r.drop(key)
	}
	return len(keys)
}

// Usage reports what is held: incomplete objects and part bytes, per sender
// and in total.
type Usage struct {
	Objects    int
	TotalBytes int
	PeerBytes  map[string]int
	PeerCount  map[string]int
	ObjectKeys []string
}

// Usage returns a snapshot of the held parts.
func (r *Reassembler) Usage() Usage {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	usage := Usage{Objects: len(r.objects), TotalBytes: r.total, PeerBytes: map[string]int{}, PeerCount: map[string]int{}}
	for sender, value := range r.peerBytes {
		usage.PeerBytes[sender] = value
	}
	for sender, value := range r.peerCount {
		usage.PeerCount[sender] = value
	}
	for key := range r.objects {
		usage.ObjectKeys = append(usage.ObjectKeys, key.sender+"/"+hex.EncodeToString(key.digest[:]))
	}
	sort.Strings(usage.ObjectKeys)
	return usage
}

// drop removes one incomplete object and its accounting. The mutex is held.
func (r *Reassembler) drop(key reassemblyKey) {
	object, held := r.objects[key]
	if !held {
		return
	}
	delete(r.objects, key)
	r.total -= object.bytes
	r.peerBytes[key.sender] -= object.bytes
	if r.peerBytes[key.sender] <= 0 {
		delete(r.peerBytes, key.sender)
	}
	r.peerCount[key.sender]--
	if r.peerCount[key.sender] <= 0 {
		delete(r.peerCount, key.sender)
	}
}

// roomPrefix reads the type and room of a room object from its first bytes,
// which part 0 always holds.
func roomPrefix(part []byte) (string, uint8, error) {
	prefix := len(canon.DomainRelayRoomObject)
	if len(part) < RoomObjectFixedBytes || !bytes.HasPrefix(part, []byte(canon.DomainRelayRoomObject)) {
		return "", 0, ErrRoomObjectMalformed
	}
	kind := part[prefix]
	if kind < RoomCommit || kind > RoomRoster {
		return "", 0, ErrRoomObjectMalformed
	}
	return "room_" + hex.EncodeToString(part[prefix+1:prefix+1+sha256.Size]), kind, nil
}
