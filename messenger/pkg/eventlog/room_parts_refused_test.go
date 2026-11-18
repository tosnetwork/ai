package eventlog

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// The tombstones of refused objects: a later part of a refused object is
// refused without being stored, only for its own authenticated sender, until
// an accepted part 0 lifts the tombstone or the part lifetime ends it. They
// are bounded per sender and in total.

func openRefusalParts(t *testing.T, senders ...string) (*Journal, *RoomParts, time.Time) {
	t.Helper()
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Unix(1_900_000_000, 0)
	parts, _ := openParts(t, journal, allowSenders(senders...), now)
	return journal, parts, now
}

func TestRoomPartOfARefusedObjectIsRefusedUnstored(t *testing.T) {
	sender := fusedAgent(1)
	journal, parts, now := openRefusalParts(t, sender)
	frames, digest := splitObject(t, 1, 2500, 1024)
	if _, err := parts.Add(sender, frames[1], now); err != nil {
		t.Fatal(err)
	}
	if err := parts.Refuse(sender, digest, now); err != nil {
		t.Fatal(err)
	}
	if !parts.RefusedObject(sender, digest, now) {
		t.Fatal("the refusal left no tombstone")
	}
	for _, frame := range frames[1:] {
		if _, err := parts.Add(sender, frame, now.Add(time.Second)); !errors.Is(err, ErrRoomPartRefusedObject) {
			t.Fatalf("a later part of a refused object: %v", err)
		}
	}
	if count := storedPartCount(t, journal); count != 0 {
		t.Fatalf("%d parts of a refused object stored", count)
	}
	if usage := parts.Usage(); usage.Objects != 0 {
		t.Fatalf("the Reassembler holds a refused object: %+v", usage)
	}
}

func TestRoomPartTombstoneIsTheSendersOwn(t *testing.T) {
	sender, other := fusedAgent(1), fusedAgent(2)
	journal, parts, now := openRefusalParts(t, sender, other)
	frames, digest := splitObject(t, 1, 2500, 1024)
	if err := parts.Refuse(other, digest, now); err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames[1:] {
		if _, err := parts.Add(sender, frame, now); err != nil {
			t.Fatalf("another sender's tombstone refused a part: %v", err)
		}
	}
	if count := storedPartCount(t, journal); count != len(frames)-1 {
		t.Fatalf("%d parts stored, want %d", count, len(frames)-1)
	}
}

func TestRoomPartAcceptedPartZeroLiftsTheTombstone(t *testing.T) {
	sender := fusedAgent(1)
	_, parts, now := openRefusalParts(t, sender)
	frames, digest := splitObject(t, 1, 2500, 1024)
	if err := parts.Refuse(sender, digest, now); err != nil {
		t.Fatal(err)
	}
	for index, frame := range frames {
		result, err := parts.Add(sender, frame, now)
		if err != nil {
			t.Fatalf("part %d after an accepted part 0: %v", index, err)
		}
		if index == len(frames)-1 && result.Status != relayframe.PartComplete {
			t.Fatalf("the object did not complete: %+v", result.Status)
		}
	}
	if parts.RefusedObject(sender, digest, now) {
		t.Fatal("an accepted part 0 left the tombstone")
	}
}

func TestRoomPartTombstoneEndsWithThePartLifetime(t *testing.T) {
	sender := fusedAgent(1)
	_, parts, now := openRefusalParts(t, sender)
	frames, digest := splitObject(t, 1, 2500, 1024)
	if err := parts.Refuse(sender, digest, now); err != nil {
		t.Fatal(err)
	}
	lifetime := relayframe.DefaultReassemblyLimits().Lifetime
	if !parts.RefusedObject(sender, digest, now.Add(lifetime-time.Second)) {
		t.Fatal("the tombstone ended before the part lifetime")
	}
	if _, err := parts.Add(sender, frames[1], now.Add(lifetime)); err != nil {
		t.Fatalf("a part after the tombstone's lifetime: %v", err)
	}
}

func TestRoomPartTombstonesAreBounded(t *testing.T) {
	sender, other := fusedAgent(1), fusedAgent(2)
	_, parts, now := openRefusalParts(t, sender, other)
	digestOf := func(n int) [sha256.Size]byte {
		var digest [sha256.Size]byte
		digest[0], digest[1] = byte(n>>8), byte(n)
		return digest
	}
	// Per sender: the sender's oldest gives way, not another sender's older
	// one.
	if err := parts.Refuse(other, digestOf(0), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for n := 0; n <= MaxRefusedRoomObjectsPerSender; n++ {
		if err := parts.Refuse(sender, digestOf(n), now.Add(time.Duration(n)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	at := now.Add(time.Hour)
	if parts.RefusedObject(sender, digestOf(0), at) {
		t.Fatal("the per-sender bound kept the oldest tombstone")
	}
	for n := 1; n <= MaxRefusedRoomObjectsPerSender; n++ {
		if !parts.RefusedObject(sender, digestOf(n), at) {
			t.Fatalf("tombstone %d was dropped below the per-sender bound", n)
		}
	}
	if !parts.RefusedObject(other, digestOf(0), at) {
		t.Fatal("the per-sender bound dropped another sender's tombstone")
	}
	// In total: many senders, the oldest of all gives way.
	senders := make([]string, 0, MaxRefusedRoomObjects)
	for n := 0; len(senders)*MaxRefusedRoomObjectsPerSender < MaxRefusedRoomObjects+MaxRefusedRoomObjectsPerSender; n++ {
		senders = append(senders, fusedAgent(3+n))
	}
	refusedAt := now.Add(time.Minute)
	for index, agent := range senders {
		for n := 0; n < MaxRefusedRoomObjectsPerSender; n++ {
			refusedAt = refusedAt.Add(time.Millisecond)
			if err := parts.Refuse(agent, digestOf(index*MaxRefusedRoomObjectsPerSender+n), refusedAt); err != nil {
				t.Fatal(err)
			}
		}
	}
	parts.mutex.Lock()
	total := len(parts.refused)
	parts.mutex.Unlock()
	if total != MaxRefusedRoomObjects {
		t.Fatalf("%d tombstones held, bound %d", total, MaxRefusedRoomObjects)
	}
	if parts.RefusedObject(other, digestOf(0), at) || parts.RefusedObject(sender, digestOf(MaxRefusedRoomObjectsPerSender), at) {
		t.Fatal("the total bound kept the oldest tombstones")
	}
	last := senders[len(senders)-1]
	if !parts.RefusedObject(last, digestOf((len(senders)-1)*MaxRefusedRoomObjectsPerSender+MaxRefusedRoomObjectsPerSender-1), at) {
		t.Fatal("the newest tombstone was dropped")
	}
}
