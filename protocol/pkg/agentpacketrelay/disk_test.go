package agentpacketrelay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func openDisk(t *testing.T, dir string, clock *fakeClock) *Store {
	t.Helper()
	store, err := OpenDiskStore(dir, testLimits(), clock.Now())
	if err != nil {
		t.Fatalf("open disk store: %v", err)
	}
	return store
}

func TestDiskRestartDurability(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	store := openDisk(t, dir, clock)
	relay := newTestRelayWithStore(t, store, clock)
	alice := newRecipient(t)
	kept := alice.seal(t, testPacket(10_000), clock.unix()+3600)
	acked := alice.seal(t, testPacket(10), clock.unix()+3600)
	short := alice.seal(t, testPacket(10), clock.unix()+60)
	for _, env := range []sealed{kept, acked, short} {
		expectStatus(t, relay.putSealed(env), 201)
	}
	expectStatus(t, relay.ackRaw(alice.agentID, acked.id, acked.secret[:]), 204)
	before, err := relay.client.List(context.Background(), alice.agentID)
	if err != nil || len(before.Envelopes) != 3-1 {
		t.Fatalf("list = %+v, %v", before, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openDisk(t, dir, clock)
	relay2 := newTestRelayWithStore(t, reopened, clock)
	after, err := relay2.client.List(context.Background(), alice.agentID)
	if err != nil || fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("listing changed across restart:\n%+v\n%+v (%v)", before, after, err)
	}
	if raw, err := relay2.client.Download(context.Background(), alice.agentID, kept.id); err != nil || !bytes.Equal(raw, kept.envelope) {
		t.Fatalf("download after restart: %v", err)
	}
	expectStatus(t, relay2.putSealed(acked), 410)
	expectStatus(t, relay2.ackRaw(alice.agentID, acked.id, acked.secret[:]), 204)
	expectStatus(t, relay2.putSealed(kept), 200)
	checkAccounting(t, reopened)
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening after the short envelope expired removes its file.
	clock.Advance(2 * time.Minute)
	third := openDisk(t, dir, clock)
	defer third.Close()
	if _, err := os.Stat(filepath.Join(dir, dirEnvelopes, keyFileName(short.key(t)))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired envelope file survived reopen: %v", err)
	}
	if usage := third.Usage(); usage.Envelopes != 1 || usage.Tombstones != 1 {
		t.Fatalf("usage after expiry reopen = %+v", usage)
	}
	// The sweep removes files too.
	clock.Advance(time.Hour)
	if err := third.Sweep(clock.Now()); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{dirEnvelopes, dirTombstones} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil || len(entries) != 0 {
			t.Fatalf("%s after sweep: %d entries, %v", sub, len(entries), err)
		}
	}
}

// TestDiskCrashBetweenTombstoneAndDelete leaves both files, as a crash
// between the two steps of an acknowledgement does: the tombstone wins.
func TestDiskCrashBetweenTombstoneAndDelete(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	store := openDisk(t, dir, clock)
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(10), clock.unix()+3600)
	relay := newTestRelayWithStore(t, store, clock)
	expectStatus(t, relay.putSealed(env), 201)
	digest, err := agentpacketseal.AgentDigest(alice.agentID)
	if err != nil {
		t.Fatal(err)
	}
	backend := store.backend.(*diskBackend)
	if err := backend.putTombstone(env.key(t), tombstone{agent: digest, expires: clock.unix() + 3600}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openDisk(t, dir, clock)
	defer reopened.Close()
	if usage := reopened.Usage(); usage.Envelopes != 0 || usage.Tombstones != 1 {
		t.Fatalf("usage = %+v", usage)
	}
	if _, err := os.Stat(backend.envelopePath(env.key(t))); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the acknowledged envelope file survived reopen")
	}
}

func TestDiskRefusesCorruptOrForeignState(t *testing.T) {
	clock := newClock()
	alice := newRecipient(t)
	prepare := func(t *testing.T) (string, sealed) {
		dir := t.TempDir()
		store := openDisk(t, dir, clock)
		relay := newTestRelayWithStore(t, store, clock)
		env := alice.seal(t, testPacket(100), clock.unix()+3600)
		expectStatus(t, relay.putSealed(env), 201)
		other := alice.seal(t, testPacket(100), clock.unix()+3600)
		expectStatus(t, relay.putSealed(other), 201)
		expectStatus(t, relay.ackRaw(alice.agentID, other.id, other.secret[:]), 204)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		return dir, env
	}
	flip := func(path string, offset int) func(*testing.T) {
		return func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if offset < 0 {
				offset += len(raw)
			}
			raw[offset] ^= 1
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := map[string]func(dir string, env sealed) func(*testing.T){
		"envelope record byte": func(dir string, env sealed) func(*testing.T) {
			return flip(filepath.Join(dir, dirEnvelopes, keyFileName(env.key(t))), -1)
		},
		"envelope record meta": func(dir string, env sealed) func(*testing.T) {
			return flip(filepath.Join(dir, dirEnvelopes, keyFileName(env.key(t))), 10)
		},
		"tombstone byte": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				entries, err := os.ReadDir(filepath.Join(dir, dirTombstones))
				if err != nil || len(entries) != 1 {
					t.Fatal(err)
				}
				flip(filepath.Join(dir, dirTombstones, entries[0].Name()), 12)(t)
			}
		},
		// A flipped expiry byte changes no name and no ID: only the
		// tombstone's checksum can catch it.
		"tombstone expiry byte": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				entries, err := os.ReadDir(filepath.Join(dir, dirTombstones))
				if err != nil || len(entries) != 1 {
					t.Fatal(err)
				}
				flip(filepath.Join(dir, dirTombstones, entries[0].Name()), tombstoneSize-33)(t)
			}
		},
		"truncated record": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				path := filepath.Join(dir, dirEnvelopes, keyFileName(env.key(t)))
				if err := os.Truncate(path, 500); err != nil {
					t.Fatal(err)
				}
			}
		},
		"record under another name": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				other := env.key(t)
				other.id[0] ^= 1
				if err := os.Rename(filepath.Join(dir, dirEnvelopes, keyFileName(env.key(t))),
					filepath.Join(dir, dirEnvelopes, keyFileName(other))); err != nil {
					t.Fatal(err)
				}
			}
		},
		"record under another mailbox": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				other := env.key(t)
				other.agent[0] ^= 1
				if err := os.Rename(filepath.Join(dir, dirEnvelopes, keyFileName(env.key(t))),
					filepath.Join(dir, dirEnvelopes, keyFileName(other))); err != nil {
					t.Fatal(err)
				}
			}
		},
		"tombstone under another mailbox": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				entries, err := os.ReadDir(filepath.Join(dir, dirTombstones))
				if err != nil || len(entries) != 1 {
					t.Fatal(err)
				}
				name := entries[0].Name()
				moved := "0" + name[1:]
				if name[0] == '0' {
					moved = "1" + name[1:]
				}
				if err := os.Rename(filepath.Join(dir, dirTombstones, name), filepath.Join(dir, dirTombstones, moved)); err != nil {
					t.Fatal(err)
				}
			}
		},
		"old ID-only file name": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				if err := os.Rename(filepath.Join(dir, dirEnvelopes, keyFileName(env.key(t))),
					filepath.Join(dir, dirEnvelopes, hex.EncodeToString(env.id[:]))); err != nil {
					t.Fatal(err)
				}
			}
		},
		"unknown file": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(dir, dirEnvelopes, "notes.txt"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
		"wrong format": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(dir, "FORMAT"), []byte("v2\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
		"missing format": func(dir string, env sealed) func(*testing.T) {
			return func(t *testing.T) {
				if err := os.Remove(filepath.Join(dir, "FORMAT")); err != nil {
					t.Fatal(err)
				}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir, env := prepare(t)
			// The untouched directory opens.
			store := openDisk(t, dir, clock)
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			mutate(dir, env)(t)
			if store, err := OpenDiskStore(dir, testLimits(), clock.Now()); err == nil {
				store.Close()
				t.Fatal("corrupt state directory opened")
			}
		})
	}
}

func TestDiskTempAndLock(t *testing.T) {
	dir := t.TempDir()
	clock := newClock()
	store := openDisk(t, dir, clock)
	if _, err := OpenDiskStore(dir, testLimits(), clock.Now()); err == nil {
		t.Fatal("a second process could open a held state directory")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(dir, dirTemp, "write-123")
	if err := os.WriteFile(partial, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	store = openDisk(t, dir, clock)
	defer store.Close()
	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a partial write survived reopen")
	}
	if _, err := OpenDiskStore("relative/dir", testLimits(), clock.Now()); err == nil {
		t.Fatal("relative state directory accepted")
	}
	for _, sub := range []string{"", dirEnvelopes, dirTombstones, dirTemp} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil || info.Mode().Perm()&0o077 != 0 && sub != "" {
			t.Fatalf("%s mode %v, %v", sub, info.Mode(), err)
		}
	}
}

func TestDiskRecordEncoding(t *testing.T) {
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(10), 1_900_000_000)
	header, err := agentpacketseal.ParseEnvelope(env.envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := agentpacketseal.AgentDigest(alice.agentID)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []string{"192.0.2.1", "2001:db8::"} {
		rec := record{agent: digest, keyID: header.RecipientKeyID, id: env.id, size: int64(len(env.envelope)),
			received: 1_800_000_000, expires: 1_800_003_600, client: netip.MustParseAddr(client)}
		raw := encodeEnvelopeRecord(rec, env.envelope)
		got, envelope, err := decodeEnvelopeRecord(entryKey{agent: digest, id: env.id}, raw)
		if err != nil || !bytes.Equal(envelope, env.envelope) || got.client != rec.client || got.received != rec.received ||
			got.expires != rec.expires || got.agent != digest || got.size != rec.size {
			t.Fatalf("%s: decode = %+v, %v", client, got, err)
		}
		// An effective expiry past the envelope's own is corrupt.
		rec.expires = header.ExpiresAtUnix + 1
		if _, _, err := decodeEnvelopeRecord(entryKey{agent: digest, id: env.id}, encodeEnvelopeRecord(rec, env.envelope)); err == nil {
			t.Fatal("record with an expiry past the envelope's accepted")
		}
		// A record read under another mailbox's name is corrupt.
		rec.expires = header.ExpiresAtUnix
		otherAgent := digest
		otherAgent[0] ^= 1
		if _, _, err := decodeEnvelopeRecord(entryKey{agent: otherAgent, id: env.id}, encodeEnvelopeRecord(rec, env.envelope)); err == nil {
			t.Fatal("record under another mailbox accepted")
		}
	}
}

// crashChildEnv names the state directory of the crash child process.
const crashChildEnv = "AGENTPACKETRELAY_CRASH_CHILD_DIR"

// TestCrashChild is the child half of TestDiskKillDuringWrites. It deposits
// and acknowledges large envelopes as fast as it can and prints each ID once
// the store has answered, until it is killed.
func TestCrashChild(t *testing.T) {
	dir := os.Getenv(crashChildEnv)
	if dir == "" {
		return
	}
	store, err := OpenDiskStore(dir, DefaultLimits(1<<20, 1<<34), time.Now())
	if err != nil {
		fmt.Println("OPEN-FAILED", err)
		os.Exit(3)
	}
	writer := bufio.NewWriter(os.Stdout)
	alice := newRecipient(t)
	client := mustAddr(t, "192.0.2.1")
	for index := 0; ; index++ {
		r := alice
		if index%16 == 0 {
			// New recipients keep each mailbox below its quota.
			alice = newRecipient(t)
			r = alice
		}
		env := r.seal(t, testPacket(150_000+index%1000), uint64(time.Now().Unix())+3600)
		header, err := agentpacketseal.ParseEnvelope(env.envelope)
		if err != nil {
			os.Exit(4)
		}
		now := uint64(time.Now().Unix())
		status, err := store.deposit(context.Background(), depositInput{header: header, envelope: env.envelope,
			client: client, now: now, expires: header.ExpiresAtUnix})
		if err != nil || status != depositCreated {
			fmt.Println("DEPOSIT-FAILED", status, err)
			os.Exit(5)
		}
		fmt.Fprintf(writer, "D %s %x\n", r.agentID, env.id)
		if index%3 == 0 {
			digest, _ := agentpacketseal.AgentDigest(r.agentID)
			if status, err := store.ack(context.Background(), digest, env.id, now); err != nil || status != ackDeleted {
				fmt.Println("ACK-FAILED", status, err)
				os.Exit(6)
			}
			fmt.Fprintf(writer, "A %s %x\n", r.agentID, env.id)
		}
		if err := writer.Flush(); err != nil {
			os.Exit(7)
		}
	}
}

// TestDiskKillDuringWrites kills a writing process with SIGKILL at varying
// moments, reopens its state directory each time, and checks that every
// write the process had been told was durable survived, every
// acknowledgement left a tombstone and no envelope, every record verifies,
// and the accounting matches a recount.
func TestDiskKillDuringWrites(t *testing.T) {
	if os.Getenv(crashChildEnv) != "" {
		t.Skip("child process")
	}
	dir := t.TempDir()
	deposited := map[string]bool{}
	acknowledged := map[string]bool{}
	killedMidWrite := 0
	for round := range 6 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), crashChildEnv+"="+dir)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(stdout)
		target := 20 + round*7
		lines := 0
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 3 || (fields[0] != "D" && fields[0] != "A") {
				t.Fatalf("child: %q", scanner.Text())
			}
			key := fields[1] + "/" + fields[2]
			if fields[0] == "D" {
				deposited[key] = true
			} else {
				acknowledged[key] = true
			}
			if lines++; lines >= target {
				break
			}
		}
		// Kill while the next write is in flight.
		if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		if lines < target {
			t.Fatalf("round %d: child stopped after %d lines", round, lines)
		}
		if partial, err := os.ReadDir(filepath.Join(dir, dirTemp)); err == nil && len(partial) > 0 {
			killedMidWrite++
		}

		store, err := OpenDiskStore(dir, DefaultLimits(1<<20, 1<<34), time.Now())
		if err != nil {
			t.Fatalf("round %d: reopen after SIGKILL: %v", round, err)
		}
		clock := &fakeClock{now: time.Now()}
		relay := newTestRelayWithStore(t, store, clock)
		for key := range deposited {
			agentID, idText, _ := strings.Cut(key, "/")
			id, _ := parseEnvelopeIDText(idText)
			storeKey := keyFor(t, agentID, id)
			got := relay.do(http.MethodGet, relay.envelopeURL(agentID, id), "", nil)
			if acknowledged[key] {
				if got.status != 404 {
					t.Fatalf("round %d: acknowledged envelope still downloadable", round)
				}
				store.mu.Lock()
				_, held := store.tombstones[storeKey]
				store.mu.Unlock()
				if !held {
					t.Fatalf("round %d: acknowledged ID has no tombstone", round)
				}
				continue
			}
			if got.status == 404 {
				// The child may have acknowledged it after the last line
				// this side read; then, and only then, a tombstone holds.
				store.mu.Lock()
				_, held := store.tombstones[storeKey]
				store.mu.Unlock()
				if held {
					continue
				}
			}
			if got.status != 200 {
				t.Fatalf("round %d: durable envelope lost: %d", round, got.status)
			}
			if header, err := agentpacketseal.ParseEnvelope(got.body); err != nil || header.EnvelopeID != id {
				t.Fatalf("round %d: torn envelope", round)
			}
		}
		checkAccounting(t, store)
		entries, err := os.ReadDir(filepath.Join(dir, dirTemp))
		if err != nil || len(entries) != 0 {
			t.Fatalf("round %d: tmp holds %d entries, %v", round, len(entries), err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d of 6 kills left a partial write in tmp/", killedMidWrite)
	if len(deposited) < 50 || len(acknowledged) < 10 {
		t.Fatalf("too little traffic to be evidence: %d deposits, %d acks", len(deposited), len(acknowledged))
	}
}
