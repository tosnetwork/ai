package eventlog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectConversationPinsAgentIdentityAcrossRetryRotationAndRestart(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	local := "agent_" + strings.Repeat("1", 64)
	remoteA := "agent_" + strings.Repeat("2", 64)
	remoteB := "agent_" + strings.Repeat("3", 64)
	endpointA1 := "mep_" + strings.Repeat("4", 64)
	endpointA2 := "mep_" + strings.Repeat("5", 64)
	endpointB := "mep_" + strings.Repeat("6", 64)
	now := time.Unix(1_800_000_000, 0)

	first, created, err := journal.EnsureDirectConversation(local, remoteA, endpointA1, 100, now, [32]byte{1})
	if err != nil || !created || first.RemoteAgentID != remoteA || first.VerifiedRemoteEndpointID != endpointA1 ||
		first.State != DirectConversationDiscovered {
		t.Fatalf("first ensure: record=%+v created=%v err=%v", first, created, err)
	}
	retry, created, err := journal.EnsureDirectConversation(local, remoteA, endpointA1, 100, now, [32]byte{2})
	if err != nil || created || retry.ConversationID != first.ConversationID {
		t.Fatalf("retry replaced conversation: record=%+v created=%v err=%v", retry, created, err)
	}
	rotated, created, err := journal.EnsureDirectConversation(
		local, remoteA, endpointA2, 101, now.Add(time.Second), [32]byte{3},
	)
	if err != nil || created || rotated.ConversationID != first.ConversationID ||
		rotated.VerifiedRemoteEndpointID != endpointA2 {
		t.Fatalf("rotation changed identity: record=%+v created=%v err=%v", rotated, created, err)
	}
	transferred, created, err := journal.EnsureDirectConversation(
		local, remoteB, endpointB, 102, now.Add(2*time.Second), [32]byte{4},
	)
	if err != nil || !created || transferred.ConversationID == first.ConversationID {
		t.Fatalf("new Agent reused old conversation: record=%+v created=%v err=%v", transferred, created, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, found, err := reopened.DirectConversation(local, remoteA)
	if err != nil || !found || restored.ConversationID != first.ConversationID ||
		restored.RemoteAgentID != remoteA || restored.VerifiedRemoteEndpointID != endpointA2 {
		t.Fatalf("restart lost pinned conversation: record=%+v found=%v err=%v", restored, found, err)
	}
}

func TestDirectConversationRejectsRollbackSubstitutionAndCorruption(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	local := "agent_" + strings.Repeat("1", 64)
	remote := "agent_" + strings.Repeat("2", 64)
	endpoint := "mep_" + strings.Repeat("3", 64)
	now := time.Unix(1_800_000_000, 0)
	if _, _, err := journal.EnsureDirectConversation(local, remote, endpoint, 100, now, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.EnsureDirectConversation(
		local, remote, endpoint, 99, now.Add(time.Second), [32]byte{2},
	); !errors.Is(err, ErrDirectConversationRollback) {
		t.Fatalf("checkpoint rollback error=%v", err)
	}
	if _, _, err := journal.EnsureDirectConversation(
		local, remote, "mep_"+strings.Repeat("4", 64), 100, now.Add(time.Second), [32]byte{2},
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-checkpoint endpoint substitution error=%v", err)
	}
	if _, _, err := journal.EnsureDirectConversation(local, local, endpoint, 101, now, [32]byte{2}); err == nil {
		t.Fatal("self conversation was accepted")
	}
	if _, _, err := journal.EnsureDirectConversation(local, "agent_"+strings.Repeat("5", 64), endpoint, 101, now, [32]byte{}); err == nil {
		t.Fatal("zero conversation entropy was accepted")
	}
	if _, _, err := journal.DirectConversation("agent_"+strings.Repeat("6", 64), remote); err == nil {
		t.Fatal("conversation was readable under another local Agent")
	}
	path := journal.directConversationPath(remote)
	if err := os.WriteFile(path, []byte("{\"schema\":\"unknown\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.DirectConversation(local, remote); err == nil {
		t.Fatal("corrupt direct conversation was accepted")
	}
}

func listingJournal(t *testing.T, count int) (*Journal, string, time.Time) {
	t.Helper()
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	local := "agent_" + strings.Repeat("1", 64)
	start := time.Unix(1_800_000_000, 0)
	for index := 0; index < count; index++ {
		remote := fmt.Sprintf("agent_%064x", index+2)
		at := start.Add(time.Duration(index/3) * time.Second)
		if _, _, err := journal.EnsureDirectConversation(local, remote, fmt.Sprintf("mep_%064x", index+2), 10, at,
			[32]byte{byte(index), 7}); err != nil {
			t.Fatal(err)
		}
	}
	return journal, local, start
}

// A leftover temporary file of an interrupted write is neither listed nor
// counted against the ledger bound.
func TestDirectConversationListingSkipsTransitionFiles(t *testing.T) {
	journal, local, _ := listingJournal(t, 3)
	dir := filepath.Join(journal.root, directConversationDir)
	for _, name := range []string{".transition-123", ".tmp-456"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	records, err := journal.ListDirectConversations(local, 0, "", MaxDirectConversationsPerPage)
	if err != nil || len(records) != 3 {
		t.Fatalf("listing with leftovers: %d records, %v", len(records), err)
	}
}

// A conversation updated between two pages of a walk is listed exactly once:
// the walk is ordered by creation, which an update does not change.
func TestDirectConversationWalkIsStableAcrossAnUpdate(t *testing.T) {
	journal, local, start := listingJournal(t, 9)
	first, err := journal.ListDirectConversations(local, 0, "", 4)
	if err != nil || len(first) != 4 {
		t.Fatalf("first page: %d, %v", len(first), err)
	}
	// The oldest conversation, not yet listed, is refreshed now: by update
	// time it would move before the cursor and never be listed.
	oldest := fmt.Sprintf("agent_%064x", 2)
	if _, _, err := journal.EnsureDirectConversation(local, oldest, fmt.Sprintf("mep_%064x", 2), 11,
		start.Add(time.Hour), [32]byte{9, 9}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, record := range first {
		seen[record.RemoteAgentID]++
	}
	last := first[len(first)-1]
	for pages := 0; pages < 4; pages++ {
		page, err := journal.ListDirectConversations(local, last.CreatedAtUnix, last.ConversationID, 4)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range page {
			seen[record.RemoteAgentID]++
		}
		if len(page) < 4 {
			break
		}
		last = page[len(page)-1]
	}
	if len(seen) != 9 {
		t.Fatalf("walk listed %d of 9 conversations: %v", len(seen), seen)
	}
	for remote, times := range seen {
		if times != 1 {
			t.Fatalf("%s listed %d times", remote, times)
		}
	}
}

// Temporary files do not count toward the ledger's bound when a new
// conversation is created.
func TestDirectConversationCountSkipsTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".transition-1", ".tmp-2", "a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := countRecords(entries); got != 2 {
		t.Fatalf("counted %d records", got)
	}
}
