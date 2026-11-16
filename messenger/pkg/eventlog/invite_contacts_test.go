package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const inviteTestToken = "invite_" + "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

func TestPresentedInviteLivesUntilSettledOrExpired(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(10_000, 0)
	recipient := fusedAgent(3)
	if _, err := journal.PresentInvite(recipient, "invite_short", now.Add(time.Hour), now); err == nil {
		t.Fatal("a malformed token was presented")
	}
	if _, err := journal.PresentInvite(recipient, inviteTestToken, now, now); err == nil {
		t.Fatal("an already expired invite was presented")
	}
	if _, err := journal.PresentInvite(recipient, inviteTestToken, now.Add(MaxAdmissionInviteLifetime+time.Second), now); err == nil {
		t.Fatal("an invite beyond the lifetime bound was presented")
	}
	if _, err := journal.PresentInvite(recipient, inviteTestToken, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if token, found, err := journal.PresentedInviteFor(recipient, now); err != nil || !found || token != inviteTestToken {
		t.Fatalf("presented invite: %v %v", found, err)
	}
	if settled, err := journal.SettlePresentedInvite(recipient, "invite_"+strings.Repeat("A", 43)); err != nil || settled {
		t.Fatal("another token settled the presented invite")
	}
	if settled, err := journal.SettlePresentedInvite(recipient, inviteTestToken); err != nil || !settled {
		t.Fatalf("settle: %v %v", settled, err)
	}
	if _, found, _ := journal.PresentedInviteFor(recipient, now); found {
		t.Fatal("a settled invite is still presented")
	}
	if _, err := journal.PresentInvite(recipient, inviteTestToken, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := journal.PresentedInviteFor(recipient, now.Add(time.Hour)); err != nil || found {
		t.Fatalf("an expired invite is still presented: %v", err)
	}
	if _, err := os.Stat(journal.agentRecordPath(presentedInviteDir, recipient)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an expired invite was not deleted")
	}
}

func TestInvitedContactsAreIdempotentRemovableAndFailClosed(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10_000, 0)
	agent := fusedAgent(4)
	event := "evt_" + strings.Repeat("e", 64)
	if added, err := journal.AddInvitedContact(agent, event, inviteTestToken, now); err != nil || !added {
		t.Fatalf("add: %v %v", added, err)
	}
	if added, err := journal.AddInvitedContact(agent, event, inviteTestToken, now); err != nil || added {
		t.Fatalf("a repeated add is not a no-op: %v %v", added, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if invited, err := journal.IsInvitedContact(agent); err != nil || !invited {
		t.Fatalf("the contact did not survive restart: %v %v", invited, err)
	}
	// Maintenance never sweeps the list.
	if _, err := journal.Prune(now.Add(365*24*time.Hour), MinClaimRetention); err != nil {
		t.Fatal(err)
	}
	if invited, _ := journal.IsInvitedContact(agent); !invited {
		t.Fatal("maintenance swept an invited contact")
	}
	if removed, err := journal.RemoveInvitedContact(agent); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if removed, err := journal.RemoveInvitedContact(agent); err != nil || removed {
		t.Fatal("a missing contact was removed")
	}
	// A damaged record fails the lookup instead of admitting.
	path := filepath.Join(root, invitedContactDir, agent[len("agent_"):]+".json")
	if err := os.WriteFile(path, []byte(`{"schema":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if invited, err := journal.IsInvitedContact(agent); err == nil || invited {
		t.Fatal("a damaged invited contact record admitted")
	}
}
