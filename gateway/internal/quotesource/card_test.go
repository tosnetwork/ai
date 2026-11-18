package quotesource

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal/keycardtest"
)

func profileCard(t *testing.T, agent string, seed byte, now time.Time) []byte {
	t.Helper()
	start := uint64(now.Add(-time.Hour).Unix())
	return keycardtest.JSON(t, keycardtest.Spec{AgentID: agent, Controller: "provider-packet", Seed: seed,
		NotBeforeUnix: start, NotAfterUnix: start + 7*24*3600})
}

// cardProfile writes a profile naming a card file holding card, and loads
// it.
func cardProfile(t *testing.T, card []byte, mode os.FileMode) (Profile, string) {
	t.Helper()
	files := newProfileFiles(t, actorCodeHash)
	path := filepath.Join(files.directory, "provider-card.json")
	if card != nil {
		writePrivate(t, path, card)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	document := files.document()
	document["provider_key_card_file"] = path
	profile, _, err := LoadProfile(files.write(t, document, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	return profile, path
}

func TestAProfileWithoutACardFileServesNoCard(t *testing.T) {
	files := newProfileFiles(t, actorCodeHash)
	profile, _, err := LoadProfile(files.write(t, files.document(), 0o600))
	if err != nil {
		t.Fatal(err)
	}
	cards, err := LoadCardFile(profile, time.Now())
	if err != nil || cards != nil {
		t.Fatalf("a profile without a card file gave a card source: %v %v", cards, err)
	}
}

func TestTheCardFileServesTheCurrentCardAndFollowsARepublication(t *testing.T) {
	now := time.Now()
	first := profileCard(t, providerAgentID, 1, now)
	profile, path := cardProfile(t, first, 0o600)
	cards, err := LoadCardFile(profile, now)
	if err != nil || cards == nil {
		t.Fatalf("a valid card file was refused: %v", err)
	}
	served, err := cards.ProviderKeyCard()
	if err != nil || !bytes.Equal(served, first) {
		t.Fatalf("the card file did not serve its card: %v", err)
	}
	// The provider republishes by replacing the file; the next Quote serves
	// the successor without a restart.
	successor := profileCard(t, providerAgentID, 2, now)
	replacement := path + ".next"
	writePrivate(t, replacement, successor)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	served, err = cards.ProviderKeyCard()
	if err != nil || !bytes.Equal(served, successor) {
		t.Fatalf("the republished card was not served: %v", err)
	}
}

func TestAMisconfiguredCardFileIsRefusedAtStart(t *testing.T) {
	now := time.Now()
	valid := profileCard(t, providerAgentID, 1, now)
	cases := map[string]func(*testing.T) Profile{
		"missing": func(t *testing.T) Profile {
			profile, _ := cardProfile(t, nil, 0o600)
			return profile
		},
		"group-readable": func(t *testing.T) Profile {
			profile, _ := cardProfile(t, valid, 0o640)
			return profile
		},
		"another Agent's card": func(t *testing.T) Profile {
			profile, _ := cardProfile(t, profileCard(t, "agent_"+strings.Repeat("66", 32), 1, now), 0o600)
			return profile
		},
		"expired": func(t *testing.T) Profile {
			profile, _ := cardProfile(t, profileCard(t, providerAgentID, 1, now.Add(-8*24*time.Hour)), 0o600)
			return profile
		},
		"over the card bound": func(t *testing.T) Profile {
			profile, _ := cardProfile(t, append(bytes.Repeat([]byte{' '}, 16<<10), valid...), 0o600)
			return profile
		},
		"relative path": func(t *testing.T) Profile {
			profile, _ := cardProfile(t, valid, 0o600)
			profile.ProviderKeyCardFile = "provider-card.json"
			return profile
		},
	}
	for name, build := range cases {
		if cards, err := LoadCardFile(build(t), now); err == nil || cards != nil {
			t.Errorf("%s: a misconfigured card file was accepted", name)
		}
	}
}

func TestANilCardFileFailsClosed(t *testing.T) {
	var cards *CardFile
	if raw, err := cards.ProviderKeyCard(); err == nil || raw != nil {
		t.Fatal("a nil card file served a card")
	}
}
