package agentcarrier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeysRotateRetainAndRemainSeparateByLane(t *testing.T) {
	f := newFixture(t)
	first, err := f.lane.CurrentCard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	same, err := f.lane.CurrentCard(t.Context())
	if err != nil || !bytes.Equal(first.Packet, same.Packet) {
		t.Fatal("fresh key changed", err)
	}
	if err = f.lane.Close(); err != nil {
		t.Fatal(err)
	}
	f.lane, err = Open(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	same, err = f.lane.CurrentCard(t.Context())
	if err != nil || !bytes.Equal(first.Packet, same.Packet) {
		t.Fatal("restart reissued the key", err)
	}
	chatConfig := f.config
	chatConfig.Kind = Chat
	chat, err := Open(t.Context(), chatConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := chat.Close(); e != nil {
			t.Error(e)
		}
	}()
	other, err := chat.CurrentCard(t.Context())
	if err != nil || other.Card.KeyID == first.Card.KeyID {
		t.Fatal("lane families share a key", err)
	}
	f.clock.n.Store(int64(first.Card.NotAfterUnix) - int64(SuccessorLead/time.Second))
	next, err := f.lane.CurrentCard(t.Context())
	if err != nil || next.Card.KeyID == first.Card.KeyID {
		t.Fatal("successor not issued", err)
	}
	path := filepath.Join(f.config.StateDir, string(Rail), keyName(first.Card.KeyID))
	info, err := os.Lstat(path)
	if err != nil || !singlePrivate(info) {
		t.Fatal("unsafe retained key", err)
	}
	f.clock.n.Store(int64(first.Card.NotAfterUnix) + int64(KeyRetention/time.Second) - 1)
	held, _, err := f.lane.heldKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := held[first.Card.KeyID]; !ok {
		t.Fatal("key removed before retention ended")
	}
	f.clock.n.Add(1)
	held, _, err = f.lane.heldKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := held[first.Card.KeyID]; ok {
		t.Fatal("key retained after its destruction deadline")
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expired seed remains on disk", err)
	}
}
func TestSixteenKeysAreAHardBound(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < MaxKeys; i++ {
		f.lane.config.Relays = []string{fmt.Sprintf("https://127.0.0.1/k%d", i)}
		if _, err := f.lane.CurrentCard(t.Context()); err != nil {
			t.Fatal(i, err)
		}
	}
	f.lane.config.Relays = []string{"https://127.0.0.1/overflow"}
	sign := f.lane.config.SignCard
	signs := 0
	f.lane.config.SignCard = func(ctx context.Context, c agentpacketseal.KeyCard) ([]byte, error) { signs++; return sign(ctx, c) }
	if _, err := f.lane.CurrentCard(t.Context()); !errors.Is(err, ErrCapacity) || signs != 0 {
		t.Fatal("key bound was not enforced before signing", err, signs)
	}
}
func TestOutboxAndPollTargetsHaveHardBounds(t *testing.T) {
	f := newFixture(t)
	if err := f.lane.Close(); err != nil {
		t.Fatal(err)
	}
	f.config.OutboxLimit = 1
	var err error
	f.lane, err = Open(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	raw := f.message(f.alice, f.bob)
	if _, err = f.lane.Queue(t.Context(), "one", raw, start+7200); err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Queue(t.Context(), "two", raw, start+7200); !errors.Is(err, ErrCapacity) {
		t.Fatal("outbox overflow accepted", err)
	}
	for i := 2; i < MaxPollRelays; i++ {
		if err = f.lane.TrackRelays(t.Context(), []string{fmt.Sprintf("https://127.0.0.1/%d", i)}, start+1000); err != nil {
			t.Fatal(i, err)
		}
	}
	if err = f.lane.TrackRelays(t.Context(), []string{"https://127.0.0.1/full"}, start+1000); !errors.Is(err, ErrCapacity) {
		t.Fatal("poll target overflow", err)
	}
	targets, err := f.lane.pollTargets()
	if err != nil || len(targets) != MaxPollRelays {
		t.Fatal(len(targets), err)
	}
	if err = f.lane.TrackRelays(t.Context(), []string{relayOne}, start+1); err != nil {
		t.Fatal(err)
	}
	targets, err = f.lane.pollTargets()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range targets {
		if r.URL == relayOne && r.Until <= start+1 {
			t.Fatal("retired relay was forgotten early")
		}
	}
}
func TestExclusiveStoreAndUnsafeFilesRefuse(t *testing.T) {
	f := newFixture(t)
	if second, err := Open(t.Context(), f.config); err == nil {
		if e := second.Close(); e != nil {
			t.Error(e)
		}
		t.Fatal("two writers opened one lane")
	}
	card, err := f.lane.CurrentCard(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.config.StateDir, string(Rail), keyName(card.Card.KeyID))
	if err = f.lane.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(t.Context(), f.config); err == nil {
		t.Fatal("public seed accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked")
	if err = os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(t.Context(), f.config); err == nil {
		t.Fatal("linked seed accepted")
	}
	if err = os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(link, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(link, path); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(t.Context(), f.config); err == nil {
		t.Fatal("symlink seed accepted")
	}
}
func TestUsedStoreRefusesMissingIdentityAndCorruptJournal(t *testing.T) {
	for _, damage := range []string{"identity", "checksum", "lane"} {
		t.Run(damage, func(t *testing.T) {
			f := newFixture(t)
			if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
				t.Fatal(err)
			}
			if damage == "lane" {
				r, err := f.lane.readDelivery(deliveryName("id"))
				if err != nil {
					t.Fatal(err)
				}
				r.Identity.Kind = Chat
				if err = f.lane.disk.write(deliveryName("id"), r); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.lane.Close(); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(f.config.StateDir, string(Rail))
			if damage == "identity" {
				if err := os.Remove(filepath.Join(root, "identity")); err != nil {
					t.Fatal(err)
				}
			}
			if damage == "checksum" {
				p := filepath.Join(root, deliveryName("id"))
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				raw = bytes.Replace(raw, []byte(`"pending"`), []byte(`"carried"`), 1)
				if err = os.WriteFile(p, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Open(t.Context(), f.config); err == nil {
				t.Fatal("damaged used state accepted")
			}
		})
	}
}
func TestAtomicWriteRefusalAndRecordSizeKeepThePreviousFile(t *testing.T) {
	f := newFixture(t)
	if err := f.lane.disk.write("test", map[string]string{"value": "old"}); err != nil {
		t.Fatal(err)
	}
	if err := f.lane.disk.write("test", map[string]string{"value": strings.Repeat("x", MaxRecordBytes)}); !errors.Is(err, ErrCapacity) {
		t.Fatal("oversized write accepted", err)
	}
	var v map[string]string
	if err := f.lane.disk.read("test", &v); err != nil || v["value"] != "old" {
		t.Fatal("refused size changed the old record", err)
	}
	f.lane.disk.cut = func(step string) error {
		if step == "synced" {
			return errors.New("cut")
		}
		return nil
	}
	if err := f.lane.disk.write("test", map[string]string{"value": "new"}); err == nil {
		t.Fatal("cut write passed")
	}
	if err := f.lane.disk.read("test", &v); !errors.Is(err, ErrStorage) {
		t.Fatal("uncertain write did not poison the instance", err)
	}
}
func TestCredentialsCannotBePrintedOrMarshalled(t *testing.T) {
	f := newFixture(t)
	secret := f.auth.owner
	for _, format := range []string{"%v", "%+v", "%#v", "%x", "%d"} {
		if got := fmt.Sprintf(format, secret); got != "[carrier credential]" {
			t.Fatal("credential format leaked data", got)
		}
	}
	if _, err := json.Marshal(secret); err == nil {
		t.Fatal("credential could escape into JSON")
	}
	bad := bytes.Clone(f.alice.holder)
	bad[0] ^= 1
	if _, err := NewCredential(secret.wire, bad); err == nil {
		t.Fatal("wrong holder accepted")
	}
}
func TestNoSigningOrMutationOnInvalidConfiguration(t *testing.T) {
	f := newFixture(t)
	for _, change := range []func(*Config){func(c *Config) { c.Kind = "legacy" }, func(c *Config) { c.OutboxLimit = MaxOutbox + 1 }, func(c *Config) { c.Relays = []string{relayOne, relayOne} }, func(c *Config) { c.StateDir = "relative" }, func(c *Config) { c.Delegation = nil }, func(c *Config) { c.VerifyPacket = nil }} {
		c := f.config
		c.StateDir = t.TempDir()
		if err := os.Chmod(c.StateDir, 0700); err != nil {
			t.Fatal(err)
		}
		change(&c)
		if l, err := Open(context.Background(), c); err == nil {
			if e := l.Close(); e != nil {
				t.Error(e)
			}
			t.Fatal("invalid configuration opened")
		}
	}
}
