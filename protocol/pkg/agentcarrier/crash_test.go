package agentcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCarrierProcessCrashChild(t *testing.T) {
	root := os.Getenv("CARRIER_CRASH_ROOT")
	if root == "" {
		return
	}
	f := newFixture(t)
	if err := f.lane.Close(); err != nil {
		t.Fatal(err)
	}
	f.config.StateDir = root
	var err error
	f.lane, err = Open(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	action, step := os.Getenv("CARRIER_CRASH_ACTION"), os.Getenv("CARRIER_CRASH_STEP")
	writes := 0
	f.lane.disk.cut = func(stage string) error {
		if stage == "synced" {
			writes++
		}
		wanted := 1
		if action == "outcome" {
			wanted = 3
		}
		if writes == wanted && stage == step {
			os.Exit(29)
		}
		return nil
	}
	if action == "queue" {
		_, err = f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200)
	} else {
		if action == "outcome" {
			f.relays[relayOne].before = func(raw []byte) {
				file, e := os.OpenFile(filepath.Join(root, "receipt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
				if e != nil {
					t.Fatal(e)
				}
				_, e = file.Write(raw)
				if closeErr := errors.Join(e, file.Sync(), file.Close()); closeErr != nil {
					t.Fatal(closeErr)
				}
			}
		}
		_, err = f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0)
	}
	t.Fatal("crash cut was not reached", err, writes)
}
func TestProcessCrashCutsPreserveJournalAndInventory(t *testing.T) {
	for _, action := range []string{"queue", "seal", "outcome"} {
		for _, step := range []string{"synced", "renamed"} {
			t.Run(action+"-"+step, func(t *testing.T) {
				f := newFixture(t)
				if action != "queue" {
					if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.lane.Close(); err != nil {
					t.Fatal(err)
				}
				binary, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, "-test.run=^TestCarrierProcessCrashChild$")
				scratch := t.TempDir()
				if err := os.Chmod(scratch, 0700); err != nil {
					t.Fatal(err)
				}
				cmd.Env = append(os.Environ(), "CARRIER_CRASH_ROOT="+f.config.StateDir, "CARRIER_CRASH_ACTION="+action, "CARRIER_CRASH_STEP="+step, "TMPDIR="+scratch)
				output, err := cmd.CombinedOutput()
				var exited *exec.ExitError
				if !errors.As(err, &exited) || exited.ExitCode() != 29 {
					t.Fatalf("child did not hit its cut: %v %s", err, output)
				}
				f.lane, err = Open(t.Context(), f.config)
				if err != nil {
					t.Fatal("restart refused a real process-crash cut", err)
				}
				if action == "queue" {
					if indexed, err := f.lane.indexed(deliveryName("id")); err != nil || indexed {
						t.Fatal("unfinished queue entered inventory", indexed, err)
					}
					if _, err = f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
						t.Fatal(err)
					}
					return
				}
				r, err := f.lane.readDelivery(deliveryName("id"))
				if err != nil {
					t.Fatal(err)
				}
				var expected []byte
				if action == "outcome" {
					expected, err = os.ReadFile(filepath.Join(f.config.StateDir, "receipt"))
					if err != nil {
						t.Fatal(err)
					}
				} else if step == "renamed" {
					if len(r.Generations) != 1 {
						t.Fatal("renamed seal missing")
					}
					expected = bytes.Clone(r.Generations[0].Envelope)
				}
				result, err := f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0)
				if err != nil || !result.Accepted {
					t.Fatal("restart did not continue", result, err)
				}
				if action == "outcome" && step == "renamed" {
					if len(f.relays[relayOne].deposits) != 0 {
						t.Fatal("already committed acceptance resent")
					}
				} else {
					if len(f.relays[relayOne].deposits) != 1 {
						t.Fatal("retry count", len(f.relays[relayOne].deposits))
					}
					if expected != nil && !bytes.Equal(expected, f.relays[relayOne].deposits[0]) {
						t.Fatal("crash changed the sealed bytes")
					}
				}
			})
		}
	}
}
func TestUsedInventoryRefusesMissingKeysAndDeliveries(t *testing.T) {
	for _, which := range []string{"key", "delivery"} {
		t.Run(which, func(t *testing.T) {
			f := newFixture(t)
			var name string
			if which == "key" {
				card, err := f.lane.CurrentCard(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				name = keyName(card.Card.KeyID)
			} else {
				if _, err := f.lane.Queue(t.Context(), "id", f.message(f.alice, f.bob), start+7200); err != nil {
					t.Fatal(err)
				}
				name = deliveryName("id")
			}
			if err := f.lane.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(f.config.StateDir, string(Rail), name)); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(t.Context(), f.config); err == nil {
				t.Fatal("missing used file silently became new state")
			}
		})
	}
}
func TestMissingUsedDeliveryCannotBeRequeuedInAStartedLane(t *testing.T) {
	f := newFixture(t)
	raw := f.message(f.alice, f.bob)
	if _, err := f.lane.Queue(t.Context(), "id", raw, start+7200); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.config.StateDir, string(Rail), deliveryName("id"))); err != nil {
		t.Fatal(err)
	}
	if _, err := f.lane.Queue(t.Context(), "id", raw, start+7200); err == nil {
		t.Fatal("missing used delivery was replaced")
	}
}
func TestUncertainPostRenameIsReadableOnlyAfterRestart(t *testing.T) {
	f := newFixture(t)
	raw := f.message(f.alice, f.bob)
	if _, err := f.lane.Queue(t.Context(), "id", raw, start+7200); err != nil {
		t.Fatal(err)
	}
	f.lane.disk.cut = func(step string) error {
		if step == "renamed" {
			return errors.New("cut")
		}
		return nil
	}
	if _, err := f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0); err == nil {
		t.Fatal("uncertain commit continued to send")
	}
	if len(f.relays[relayOne].deposits) != 0 {
		t.Fatal("uncertain write sent")
	}
	if err := f.lane.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.lane, err = Open(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.lane.readDelivery(deliveryName("id"))
	if err != nil || len(r.Generations) != 1 {
		t.Fatal("renamed bytes not recovered", err)
	}
	sum := sha256.Sum256(r.Generations[0].Envelope)
	if _, err = f.lane.Attempt(t.Context(), "id", f.peerRoute(), 0); err != nil {
		t.Fatal(err)
	}
	actual := sha256.Sum256(f.relays[relayOne].deposits[0])
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(actual[:]) {
		t.Fatal("recovery re-sealed the envelope")
	}
}
