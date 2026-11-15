package railgate

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const (
	reconcileHelperEnv = "TOS_AI_RAILGATE_TEST_HELPER"
	reconcileSlotsEnv  = "TOS_AI_RAILGATE_TEST_SLOTS"
	reconcileCountEnv  = "TOS_AI_RAILGATE_TEST_COUNT"
)

// TestMain doubles as the process that is killed while it reconciles slots.
func TestMain(m *testing.M) {
	if os.Getenv(reconcileHelperEnv) == "reconcile" {
		os.Exit(reconcileHelper())
	}
	os.Exit(m.Run())
}

var otherHash = strings.Repeat("ef", 32)

// restartedGate admits and starts the fixture's request, then reopens the
// slot directory as a restarted process would, leaving the slot ambiguous.
func restartedGate(t *testing.T, f *fixture) (*Gate, string, Slot) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "slots")
	gate, err := OpenGate(f.verifier, directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	slot, _, err := gate.Admit(ctx, f.claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Run(ctx, slot, f.claim, func(context.Context, *Verified) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGate(f.verifier, directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	current := mustSlot(t, reopened, slot.Key())
	if current.State != SlotAmbiguous || current.AmbiguousCause != AmbiguousAfterRestart {
		t.Fatalf("after the restart: %+v", current)
	}
	return reopened, directory, current
}

func mustSlot(t *testing.T, gate *Gate, key SlotKey) Slot {
	t.Helper()
	slot, found, err := gate.Lookup(key)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	return slot
}

func TestReconcileCompletesASlotLeftAmbiguousByARestart(t *testing.T) {
	f := newFixture(t)
	gate, directory, ambiguous := restartedGate(t, f)
	ctx := context.Background()
	// Until it is reconciled the slot is not attestable.
	first, err := f.verifier.Verify(ctx, f.claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Recheck(ctx, ambiguous, f.claim, first); err == nil {
		t.Fatal("an ambiguous slot was rechecked for respond")
	}
	slot, verified, err := gate.Reconcile(ctx, f.claim, goodHash)
	if err != nil {
		t.Fatal(err)
	}
	if slot.State != SlotCompleted || slot.ResponseHash != goodHash || !slot.Reconciled || slot.AmbiguousCause != "" ||
		slot.Key() != ambiguous.Key() || slot.RequestHash != ambiguous.RequestHash {
		t.Fatalf("reconciled slot = %+v", slot)
	}
	if verified == nil || verified.SlotKey() != slot.Key() || verified.ExecutionID != f.claim.ExecutionID ||
		verified.InputDigest != f.claim.InputDigest {
		t.Fatalf("verified = %+v", verified)
	}
	if recorded := mustSlot(t, gate, slot.Key()); recorded != slot {
		t.Fatalf("recorded = %+v, returned = %+v", recorded, slot)
	}
	// It now behaves as any completed slot: one respond is possible.
	if err := gate.Recheck(ctx, slot, f.claim, verified); err != nil {
		t.Fatalf("recheck of the reconciled slot: %v", err)
	}
	// Idempotent with the same hash; nothing is rewritten.
	again, _, err := gate.Reconcile(ctx, f.claim, goodHash)
	if err != nil || again != slot {
		t.Fatalf("second reconcile: %+v %v", again, err)
	}
	// Refused with another hash; the recorded one stays.
	if conflicting, verifiedAgain, err := gate.Reconcile(ctx, f.claim, otherHash); !errors.Is(err, ErrReconcileConflict) ||
		verifiedAgain != nil || conflicting != slot {
		t.Fatalf("conflicting reconcile: %+v %v", conflicting, err)
	}
	if recorded := mustSlot(t, gate, slot.Key()); recorded != slot {
		t.Fatalf("after a conflicting reconcile: %+v", recorded)
	}
	// Still at most once: never admitted, completed or failed again.
	if _, _, err := gate.Admit(ctx, f.claim); !errors.Is(err, ErrSlotTaken) {
		t.Fatalf("admit after reconcile: %v", err)
	}
	if err := gate.Complete(slot.Key(), otherHash); err == nil {
		t.Fatal("a reconciled slot was completed again")
	}
	if err := gate.Fail(slot.Key()); err == nil {
		t.Fatal("a reconciled slot was failed")
	}
	// Durable: the next process finds it completed and attestable.
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := OpenGate(f.verifier, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if recorded := mustSlot(t, next, slot.Key()); recorded != slot {
		t.Fatalf("after another restart: %+v", recorded)
	}
	if err := next.Recheck(ctx, slot, f.claim, verified); err != nil {
		t.Fatalf("recheck after another restart: %v", err)
	}
	// Once responded, the completed slot is no longer attestable either.
	f.transition(t, toschain.ActorTxRespond, uint32(fxNow.Unix())-10, fxOwner, true, nil, nil, nil)
	if err := next.Recheck(ctx, slot, f.claim, verified); err == nil {
		t.Fatal("a responded request passed the recheck")
	}
}

// secondRequest adds another pending request of the same buyer and quote to
// the chain and returns its claim.
func secondRequest(t *testing.T, f *fixture) Claim {
	t.Helper()
	quote, _, err := nativecore.BuildAcceptedQuoteCommitment(fxNetwork, f.pkg.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	var quoteHash, requestHash [32]byte
	copy(quoteHash[:], quote.Hash())
	requestCell, err := nativecore.BuildServiceRequestCellV1(nativecore.ServiceRequestV1{QuoteCommitment: quoteHash,
		ExecutionID: digest32(3), InputDigest: digest32(4)})
	if err != nil {
		t.Fatal(err)
	}
	copy(requestHash[:], requestCell.Hash())
	second := fxCall(t, fxBuyer, 1, requestHash, uint32(fxNow.Unix())-50, 11, f.terms)
	snapshot, err := second.Snapshot.Decode()
	if err != nil {
		t.Fatal(err)
	}
	f.chain.history = append([]toschain.ActorTransaction{second}, f.chain.history...)
	f.chain.data = fxData(t, f.policy, 2, map[uint64]nativecore.ServiceActorRequestSnapshotV1{0: f.snapshot, 1: snapshot}, nil)
	claim := f.claim
	claim.ExecutionID, claim.InputDigest, claim.RequestID = digest32(3), digest32(4), 1
	claim.Call = toschain.ActorTxID{LT: second.LT, Hash: second.Hash}
	if _, err := f.verifier.Verify(context.Background(), claim); err != nil {
		t.Fatalf("the second request does not verify: %v", err)
	}
	return claim
}

func TestReconcileRefusesAnOutcomeThatIsNotTheSlotsOwn(t *testing.T) {
	ctx := context.Background()
	for name, attempt := range map[string]func(t *testing.T, f *fixture, gate *Gate) error{
		"malformed response hash": func(_ *testing.T, f *fixture, gate *Gate) error {
			_, _, err := gate.Reconcile(ctx, f.claim, "CD"+goodHash[2:])
			return err
		},
		"short response hash": func(_ *testing.T, f *fixture, gate *Gate) error {
			_, _, err := gate.Reconcile(ctx, f.claim, goodHash[:62])
			return err
		},
		"claim with another input digest": func(_ *testing.T, f *fixture, gate *Gate) error {
			claim := f.claim
			claim.InputDigest = digest32(9)
			_, _, err := gate.Reconcile(ctx, claim, goodHash)
			return err
		},
		"claim with another execution id": func(_ *testing.T, f *fixture, gate *Gate) error {
			claim := f.claim
			claim.ExecutionID = digest32(9)
			_, _, err := gate.Reconcile(ctx, claim, goodHash)
			return err
		},
		"claim of another buyer": func(_ *testing.T, f *fixture, gate *Gate) error {
			claim := f.claim
			claim.BuyerWallet = fxOwner
			_, _, err := gate.Reconcile(ctx, claim, goodHash)
			return err
		},
		"incomplete claim": func(_ *testing.T, _ *fixture, gate *Gate) error {
			_, _, err := gate.Reconcile(ctx, Claim{}, goodHash)
			return err
		},
		"another request, which has no slot": func(t *testing.T, f *fixture, gate *Gate) error {
			_, _, err := gate.Reconcile(ctx, secondRequest(t, f), goodHash)
			if !errors.Is(err, ErrNotReconcilable) {
				t.Errorf("err = %v", err)
			}
			return err
		},
		"request already responded": func(t *testing.T, f *fixture, gate *Gate) error {
			f.transition(t, toschain.ActorTxRespond, uint32(fxNow.Unix())-10, fxOwner, true, nil, nil, nil)
			_, _, err := gate.Reconcile(ctx, f.claim, goodHash)
			return err
		},
		"no respond budget left": func(_ *testing.T, f *fixture, gate *Gate) error {
			f.chain.chainTime = time.Unix(int64(f.snapshot.ResponseDeadline)-120, 0)
			_, _, err := gate.Reconcile(ctx, f.claim, goodHash)
			return err
		},
		"resolver unavailable": func(t *testing.T, f *fixture, gate *Gate) error {
			config := f.verifier.config
			config.Reader = unavailableReader{}
			verifier, err := NewVerifier(config)
			if err != nil {
				t.Fatal(err)
			}
			gate.verifier = verifier
			_, _, err = gate.Reconcile(ctx, f.claim, goodHash)
			if !errors.Is(err, ErrResolverUnavailable) {
				t.Errorf("err = %v", err)
			}
			return err
		},
	} {
		f := newFixture(t)
		gate, _, ambiguous := restartedGate(t, f)
		if err := attempt(t, f, gate); err == nil {
			t.Errorf("%s: reconciled", name)
		}
		if current := mustSlot(t, gate, ambiguous.Key()); current != ambiguous {
			t.Errorf("%s: the slot changed: %+v", name, current)
		}
	}
	// With exactly the respond budget's last second left it still works.
	f := newFixture(t)
	gate, _, _ := restartedGate(t, f)
	f.chain.chainTime = time.Unix(int64(f.snapshot.ResponseDeadline)-121, 0)
	if _, _, err := gate.Reconcile(ctx, f.claim, goodHash); err != nil {
		t.Fatalf("with the respond budget left: %v", err)
	}
}

func TestReconcileRefusesASlotHoldingAnotherRequestHash(t *testing.T) {
	f := newFixture(t)
	gate, _, ambiguous := restartedGate(t, f)
	// The slot of this key records another request than the claim proves.
	foreign := ambiguous
	foreign.RequestHash = strings.Repeat("ab", 32)
	if err := gate.write(foreign, false); err != nil {
		t.Fatal(err)
	}
	slot, verified, err := gate.Reconcile(context.Background(), f.claim, goodHash)
	if !errors.Is(err, ErrNotReconcilable) || verified != nil || slot != foreign {
		t.Fatalf("slot=%+v err=%v", slot, err)
	}
	if current := mustSlot(t, gate, foreign.Key()); current != foreign {
		t.Fatalf("the slot changed: %+v", current)
	}
}

func TestReconcileAcceptsOnlyAmbiguityCausedByARestart(t *testing.T) {
	ctx := context.Background()
	// A slot in any other state is refused and left alone, whatever hash
	// is offered.
	for name, prepare := range map[string]func(t *testing.T, f *fixture, gate *Gate, slot Slot){
		"admitted": func(*testing.T, *fixture, *Gate, Slot) {},
		"started in this process": func(t *testing.T, f *fixture, gate *Gate, slot Slot) {
			if err := gate.Run(ctx, slot, f.claim, func(context.Context, *Verified) error { return nil }); err != nil {
				t.Fatal(err)
			}
		},
		"failed": func(t *testing.T, f *fixture, gate *Gate, slot Slot) {
			_ = gate.Run(ctx, slot, f.claim, func(context.Context, *Verified) error { return errors.New("exit 1") })
			if err := gate.Fail(slot.Key()); err != nil {
				t.Fatal(err)
			}
		},
		"abandoned": func(t *testing.T, _ *fixture, gate *Gate, slot Slot) {
			if err := gate.transition(slot.Key(), SlotAdmitted, SlotAbandoned, ""); err != nil {
				t.Fatal(err)
			}
		},
		"ambiguous without a recorded cause": func(t *testing.T, _ *fixture, gate *Gate, slot Slot) {
			slot.State = SlotAmbiguous
			if err := gate.write(slot, false); err != nil {
				t.Fatal(err)
			}
		},
	} {
		f := newFixture(t)
		gate, _ := openGate(t, f)
		slot, _, err := gate.Admit(ctx, f.claim)
		if err != nil {
			t.Fatal(err)
		}
		prepare(t, f, gate, slot)
		before := mustSlot(t, gate, slot.Key())
		returned, verified, err := gate.Reconcile(ctx, f.claim, goodHash)
		if !errors.Is(err, ErrNotReconcilable) || verified != nil || returned != before {
			t.Errorf("%s: slot=%+v err=%v", name, returned, err)
		}
		if after := mustSlot(t, gate, slot.Key()); after != before {
			t.Errorf("%s: the slot changed: %+v", name, after)
		}
	}
	// A slot the run itself completed: the same hash is a no-op, another
	// one a conflict, and it is not marked as reconciled.
	f := newFixture(t)
	gate, _ := openGate(t, f)
	slot, _, err := gate.Admit(ctx, f.claim)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Run(ctx, slot, f.claim, func(context.Context, *Verified) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := gate.Complete(slot.Key(), goodHash); err != nil {
		t.Fatal(err)
	}
	completed := mustSlot(t, gate, slot.Key())
	if same, verified, err := gate.Reconcile(ctx, f.claim, goodHash); err != nil || verified == nil || same != completed || same.Reconciled {
		t.Fatalf("same hash on a completed slot: %+v %v", same, err)
	}
	if _, _, err := gate.Reconcile(ctx, f.claim, otherHash); !errors.Is(err, ErrReconcileConflict) {
		t.Fatalf("another hash on a completed slot: %v", err)
	}
	if after := mustSlot(t, gate, slot.Key()); after != completed {
		t.Fatalf("the completed slot changed: %+v", after)
	}
}

func TestOnlyARestartMarksASlotReconcilable(t *testing.T) {
	f := newFixture(t)
	directory := filepath.Join(t.TempDir(), "slots")
	gate, err := OpenGate(f.verifier, directory)
	if err != nil {
		t.Fatal(err)
	}
	slot, _, err := gate.Admit(context.Background(), f.claim)
	if err != nil {
		t.Fatal(err)
	}
	// An ambiguous record without a cause, as written before causes were
	// recorded, is not given one by a later restart.
	slot.State = SlotAmbiguous
	if err := gate.write(slot, false); err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenGate(f.verifier, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if current := mustSlot(t, reopened, slot.Key()); current.AmbiguousCause != "" || current.State != SlotAmbiguous {
		t.Fatalf("an old ambiguous slot became %+v", current)
	}
	if _, _, err := reopened.Reconcile(context.Background(), f.claim, goodHash); !errors.Is(err, ErrNotReconcilable) {
		t.Fatalf("an old ambiguous slot was reconciled: %v", err)
	}
}

func TestSlotRecordsWithMisplacedReconcileFieldsAreInvalid(t *testing.T) {
	base := Slot{Schema: slotSchema, QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("11", 32),
		Actor: "0:" + strings.Repeat("77", 32), RequestHash: strings.Repeat("22", 32), UpdatedUnix: 1}
	with := func(edit func(*Slot)) Slot {
		slot := base
		edit(&slot)
		return slot
	}
	for name, slot := range map[string]Slot{
		"ambiguous after restart": with(func(s *Slot) { s.State, s.AmbiguousCause = SlotAmbiguous, AmbiguousAfterRestart }),
		"ambiguous, no cause":     with(func(s *Slot) { s.State = SlotAmbiguous }),
		"completed":               with(func(s *Slot) { s.State, s.ResponseHash = SlotCompleted, goodHash }),
		"completed by reconcile":  with(func(s *Slot) { s.State, s.ResponseHash, s.Reconciled = SlotCompleted, goodHash, true }),
		"started":                 with(func(s *Slot) { s.State = SlotStarted }),
	} {
		if !slot.valid() {
			t.Errorf("%s: invalid", name)
		}
	}
	for name, slot := range map[string]Slot{
		"unknown cause":            with(func(s *Slot) { s.State, s.AmbiguousCause = SlotAmbiguous, "operator" }),
		"ambiguous and reconciled": with(func(s *Slot) { s.State, s.Reconciled = SlotAmbiguous, true }),
		"ambiguous with a hash":    with(func(s *Slot) { s.State, s.ResponseHash = SlotAmbiguous, goodHash }),
		"completed with a cause": with(func(s *Slot) {
			s.State, s.ResponseHash, s.AmbiguousCause = SlotCompleted, goodHash, AmbiguousAfterRestart
		}),
		"reconciled without a hash": with(func(s *Slot) { s.State, s.Reconciled = SlotCompleted, true }),
		"started with a cause":      with(func(s *Slot) { s.State, s.AmbiguousCause = SlotStarted, AmbiguousAfterRestart }),
		"failed and reconciled":     with(func(s *Slot) { s.State, s.Reconciled = SlotFailed, true }),
		"admitted and reconciled":   with(func(s *Slot) { s.State, s.Reconciled = SlotAdmitted, true }),
	} {
		if slot.valid() {
			t.Errorf("%s: valid", name)
		}
	}
}

func TestConcurrentReconcilesAgreeOnOneOutcome(t *testing.T) {
	ctx := context.Background()
	for round := 0; round < 20; round++ {
		f := newFixture(t)
		gate, _, ambiguous := restartedGate(t, f)
		const callers = 16
		start := make(chan struct{})
		type answer struct {
			hash string
			slot Slot
			err  error
		}
		answers := make(chan answer, callers)
		var group sync.WaitGroup
		for caller := 0; caller < callers; caller++ {
			hash := goodHash
			if caller%2 == 1 {
				hash = otherHash
			}
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				slot, _, err := gate.Reconcile(ctx, f.claim, hash)
				answers <- answer{hash, slot, err}
			}()
		}
		close(start)
		group.Wait()
		close(answers)
		final := mustSlot(t, gate, ambiguous.Key())
		if final.State != SlotCompleted || !final.Reconciled || (final.ResponseHash != goodHash && final.ResponseHash != otherHash) {
			t.Fatalf("round %d: final slot = %+v", round, final)
		}
		for got := range answers {
			switch {
			case got.hash == final.ResponseHash:
				if got.err != nil || got.slot != final {
					t.Fatalf("round %d: the recorded hash was answered %+v %v", round, got.slot, got.err)
				}
			case !errors.Is(got.err, ErrReconcileConflict) || got.slot != final:
				t.Fatalf("round %d: the other hash was answered %+v %v", round, got.slot, got.err)
			}
		}
	}
}

// reconcileKey is the key of the n-th slot of the kill test.
func reconcileKey(n int) SlotKey {
	return SlotKey{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("11", 32),
		Actor: "0:" + strings.Repeat("77", 32), RequestID: uint64(n)}
}

// reconcileHelper reconciles every prepared slot through the gate's own
// durable path, and is killed by its parent somewhere along the way.
func reconcileHelper() int {
	count, err := strconv.Atoi(os.Getenv(reconcileCountEnv))
	if err != nil {
		return 2
	}
	gate, err := OpenGate(&Verifier{}, os.Getenv(reconcileSlotsEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// One line per reconciled slot, so the parent can kill at a chosen
	// point of the work whatever the disk's speed.
	for n := 0; n < count; n++ {
		if _, err := gate.reconcile(reconcileKey(n), strings.Repeat("22", 32), goodHash); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		fmt.Println(n)
	}
	return 0
}

// TestKilledReconcileLeavesEachSlotAmbiguousOrCompleted kills a real process
// in the middle of reconciling many slots. Whatever instant the kill lands
// on, every slot must read back as a valid record that is either still
// ambiguous after a restart or completed with the offered hash.
func TestKilledReconcileLeavesEachSlotAmbiguousOrCompleted(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const count = 400
	sawBoth := false
	for round, killAfter := range []int{5, 20, 60, 120, 200, 300} {
		directory := filepath.Join(t.TempDir(), "slots")
		gate, err := OpenGate(&Verifier{}, directory)
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < count; n++ {
			key := reconcileKey(n)
			slot := Slot{Schema: slotSchema, QuoteCommitment: key.QuoteCommitment, Actor: key.Actor, RequestID: key.RequestID,
				RequestHash: strings.Repeat("22", 32), State: SlotStarted, UpdatedUnix: 1}
			if err := gate.write(slot, true); err != nil {
				t.Fatal(err)
			}
		}
		if err := gate.Close(); err != nil {
			t.Fatal(err)
		}
		// The helper's own open is the restart that makes them ambiguous.
		helper := exec.Command(executable, "-test.run=^$")
		helper.Env = append(os.Environ(), reconcileHelperEnv+"=reconcile", reconcileSlotsEnv+"="+directory,
			reconcileCountEnv+"="+strconv.Itoa(count))
		stdout, err := helper.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := helper.Start(); err != nil {
			t.Fatal(err)
		}
		progress := bufio.NewScanner(stdout)
		for reported := 0; reported < killAfter; reported++ {
			if !progress.Scan() {
				_ = helper.Process.Kill()
				t.Fatalf("round %d: the helper stopped after %d slots", round, reported)
			}
		}
		_ = helper.Process.Signal(syscall.SIGKILL)
		_ = helper.Wait()
		// Opening reads and validates every record; a torn or third-state
		// record refuses the open.
		reopened, err := OpenGate(&Verifier{}, directory)
		if err != nil {
			t.Fatalf("round %d: the slot directory does not open after the kill: %v", round, err)
		}
		completed, ambiguous := 0, 0
		for n := 0; n < count; n++ {
			slot := mustSlot(t, reopened, reconcileKey(n))
			switch {
			case slot.State == SlotCompleted && slot.ResponseHash == goodHash && slot.Reconciled && slot.AmbiguousCause == "":
				completed++
			case slot.State == SlotAmbiguous && slot.AmbiguousCause == AmbiguousAfterRestart && slot.ResponseHash == "" && !slot.Reconciled:
				ambiguous++
			default:
				t.Fatalf("round %d: slot %d is in a third state: %+v", round, n, slot)
			}
		}
		// The interrupted work can simply be done again.
		for n := 0; n < count; n++ {
			if _, err := reopened.reconcile(reconcileKey(n), strings.Repeat("22", 32), goodHash); err != nil {
				t.Fatalf("round %d: reconcile after the kill: %v", round, err)
			}
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		if completed > 0 && ambiguous > 0 {
			sawBoth = true
		}
		t.Logf("round %d: killed with %d completed and %d still ambiguous", round, completed, ambiguous)
	}
	if !sawBoth {
		t.Fatal("no kill landed in the middle of the work; the test proved nothing")
	}
}
