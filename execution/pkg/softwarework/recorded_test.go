package softwarework

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecordedReadsTheJournalWithoutClaiming(t *testing.T) {
	runner, backend, journal, request := fixture(t)
	defer journal.Close()
	// An identity that was never claimed is reported as such and stays
	// unclaimed: the run that follows is the first one.
	if _, found, err := runner.Recorded(request); found || err != nil {
		t.Fatalf("unclaimed: found=%v err=%v", found, err)
	}
	want, err := runner.Execute(context.Background(), request)
	if err != nil || backend.calls != 1 {
		t.Fatalf("first run err=%v calls=%d", err, backend.calls)
	}
	got, found, err := runner.Recorded(request)
	if err != nil || !found || got != want {
		t.Fatalf("recorded = %+v found=%v err=%v, want %+v", got, found, err, want)
	}
	other := request
	other.InputDigest = digest([]byte("other input"))
	if _, found, err := runner.Recorded(other); found || !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: found=%v err=%v", found, err)
	}
	malformed := request
	malformed.SourceDigest = digest([]byte("another archive"))
	if _, found, err := runner.Recorded(malformed); found || !errors.Is(err, ErrRequestMismatch) {
		t.Fatalf("mismatch: found=%v err=%v", found, err)
	}
	if backend.calls != 1 {
		t.Fatalf("a lookup ran the executor: calls=%d", backend.calls)
	}
}

func TestRecordedReportsAClaimWithoutOutcomeAsAmbiguous(t *testing.T) {
	runner, backend, journal, request := fixture(t)
	defer journal.Close()
	backend.err = errors.New("runtime connection lost")
	if _, err := runner.Execute(context.Background(), request); err == nil {
		t.Fatal("the failing run succeeded")
	}
	if _, found, err := runner.Recorded(request); found || !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("found=%v err=%v", found, err)
	}
	backend.err = nil
	if _, err := runner.Execute(context.Background(), request); !errors.Is(err, ErrAmbiguous) || backend.calls != 1 {
		t.Fatalf("replay err=%v calls=%d", err, backend.calls)
	}
}

func TestManifestContractOnlyTightensTheFrozenPreset(t *testing.T) {
	manifest := digest([]byte("published manifest"))
	frozen := FrozenV1ManifestLimits()
	contract, err := ManifestContract(manifest, frozen)
	if err != nil || contract.Limits != FrozenV1Limits() || contract.ManifestDigest != manifest || contract.SandboxDigest != manifest {
		t.Fatalf("frozen bounds: %+v %v", contract, err)
	}
	tight := ManifestLimits{CPUMillis: 30_000, MemoryBytes: 256 << 20, ScratchBytes: 512 << 20, OutputBytes: 1 << 20, WallClockMillis: 30_000}
	contract, err = ManifestContract(manifest, tight)
	want := FrozenV1Limits()
	want.CPUMillis, want.MemoryBytes, want.DiskBytes, want.OutputBytes, want.ExecutionTime = 30_000, 256<<20, 512<<20, 1<<20, 30*time.Second
	if err != nil || contract.Limits != want {
		t.Fatalf("tight bounds: %+v %v", contract.Limits, err)
	}
	// Everything a caller cannot choose stays the frozen contract's.
	fixed := FrozenV1Contract()
	if contract.ToolchainDigest != fixed.ToolchainDigest || contract.Executable != fixed.Executable ||
		len(contract.Arguments) != len(fixed.Arguments) || contract.UserID != fixed.UserID || contract.Limits.PIDs != fixed.Limits.PIDs {
		t.Fatalf("contract changed a fixed field: %+v", contract)
	}
	for name, edit := range map[string]func(*ManifestLimits){
		"cpu above":        func(l *ManifestLimits) { l.CPUMillis = frozen.CPUMillis + 1 },
		"memory above":     func(l *ManifestLimits) { l.MemoryBytes = frozen.MemoryBytes + 1 },
		"scratch above":    func(l *ManifestLimits) { l.ScratchBytes = frozen.ScratchBytes + 1 },
		"output above":     func(l *ManifestLimits) { l.OutputBytes = frozen.OutputBytes + 1 },
		"wall clock above": func(l *ManifestLimits) { l.WallClockMillis = frozen.WallClockMillis + 1 },
		"huge wall clock":  func(l *ManifestLimits) { l.WallClockMillis = 1 << 63 },
		"zero cpu":         func(l *ManifestLimits) { l.CPUMillis = 0 },
		"zero memory":      func(l *ManifestLimits) { l.MemoryBytes = 0 },
		"zero scratch":     func(l *ManifestLimits) { l.ScratchBytes = 0 },
		"zero output":      func(l *ManifestLimits) { l.OutputBytes = 0 },
		"zero wall clock":  func(l *ManifestLimits) { l.WallClockMillis = 0 },
	} {
		limits := tight
		edit(&limits)
		var refused *LimitError
		if _, err := ManifestContract(manifest, limits); !errors.As(err, &refused) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	for _, bad := range []string{"", "sha256:abc", "SHA256:" + manifest[7:], manifest[:70] + "G"} {
		if _, err := ManifestContract(bad, tight); !errors.Is(err, ErrManifestDigest) {
			t.Errorf("manifest digest %q: err=%v", bad, err)
		}
	}
}

func TestBoundLimitsMakeARepeatUnderOtherLimitsAConflict(t *testing.T) {
	runner, backend, journal, request := fixture(t)
	defer journal.Close()
	rebuilt := func(edit func(*Contract), options ...RunnerOption) *Runner {
		t.Helper()
		contract := runner.contract
		edit(&contract)
		built, err := NewRunner(backend, runner.store, journal, contract, options...)
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	same := func(*Contract) {}
	tighter := func(contract *Contract) { contract.Limits.OutputBytes-- }
	if _, err := rebuilt(same, BindLimits()).Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, found, err := rebuilt(same, BindLimits()).Recorded(request); !found || err != nil {
		t.Fatalf("same limits: found=%v err=%v", found, err)
	}
	for name, edit := range map[string]func(*Contract){
		"output":     tighter,
		"cpu":        func(contract *Contract) { contract.Limits.CPUMillis-- },
		"memory":     func(contract *Contract) { contract.Limits.MemoryBytes-- },
		"disk":       func(contract *Contract) { contract.Limits.DiskBytes-- },
		"pids":       func(contract *Contract) { contract.Limits.PIDs-- },
		"wall clock": func(contract *Contract) { contract.Limits.ExecutionTime-- },
	} {
		other := rebuilt(edit, BindLimits())
		if _, _, err := other.Recorded(request); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: lookup err = %v", name, err)
		}
		if _, err := other.Execute(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Errorf("%s: execute err = %v", name, err)
		}
	}
	if backend.calls != 1 {
		t.Fatalf("a conflicting repeat ran: %d", backend.calls)
	}
	if _, err := NewRunner(backend, runner.store, journal, runner.contract, nil); err == nil {
		t.Fatal("accepted a nil option")
	}
}

func TestUnboundFingerprintIsUnchangedByLimits(t *testing.T) {
	runner, backend, journal, request := fixture(t)
	defer journal.Close()
	if _, err := runner.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	// A runner whose limits are fixed by its manifest keeps answering a
	// repeat from the journal whatever its limits are now.
	contract := runner.contract
	contract.Limits.OutputBytes--
	other, err := NewRunner(backend, runner.store, journal, contract)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := other.Recorded(request); !found || err != nil || backend.calls != 1 {
		t.Fatalf("found=%v err=%v calls=%d", found, err, backend.calls)
	}
	// Its fingerprint is the encoding identities were journaled under
	// before limits could be bound.
	legacy := digest([]byte(`{"manifest":"` + contract.ManifestDigest + `","quote":"` + request.QuoteCommitment +
		`","execution":"` + request.ExecutionID + `","input":"` + request.InputDigest + `","source":"` + request.SourceDigest + `"}`))
	if got := requestFingerprint(contract, request, false); got != legacy {
		t.Fatalf("unbound fingerprint changed: %s", got)
	}
	if requestFingerprint(contract, request, true) == legacy {
		t.Fatal("bound fingerprint ignores the limits")
	}
}
