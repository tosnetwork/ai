package softwarework

import (
	"errors"
	"time"

	"github.com/tosnetwork/ai/execution/pkg/executor"
)

const (
	FrozenV1ManifestDigest = "sha256:e4db0138ca2a4d5ad8f3c7ec458304927344e341ae610ee0a682b9cc5b00594e"
	FrozenV1ImageDigest    = "sha256:9624bca74096f810c5b24e489521dde124fadcfa1808581648b38bdc1ba1b105"
	FrozenV1ImageReference = "docker.io/tosnetwork/software-work-go:1.26.5@" + FrozenV1ImageDigest
)

// FrozenV1Limits, FrozenV1Policy and FrozenV1Contract are the single local
// source for both the one-shot executor and long-running Messenger worker.
// Each call returns fresh mutable collections so callers cannot alter another
// runtime's authority.
func FrozenV1Limits() executor.Limits {
	return executor.Limits{CPUMillis: 120_000, MemoryBytes: 1 << 30, DiskBytes: 2 << 30,
		PIDs: 64, ExecutionTime: 180 * time.Second, OutputBytes: 16 << 20}
}

func FrozenV1Policy() executor.Policy {
	return executor.Policy{AllowedImages: map[string]struct{}{FrozenV1ImageDigest: {}},
		MaxAllowedImages: 1, MaxEnvironment: 8, MaxArguments: 8, MaxAllowedHosts: 0,
		MaxStringBytes: 4096, MaxInputBytes: 16 << 20, Ceiling: FrozenV1Limits(), RequireReadOnlyRoot: true}
}

func FrozenV1Contract() Contract {
	return Contract{ManifestDigest: FrozenV1ManifestDigest, ToolchainDigest: FrozenV1ImageDigest,
		SandboxDigest: FrozenV1ManifestDigest, Executable: "/usr/local/bin/go",
		Arguments: []string{"test", "./...", "-count=1"}, WorkingDirectory: "/workspace/source",
		Limits: FrozenV1Limits(), UserID: 65532, GroupID: 65532}
}

// ManifestLimits are the limits a published manifest commits to, in the
// manifest's own units.
type ManifestLimits struct {
	CPUMillis       uint64
	MemoryBytes     uint64
	ScratchBytes    uint64
	OutputBytes     uint64
	WallClockMillis uint64
}

// FrozenV1ManifestLimits is the frozen preset stated as manifest limits: the
// loosest limits a manifest may commit to.
func FrozenV1ManifestLimits() ManifestLimits {
	frozen := FrozenV1Limits()
	return ManifestLimits{CPUMillis: frozen.CPUMillis, MemoryBytes: frozen.MemoryBytes, ScratchBytes: frozen.DiskBytes,
		OutputBytes: frozen.OutputBytes, WallClockMillis: uint64(frozen.ExecutionTime / time.Millisecond)}
}

// ErrManifestDigest reports a manifest digest that is not sha256:<64
// lowercase hex>.
var ErrManifestDigest = errors.New("manifest digest must be sha256:<64 lowercase hex>")

// LimitError reports a manifest limit that is zero or looser than the frozen
// preset can enforce.
type LimitError struct {
	Name  string
	Value uint64
	Upper uint64
}

func (e *LimitError) Error() string {
	return "a manifest limit is outside what the executor enforces"
}

// ManifestContract is the frozen contract bound to a published manifest:
// its digest names the sandbox, and every limit is set to exactly what the
// manifest commits to. A limit left at zero, or set above the frozen preset,
// refuses the manifest instead of silently running under another bound, so
// limits can only ever be tightened.
func ManifestContract(manifestDigest string, limits ManifestLimits) (Contract, error) {
	if !executionIDPattern.MatchString(manifestDigest) {
		return Contract{}, ErrManifestDigest
	}
	contract := FrozenV1Contract()
	upper := FrozenV1ManifestLimits()
	for _, limit := range []struct {
		name            string
		manifest, upper uint64
	}{
		{"cpu_millis", limits.CPUMillis, upper.CPUMillis},
		{"memory_bytes", limits.MemoryBytes, upper.MemoryBytes},
		{"scratch_bytes", limits.ScratchBytes, upper.ScratchBytes},
		{"output_bytes", limits.OutputBytes, upper.OutputBytes},
		{"wall_clock_millis", limits.WallClockMillis, upper.WallClockMillis},
	} {
		if limit.manifest == 0 || limit.manifest > limit.upper {
			return Contract{}, &LimitError{Name: limit.name, Value: limit.manifest, Upper: limit.upper}
		}
	}
	contract.ManifestDigest, contract.SandboxDigest = manifestDigest, manifestDigest
	contract.Limits.CPUMillis = limits.CPUMillis
	contract.Limits.MemoryBytes = limits.MemoryBytes
	contract.Limits.DiskBytes = limits.ScratchBytes
	contract.Limits.OutputBytes = limits.OutputBytes
	// Bounded by the frozen wall clock above, so the conversion cannot
	// overflow.
	contract.Limits.ExecutionTime = time.Duration(limits.WallClockMillis) * time.Millisecond
	return contract, nil
}
