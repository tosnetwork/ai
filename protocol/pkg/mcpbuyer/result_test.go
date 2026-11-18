package mcpbuyer

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

var testRequestHash = strings.Repeat("ab", 32)

func sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// acceptedView is an accepted result whose output.log is output.
func acceptedView(t *testing.T, output string) *buyeragent.AcceptedView {
	t.Helper()
	return acceptedViewWith(t, output, 0o644, "")
}

// acceptedViewWith builds the artifact's members with mode, and attests
// claimedOutput's digest as the result digest when it is set.
func acceptedViewWith(t *testing.T, output string, mode int64, claimedOutput string) *buyeragent.AcceptedView {
	t.Helper()
	var artifact bytes.Buffer
	writer := tar.NewWriter(&artifact)
	report := `{"ok":true}`
	if claimedOutput == "" {
		claimedOutput = output
	}
	for _, member := range [][2]string{{"output.log", output}, {"report.json", report}} {
		if err := writer.WriteHeader(&tar.Header{Name: member[0], Mode: mode, Size: int64(len(member[1])),
			Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(member[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var executionID, inputDigest [32]byte
	executionID[0], inputDigest[0] = 1, 2
	provider := "agent_" + strings.Repeat("4", 64)
	root, hash, err := railwork.BuildReceipt(railwork.ReceiptBinding{QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("3c", 32),
		ExecutionID: executionID, InputDigest: inputDigest, SourceDigest: "sha256:" + strings.Repeat("12", 32),
		Price: big.NewInt(300000000), ProviderAgentID: provider, ToolchainDigest: "sha256:" + strings.Repeat("34", 32),
		SandboxDigest: "sha256:" + strings.Repeat("56", 32)}, railwork.Outcome{ResultDigest: sha([]byte(claimedOutput)),
		ArtifactDigest: sha(artifact.Bytes()), ReportDigest: sha([]byte(report)), CompletedAtUnix: 2_000_000_000})
	if err != nil {
		t.Fatal(err)
	}
	return &buyeragent.AcceptedView{RequestHash: testRequestHash, Reference: "abab-abab-abab-abab",
		ResponseHash: hex.EncodeToString(hash[:]), ProviderAgentID: provider, ArtifactDigest: sha(artifact.Bytes()),
		ResultDigest: sha([]byte(output)), ReportDigest: sha([]byte(report)), PriceNanoTOS: "300000000",
		ReceiptBase64: base64.StdEncoding.EncodeToString(root.ToBOC()), ArtifactBase64: base64.StdEncoding.EncodeToString(artifact.Bytes())}
}

func resultsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := NewResultsDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestTheResultToolWritesTheCheckedFilesAndShowsTheirStart(t *testing.T) {
	results := resultsDir(t)
	view := acceptedView(t, strings.Repeat("line\n", 100))
	h := connectWith(t, &fakeAgent{accepted: view}, results)
	result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash, "max_inline_bytes": 10})
	if result.IsError {
		t.Fatalf("result: %s", text(result))
	}
	var out Result
	structured(t, result, &out)
	directory := filepath.Join(results, testRequestHash)
	if out.Files == nil || out.Files.Directory != directory || len(out.Checked) == 0 || out.DoesNotProve == "" ||
		out.OutputBytes != 500 || out.Output.Bytes != 500 || out.Output.Text != `line\u{000A}line\u{000A}` ||
		len(out.Output.Text) > 40 || out.Result.ReceiptBase64 != "" || out.Result.ArtifactBase64 != "" {
		t.Fatalf("result %+v", out)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("the result directory: %v %v", info, err)
	}
	artifact, _ := base64.StdEncoding.DecodeString(view.ArtifactBase64)
	output, _, _ := railwork.ArtifactMembers(artifact)
	for name, want := range map[string][]byte{ArtifactFile: artifact, OutputFile: output} {
		got, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if !strings.Contains(text(result), "<<<UNTRUSTED") || !strings.Contains(text(result), "does not prove") {
		t.Fatalf("text %s", text(result))
	}
	// The same result again keeps the files.
	if again := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); again.IsError {
		t.Fatalf("the same result again: %s", text(again))
	}
}

// An existing file with other bytes is never replaced, and no link is
// followed: neither a linked result directory nor a linked file.
func TestTheResultToolNeverReplacesOrFollows(t *testing.T) {
	results := resultsDir(t)
	directory := filepath.Join(results, testRequestHash)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, OutputFile), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := connectWith(t, &fakeAgent{accepted: acceptedView(t, "built")}, results)
	if result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); !result.IsError {
		t.Fatal("a file with other bytes was accepted")
	}
	if got, _ := os.ReadFile(filepath.Join(directory, OutputFile)); string(got) != "mine" {
		t.Fatal("an existing file was replaced")
	}
	// A linked file, even to a file holding exactly the bytes to write.
	elsewhere := t.TempDir()
	victim := filepath.Join(elsewhere, "victim")
	view := acceptedView(t, "built")
	receipt, _ := base64.StdEncoding.DecodeString(view.ReceiptBase64)
	if err := os.WriteFile(victim, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	g := resultsDir(t)
	if err := os.Mkdir(filepath.Join(g, testRequestHash), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(g, testRequestHash, ReceiptFile)); err != nil {
		t.Fatal(err)
	}
	h = connectWith(t, &fakeAgent{accepted: view}, g)
	if result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); !result.IsError {
		t.Fatal("a linked file was taken for the result file")
	}
	// A result directory others can enter.
	open := resultsDir(t)
	if err := os.Mkdir(filepath.Join(open, testRequestHash), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(open, testRequestHash), 0o755); err != nil {
		t.Fatal(err)
	}
	h = connectWith(t, &fakeAgent{accepted: acceptedView(t, "built")}, open)
	if result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); !result.IsError {
		t.Fatal("a result directory others can enter was used")
	}
	// A linked result directory.
	k := resultsDir(t)
	if err := os.Symlink(elsewhere, filepath.Join(k, testRequestHash)); err != nil {
		t.Fatal(err)
	}
	h = connectWith(t, &fakeAgent{accepted: acceptedView(t, "built")}, k)
	if result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); !result.IsError {
		t.Fatal("a linked result directory was used")
	}
	if _, err := os.Lstat(filepath.Join(elsewhere, OutputFile)); err == nil {
		t.Fatal("a file was written through a linked directory")
	}
}

// A request hash that is not 64 lowercase hex never reaches the agent or
// the file system; nor does an inline bound out of range.
func TestTheResultToolRefusesPathTricksAndBadBounds(t *testing.T) {
	results := resultsDir(t)
	agent := &fakeAgent{accepted: acceptedView(t, "built")}
	h := connectWith(t, agent, results)
	for _, hash := range []string{"../" + strings.Repeat("ab", 31), strings.Repeat("AB", 32), testRequestHash + "/x", ""} {
		if result := h.call(t, ToolResult, map[string]any{"request_hash": hash}); !result.IsError {
			t.Fatalf("%q was accepted", hash)
		}
	}
	for _, bound := range []int{-1, MaxInlineBytes + 1} {
		if result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash, "max_inline_bytes": bound}); !result.IsError {
			t.Fatalf("max_inline_bytes %d was accepted", bound)
		}
	}
	if calls, _ := agent.recorded(); len(calls) != 0 {
		t.Fatalf("a refused input reached the agent: %v", calls)
	}
	if entries, _ := os.ReadDir(results); len(entries) != 0 {
		t.Fatal("a refused input wrote a file")
	}
	// Without a results directory the tool refuses.
	none := connectWith(t, &fakeAgent{accepted: acceptedView(t, "built")}, "")
	if result := none.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); !result.IsError {
		t.Fatal("a server without a results directory wrote a result")
	}
}

// A result whose bytes do not match its Receipt writes nothing.
func TestTheResultToolChecksTheBytesItWrites(t *testing.T) {
	for name, edit := range map[string]func(*buyeragent.AcceptedView){
		"another artifact": func(v *buyeragent.AcceptedView) {
			v.ArtifactBase64 = acceptedView(t, "other").ArtifactBase64
		},
		"another response hash": func(v *buyeragent.AcceptedView) { v.ResponseHash = strings.Repeat("00", 32) },
		"another artifact digest": func(v *buyeragent.AcceptedView) {
			v.ArtifactDigest = "sha256:" + strings.Repeat("00", 32)
		},
		"another request": func(v *buyeragent.AcceptedView) { v.RequestHash = strings.Repeat("cd", 32) },
		// The same members in other tar bytes: only the artifact digest
		// tells them apart.
		"the same members, other tar bytes": func(v *buyeragent.AcceptedView) {
			v.ArtifactBase64 = acceptedViewWith(t, "built", 0o600, "").ArtifactBase64
		},
		// A Receipt that attests another output than the artifact holds.
		"a Receipt of another output": func(v *buyeragent.AcceptedView) {
			*v = *acceptedViewWith(t, "built", 0o644, "other")
		},
	} {
		results := resultsDir(t)
		view := acceptedView(t, "built")
		edit(view)
		h := connectWith(t, &fakeAgent{accepted: view}, results)
		if result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash}); !result.IsError {
			t.Errorf("%s: accepted", name)
		}
		if entries, _ := os.ReadDir(results); len(entries) != 0 {
			t.Errorf("%s: files were written", name)
		}
	}
}

// Before acceptance the tool reports RESULT_NOT_READY with the status.
func TestTheResultToolReportsNotReadyWithTheStatus(t *testing.T) {
	h := connectWith(t, &fakeAgent{notReady: true}, resultsDir(t))
	result := h.call(t, ToolResult, map[string]any{"request_hash": testRequestHash})
	var out Result
	structured(t, result, &out)
	if !result.IsError || out.Error == nil || out.Error.Code != buyeragent.CodeResultNotReady || out.Status == nil ||
		out.Status.RequestHash != testRequestHash {
		t.Fatalf("not ready: %+v", out)
	}
}

func TestTheResultsDirectoryIsResolvedAndPrivate(t *testing.T) {
	if _, err := NewResultsDir("relative"); err == nil {
		t.Fatal("a relative results directory")
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResultsDir(open); err == nil {
		t.Fatal("a results directory others can write")
	}
	real := resultsDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if resolved, err := NewResultsDir(link); err != nil || resolved != real {
		t.Fatalf("a linked results directory resolves to %q: %v", resolved, err)
	}
}
