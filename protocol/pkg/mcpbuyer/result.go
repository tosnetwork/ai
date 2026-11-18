package mcpbuyer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyerconfirm"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// ToolResult names the result tool (section 4.9).
const ToolResult = "tos_buyer_result"

// Inline bounds of tos_buyer_result.
const (
	DefaultInlineBytes = 16384
	MaxInlineBytes     = 65536
)

// The files tos_buyer_result writes under <results_dir>/<request_hash>/.
const (
	ReceiptFile  = "receipt.boc"
	ArtifactFile = "artifact.tar"
	OutputFile   = "output.log"
	ReportFile   = "report.json"
)

var requestHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// errResultWrite is a refusal to write a result file: the results
// directory or a file in it is not what the server would write.
var errResultWrite = errors.New("the result files cannot be written under the results directory")

// NewResultsDir resolves the results directory to its real path. It must
// be an absolute directory the server's account owns and others cannot
// write.
func NewResultsDir(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("the results directory must be an absolute path")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return "", errors.New("the results directory must be a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("the results directory must not be writable by group or others")
	}
	return real, nil
}

// ResultInput is tos_buyer_result's input.
type ResultInput struct {
	RequestHash    string `json:"request_hash" jsonschema:"the purchase's request_hash: 64 lowercase hex digits"`
	MaxInlineBytes *int   `json:"max_inline_bytes,omitempty" jsonschema:"bytes of output.log and of report.json to show, 0 to 65536; default 16384"`
}

// ResultFiles are the paths of the written result files.
type ResultFiles struct {
	Directory string `json:"directory"`
	Receipt   string `json:"receipt_boc"`
	Artifact  string `json:"artifact_tar"`
	Output    string `json:"output_log"`
	Report    string `json:"report_json"`
}

// Result is the structured content of tos_buyer_result.
type Result struct {
	Result *buyeragent.AcceptedView `json:"result,omitempty"`
	// Checked lists what the agent and this server checked; Proves and
	// DoesNotProve say what the Receipt is evidence of.
	Checked      []string      `json:"checked,omitempty"`
	Proves       string        `json:"proves,omitempty"`
	DoesNotProve string        `json:"does_not_prove,omitempty"`
	Files        *ResultFiles  `json:"files,omitempty"`
	OutputBytes  int           `json:"output_bytes,omitempty"`
	ReportBytes  int           `json:"report_bytes,omitempty"`
	Output       UntrustedText `json:"untrusted_output"`
	Report       UntrustedText `json:"untrusted_report"`
	// Status is the purchase's status while no result is accepted.
	Status *Purchase  `json:"status,omitempty"`
	Error  *ToolError `json:"error,omitempty"`
}

// checks is what an accepted result has passed (frames 7.2; section 4.9).
var checks = []string{
	"the Receipt is a canonical single-root BOC of at most 512 bytes",
	"the Receipt's cell hash equals the finalized respond's response_hash",
	"the Receipt binds this purchase's quote_commitment, execution_id, input_digest, source_digest, price, " +
		"provider, toolchain and manifest digests",
	"exit_code is 0 and completed_at is set",
	"the artifact is a two-member USTAR tar whose SHA-256 is the Receipt's artifact_digest",
	"output.log and report.json hash to the Receipt's result_digest and report_digest",
}

const (
	provesText = "The provider's attestor signed a respond whose response_hash commits to this Receipt: the " +
		"provider states that it ran the bound toolchain and manifest on this purchase's source and produced these " +
		"bytes, and it was paid on that statement."
	notProvesText = "It does not prove the computation was correct or that the output is useful: it is an attested " +
		"statement of the bound digests, not a proof of execution."
)

func (t *Tools) result(ctx context.Context, _ *mcp.CallToolRequest, input ResultInput) (*mcp.CallToolResult, Result, error) {
	if !requestHashPattern.MatchString(input.RequestHash) {
		result, toolErr := refused(badInput("request_hash must be 64 lowercase hex digits"))
		return result, Result{Error: toolErr}, nil
	}
	limit := DefaultInlineBytes
	if input.MaxInlineBytes != nil {
		limit = *input.MaxInlineBytes
	}
	if limit < 0 || limit > MaxInlineBytes {
		result, toolErr := refused(badInput("max_inline_bytes must be 0 to 65536"))
		return result, Result{Error: toolErr}, nil
	}
	if t.results == "" {
		result, toolErr := refused(badInput("this server has no results directory"))
		return result, Result{Error: toolErr}, nil
	}
	var raw json.RawMessage
	err := t.agent.Call(ctx, "result", buyeragent.RequestHashParams{RequestHash: input.RequestHash}, &raw)
	var known *buyeragent.Error
	if errors.As(err, &known) && known.Code == buyeragent.CodeResultNotReady {
		out := Result{}
		var status buyeragent.PurchaseView
		if json.Unmarshal(raw, &status) == nil && status.RequestHash == input.RequestHash {
			out.Status = purchaseOf(status)
		}
		result, toolErr := refused(err)
		out.Error = toolErr
		return result, out, nil
	}
	if err != nil {
		result, toolErr := refused(err)
		return result, Result{Error: toolErr}, nil
	}
	var view buyeragent.AcceptedView
	if err := json.Unmarshal(raw, &view); err != nil || view.RequestHash != input.RequestHash {
		result, toolErr := refused(errors.New("the agent's result does not decode"))
		return result, Result{Error: toolErr}, nil
	}
	receipt, artifact, output, report, err := checkAccepted(view)
	if err != nil {
		result, toolErr := refused(err)
		return result, Result{Error: toolErr}, nil
	}
	files, err := writeResult(t.results, input.RequestHash, map[string][]byte{ReceiptFile: receipt,
		ArtifactFile: artifact, OutputFile: output, ReportFile: report})
	if err != nil {
		// The path stays out of the message: a fixed text only.
		result, toolErr := refused(badInput(errResultWrite.Error()))
		return result, Result{Error: toolErr}, nil
	}
	view.ReceiptBase64, view.ArtifactBase64 = "", ""
	out := Result{Result: &view, Checked: checks, Proves: provesText, DoesNotProve: notProvesText, Files: files,
		OutputBytes: len(output), ReportBytes: len(report), Output: untrustedPrefix(output, limit),
		Report: untrustedPrefix(report, limit)}
	text, err := t.renderResult(out)
	if err != nil {
		return nil, Result{}, err
	}
	return text, out, nil
}

func badInput(message string) error {
	return &buyeragent.Error{Code: buyeragent.CodeBadInput, Disposition: buyeragent.DispositionNever, Message: message}
}

// checkAccepted repeats the cheap checks of an accepted result on the bytes
// the agent sent: the Receipt hashes to the response hash, the artifact to
// the Receipt's digest, and its members to theirs.
func checkAccepted(view buyeragent.AcceptedView) (receipt, artifact, output, report []byte, err error) {
	receipt, err = base64.StdEncoding.Strict().DecodeString(view.ReceiptBase64)
	if err != nil {
		return nil, nil, nil, nil, errors.New("the Receipt is not Base64")
	}
	artifact, err = base64.StdEncoding.Strict().DecodeString(view.ArtifactBase64)
	if err != nil {
		return nil, nil, nil, nil, errors.New("the artifact is not Base64")
	}
	decoded, hash, err := railwork.DecodeReceipt(receipt)
	if err != nil || hex.EncodeToString(hash[:]) != view.ResponseHash {
		return nil, nil, nil, nil, errors.New("the Receipt does not hash to the response hash")
	}
	if decoded.ArtifactDigest != digest(artifact) || decoded.ArtifactDigest != view.ArtifactDigest {
		return nil, nil, nil, nil, errors.New("the artifact does not match the Receipt")
	}
	output, report, err = railwork.ArtifactMembers(artifact)
	if err != nil || decoded.ResultDigest != digest(output) || decoded.ReportDigest != digest(report) {
		return nil, nil, nil, nil, errors.New("the artifact's members do not match the Receipt")
	}
	return receipt, artifact, output, report, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeResult writes the files under <results>/<requestHash>/. The
// directory is created 0700 or must already be a directory, never a link;
// each file is written to a fresh temporary file and linked into place, so
// no link is followed and an existing file is never replaced. An existing
// file with the same bytes is kept; one with other bytes is refused.
func writeResult(results, requestHash string, files map[string][]byte) (*ResultFiles, error) {
	if !requestHashPattern.MatchString(requestHash) {
		return nil, errResultWrite
	}
	directory := filepath.Join(results, requestHash)
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.Join(errResultWrite, err)
	}
	info, err := os.Lstat(directory)
	// Lstat reports a link as a link, never as a directory.
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errResultWrite
	}
	for _, name := range []string{ReceiptFile, ArtifactFile, OutputFile, ReportFile} {
		if err := placeFile(directory, name, files[name]); err != nil {
			return nil, err
		}
	}
	return &ResultFiles{Directory: directory, Receipt: filepath.Join(directory, ReceiptFile),
		Artifact: filepath.Join(directory, ArtifactFile), Output: filepath.Join(directory, OutputFile),
		Report: filepath.Join(directory, ReportFile)}, nil
}

func placeFile(directory, name string, content []byte) error {
	target := filepath.Join(directory, name)
	if existing, err := readNoFollow(target); err == nil {
		if !bytes.Equal(existing, content) {
			return errResultWrite
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errResultWrite, err)
	}
	temporary, err := os.CreateTemp(directory, ".tmp-*")
	if err != nil {
		return errors.Join(errResultWrite, err)
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return errors.Join(errResultWrite, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.Join(errResultWrite, err)
	}
	if err := temporary.Close(); err != nil {
		return errors.Join(errResultWrite, err)
	}
	// A link never replaces an existing name and never follows one.
	if err := os.Link(temporary.Name(), target); err != nil {
		if existing, readErr := readNoFollow(target); readErr == nil && bytes.Equal(existing, content) {
			return nil
		}
		return errors.Join(errResultWrite, err)
	}
	return nil
}

// readNoFollow reads a regular file without following a link.
func readNoFollow(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errResultWrite
	}
	return io.ReadAll(io.LimitReader(file, railwork.MaxResultBytes+1))
}

// untrustedPrefix is at most limit bytes of value as untrusted text, with
// the length and digest of the whole value.
func untrustedPrefix(value []byte, limit int) UntrustedText {
	sum := sha256.Sum256(value)
	shown := value
	limit = max(limit, 0)
	if len(shown) > limit {
		shown = shown[:limit]
	}
	return UntrustedText{Text: buyerconfirm.Escape(string(shown), limit), Bytes: len(value),
		SHA256: hex.EncodeToString(sum[:])}
}

func (t *Tools) renderResult(out Result) (*mcp.CallToolResult, error) {
	d, err := newDelimiter(t.random)
	if err != nil {
		return nil, err
	}
	view := out.Result
	var b strings.Builder
	fmt.Fprintf(&b, "Accepted result of purchase %s (request_hash %s), response_hash %s.\n", view.Reference,
		view.RequestHash, view.ResponseHash)
	b.WriteString("Checked:\n")
	for _, check := range out.Checked {
		b.WriteString("- " + check + "\n")
	}
	fmt.Fprintf(&b, "Receipt: provider %s, toolchain %s, manifest %s, source %s, price %s nanoTOS, exit code %d.\n",
		view.ProviderAgentID, view.ToolchainDigest, view.ManifestDigest, view.SourceDigest, view.PriceNanoTOS, view.ExitCode)
	b.WriteString(out.Proves + "\n" + out.DoesNotProve + "\n")
	fmt.Fprintf(&b, "Files: %s, %s, %s (%d bytes), %s (%d bytes).\n", out.Files.Receipt, out.Files.Artifact,
		out.Files.Output, out.OutputBytes, out.Files.Report, out.ReportBytes)
	b.WriteString(d.span("output.log (start)", out.Output))
	b.WriteString(d.span("report.json (start)", out.Report))
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, nil
}
