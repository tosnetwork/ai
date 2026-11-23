package mcpprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
)

// MaxOfferBytes bounds the offer file (spec section 4.8).
const MaxOfferBytes = 256 << 10

// offerSchema is the offer file's schema.
const offerSchema = "tos.openfox.rail-offer.v2"

var (
	capabilityIDPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	// fileVersionPattern is a capability version that can name a file: the
	// version is any printable ASCII, which may hold a path separator.
	fileVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

// errExportWrite refuses to write the offer file: the export directory or
// the file in it is not what the server would write.
var errExportWrite = errors.New("the offer file cannot be written under the export directory")

// NewExportDir resolves the export directory to its real path once. It must
// be an absolute directory that group and others cannot write.
func NewExportDir(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("the export directory must be an absolute path")
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(real)
	if err != nil || !info.IsDir() {
		return "", errors.New("the export directory must be a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return "", errors.New("the export directory must not be writable by group or others")
	}
	return real, nil
}

// ExportResult is the result of tos_provider_export_offer.
type ExportResult struct {
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	SHA256            string `json:"sha256"`
	Bytes             int    `json:"bytes"`
	File              string `json:"file"`
}

func (t *Tools) exportOffer(ctx context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, Output, error) {
	if t.export == "" {
		return t.refuse(badInput("this server has no export directory"))
	}
	callCtx, cancel := context.WithTimeout(ctx, ToolTimeout)
	defer cancel()
	var view agentapi.ExportView
	if err := t.agent.Call(callCtx, agentapi.MethodExportOffer, agentapi.Empty{}, &view); err != nil {
		return t.refuse(err)
	}
	content, err := checkExport(view)
	if err != nil {
		return t.refuse(err)
	}
	name := "offer-" + view.CapabilityID + "-" + view.CapabilityVersion + ".json"
	if err := placeFile(t.export, name, content); err != nil {
		// The path stays out of the message: a fixed text only.
		return t.refuse(badInput(errExportWrite.Error()))
	}
	result := ExportResult{CapabilityID: view.CapabilityID, CapabilityVersion: view.CapabilityVersion,
		SHA256: view.SHA256, Bytes: view.Bytes, File: filepath.Join(t.export, name)}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, Output{}, err
	}
	answer, err := shape(raw)
	if err != nil {
		return nil, Output{}, err
	}
	return t.finish(answer, nil, "Offer file written to "+result.File+"; it is public by design (the manifest and "+
		"the provider's key card). Hand it to the buyer's workspace.")
}

// checkExport checks the agent's offer bytes: Base64, the stated length and
// digest, the bound, the schema, and names that can form a file name.
func checkExport(view agentapi.ExportView) ([]byte, error) {
	if !capabilityIDPattern.MatchString(view.CapabilityID) || !fileVersionPattern.MatchString(view.CapabilityVersion) {
		return nil, badInput("the offer's capability id or version cannot name a file; export it with the program")
	}
	content, err := base64.StdEncoding.Strict().DecodeString(view.OfferBase64)
	if err != nil || len(content) != view.Bytes || len(content) > MaxOfferBytes {
		return nil, errAgentAnswer
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != view.SHA256 {
		return nil, errAgentAnswer
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(content, &header); err != nil || header.Schema != offerSchema {
		return nil, errAgentAnswer
	}
	return content, nil
}

// placeFile writes content as directory/name: to a fresh temporary file,
// then linked into place, so no link is followed and an existing file is
// never replaced. An existing file with the same bytes is kept; one with
// other bytes is refused. The offer file is public, so it is readable by
// all.
func placeFile(directory, name string, content []byte) error {
	target := filepath.Join(directory, name)
	if existing, err := readNoFollow(target); err == nil {
		if !bytes.Equal(existing, content) {
			return errExportWrite
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errExportWrite, err)
	}
	temporary, err := os.CreateTemp(directory, ".tmp-offer-*")
	if err != nil {
		return errors.Join(errExportWrite, err)
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err := temporary.Write(content); err != nil {
		return errors.Join(errExportWrite, err, temporary.Close())
	}
	if err := temporary.Chmod(0o644); err != nil {
		return errors.Join(errExportWrite, err, temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(errExportWrite, err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return errors.Join(errExportWrite, err)
	}
	// A link never replaces an existing name and never follows one.
	if err := os.Link(temporary.Name(), target); err != nil {
		if existing, readErr := readNoFollow(target); readErr == nil && bytes.Equal(existing, content) {
			return nil
		}
		return errors.Join(errExportWrite, err)
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
		return nil, errExportWrite
	}
	return io.ReadAll(io.LimitReader(file, MaxOfferBytes+1))
}
