package buyeragent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tosnetwork/ai/protocol/internal/osguard"
)

const (
	purchaseSchema = "tos.service.mcp-buyer.purchase.v1"
	keySchema      = "tos.service.mcp-buyer.idempotency-key.v1"
	quoteSchema    = "tos.service.mcp-buyer.quote.v1"

	maxRecordBytes = 4 << 20
)

var (
	hex64Pattern          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	agentIDPattern        = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

// PurchaseRecord is the agent's durable record of one prepared purchase
// beside its journal record. The journal phase is the authority on whether
// the call may still be sent; this record holds what the journal does not.
type PurchaseRecord struct {
	Schema         string   `json:"schema"`
	RequestHash    string   `json:"request_hash"`
	QuoteID        string   `json:"quote_id"`
	IdempotencyKey string   `json:"idempotency_key"`
	SourceDigest   string   `json:"source_digest"`
	ExecutionNonce string   `json:"execution_nonce"`
	ArchiveBytes   int      `json:"archive_bytes"`
	Members        []Member `json:"members"`
	// RequestedUnix is when a client asked for the human's decision; only a
	// requested purchase is shown to the confirmer.
	RequestedUnix int64 `json:"requested_unix,omitempty"`
	// ConfirmationNonce and PresentedUnix belong to the current
	// presentation. They are drawn only when the confirmer fetches the
	// purchase and are never sent to a client.
	ConfirmationNonce string `json:"confirmation_nonce,omitempty"`
	PresentedUnix     int64  `json:"presented_unix,omitempty"`
	CodeFailures      int    `json:"code_failures,omitempty"`
	// Outcome says why a purchase left the prepared phase without a send:
	// declined, withdrawn, or code-failures.
	Outcome     string `json:"outcome,omitempty"`
	CreatedUnix int64  `json:"created_unix"`
	// From the validated Quote at prepare: the provider, the manifest and
	// its human-readable text, which is the provider's own and untrusted,
	// and the result retention.
	ProviderAgentID     string `json:"provider_agent_id"`
	ManifestDigest      string `json:"manifest_digest"`
	ProviderName        string `json:"untrusted_provider_name"`
	ProviderDescription string `json:"untrusted_provider_description"`
	RetentionSeconds    uint64 `json:"retention_seconds"`
}

// keyRecord binds an idempotency key to one purchase intent. It is written
// before the journal record, so a retry after a crash derives the same
// execution nonce and so the same request hash.
type keyRecord struct {
	Schema         string `json:"schema"`
	IdempotencyKey string `json:"idempotency_key"`
	QuoteID        string `json:"quote_id"`
	SourceDigest   string `json:"source_digest"`
	ExecutionNonce string `json:"execution_nonce"`
	RequestHash    string `json:"request_hash"`
}

// quoteRecord is a Quote the agent built or validated, stored under its
// quote ID for a later prepare.
type quoteRecord struct {
	Schema            string `json:"schema"`
	QuoteID           string `json:"quote_id"`
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	BuyerAddress      string `json:"buyer_address"`
	PackageBase64     string `json:"package_base64"`
}

// store is the agent's owner-private state directory.
type store struct{ root string }

func (s store) dir(name string) string { return filepath.Join(s.root, name) }

func (s store) ensure() error {
	for _, name := range []string{"purchases", "keys", "quotes", "archives"} {
		path := s.dir(name)
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := checkPrivateDir(path); err != nil {
			return err
		}
	}
	return nil
}

func (s store) purchasePath(requestHash string) string {
	return filepath.Join(s.dir("purchases"), requestHash+".json")
}

func (s store) keyPath(key string) string { return filepath.Join(s.dir("keys"), key+".json") }

func (s store) quotePath(id string) string { return filepath.Join(s.dir("quotes"), id+".json") }

func (s store) archivePath(requestHash string) string {
	return filepath.Join(s.dir("archives"), requestHash+".tar")
}

// checkPrivateDir refuses a directory that is a link, is not owned by the
// agent's account, or is open to group or others.
func checkPrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) {
		return fmt.Errorf("%s must be a directory private to the agent's account", path)
	}
	return nil
}

// readPrivate reads an owner-private regular file of bounded size.
func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) ||
		info.Size() > maxRecordBytes {
		return nil, errors.New("an agent state file is not an owner-private regular file")
	}
	return os.ReadFile(path)
}

func readJSON(path string, value any) error {
	raw, err := readPrivate(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("agent state file %s does not decode: %w", filepath.Base(path), err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("an agent state file has trailing data")
	}
	return nil
}

// writePrivate atomically replaces path with an owner-only file holding
// value, synced before and after the rename. With exclusive set it refuses
// to replace an existing file.
func writePrivate(path string, value []byte, exclusive bool) error {
	if len(value) > maxRecordBytes {
		return errors.New("an agent state file would exceed its bound")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".tmp-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if exclusive {
		// A hard link fails when the target exists, so two writers can never
		// both create the same key.
		if err := os.Link(name, path); err != nil {
			return err
		}
	} else if err := os.Rename(name, path); err != nil {
		return err
	}
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func writeJSON(path string, value any, exclusive bool) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivate(path, append(raw, '\n'), exclusive)
}

func (s store) readPurchase(requestHash string) (PurchaseRecord, error) {
	var record PurchaseRecord
	if !hex64Pattern.MatchString(requestHash) {
		return record, errors.New("invalid request hash")
	}
	if err := readJSON(s.purchasePath(requestHash), &record); err != nil {
		return record, err
	}
	if record.Schema != purchaseSchema || record.RequestHash != requestHash {
		return record, errors.New("a purchase record names another purchase")
	}
	return record, nil
}

func (s store) writePurchase(record PurchaseRecord) error {
	record.Schema = purchaseSchema
	return writeJSON(s.purchasePath(record.RequestHash), record, false)
}

func (s store) readKey(key string) (keyRecord, bool, error) {
	var record keyRecord
	err := readJSON(s.keyPath(key), &record)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if record.Schema != keySchema || record.IdempotencyKey != key {
		return record, false, errors.New("an idempotency record names another key")
	}
	return record, true, nil
}

func (s store) readQuote(id string) (quoteRecord, error) {
	var record quoteRecord
	if err := readJSON(s.quotePath(id), &record); err != nil {
		return record, err
	}
	if record.Schema != quoteSchema || record.QuoteID != id {
		return record, errors.New("a Quote record names another Quote")
	}
	return record, nil
}
