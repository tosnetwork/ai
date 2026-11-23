package provideragent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
)

// The agent's own records (section 8).
const (
	actionSchema      = "tos.service.mcp-provider.action.v1"
	keySchema         = "tos.service.mcp-provider.idempotency-key.v1"
	pauseOriginSchema = "tos.service.mcp-provider.pause-origin.v1"

	actionIDDomain = "tos.service.mcp-provider.action.v1"

	actionsDir      = "actions"
	keysDir         = "keys"
	pauseOriginFile = "pause-origin.json"
	// directoryLock is held for the agent's whole life: one agent per state
	// directory. actionLock is held only around one action's apply, so the
	// two never double as each other.
	directoryLock = "agent.lock"
	actionLock    = "action.lock"

	// terminalRetention is how long a terminal action is kept.
	terminalRetentionSeconds = 30 * 24 * 3600
)

var (
	actionIDPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
)

// actionRecord is one confirmable action (section 8.1). The nonce, its draw
// time and the failure count never leave the custody account.
type actionRecord struct {
	Schema            string          `json:"schema"`
	ActionID          string          `json:"action_id"`
	Kind              string          `json:"kind"`
	IdempotencyKey    string          `json:"idempotency_key"`
	Inputs            json.RawMessage `json:"inputs"`
	Preview           json.RawMessage `json:"preview"`
	PreviewDigest     string          `json:"preview_digest"`
	State             string          `json:"state"`
	RequestedUnix     int64           `json:"requested_unix,omitempty"`
	ConfirmationNonce string          `json:"confirmation_nonce,omitempty"`
	PresentedUnix     int64           `json:"presented_unix,omitempty"`
	CodeFailures      int             `json:"code_failures,omitempty"`
	ApplyingUnix      int64           `json:"applying_unix,omitempty"`
	// PriorWithdrawals are the query ids of the node's withdrawal records
	// just before a confirmed withdrawal is sent, and PriorRecorded says they
	// were stored; both are written durably before the send, so recovery
	// finds the send's own record by its query id (section 8.1).
	PriorWithdrawals []uint64        `json:"prior_withdrawals,omitempty"`
	PriorRecorded    bool            `json:"prior_withdrawals_recorded,omitempty"`
	Result           json.RawMessage `json:"result,omitempty"`
	FailureCode      string          `json:"failure_code,omitempty"`
	FailureMessage   string          `json:"failure_message,omitempty"`
	CreatedUnix      int64           `json:"created_unix"`
	UpdatedUnix      int64           `json:"updated_unix"`
	ExpiresUnix      int64           `json:"expires_at_unix"`
}

func terminal(state string) bool {
	switch state {
	case agentapi.StateCancelled, agentapi.StateDeclined, agentapi.StateExpired, agentapi.StateApplied,
		agentapi.StateFailed:
		return true
	}
	return false
}

// keyRecord binds an idempotency key of one kind to its action.
type keyRecord struct {
	Schema         string `json:"schema"`
	Kind           string `json:"kind"`
	IdempotencyKey string `json:"idempotency_key"`
	ActionID       string `json:"action_id"`
}

// Why the agent wrote a pause marker.
const (
	pauseForModel       = "model"
	pauseForWalletFloor = "wallet_floor"
)

// pauseOrigin is the pause-origin record (section 8.2): the exact bytes of
// the agent marker the agent wrote, and why.
type pauseOrigin struct {
	Schema      string `json:"schema"`
	Marker      []byte `json:"marker"`
	Why         string `json:"why"`
	WrittenUnix int64  `json:"written_unix"`
}

// store is the agent's owner-private state directory.
type store struct{ root string }

func (s store) ensure() error {
	for _, name := range []string{actionsDir, keysDir} {
		if err := ensurePrivateDir(filepath.Join(s.root, name)); err != nil {
			return err
		}
	}
	return nil
}

func (s store) actionPath(id string) string { return filepath.Join(s.root, actionsDir, id+".json") }

func (s store) keyPath(kind, key string) string {
	return filepath.Join(s.root, keysDir, kind+"-"+key+".json")
}

func (s store) readAction(id string) (actionRecord, error) {
	var record actionRecord
	if !actionIDPattern.MatchString(id) {
		return record, agentapi.Refusal(agentapi.CodeBadInput, "action_id must be 64 lowercase hex digits", nil)
	}
	err := readJSON(s.actionPath(id), &record)
	if errors.Is(err, os.ErrNotExist) {
		return record, agentapi.Refusal(agentapi.CodeNotFound, "no such action", err)
	}
	if err != nil {
		return record, err
	}
	if record.Schema != actionSchema || record.ActionID != id {
		return record, errors.New("an action record names another action")
	}
	return record, nil
}

func (s store) writeAction(record actionRecord, exclusive bool) error {
	record.Schema = actionSchema
	return writeJSON(s.actionPath(record.ActionID), record, exclusive)
}

func (s store) actions() ([]actionRecord, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, actionsDir))
	if err != nil {
		return nil, err
	}
	var records []actionRecord
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !actionIDPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			continue
		}
		record, err := s.readAction(strings.TrimSuffix(name, ".json"))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CreatedUnix != records[j].CreatedUnix {
			return records[i].CreatedUnix > records[j].CreatedUnix
		}
		return records[i].ActionID < records[j].ActionID
	})
	return records, nil
}

func (s store) readKey(kind, key string) (keyRecord, bool, error) {
	var record keyRecord
	err := readJSON(s.keyPath(kind, key), &record)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if record.Schema != keySchema || record.Kind != kind || record.IdempotencyKey != key {
		return record, false, errors.New("an idempotency record names another key")
	}
	return record, true, nil
}

func (s store) writeKey(kind, key, actionID string) error {
	return writeJSON(s.keyPath(kind, key), keyRecord{Schema: keySchema, Kind: kind, IdempotencyKey: key,
		ActionID: actionID}, true)
}

// removeAction drops a terminal action past its retention, with its key.
func (s store) removeAction(record actionRecord) error {
	if err := removeSynced(s.keyPath(record.Kind, record.IdempotencyKey)); err != nil {
		return err
	}
	return removeSynced(s.actionPath(record.ActionID))
}

func (s store) readOrigin() (*pauseOrigin, error) {
	var record pauseOrigin
	err := readJSON(filepath.Join(s.root, pauseOriginFile), &record)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if record.Schema != pauseOriginSchema || len(record.Marker) == 0 ||
		(record.Why != pauseForModel && record.Why != pauseForWalletFloor) {
		return nil, errors.New("the pause-origin record is invalid")
	}
	return &record, nil
}

func (s store) writeOrigin(record pauseOrigin) error {
	record.Schema = pauseOriginSchema
	return writeJSON(filepath.Join(s.root, pauseOriginFile), record, false)
}

func (s store) clearOrigin() error { return removeSynced(filepath.Join(s.root, pauseOriginFile)) }

// actionID derives an action's identity from its kind, key and inputs.
func actionID(kind, key string, canonicalInputs []byte) string {
	hash := sha256.New()
	for _, part := range [][]byte{[]byte(actionIDDomain), []byte(kind), []byte(key)} {
		hash.Write(part)
		hash.Write([]byte{0})
	}
	hash.Write(canonicalInputs)
	return hex.EncodeToString(hash.Sum(nil))
}

// previewDigest is the SHA-256 of the canonical JSON of the stored inputs
// and preview.
func previewDigest(inputs, preview json.RawMessage) (string, error) {
	canonical, err := canonicalJSON(map[string]json.RawMessage{"inputs": inputs, "preview": preview})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// actionReference identifies an action across the MCP client and the
// confirmer. It authorizes nothing.
func actionReference(id string) string {
	if len(id) < 16 {
		return ""
	}
	return groupHex(id[:16])
}

func groupHex(digits string) string {
	return digits[0:4] + "-" + digits[4:8] + "-" + digits[8:12] + "-" + digits[12:16]
}
