package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	// DirectConversationRecordSchema identifies the AgentID-keyed durable
	// first-contact record. It deliberately contains no alias or session secret.
	DirectConversationRecordSchema = "tos.messaging.direct-conversation.v1"
	// MaxDirectConversations bounds peer-controlled durable state growth.
	MaxDirectConversations = 4096

	DirectConversationDiscovered = "discovered"
)

var ErrDirectConversationRollback = errors.New("direct conversation directory evidence rolled back")

// DirectConversationRecord pins one direct conversation to the immutable local
// and remote Agent identities. Endpoint evidence may advance monotonically;
// it never changes the counterparty or daemon-generated conversation ID.
type DirectConversationRecord struct {
	Schema                   string `json:"schema"`
	LocalAgentID             string `json:"local_agent_id"`
	RemoteAgentID            string `json:"remote_agent_id"`
	ConversationID           string `json:"conversation_id"`
	State                    string `json:"state"`
	VerifiedRemoteEndpointID string `json:"verified_remote_endpoint_id"`
	FinalizedCheckpoint      uint64 `json:"finalized_checkpoint"`
	DirectoryVerifiedAtUnix  uint64 `json:"directory_verified_at_unix"`
	CreatedAtUnix            uint64 `json:"created_at_unix"`
	UpdatedAtUnix            uint64 `json:"updated_at_unix"`
}

// EnsureDirectConversation atomically creates or reloads the direct
// conversation for one canonical remote AgentID. Entropy is caller-generated;
// an exact retry after creation returns the recorded ID and ignores new entropy.
func (j *Journal) EnsureDirectConversation(
	localAgentID, remoteAgentID, remoteEndpointID string,
	finalizedCheckpoint uint64,
	verifiedAt time.Time,
	entropy [32]byte,
) (DirectConversationRecord, bool, error) {
	if err := j.usable(); err != nil {
		return DirectConversationRecord{}, false, err
	}
	if !ids.Agent.MatchString(localAgentID) || !ids.Agent.MatchString(remoteAgentID) ||
		localAgentID == remoteAgentID || !ids.Endpoint.MatchString(remoteEndpointID) ||
		finalizedCheckpoint == 0 || verifiedAt.IsZero() || verifiedAt.Unix() < 0 {
		return DirectConversationRecord{}, false, errors.New("invalid direct conversation evidence")
	}
	conversationID, err := ids.Format("conv_", entropy[:])
	if err != nil {
		return DirectConversationRecord{}, false, errors.New("invalid direct conversation entropy")
	}
	now := uint64(verifiedAt.Unix())

	j.mutex.Lock()
	defer j.mutex.Unlock()
	existing, found, err := j.readDirectConversation(localAgentID, remoteAgentID)
	if err != nil {
		return DirectConversationRecord{}, false, err
	}
	if found {
		if finalizedCheckpoint < existing.FinalizedCheckpoint || now < existing.DirectoryVerifiedAtUnix {
			return DirectConversationRecord{}, false, ErrDirectConversationRollback
		}
		if finalizedCheckpoint == existing.FinalizedCheckpoint &&
			remoteEndpointID != existing.VerifiedRemoteEndpointID {
			return DirectConversationRecord{}, false, ErrConflict
		}
		if finalizedCheckpoint == existing.FinalizedCheckpoint && now == existing.DirectoryVerifiedAtUnix {
			return existing, false, nil
		}
		existing.VerifiedRemoteEndpointID = remoteEndpointID
		existing.FinalizedCheckpoint = finalizedCheckpoint
		existing.DirectoryVerifiedAtUnix = now
		existing.UpdatedAtUnix = now
		if err := j.writeDirectConversation(existing); err != nil {
			return DirectConversationRecord{}, false, err
		}
		return existing, false, nil
	}

	entries, err := os.ReadDir(filepath.Join(j.root, directConversationDir))
	if err != nil {
		return DirectConversationRecord{}, false, errors.New("read direct conversations")
	}
	if len(entries) >= MaxDirectConversations {
		return DirectConversationRecord{}, false, errors.New("direct conversation ledger is full")
	}
	record := DirectConversationRecord{
		Schema:       DirectConversationRecordSchema,
		LocalAgentID: localAgentID, RemoteAgentID: remoteAgentID,
		ConversationID: conversationID, State: DirectConversationDiscovered,
		VerifiedRemoteEndpointID: remoteEndpointID, FinalizedCheckpoint: finalizedCheckpoint,
		DirectoryVerifiedAtUnix: now, CreatedAtUnix: now, UpdatedAtUnix: now,
	}
	if err := j.writeDirectConversation(record); err != nil {
		return DirectConversationRecord{}, false, err
	}
	return record, true, nil
}

// DirectConversation returns the current identity-bound record without
// refreshing discovery. Callers must not treat this read as current route
// authority.
func (j *Journal) DirectConversation(localAgentID, remoteAgentID string) (DirectConversationRecord, bool, error) {
	if err := j.usable(); err != nil {
		return DirectConversationRecord{}, false, err
	}
	if !ids.Agent.MatchString(localAgentID) || !ids.Agent.MatchString(remoteAgentID) || localAgentID == remoteAgentID {
		return DirectConversationRecord{}, false, errors.New("invalid direct conversation identity")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readDirectConversation(localAgentID, remoteAgentID)
}

// MaxDirectConversationsPerPage bounds one page of ListDirectConversations.
const MaxDirectConversationsPerPage = 64

// ListDirectConversations returns at most limit direct conversations of the
// local Agent, newest first by creation time and then by conversation ID
// descending. Creation time never changes, so a walk is stable while
// conversations are updated between its pages. A page continues strictly
// after the cursor (before, beforeID): the creation time and ID of the last
// entry of the previous page, or zero and empty for the first page. It reads
// one directory of at most MaxDirectConversations records under the journal
// lock, so a page is one snapshot; temporary files of an interrupted write are
// neither listed nor counted.
func (j *Journal) ListDirectConversations(localAgentID string, before uint64, beforeID string,
	limit int) ([]DirectConversationRecord, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if !ids.Agent.MatchString(localAgentID) || limit < 1 || limit > MaxDirectConversationsPerPage ||
		(before == 0) != (beforeID == "") || beforeID != "" && !ids.Conversation.MatchString(beforeID) {
		return nil, errors.New("invalid direct conversation listing")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	entries, err := os.ReadDir(filepath.Join(j.root, directConversationDir))
	if err != nil {
		return nil, errors.New("read direct conversations")
	}
	records := make([]DirectConversationRecord, 0, len(entries))
	counted := 0
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) || strings.HasPrefix(name, ".tmp-") {
			continue
		}
		if counted++; counted > MaxDirectConversations {
			return nil, errors.New("direct conversation ledger exceeds its bound")
		}
		if !entry.Type().IsRegular() || filepath.Ext(name) != ".json" {
			return nil, errors.New("direct conversation ledger holds an unexpected entry")
		}
		remote := "agent_" + name[:len(name)-len(".json")]
		if !ids.Agent.MatchString(remote) {
			return nil, errors.New("direct conversation ledger holds an unexpected entry")
		}
		record, found, err := j.readDirectConversation(localAgentID, remote)
		if err != nil || !found {
			return nil, errors.New("read direct conversation")
		}
		if before != 0 && (record.CreatedAtUnix > before ||
			record.CreatedAtUnix == before && record.ConversationID >= beforeID) {
			continue
		}
		records = append(records, record)
	}
	sort.Slice(records, func(a, b int) bool {
		if records[a].CreatedAtUnix != records[b].CreatedAtUnix {
			return records[a].CreatedAtUnix > records[b].CreatedAtUnix
		}
		return records[a].ConversationID > records[b].ConversationID
	})
	if len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

func (j *Journal) writeDirectConversation(record DirectConversationRecord) error {
	if err := validateDirectConversation(record); err != nil {
		return err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return errors.New("encode direct conversation")
	}
	return j.replace(j.directConversationPath(record.RemoteAgentID), encoded)
}

func (j *Journal) readDirectConversation(localAgentID, remoteAgentID string) (DirectConversationRecord, bool, error) {
	raw, err := readRecordBytes(j.directConversationPath(remoteAgentID))
	if errors.Is(err, os.ErrNotExist) {
		return DirectConversationRecord{}, false, nil
	}
	if err != nil {
		return DirectConversationRecord{}, false, errors.New("read direct conversation")
	}
	var record DirectConversationRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return DirectConversationRecord{}, false, errors.New("invalid direct conversation record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DirectConversationRecord{}, false, errors.New("direct conversation record has trailing content")
	}
	if err := validateDirectConversation(record); err != nil ||
		record.LocalAgentID != localAgentID || record.RemoteAgentID != remoteAgentID {
		return DirectConversationRecord{}, false, errors.New("direct conversation record describes another identity")
	}
	return record, true, nil
}

func validateDirectConversation(record DirectConversationRecord) error {
	if record.Schema != DirectConversationRecordSchema || !ids.Agent.MatchString(record.LocalAgentID) ||
		!ids.Agent.MatchString(record.RemoteAgentID) || record.LocalAgentID == record.RemoteAgentID ||
		!ids.Conversation.MatchString(record.ConversationID) || record.State != DirectConversationDiscovered ||
		!ids.Endpoint.MatchString(record.VerifiedRemoteEndpointID) || record.FinalizedCheckpoint == 0 ||
		record.CreatedAtUnix == 0 || record.DirectoryVerifiedAtUnix < record.CreatedAtUnix ||
		record.UpdatedAtUnix != record.DirectoryVerifiedAtUnix {
		return errors.New("invalid direct conversation record")
	}
	return nil
}

func (j *Journal) directConversationPath(remoteAgentID string) string {
	return filepath.Join(j.root, directConversationDir, remoteAgentID[len("agent_"):]+".json")
}
