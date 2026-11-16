package eventlog

// Invites over a route that has no out-of-band channel at send time.
//
// The recipient's owner issues an invite_ token (CreateAdmissionInvite) and
// hands it out of band. The sender's owner presents it here, once, for one
// recipient Agent; every delivery to that Agent then carries it sealed, so
// every re-deposit generation of an Event carries the same token, until one
// delivery to that Agent settles accepted or the token expires. The runtime
// never holds the token: it is a bearer the recipient's owner issued, and a
// runtime holding it could spend it on any Event.
//
// On the recipient a successful claim makes the sender a known contact. That
// list is journaled, is never swept (unlike the invite records), and only the
// owner removes an entry from it.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	presentedInviteDir    = "presented-invites"
	invitedContactDir     = "invited-contacts"
	presentedInviteSchema = "tos.messaging.presented-invite.v1"
	invitedContactSchema  = "tos.messaging.invited-contact.v1"
	// MaxPresentedInvites and MaxInvitedContacts bound the two lists.
	MaxPresentedInvites = 4096
	MaxInvitedContacts  = 4096
)

// PresentedInvite is one invite the owner presented for a recipient Agent.
type PresentedInvite struct {
	Schema           string `json:"schema"`
	RecipientAgentID string `json:"recipient_agent_id"`
	Token            string `json:"token"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
	PresentedAtUnix  uint64 `json:"presented_at_unix"`
}

// InvitedContact is one Agent a claimed invite made a contact.
type InvitedContact struct {
	Schema       string `json:"schema"`
	AgentID      string `json:"agent_id"`
	EventID      string `json:"claimed_event_id"`
	AddedAtUnix  uint64 `json:"added_at_unix"`
	InviteDigest string `json:"invite_digest"`
}

// PresentInvite stores a token the owner received for a recipient Agent. A
// later presentation for the same Agent replaces it.
func (j *Journal) PresentInvite(recipientAgentID, token string, expires, now time.Time) (PresentedInvite, error) {
	if err := j.usable(); err != nil {
		return PresentedInvite{}, err
	}
	if !ids.Agent.MatchString(recipientAgentID) {
		return PresentedInvite{}, errors.New("invalid invite recipient")
	}
	if _, err := decodeAdmissionInvite(token); err != nil {
		return PresentedInvite{}, err
	}
	if now.IsZero() || now.Unix() <= 0 || !expires.After(now) || expires.Sub(now) > MaxAdmissionInviteLifetime {
		return PresentedInvite{}, errors.New("invalid presented invite expiry")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(presentedInviteDir, recipientAgentID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		count, err := countEntries(filepath.Join(j.root, presentedInviteDir))
		if err != nil {
			return PresentedInvite{}, err
		}
		if count >= MaxPresentedInvites {
			return PresentedInvite{}, errors.New("presented invite list is full")
		}
	}
	record := PresentedInvite{Schema: presentedInviteSchema, RecipientAgentID: recipientAgentID, Token: token,
		ExpiresAtUnix: uint64(expires.Unix()), PresentedAtUnix: uint64(now.Unix())}
	encoded, err := json.Marshal(record)
	if err != nil {
		return PresentedInvite{}, err
	}
	if err := j.replace(path, encoded); err != nil {
		return PresentedInvite{}, err
	}
	return record, nil
}

// PresentedInviteFor returns the live token for a recipient Agent. An expired
// one is deleted and reported absent.
func (j *Journal) PresentedInviteFor(recipientAgentID string, now time.Time) (string, bool, error) {
	if err := j.usable(); err != nil {
		return "", false, err
	}
	if !ids.Agent.MatchString(recipientAgentID) || now.IsZero() {
		return "", false, errors.New("invalid presented invite lookup")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(presentedInviteDir, recipientAgentID)
	record, found, err := readPresentedInvite(path, recipientAgentID)
	if err != nil || !found {
		return "", false, err
	}
	if uint64(now.Unix()) >= record.ExpiresAtUnix {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", false, errors.New("remove expired presented invite")
		}
		return "", false, nil
	}
	return record.Token, true, nil
}

// SettlePresentedInvite deletes the token for an Agent once a delivery to it
// settled accepted. It reports whether a token was deleted; one that was
// replaced by a new presentation in the meantime is kept.
func (j *Journal) SettlePresentedInvite(recipientAgentID, token string) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Agent.MatchString(recipientAgentID) {
		return false, errors.New("invalid invite recipient")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(presentedInviteDir, recipientAgentID)
	record, found, err := readPresentedInvite(path, recipientAgentID)
	if err != nil || !found || record.Token != token {
		return false, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("remove settled presented invite")
	}
	return true, syncDirectory(filepath.Dir(path))
}

// RecordDeliveryInvite fixes the token a delivery carries. It is set once,
// on the first attempt, so every re-deposit generation of the Event carries
// the same token; a delivery already carrying one keeps it.
func (j *Journal) RecordDeliveryInvite(deliveryID, attemptID, token string) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if !validDeliveryID(deliveryID) {
		return Delivery{}, errors.New("invalid delivery identifier")
	}
	if _, err := decodeAdmissionInvite(token); err != nil {
		return Delivery{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.deliveryPath(deliveryID)
	delivery, err := readDelivery(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Delivery{}, ErrUnknown
		}
		return Delivery{}, err
	}
	if err := holdsAttempt(delivery, attemptID); err != nil {
		return Delivery{}, err
	}
	if delivery.AdmissionToken != "" {
		return delivery, nil
	}
	delivery.AdmissionToken = token
	return j.commitDelivery(path, delivery)
}

// AddInvitedContact records the sender a claimed invite admitted as a known
// contact. It is idempotent, so the exact retry after a crash between the
// claim and the Event's commit repeats it as a no-op.
func (j *Journal) AddInvitedContact(agentID, eventID, inviteToken string, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	raw, err := decodeAdmissionInvite(inviteToken)
	if err != nil || !ids.Agent.MatchString(agentID) || !ids.Event.MatchString(eventID) || now.IsZero() || now.Unix() <= 0 {
		return false, errors.New("invalid invited contact")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(invitedContactDir, agentID)
	if _, found, err := readInvitedContact(path, agentID); err != nil || found {
		return false, err
	}
	count, err := countEntries(filepath.Join(j.root, invitedContactDir))
	if err != nil {
		return false, err
	}
	if count >= MaxInvitedContacts {
		return false, errors.New("invited contact list is full")
	}
	encoded, err := json.Marshal(InvitedContact{Schema: invitedContactSchema, AgentID: agentID, EventID: eventID,
		AddedAtUnix: uint64(now.Unix()), InviteDigest: admissionInviteDigest(raw)})
	if err != nil {
		return false, err
	}
	if err := j.replace(path, encoded); err != nil {
		return false, err
	}
	return true, nil
}

// IsInvitedContact reports whether a claimed invite made an Agent a contact.
// An unreadable record fails the lookup, so a damaged list never admits.
func (j *Journal) IsInvitedContact(agentID string) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Agent.MatchString(agentID) {
		return false, errors.New("invalid invited contact")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	_, found, err := readInvitedContact(j.agentRecordPath(invitedContactDir, agentID), agentID)
	return found, err
}

// RemoveInvitedContact deletes an invited contact; the Agent's later Events
// meet the contact policy again. It reports whether an entry was removed.
func (j *Journal) RemoveInvitedContact(agentID string) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if !ids.Agent.MatchString(agentID) {
		return false, errors.New("invalid invited contact")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(invitedContactDir, agentID)
	if _, found, err := readInvitedContact(path, agentID); err != nil || !found {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		return false, errors.New("remove invited contact")
	}
	return true, syncDirectory(filepath.Dir(path))
}

func (j *Journal) agentRecordPath(dir, agentID string) string {
	return filepath.Join(j.root, dir, agentID[len("agent_"):]+".json")
}

func countEntries(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, errors.New("read journal directory")
	}
	count := 0
	for _, entry := range entries {
		if !isTransitionTemp(entry.Name()) {
			count++
		}
	}
	return count, nil
}

func readPresentedInvite(path, agentID string) (PresentedInvite, bool, error) {
	raw, err := readRecordBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		return PresentedInvite{}, false, nil
	}
	if err != nil {
		return PresentedInvite{}, false, err
	}
	var record PresentedInvite
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != presentedInviteSchema ||
		record.RecipientAgentID != agentID || record.ExpiresAtUnix <= record.PresentedAtUnix || record.PresentedAtUnix == 0 {
		return PresentedInvite{}, false, errors.New("invalid presented invite record")
	}
	if _, err := decodeAdmissionInvite(record.Token); err != nil {
		return PresentedInvite{}, false, errors.New("invalid presented invite record")
	}
	return record, true, nil
}

func readInvitedContact(path, agentID string) (InvitedContact, bool, error) {
	raw, err := readRecordBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		return InvitedContact{}, false, nil
	}
	if err != nil {
		return InvitedContact{}, false, err
	}
	var record InvitedContact
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != invitedContactSchema ||
		record.AgentID != agentID || !ids.Event.MatchString(record.EventID) || record.AddedAtUnix == 0 {
		return InvitedContact{}, false, errors.New("invalid invited contact record")
	}
	return record, true, nil
}
