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
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/canon"
	"github.com/tosnetwork/ai/messenger/internal/ids"
)

const (
	presentedInviteDir            = "presented-invites"
	invitedContactDir             = "invited-contacts"
	invitedContactTombstoneDir    = "invited-contact-tombstones"
	presentedInviteSchema         = "tos.messaging.presented-invite.v1"
	invitedContactSchema          = "tos.messaging.invited-contact.v1"
	invitedContactTombstoneSchema = "tos.messaging.invited-contact-tombstone.v1"
	// MaxPresentedInvites and MaxInvitedContacts bound the two lists.
	MaxPresentedInvites = 4096
	MaxInvitedContacts  = 4096
	// MaxInvitedContactTombstones bounds the removal tombstones. A tombstone
	// is kept only while the invite record it names exists, and there are at
	// most MaxAdmissionInvites of those.
	MaxInvitedContactTombstones = MaxAdmissionInvites
)

// presentedInviteCap is the bound the list enforces: MaxPresentedInvites,
// lowered by tests to fill the list cheaply.
var presentedInviteCap = MaxPresentedInvites

var (
	// ErrInvalidPresentedInvite reports a presentation with an invalid
	// recipient, token or expiry.
	ErrInvalidPresentedInvite = errors.New("invalid presented invite")
	// ErrPresentedInvitesFull reports a full presented-invite list after the
	// expired entries were swept.
	ErrPresentedInvitesFull = errors.New("presented invite list is full")
	// ErrInvitedContactsFull reports a full invited-contact list.
	ErrInvitedContactsFull = errors.New("invited contact list is full")
	// ErrInvitedContactRemoved reports a claim whose contact the owner already
	// removed: the same claimed invite never makes that Agent a contact again.
	ErrInvitedContactRemoved = errors.New("the owner removed the contact this invite made")
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
		return PresentedInvite{}, ErrInvalidPresentedInvite
	}
	if _, err := decodeAdmissionInvite(token); err != nil {
		return PresentedInvite{}, ErrInvalidPresentedInvite
	}
	if now.IsZero() || now.Unix() <= 0 || !expires.After(now) || expires.Sub(now) > MaxAdmissionInviteLifetime {
		return PresentedInvite{}, ErrInvalidPresentedInvite
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(presentedInviteDir, recipientAgentID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		count, err := countEntries(filepath.Join(j.root, presentedInviteDir))
		if err != nil {
			return PresentedInvite{}, err
		}
		// Expired entries never count: they are swept before the bound is
		// judged, so a list once filled does not refuse new recipients for
		// good.
		if count >= presentedInviteCap {
			if err := j.sweepPresentedInvites(uint64(now.Unix())); err != nil {
				return PresentedInvite{}, err
			}
			if count, err = countEntries(filepath.Join(j.root, presentedInviteDir)); err != nil {
				return PresentedInvite{}, err
			}
		}
		if count >= presentedInviteCap {
			return PresentedInvite{}, ErrPresentedInvitesFull
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
		return "", false, syncDirectory(filepath.Dir(path))
	}
	return record.Token, true, nil
}

// sweepPresentedInvites deletes every presented invite whose expiry passed.
// An unreadable record fails the sweep: it is never silently dropped. The
// journal mutex is held.
func (j *Journal) sweepPresentedInvites(now uint64) error {
	dir := filepath.Join(j.root, presentedInviteDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.New("read journal directory")
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".json")
		agentID := "agent_" + stem
		if !ok || entry.IsDir() || !ids.Agent.MatchString(agentID) {
			return errors.New("unexpected entry in the presented invite list")
		}
		record, found, err := readPresentedInvite(filepath.Join(dir, name), agentID)
		if err != nil {
			return err
		}
		if found && now >= record.ExpiresAtUnix {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("remove expired presented invite")
			}
			removed = true
		}
	}
	if removed {
		return syncDirectory(dir)
	}
	return nil
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
	digest := admissionInviteDigest(raw)
	j.mutex.Lock()
	defer j.mutex.Unlock()
	path := j.agentRecordPath(invitedContactDir, agentID)
	if _, found, err := readInvitedContact(path, agentID); err != nil || found {
		return false, err
	}
	// A removal is final for the invite that made the contact: replaying the
	// claimed Event must not undo the owner's decision.
	if tombstoned, err := readInvitedContactTombstone(j.tombstonePath(agentID, digest), agentID, digest); err != nil {
		return false, err
	} else if tombstoned {
		return false, ErrInvitedContactRemoved
	}
	count, err := countEntries(filepath.Join(j.root, invitedContactDir))
	if err != nil {
		return false, err
	}
	if count >= MaxInvitedContacts {
		return false, ErrInvitedContactsFull
	}
	encoded, err := json.Marshal(InvitedContact{Schema: invitedContactSchema, AgentID: agentID, EventID: eventID,
		AddedAtUnix: uint64(now.Unix()), InviteDigest: digest})
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
//
// The removal first writes a tombstone naming the Agent and the invite that
// made the contact, so the exact claimed Event presented again cannot re-add
// it. A crash between the tombstone and the deletion leaves the contact in
// place and a retry finishes the removal.
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
	record, found, err := readInvitedContact(path, agentID)
	if err != nil || !found {
		return false, err
	}
	if !canon.ValidDigest(record.InviteDigest) {
		return false, errors.New("invalid invited contact record")
	}
	if err := j.writeInvitedContactTombstone(agentID, record.InviteDigest); err != nil {
		return false, err
	}
	if err := os.Remove(path); err != nil {
		return false, errors.New("remove invited contact")
	}
	return true, syncDirectory(filepath.Dir(path))
}

type invitedContactTombstone struct {
	Schema       string `json:"schema"`
	AgentID      string `json:"agent_id"`
	InviteDigest string `json:"invite_digest"`
}

func (j *Journal) tombstonePath(agentID, inviteDigest string) string {
	return filepath.Join(j.root, invitedContactTombstoneDir, agentID[len("agent_"):]+"-"+inviteDigest[len("sha256:"):]+".json")
}

// writeInvitedContactTombstone records a removal. Tombstones whose invite
// record is gone are swept first: once the invite record is swept, the token
// no longer checks, so the claimed Event cannot reach the contact step at
// all. The journal mutex is held.
func (j *Journal) writeInvitedContactTombstone(agentID, inviteDigest string) error {
	path := j.tombstonePath(agentID, inviteDigest)
	if found, err := readInvitedContactTombstone(path, agentID, inviteDigest); err != nil || found {
		return err
	}
	if err := j.sweepInvitedContactTombstones(); err != nil {
		return err
	}
	count, err := countEntries(filepath.Join(j.root, invitedContactTombstoneDir))
	if err != nil {
		return err
	}
	if count >= MaxInvitedContactTombstones {
		return errors.New("invited contact tombstone list is full")
	}
	encoded, err := json.Marshal(invitedContactTombstone{Schema: invitedContactTombstoneSchema, AgentID: agentID, InviteDigest: inviteDigest})
	if err != nil {
		return err
	}
	return j.replace(path, encoded)
}

// sweepInvitedContactTombstones deletes the tombstones whose invite record no
// longer exists. An unreadable entry fails the sweep. The journal mutex is
// held.
func (j *Journal) sweepInvitedContactTombstones() error {
	dir := filepath.Join(j.root, invitedContactTombstoneDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.New("read journal directory")
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if isTransitionTemp(name) {
			continue
		}
		stem, ok := strings.CutSuffix(name, ".json")
		agentHex, digestHex, cut := strings.Cut(stem, "-")
		if !ok || !cut || entry.IsDir() || !ids.Agent.MatchString("agent_"+agentHex) || !canon.HashPattern.MatchString(digestHex) {
			return errors.New("unexpected entry in the invited contact tombstones")
		}
		digest := "sha256:" + digestHex
		if found, err := readInvitedContactTombstone(filepath.Join(dir, name), "agent_"+agentHex, digest); err != nil || !found {
			return errors.New("invalid invited contact tombstone")
		}
		if _, found, err := j.readAdmissionInvite(digest); err != nil {
			return err
		} else if found {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove invited contact tombstone")
		}
		removed = true
	}
	if removed {
		return syncDirectory(dir)
	}
	return nil
}

func readInvitedContactTombstone(path, agentID, inviteDigest string) (bool, error) {
	raw, err := readRecordBytes(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var record invitedContactTombstone
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != invitedContactTombstoneSchema ||
		record.AgentID != agentID || record.InviteDigest != inviteDigest {
		return false, errors.New("invalid invited contact tombstone")
	}
	return true, nil
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
