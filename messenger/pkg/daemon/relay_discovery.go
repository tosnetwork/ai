package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/securefile"
	"github.com/tosnetwork/ai/messenger/pkg/directory"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
)

// buildContactFileDiscovery assembles discovery for the relay route: peers
// are learned from owner-placed contact files and from in-band evidence, and
// every check reads finalized state without any locator.
func buildContactFileDiscovery(config Config, journal *eventlog.Journal, observer Observer,
	resolver identity.AgentResolver, chain identity.ChainPolicy) (*discoveryRuntime, error) {
	devices, err := journal.OpenDevices()
	if err != nil {
		return nil, errors.New("open peer device ledger: " + err.Error())
	}
	contacts := make(map[string]struct{}, len(config.Admission.KnownAgentIDs))
	for _, agentID := range config.Admission.KnownAgentIDs {
		contacts[agentID] = struct{}{}
	}
	verifier := &directory.RelayVerifier{Resolver: resolver, Network: config.Network(), Chain: chain,
		Judge: devices, Admitter: devices, Store: journal, LocalAgentID: config.AgentID, Contacts: contacts}
	importer := &contactImporter{dir: config.Discovery.ContactDir, verifier: verifier, observer: observer,
		localAgentID: config.AgentID, now: time.Now}
	return &discoveryRuntime{runner: importer, contacts: relayDirectory{verifier: verifier, now: time.Now, public: &publicSlot{}},
		chain: chain, resolver: resolver, devices: devices, relay: verifier}, nil
}

// publicContact resolves a peer by Agent ID through hint directories: the
// builtin lane.
type publicContact interface {
	ResolvePublicContact(ctx context.Context, peer string) (card, evidence []byte, err error)
	LearnCard(ctx context.Context, peer string, card []byte) error
}

// publicSlot holds the lane once it is open; the directory exists earlier.
type publicSlot struct {
	mu     sync.Mutex
	source publicContact
}

func (s *publicSlot) set(source publicContact) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.source = source
}

func (s *publicSlot) get() publicContact {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.source
}

// relayDirectory answers the daemon's contact lookups from committed relay
// evidence. Each lookup is a CheckPeer of that evidence, so a revoked
// Endpoint fails at once and an expired descriptor fails until fresher
// evidence is committed.
type relayDirectory struct {
	verifier *directory.RelayVerifier
	now      func() time.Time
	// public resolves a peer without stored evidence by its Agent ID alone,
	// from the contact its hint discloses; empty with an external carrier.
	public *publicSlot
}

func (r relayDirectory) Ensure(ctx context.Context, agentID string) (directory.RefreshResult, error) {
	if ctx == nil || r.verifier == nil {
		return directory.RefreshResult{}, errors.New("relay directory is not configured")
	}
	now := r.now()
	peer, err := r.verifier.CheckStoredContact(agentID, now)
	if err != nil && errors.Is(err, directory.ErrRelayEvidenceUnknown) {
		if source := r.public.get(); source != nil {
			if publicErr := r.resolvePublic(ctx, source, agentID, now); publicErr != nil {
				return directory.RefreshResult{}, publicErr
			}
			peer, err = r.verifier.CheckStoredContact(agentID, now)
		}
	}
	if err != nil {
		return directory.RefreshResult{}, err
	}
	return directory.RefreshResult{Delegation: peer.Delegation, Descriptor: peer.Descriptor, Bundles: peer.Bundles,
		FinalizedCheckpoint: peer.FinalizedCheckpoint, RefreshedAt: now}, nil
}

// resolvePublic commits the relay evidence a peer's verified hint discloses,
// after the same checks a contact file gets: the card is the peer's, the
// evidence verifies against finalized state and names the peer. Resolving a
// peer to write to it is this installation's decision to contact it, as
// importing its contact file is.
func (r relayDirectory) resolvePublic(ctx context.Context, source publicContact, agentID string, now time.Time) error {
	card, evidence, err := source.ResolvePublicContact(ctx, agentID)
	if err != nil {
		return errors.New("resolve the peer through its hint: " + err.Error())
	}
	if err := checkCardShape(card, agentID); err != nil {
		return err
	}
	peer, err := r.verifier.CheckContact(agentID, evidence, now)
	if err != nil {
		return err
	}
	if _, err := r.verifier.CommitPeer(peer, now); err != nil {
		return err
	}
	return source.LearnCard(ctx, agentID, card)
}

// contactImporter commits the relay evidence of every valid contact file in
// the import directory, once at start and then on each refresh interval.
// Importing a file is the owner's decision, so its peer is admitted.
type contactImporter struct {
	dir          string
	verifier     *directory.RelayVerifier
	observer     Observer
	localAgentID string
	now          func() time.Time
	// learner keeps an imported contact's card for the builtin lane, which
	// seals to it; nil with an external carrier, which imports its own.
	learner cardLearner
}

func (c *contactImporter) Run(ctx context.Context, _ []string, interval time.Duration) error {
	if ctx == nil || c == nil || c.verifier == nil {
		return errors.New("contact importer is not configured")
	}
	if interval < time.Second {
		return errors.New("contact import interval is below its floor")
	}
	c.importAll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.importAll()
		}
	}
}

func (c *contactImporter) importAll() {
	entries, err := os.ReadDir(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		c.report("contact import", errors.New("read contact directory"))
		return
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && filepath.Ext(entry.Name()) == ".json" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) > MaxContactFiles {
		c.report("contact import", errors.New("contact directory holds more files than one pass imports"))
		names = names[:MaxContactFiles]
	}
	for _, name := range names {
		if _, err := c.importFile(filepath.Join(c.dir, name)); err != nil {
			c.report("contact import "+name, err)
		}
	}
}

// importFile verifies one contact file and commits its evidence. It reports
// whether the evidence was newer than what was stored.
func (c *contactImporter) importFile(path string) (bool, error) {
	raw, err := securefile.ReadBoundedRegular(path, relayframe.MaxContactBytes)
	if err != nil {
		return false, err
	}
	contact, err := relayframe.DecodeContactJSON(raw)
	if err != nil {
		return false, err
	}
	if contact.AgentID == c.localAgentID {
		return false, errors.New("a contact file names this installation")
	}
	if err := checkCardShape(contact.Card, contact.AgentID); err != nil {
		return false, err
	}
	now := c.now()
	peer, err := c.verifier.CheckContact(contact.AgentID, contact.Evidence, now)
	if err != nil {
		return false, err
	}
	committed, err := c.verifier.CommitPeer(peer, now)
	if err != nil {
		return committed, err
	}
	if c.learner != nil {
		ctx, cancel := context.WithTimeout(context.Background(), credentialIssueTimeout)
		defer cancel()
		if err := c.learner.LearnCard(ctx, contact.AgentID, contact.Card); err != nil {
			return committed, errors.New("keep the contact's chat card: " + err.Error())
		}
	}
	return committed, nil
}

func (c *contactImporter) report(stage string, err error) {
	if c.observer != nil && err != nil {
		c.observer.Failed(stage, err)
	}
}

// checkCardShape refuses a card that is not one canonical Agent Packet sent
// by the named Agent. The card's ML-DSA-44 signature and its key are the
// carrier's to verify with VerifyKeyCard; Messenger only refuses a card that
// cannot be the named Agent's.
func checkCardShape(card []byte, agentID string) error {
	if len(card) == 0 || len(card) > relayframe.MaxCardBytes {
		return relayframe.ErrCardTooLarge
	}
	packet, err := agentpacket.DecodeJSON(card)
	if err != nil {
		return errors.New("chat card is not an Agent Packet")
	}
	encoded, err := agentpacket.EncodeJSON(packet)
	if err != nil || !bytes.Equal(encoded, card) {
		return errors.New("chat card is not canonical")
	}
	if packet.SenderAgentID != agentID {
		return errors.New("chat card belongs to another Agent")
	}
	return nil
}
