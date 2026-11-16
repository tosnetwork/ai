package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
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
	verifier := &directory.RelayVerifier{Resolver: resolver, Network: config.Network(), Chain: chain,
		Judge: devices, Admitter: devices, Store: journal, LocalAgentID: config.AgentID}
	importer := &contactImporter{dir: config.Discovery.ContactDir, verifier: verifier, observer: observer,
		localAgentID: config.AgentID, now: time.Now}
	return &discoveryRuntime{runner: importer, contacts: relayDirectory{verifier: verifier, now: time.Now},
		chain: chain, resolver: resolver, devices: devices, relay: verifier}, nil
}

// relayDirectory answers the daemon's contact lookups from committed relay
// evidence. Each lookup is a CheckPeer of that evidence, so a revoked
// Endpoint fails at once and an expired descriptor fails until fresher
// evidence is committed.
type relayDirectory struct {
	verifier *directory.RelayVerifier
	now      func() time.Time
}

func (r relayDirectory) Ensure(ctx context.Context, agentID string) (directory.RefreshResult, error) {
	if ctx == nil || r.verifier == nil {
		return directory.RefreshResult{}, errors.New("relay directory is not configured")
	}
	now := r.now()
	peer, err := r.verifier.CheckStoredContact(agentID, now)
	if err != nil {
		return directory.RefreshResult{}, err
	}
	return directory.RefreshResult{Delegation: peer.Delegation, Descriptor: peer.Descriptor, Bundles: peer.Bundles,
		FinalizedCheckpoint: peer.FinalizedCheckpoint, RefreshedAt: now}, nil
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
	return c.verifier.CommitPeer(peer, now)
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
