package directory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/tosnetwork/ai/messenger/internal/securefile"
	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/identity"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// Names of the files a relay evidence sink keeps in its export directory.
const (
	RelayEvidenceFile = "relay-evidence.bin"
	RelayContactFile  = "relay-contact.json"
)

// RelayEvidenceSink keeps this node's current relay identity evidence: in
// memory for every outgoing frame, and in an export directory for the owner
// to hand to a contact. The contact file carries the evidence and the local
// chat card, and no locator.
type RelayEvidenceSink struct {
	dir            string
	cardPath       string
	agentID        string
	delegationJSON []byte
	policyJSON     []byte

	mutex   sync.Mutex
	loaded  bool
	current []byte
	digest  string
	issued  uint64
}

// NewRelayEvidenceSink binds a sink to the node's own delegation and policy.
// The export directory is created private if absent.
func NewRelayEvidenceSink(dir, cardPath string, delegationJSON []byte, policy DescriptorPolicy) (*RelayEvidenceSink, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !filepath.IsAbs(cardPath) ||
		filepath.Clean(cardPath) != cardPath {
		return nil, errors.New("relay evidence export and card paths must be absolute and clean")
	}
	delegation, err := identity.DecodeJSON(delegationJSON)
	if err != nil {
		return nil, errors.New("relay evidence sink needs the node's own delegation")
	}
	if canonical, encodeErr := identity.EncodeJSON(delegation); encodeErr != nil || !bytes.Equal(canonical, delegationJSON) {
		return nil, errors.New("relay evidence delegation is not canonical")
	}
	policyJSON, err := EncodeDescriptorPolicyJSON(policy)
	if err != nil {
		return nil, err
	}
	if digest, digestErr := policy.Digest(); digestErr != nil || digest != delegation.ContactDescriptorPolicyDigest {
		return nil, errors.New("relay evidence policy is not the one the delegation commits")
	}
	if len(delegationJSON) > relayframe.MaxEvidenceDelegationBytes || len(policyJSON) > relayframe.MaxEvidencePolicyBytes {
		return nil, relayframe.ErrRelayEvidenceTooLarge
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errors.New("create relay evidence export directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("relay evidence export directory must be private")
	}
	return &RelayEvidenceSink{dir: dir, cardPath: cardPath, agentID: delegation.AgentID,
		delegationJSON: append([]byte(nil), delegationJSON...), policyJSON: policyJSON}, nil
}

// LastRelayDescriptor reports the descriptor of the evidence last exported,
// including by a previous process.
func (s *RelayEvidenceSink) LastRelayDescriptor() (string, uint64, bool, error) {
	if s == nil {
		return "", 0, false, errors.New("no relay evidence sink")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.loadLocked(); err != nil {
		return "", 0, false, err
	}
	return s.digest, s.issued, s.current != nil, nil
}

// PutRelayEvidence installs new own evidence. Identical evidence is a no-op;
// different evidence must have a strictly later descriptor issue time than
// the evidence it replaces, which is the publisher invariant every "newer"
// comparison relies on.
func (s *RelayEvidenceSink) PutRelayEvidence(descriptor Descriptor, descriptorJSON, bundleSetJSON []byte) error {
	if s == nil {
		return errors.New("no relay evidence sink")
	}
	if descriptor.AgentID != s.agentID {
		return errors.New("relay evidence descriptor belongs to another Agent")
	}
	bundles, err := e2ee.DecodeBundleSetJSON(bundleSetJSON)
	if err != nil {
		return err
	}
	if len(bundles) != 1 {
		return errors.New("relay evidence carries exactly one device")
	}
	evidence, err := relayframe.EncodeEvidence(relayframe.Evidence{Delegation: s.delegationJSON,
		Policy: s.policyJSON, Descriptor: descriptorJSON, BundleSet: bundleSetJSON})
	if err != nil {
		return err
	}
	digest, err := DescriptorDigest(descriptor)
	if err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	if s.current != nil {
		if bytes.Equal(s.current, evidence) {
			return s.exportContactLocked()
		}
		if !NewerEvidence(digest, descriptor.IssuedAtUnix, s.digest, s.issued) {
			return errors.New("relay evidence would not be newer than the evidence it replaces")
		}
	}
	if err := writePrivateAtomic(filepath.Join(s.dir, RelayEvidenceFile), evidence); err != nil {
		return err
	}
	s.current, s.digest, s.issued = evidence, digest, descriptor.IssuedAtUnix
	return s.exportContactLocked()
}

// Current returns this node's current evidence.
func (s *RelayEvidenceSink) Current() ([]byte, string, uint64, error) {
	if s == nil {
		return nil, "", 0, errors.New("no relay evidence sink")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, "", 0, err
	}
	if s.current == nil {
		return nil, "", 0, errors.New("no relay evidence has been published yet")
	}
	return append([]byte(nil), s.current...), s.digest, s.issued, nil
}

// Card returns the local chat card the carrier republishes in the card path.
func (s *RelayEvidenceSink) Card() ([]byte, error) {
	if s == nil {
		return nil, errors.New("no relay evidence sink")
	}
	return securefile.ReadBoundedRegular(s.cardPath, relayframe.MaxCardBytes)
}

func (s *RelayEvidenceSink) loadLocked() error {
	if s.loaded {
		return nil
	}
	path := filepath.Join(s.dir, RelayEvidenceFile)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		s.loaded = true
		return nil
	}
	raw, err := securefile.ReadBoundedRegular(path, relayframe.MaxEvidenceBytes)
	if err != nil {
		return errors.New("read exported relay evidence: " + err.Error())
	}
	digest, issued, err := EvidenceDescriptor(raw)
	if err != nil {
		return errors.New("exported relay evidence is unreadable: " + err.Error())
	}
	s.current, s.digest, s.issued, s.loaded = raw, digest, issued, true
	return nil
}

// exportContactLocked writes the contact file when the local card is
// readable. A missing card leaves the evidence exported and the contact file
// as it was; the next publication retries.
func (s *RelayEvidenceSink) exportContactLocked() error {
	card, err := securefile.ReadBoundedRegular(s.cardPath, relayframe.MaxCardBytes)
	if err != nil {
		return nil
	}
	contact, err := relayframe.EncodeContactJSON(relayframe.Contact{AgentID: s.agentID, Evidence: s.current, Card: card})
	if err != nil {
		return err
	}
	return writePrivateAtomic(filepath.Join(s.dir, RelayContactFile), contact)
}

func writePrivateAtomic(path string, raw []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".relay-export-")
	if err != nil {
		return errors.New("create relay export temporary file")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("protect relay export file")
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return errors.New("write relay export file")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("sync relay export file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close relay export file")
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("install relay export file")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("open relay export directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync relay export directory")
	}
	return nil
}
