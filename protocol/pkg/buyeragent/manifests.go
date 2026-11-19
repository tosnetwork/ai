package buyeragent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// MaxManifestBytes bounds a manifest the agent fetches or stores. A
// carriable Quote package holds its manifest in at most 31,611 bytes, so a
// larger manifest could never be bought anyway.
const MaxManifestBytes = 1 << 20

var manifestDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func manifestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ManifestStore keeps manifests by digest in an owner-private directory.
// The agent stores the manifest of every Quote it accepts, so the buyer's
// admission at prepare (buyersdk, serviceactor.Gather) finds it without a
// gateway. It is content-addressed: a file is served only when its bytes
// hash to the digest asked for.
type ManifestStore struct{ dir string }

// NewManifestStore opens, creating it when absent, an owner-private (0700)
// manifest directory.
func NewManifestStore(dir string) (*ManifestStore, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("the manifest directory must be absolute and clean")
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := checkPrivateDir(dir); err != nil {
		return nil, err
	}
	return &ManifestStore{dir: dir}, nil
}

func (s *ManifestStore) path(digest string) string {
	return filepath.Join(s.dir, strings.TrimPrefix(digest, "sha256:")+".cbor")
}

// Manifest returns the stored manifest for digest; it implements
// serviceactor.ManifestSource.
func (s *ManifestStore) Manifest(_ context.Context, digest string) ([]byte, error) {
	if !manifestDigestPattern.MatchString(digest) {
		return nil, errors.New("invalid manifest digest")
	}
	raw, err := readPrivate(s.path(digest))
	if err != nil {
		return nil, err
	}
	if manifestDigest(raw) != digest {
		return nil, errors.New("a stored manifest does not hash to its digest")
	}
	return raw, nil
}

// Put stores manifest bytes under their digest.
func (s *ManifestStore) Put(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return "", errors.New("a manifest is empty or over its bound")
	}
	digest := manifestDigest(raw)
	if err := writePrivate(s.path(digest), raw, true); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return digest, nil
}

// manifestFetch is one source of manifest bytes by digest.
type manifestFetch func(ctx context.Context, digest string) ([]byte, error)

// manifestRecorder asks its sources in order for a manifest and keeps the
// first bytes that hash to the digest asked for, so a search or a quote
// reads the human-readable text of exactly the bytes the finalized check
// used. Every source is a hint; the finalized digest decides.
type manifestRecorder struct {
	sources []manifestFetch
	mu      sync.Mutex
	held    map[string][]byte
}

func (m *manifestRecorder) Manifest(ctx context.Context, digest string) ([]byte, error) {
	if !manifestDigestPattern.MatchString(digest) {
		return nil, errors.New("invalid manifest digest")
	}
	if raw, ok := m.get(digest); ok {
		return raw, nil
	}
	for _, source := range m.sources {
		raw, err := source(ctx, digest)
		if err != nil || len(raw) == 0 || len(raw) > MaxManifestBytes || manifestDigest(raw) != digest {
			continue
		}
		raw = append([]byte(nil), raw...)
		m.mu.Lock()
		if m.held == nil {
			m.held = map[string][]byte{}
		}
		m.held[digest] = raw
		m.mu.Unlock()
		return raw, nil
	}
	return nil, errors.New("no source holds the manifest")
}

func (m *manifestRecorder) get(digest string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.held[digest]
	return raw, ok
}
