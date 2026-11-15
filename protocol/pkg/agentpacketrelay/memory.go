package agentpacketrelay

import (
	"errors"
	"sync"
)

// memoryBackend keeps envelopes in memory. It is for tests. failWrites, when
// set, makes every write fail so tests can reach the store's error paths.
type memoryBackend struct {
	mu         sync.Mutex
	envelopes  map[[32]byte][]byte
	tombstones map[[32]byte]tombstone
	failWrites bool
}

var errInjected = errors.New("agentpacketrelay: injected persistence failure")

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{envelopes: map[[32]byte][]byte{}, tombstones: map[[32]byte]tombstone{}}
}

func (m *memoryBackend) putEnvelope(rec record, envelope []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrites {
		return errInjected
	}
	m.envelopes[rec.id] = append([]byte(nil), envelope...)
	return nil
}

func (m *memoryBackend) getEnvelope(id [32]byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.envelopes[id]
	if !ok {
		return nil, errEnvelopeAbsent
	}
	return append([]byte(nil), raw...), nil
}

func (m *memoryBackend) putTombstone(id [32]byte, stone tombstone) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrites {
		return errInjected
	}
	m.tombstones[id] = stone
	return nil
}

func (m *memoryBackend) deleteEnvelope(id [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.envelopes, id)
	return nil
}

func (m *memoryBackend) deleteTombstone(id [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tombstones, id)
	return nil
}

func (m *memoryBackend) close() error { return nil }
