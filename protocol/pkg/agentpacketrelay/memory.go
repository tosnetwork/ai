package agentpacketrelay

import (
	"errors"
	"sync"
)

// memoryBackend keeps envelopes in memory. It is for tests. failWrites, when
// set, makes every write fail so tests can reach the store's error paths.
type memoryBackend struct {
	mu         sync.Mutex
	envelopes  map[entryKey][]byte
	tombstones map[entryKey]tombstone
	failWrites bool
	// putGate, when set, holds every envelope write until it is closed or
	// receives.
	putGate chan struct{}
}

var errInjected = errors.New("agentpacketrelay: injected persistence failure")

func newMemoryBackend() *memoryBackend {
	return &memoryBackend{envelopes: map[entryKey][]byte{}, tombstones: map[entryKey]tombstone{}}
}

func (m *memoryBackend) putEnvelope(rec record, envelope []byte) error {
	m.mu.Lock()
	gate := m.putGate
	m.mu.Unlock()
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrites {
		return errInjected
	}
	m.envelopes[rec.key()] = append([]byte(nil), envelope...)
	return nil
}

func (m *memoryBackend) getEnvelope(key entryKey) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.envelopes[key]
	if !ok {
		return nil, errEnvelopeAbsent
	}
	return append([]byte(nil), raw...), nil
}

func (m *memoryBackend) putTombstone(key entryKey, stone tombstone) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failWrites {
		return errInjected
	}
	m.tombstones[key] = stone
	return nil
}

func (m *memoryBackend) deleteEnvelope(key entryKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.envelopes, key)
	return nil
}

func (m *memoryBackend) deleteTombstone(key entryKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tombstones, key)
	return nil
}

func (m *memoryBackend) close() error { return nil }
