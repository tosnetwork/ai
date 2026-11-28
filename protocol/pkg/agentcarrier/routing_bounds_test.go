package agentcarrier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRoutingRecordBudgetIncludesCardsIndexAndWithdrawals(t *testing.T) {
	p := peerHints{Agent: strings.Repeat("a", 71), Cards: map[string][]byte{}, Records: [][]byte{}, LastRelays: []string{}}
	for i := 0; i < 4; i++ {
		raw := bytes.Repeat([]byte{byte(i)}, 40960)
		p.Records = append(p.Records, raw)
		p.Cards[cacheKey(raw)] = bytes.Repeat([]byte{255}, 9216)
	}
	for i := 0; i < 16; i++ {
		p.LastRelays = append(p.LastRelays, "https://127.0.0.1/"+fmt.Sprintf("%02d", i)+strings.Repeat("p", 237))
	}
	m := schedule{ID: strings.Repeat("i", 128), Generation: ^uint32(0), Deadline: ^uint64(0), NextGeneration: ^uint64(0), ResolveAfter: ^uint64(0), ResolvedGeneration: ^uint64(0), TTL: 86400, ResolveBackoff: 600, Withdrawals: []withdrawal{}}
	for i := range m.Packet {
		m.Packet[i] = 255
	}
	for _, url := range p.LastRelays {
		m.Targets = append(m.Targets, relayRetry{URL: url, After: ^uint64(0), Backoff: 600})
	}
	for i := 0; i < MaxWithdrawals; i++ {
		w := withdrawal{Number: uint32(i + 1), Relays: p.LastRelays, Until: ^uint64(0)}
		for j := range w.Secret {
			w.Secret[j] = 255
		}
		m.Withdrawals = append(m.Withdrawals, w)
	}
	index := routingIndex{Identity: identity{Agent: p.Agent}, Names: []string{}}
	for i := 0; i < MaxRoutingRecords; i++ {
		index.Names = append(index.Names, fmt.Sprintf("r-%064x", i))
	}
	for _, model := range []any{p, m, index} {
		raw, e := json.Marshal(model)
		if e != nil || len(raw)+256 > MaxRecordBytes {
			t.Fatal("bounded model exceeds atomic record", len(raw), e)
		}
		t.Logf("%T: %d bytes under %d", model, len(raw)+256, MaxRecordBytes)
	}
}
