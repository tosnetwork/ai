package agentcarrier

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func (l *Lane) remember(table map[string]memory, id string, secret [32]byte, until, now uint64, canAck bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, value := range table {
		if value.Until <= now {
			delete(table, key)
		}
	}
	if _, exists := table[id]; !exists && len(table) >= MaxEnvelopeMemory {
		var oldest string
		first := true
		var expiry uint64
		for k, v := range table {
			if first || v.Until < expiry || (v.Until == expiry && k < oldest) {
				oldest, expiry, first = k, v.Until, false
			}
		}
		delete(table, oldest)
	}
	table[id] = memory{secret, until, canAck}
}
func (l *Lane) recalled(table map[string]memory, id string, now uint64) (memory, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	v, ok := table[id]
	return v, ok && v.Until > now
}
func (l *Lane) keysForPoll(ctx context.Context) (map[[32]byte]agentpacketseal.PrivateKey, error) {
	if err := l.keys.lock(ctx); err != nil {
		return nil, err
	}
	defer l.keys.unlock()
	held, _, err := l.heldKeys()
	return held, err
}

// Poll runs a bounded plain-listing pass over every retained relay. A runtime
// calls it every 15 seconds, independently of Wait's one long-poll request.
// The durable inbox owns packet replay/execution; a lost memory cache costs
// only another download and durable duplicate admission after restart.
func (l *Lane) Poll(ctx context.Context) (PollView, error) {
	if err := l.poll.lock(ctx); err != nil {
		return PollView{}, err
	}
	defer l.poll.unlock()
	if err := l.own(ctx); err != nil {
		return PollView{Code: ErrTransportRevoked.Error()}, err
	}
	relays, err := l.pollTargets()
	if err != nil {
		return PollView{}, err
	}
	held, err := l.keysForPoll(ctx)
	if err != nil {
		return PollView{}, err
	}
	now, err := l.now()
	if err != nil {
		return PollView{}, err
	}
	var total PollView
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range relays {
		if r.Until <= now {
			continue
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			v, e := l.pollRelay(ctx, url, held, 0)
			mu.Lock()
			defer mu.Unlock()
			total.Listed += v.Listed
			total.Stored += v.Stored
			total.Refused += v.Refused
			total.Acknowledged += v.Acknowledged
			if e != nil {
				total.Code = ErrUnavailable.Error()
			}
		}(r.URL)
	}
	wg.Wait()
	if total.Code != "" {
		return total, ErrUnavailable
	}
	return total, nil
}

// Wait uses one retained relay; concurrent Wait calls refuse instead of making
// two waiting requests. The caller selects only a retained owner poll target.
// A failed preferred relay can be replaced on the next call; Poll continues.
func (l *Lane) Wait(ctx context.Context, url string, seconds int) (PollView, error) {
	if seconds < 1 || seconds > 25 {
		return PollView{}, ErrConfig
	}
	select {
	case l.wait <- struct{}{}:
		defer l.wait.unlock()
	default:
		return PollView{}, ErrCapacity
	}
	if err := l.own(ctx); err != nil {
		return PollView{Code: ErrTransportRevoked.Error()}, err
	}
	targets, err := l.pollTargets()
	if err != nil {
		return PollView{}, err
	}
	now, err := l.now()
	if err != nil {
		return PollView{}, err
	}
	found := false
	for _, r := range targets {
		if r.URL == url && r.Until > now {
			found = true
		}
	}
	if !found {
		return PollView{}, ErrConfig
	}
	held, err := l.keysForPoll(ctx)
	if err != nil {
		return PollView{}, err
	}
	return l.pollRelay(ctx, url, held, seconds)
}
func (l *Lane) pollRelay(ctx context.Context, url string, held map[[32]byte]agentpacketseal.PrivateKey, wait int) (PollView, error) {
	total := PollView{}
	timeout := CallTimeout
	if wait > 0 {
		timeout = 40 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := l.config.Relay(url)
	if err != nil {
		return total, ErrUnavailable
	}
	auth, err := l.config.Credentials.Owner(ctx, url)
	if err != nil {
		return total, ErrTransportRevoked
	}
	now, err := l.now()
	if err != nil {
		return total, err
	}
	if checkCredential(auth, l.config.AgentID, url, agenttransport.OperationList, now, l.config.Delegation) != nil || checkCredential(auth, l.config.AgentID, url, agenttransport.OperationFetch, now, l.config.Delegation) != nil {
		return total, ErrRefused
	}
	var entries []agentpacketrelay.V2MailboxEntry
	if wait > 0 {
		entries, err = client.ListWait(ctx, l.config.AgentID, auth.wire, auth.holder, wait)
	} else {
		entries, err = client.List(ctx, l.config.AgentID, auth.wire, auth.holder)
	}
	if err != nil || len(entries) > 256 {
		return total, ErrUnavailable
	}
	total.Listed = 1
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Lane == "contact" && entries[j].Lane != "contact" })
	downloads := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return total, ErrUnavailable
		}
		if entry.EnvelopeID == ([32]byte{}) || entry.RecipientKeyID == ([32]byte{}) || entry.Size < uint32(agentpacketrelay.MinEnvelopeBytes) || entry.Size > agentpacketseal.MaxEnvelopeBytes || entry.ReceivedAtUnix == 0 || entry.ExpiresAtUnix <= entry.ReceivedAtUnix || (entry.Lane != "contact" && entry.Lane != "stranger") {
			return total, ErrUnavailable
		}
		if entry.ExpiresAtUnix <= now {
			continue
		}
		id := hex.EncodeToString(entry.EnvelopeID[:])
		local := url + "\x00" + id
		until := min(entry.ExpiresAtUnix, now+uint64(KeyRetention/time.Second))
		if mem, ok := l.recalled(l.settled, id, now); ok {
			if err := client.Acknowledge(ctx, l.config.AgentID, mem.Secret); err != nil {
				total.Code = ErrUnavailable.Error()
			} else {
				total.Acknowledged++
			}
			continue
		}
		if mem, ok := l.recalled(l.refused, local, now); ok {
			if mem.CanAck {
				if err := client.Acknowledge(ctx, l.config.AgentID, mem.Secret); err != nil {
					total.Code = ErrUnavailable.Error()
				} else {
					total.Acknowledged++
				}
			}
			continue
		}
		key, ok := held[entry.RecipientKeyID]
		if !ok {
			continue
		}
		if downloads >= 16 {
			break
		}
		downloads++
		raw, err := client.Fetch(ctx, l.config.AgentID, entry.EnvelopeID, auth.wire, auth.holder)
		if err != nil {
			total.Code = ErrUnavailable.Error()
			continue
		}
		h, err := agentpacketseal.ParseEnvelope(raw)
		if err != nil || len(raw) != int(entry.Size) || h.RecipientAgentID != l.config.AgentID || h.RecipientKeyID != entry.RecipientKeyID || h.EnvelopeID != entry.EnvelopeID || h.ExpiresAtUnix <= now {
			l.remember(l.refused, local, [32]byte{}, until, now, false)
			total.Refused++
			continue
		}
		opened, err := agentpacketseal.Open(key, raw)
		if err != nil {
			l.remember(l.refused, local, [32]byte{}, until, now, false)
			total.Refused++
			continue
		}
		p, verifyErr := packet(opened.PacketJSON)
		if verifyErr == nil && p.RecipientAgentID != l.config.AgentID {
			verifyErr = ErrRefused
		}
		if verifyErr == nil {
			verifyErr = l.config.VerifyPacket(ctx, p)
		}
		if verifyErr == nil {
			verifyErr = l.config.Store(ctx, opened.PacketJSON)
		}
		if verifyErr != nil && !errors.Is(verifyErr, ErrRefused) {
			total.Code = ErrUnavailable.Error()
			continue
		}
		if verifyErr == nil {
			l.remember(l.settled, id, opened.AckSecret, until, now, true)
			total.Stored++
		} else {
			l.remember(l.refused, local, opened.AckSecret, until, now, true)
			total.Refused++
		}
		if err = client.Acknowledge(ctx, l.config.AgentID, opened.AckSecret); err != nil {
			total.Code = ErrUnavailable.Error()
		} else {
			total.Acknowledged++
		}
	}
	if total.Code != "" {
		return total, ErrUnavailable
	}
	return total, nil
}
