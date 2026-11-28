package agentcarrier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

type keyRecord struct {
	Identity identity `json:"identity"`
	Seed     []byte   `json:"seed"`
	Packet   []byte   `json:"packet"`
}

func keyName(id [32]byte) string { return "key-" + hex.EncodeToString(id[:]) }
func (l *Lane) readKey(name string) (keyRecord, error) {
	var r keyRecord
	if l.disk.read(name, &r) != nil || r.Identity != l.identity() {
		return r, ErrStorage
	}
	private, err := agentpacketseal.NewPrivateKey(l.config.AgentID, r.Seed)
	if err != nil {
		return r, ErrStorage
	}
	p, err := agentpacket.DecodeJSON(r.Packet)
	if err != nil || p.SenderAgentID != l.config.AgentID || p.RecipientAgentID != agentpacketseal.KeyCardAudience || p.CapabilityID != agentpacketseal.KeyCardCapability || p.QuoteCommitment != "" {
		return r, ErrStorage
	}
	card, err := agentpacketseal.DecodeKeyCard(p.Payload)
	public, pubErr := private.PublicKey()
	if err != nil || pubErr != nil || name != keyName(private.KeyID) || private.KeyID != card.KeyID || !bytes.Equal(public, card.PublicKey) || card.NotAfterUnix > math.MaxInt64-uint64(KeyRetention/time.Second) {
		return r, ErrStorage
	}
	return r, nil
}
func (l *Lane) heldKeys() (map[[32]byte]agentpacketseal.PrivateKey, []keyRecord, error) {
	inventory, err := l.inventory()
	names := inventory.Keys
	if err != nil {
		return nil, nil, err
	}
	now, err := l.now()
	if err != nil {
		return nil, nil, err
	}
	held := map[[32]byte]agentpacketseal.PrivateKey{}
	records := []keyRecord{}
	for _, name := range names {
		r, err := l.readKey(name)
		if err != nil {
			return nil, nil, err
		}
		packet, err := agentpacket.DecodeJSON(r.Packet)
		if err != nil {
			clear(r.Seed)
			return nil, nil, ErrStorage
		}
		card, err := agentpacketseal.DecodeKeyCard(packet.Payload)
		if err != nil {
			clear(r.Seed)
			return nil, nil, ErrStorage
		}
		if now >= card.NotAfterUnix+uint64(KeyRetention/time.Second) {
			clear(r.Seed)
			if err = l.index(context.Background(), name, false); err != nil {
				return nil, nil, err
			}
			if err = l.disk.remove(name); err != nil {
				return nil, nil, err
			}
			continue
		}
		key, err := agentpacketseal.NewPrivateKey(l.config.AgentID, r.Seed)
		clear(r.Seed)
		r.Seed = nil
		if err != nil {
			return nil, nil, ErrStorage
		}
		held[key.KeyID] = key
		records = append(records, r)
	}
	if len(records) > MaxKeys {
		return nil, nil, ErrCapacity
	}
	return held, records, nil
}

// CurrentCard issues a successor 48 hours before expiry. Private keys are not
// returned; they remain in this lane's private, single-writer state directory.
func (l *Lane) CurrentCard(ctx context.Context) (OwnCard, error) {
	return l.CurrentCardThrough(ctx, 0)
}

// CurrentCardThrough returns an own card covering the given Unix time.
// A zero deadline uses the ordinary rotation window.
func (l *Lane) CurrentCardThrough(ctx context.Context, through uint64) (OwnCard, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	if err := l.own(ctx); err != nil {
		return OwnCard{}, err
	}
	if err := l.issue.lock(ctx); err != nil {
		return OwnCard{}, err
	}
	defer l.issue.unlock()
	if err := l.keys.lock(ctx); err != nil {
		return OwnCard{}, err
	}
	_, records, err := l.heldKeys()
	l.keys.unlock()
	if err != nil {
		return OwnCard{}, err
	}
	now, err := l.now()
	if err != nil {
		return OwnCard{}, err
	}
	if through > now && through-now > uint64(agentpacketseal.MaxKeyCardLifetime/time.Second) {
		return OwnCard{}, ErrRefused
	}
	type candidate struct {
		packet []byte
		card   agentpacketseal.KeyCard
	}
	candidates := make([]candidate, 0, len(records))
	for _, r := range records {
		p, err := agentpacket.DecodeJSON(r.Packet)
		if err != nil {
			return OwnCard{}, ErrStorage
		}
		card, err := agentpacketseal.DecodeKeyCard(p.Payload)
		if err != nil {
			return OwnCard{}, ErrStorage
		}
		candidates = append(candidates, candidate{r.Packet, card})
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i].card, candidates[j].card
		if a.NotBeforeUnix != b.NotBeforeUnix {
			return a.NotBeforeUnix > b.NotBeforeUnix
		}
		return bytes.Compare(a.KeyID[:], b.KeyID[:]) > 0
	})
	relays := append([]string(nil), l.config.Relays...)
	sort.Strings(relays)
	for _, r := range candidates {
		if !slices.Equal(r.card.Relays, relays) || r.card.NotAfterUnix <= now+uint64(SuccessorLead/time.Second) {
			continue
		}
		if r.card.NotAfterUnix < through {
			continue
		}
		_, card, err := l.verifyCard(ctx, r.packet)
		if err != nil {
			if !errors.Is(err, ErrRefused) {
				return OwnCard{}, ErrUnavailable
			}
			continue
		}
		if err = l.keys.lock(ctx); err != nil {
			return OwnCard{}, err
		}
		indexed, indexErr := l.indexed(keyName(card.KeyID))
		if indexErr == nil && indexed && agentpacketseal.CheckKeyCardTime(card, l.config.Now()) == nil {
			indexErr = l.trackRelaysLocked(l.config.Relays, card.NotAfterUnix+uint64(KeyRetention/time.Second))
		} else {
			indexErr = ErrStorage
		}
		l.keys.unlock()
		if indexErr != nil {
			return OwnCard{}, indexErr
		}
		return OwnCard{bytes.Clone(r.packet), card}, nil
	}
	if len(records) >= MaxKeys {
		return OwnCard{}, ErrCapacity
	}
	seed, err := agentpacketseal.GenerateSeed()
	if err != nil {
		return OwnCard{}, ErrUnavailable
	}
	defer clear(seed)
	key, err := agentpacketseal.NewPrivateKey(l.config.AgentID, seed)
	if err != nil {
		return OwnCard{}, ErrUnavailable
	}
	public, err := key.PublicKey()
	if err != nil {
		return OwnCard{}, ErrUnavailable
	}
	card := agentpacketseal.KeyCard{PublicKey: public, KeyID: key.KeyID, NotBeforeUnix: now, NotAfterUnix: now + uint64(KeyLifetime/time.Second), Relays: relays}
	card.NotAfterUnix = max(card.NotAfterUnix, through)
	packet, err := l.config.SignCard(ctx, card)
	if err != nil {
		return OwnCard{}, ErrUnavailable
	}
	recipient, verified, err := l.verifyCard(ctx, packet)
	if err != nil || recipient.AgentID != l.config.AgentID || recipient.KeyID != card.KeyID || !bytes.Equal(recipient.PublicKey, card.PublicKey) || !slices.Equal(verified.Relays, card.Relays) || verified.NotBeforeUnix != card.NotBeforeUnix || verified.NotAfterUnix != card.NotAfterUnix {
		return OwnCard{}, ErrRefused
	}
	if err = l.own(ctx); err != nil {
		return OwnCard{}, err
	}
	if err = l.keys.lock(ctx); err != nil {
		return OwnCard{}, err
	}
	defer l.keys.unlock()
	inventory, indexErr := l.inventory()
	if indexErr != nil {
		return OwnCard{}, indexErr
	}
	if len(inventory.Keys) >= MaxKeys {
		return OwnCard{}, ErrCapacity
	}
	if exists, err := l.indexed(keyName(key.KeyID)); err != nil || exists {
		return OwnCard{}, ErrStorage
	}
	if err = l.disk.write(keyName(key.KeyID), keyRecord{l.identity(), seed, packet}); err != nil {
		return OwnCard{}, err
	}
	if err = l.index(ctx, keyName(key.KeyID), true); err != nil {
		return OwnCard{}, err
	}
	if err = l.trackRelaysLocked(l.config.Relays, card.NotAfterUnix+uint64(KeyRetention/time.Second)); err != nil {
		return OwnCard{}, err
	}
	return OwnCard{bytes.Clone(packet), card}, nil
}
