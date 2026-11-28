package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// MaxPeerCards bounds the peers whose chat cards the lane keeps. A full store
// refuses a new peer rather than evict a valid card, so cards learned from
// strangers cannot push out a contact's.
const MaxPeerCards = 1024

const cardsDir = "peer-cards"

// maxCardBytes bounds one stored card packet.
const maxCardBytes = 16 << 10

// LearnCard keeps a peer's chat card for routing: the card a delivery to the
// peer is sealed to, beside the hint that alone supplies the route. It is
// called only for admitted peers (an admitted frame, a contact file the owner
// imported, a roster of a room the owner joined). The card must verify as the
// peer's at the lane's clock; a newer card replaces an older one.
func (b *Builtin) LearnCard(ctx context.Context, peer string, card []byte) error {
	if len(card) == 0 || len(card) > maxCardBytes {
		return agentcarrier.ErrRefused
	}
	packet, err := agentpacket.DecodeJSON(card)
	if err != nil || packet.SenderAgentID != peer || peer == b.config.Lane.AgentID {
		return agentcarrier.ErrRefused
	}
	_, verified, err := b.config.Lane.VerifyCard(ctx, card, b.now())
	if err != nil {
		return err
	}
	b.cardsMu.Lock()
	defer b.cardsMu.Unlock()
	digest, err := agentpacketseal.AgentDigest(peer)
	if err != nil {
		return agentcarrier.ErrRefused
	}
	path := filepath.Join(b.journal.cards, hex.EncodeToString(digest[:])+".json")
	existing, err := readBounded(path, maxCardBytes)
	switch {
	case err == nil:
		if bytes.Equal(existing, card) {
			return nil
		}
		if old, decodeErr := agentpacket.DecodeJSON(existing); decodeErr == nil {
			if previous, parseErr := agentpacketseal.DecodeKeyCard(old.Payload); parseErr == nil &&
				previous.NotBeforeUnix > verified.NotBeforeUnix {
				return nil
			}
		}
	case errors.Is(err, os.ErrNotExist):
		entries, err := os.ReadDir(b.journal.cards)
		if err != nil {
			return err
		}
		if len(entries) >= MaxPeerCards {
			return agentcarrier.ErrCapacity
		}
	default:
		return err
	}
	return writePrivate(path, card)
}

// peerCard returns the peer's kept card, or nil.
func (b *Builtin) peerCard(peer string) []byte {
	digest, err := agentpacketseal.AgentDigest(peer)
	if err != nil {
		return nil
	}
	b.cardsMu.Lock()
	defer b.cardsMu.Unlock()
	card, err := readBounded(filepath.Join(b.journal.cards, hex.EncodeToString(digest[:])+".json"), maxCardBytes)
	if err != nil {
		return nil
	}
	return card
}

// contact is the out-of-band input of a delivery's routing: the peer's kept
// card, never a route. The hint still comes from the resolver's cache or the
// directories.
func (b *Builtin) contact(peer string) agentcarrier.Route {
	return agentcarrier.Route{CardPacket: b.peerCard(peer)}
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || int64(len(raw)) > limit {
		return nil, errors.New("messenger transport record is unreadable")
	}
	return raw, nil
}
