package buyeragent

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// Task delivery timing (MCP_BUYER_ADAPTER_V1 section 7.2; frames 2.3 and
// 11.1; relay section 10).
const (
	// TaskResendInterval is how long one generation of the task stands
	// before the agent signs and seals a fresh one. A fresh generation every
	// 10 minutes also re-deposits the task well within any relay TTL the
	// relay rule (80 % of the smallest TTL, never more often than every 10
	// minutes) would need, so a task needs no separate re-deposit.
	TaskResendInterval = 600 * time.Second
	// MaxPacketLifetime bounds a packet's expiry after signing (frames 2.3).
	MaxPacketLifetime = 86100 * time.Second
	// DepositTimeout bounds one deposit at one relay.
	DepositTimeout = 30 * time.Second
	// maxGenerations bounds the task generations kept per purchase; the
	// oldest is dropped.
	maxGenerations = 4
)

var (
	// ErrTaskDeadlinePassed reports a task whose response deadline has
	// passed: no packet is signed or sent for it (frames 2.3).
	ErrTaskDeadlinePassed = errors.New("the task's response deadline has passed")
	// ErrNoRelayAccepted reports a generation that no relay of the provider
	// card has accepted yet; the next delivery round tries again.
	ErrNoRelayAccepted = errors.New("no relay accepted the task yet")
)

// TaskDelivery is what one delivery round needs about an admitted purchase.
type TaskDelivery struct {
	Record           buyersdk.CallRecord
	Archive          []byte
	ExecutionNonce   string
	ProviderAgentID  string
	ResponseDeadline time.Time
	RetentionSeconds uint64
	// ChainTime is the chain time of the finalized checkpoint the duty
	// round resolved the request at. It is the clock of the deadline check
	// and the packets' signing time; the host clock is never used for them.
	ChainTime time.Time
}

// DeliveryView is the outcome of one delivery round.
type DeliveryView struct {
	// Generation is the number of the current task generation, from 1.
	Generation int `json:"generation"`
	// Sealed reports that this round signed and sealed a new generation.
	Sealed bool `json:"sealed"`
	// Envelopes is the number of envelopes in the generation, one per
	// frame; Delivered counts those at least one relay accepted.
	Envelopes int `json:"envelopes"`
	Delivered int `json:"delivered"`
}

// generationRecord is one task generation: every frame of one task message
// signed into its own packet and sealed to one provider card, journaled
// before the first deposit so a deposit is always retried with the same
// bytes.
type generationRecord struct {
	Schema          string `json:"schema"`
	RequestHash     string `json:"request_hash"`
	Generation      int    `json:"generation"`
	CreatedUnix     int64  `json:"created_unix"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
	ProviderKeyID   string `json:"provider_key_id"`
	ProviderAgentID string `json:"provider_agent_id"`
	// ProviderPublicKey is the provider card's encryption key, kept to
	// re-seal a packet under a fresh envelope ID.
	ProviderPublicKey string             `json:"provider_public_key_base64"`
	Relays            []string           `json:"relays"`
	Envelopes         []envelopeDelivery `json:"envelopes"`
}

// envelopeDelivery is one sealed envelope, the signed packet it carries,
// and where it stands at each relay.
type envelopeDelivery struct {
	EnvelopeBase64 string `json:"envelope_base64"`
	PacketBase64   string `json:"packet_base64"`
	// Relays maps each relay to "accepted", "conflict", "abandoned" or
	// nothing yet.
	Relays map[string]string `json:"relays"`
}

const (
	generationSchema = "tos.service.mcp-buyer.task-generation.v1"
	relayAccepted    = "accepted"
	relayConflict    = "conflict"
	relayAbandoned   = "abandoned"
	// keyRetentionWindow is how long past a card's not_after the card's
	// Agent keeps the private key (relay 6.3): an envelope expiring later
	// could reach a provider that can no longer open it.
	keyRetentionWindow = 86400*time.Second + 300*time.Second
)

func (c *Carrier) outboxDir(requestHash string) string {
	return filepath.Join(c.config.StateDir, "outbox", requestHash)
}

// DeliverTask runs one delivery round for an admitted, pending purchase
// (section 7.2). When no generation exists, or the latest is
// TaskResendInterval old, it builds a fresh one:
//   - the task message with the purchase's call fields and a buyer card
//     covering the purchase's window (3.3);
//   - split into frames, each signed into its own packet expiring at the
//     response deadline (at most MaxPacketLifetime after signing);
//   - each sealed to the provider card the check of 7.1 selects.
//
// The generation is journaled before the first deposit. The round then
// deposits every envelope not yet accepted or abandoned at every relay of
// the card: 200, 201 and 410 accept it, 409 and other refusals abandon that
// relay for that envelope, and anything retryable waits for the next round.
// An envelope no relay accepted and some relay answered 409 to is re-sealed
// at once under a fresh envelope ID, journaled, and deposited again in the
// same round (relay 8.6).
//
// The round's clock is the finalized checkpoint's chain time
// (task.ChainTime), never the host clock: it decides the deadline, the
// resend interval and the packets' signing time.
func (c *Carrier) DeliverTask(ctx context.Context, task TaskDelivery) (DeliveryView, error) {
	record := task.Record
	if err := checkRequestHash(record.RequestHash); err != nil {
		return DeliveryView{}, err
	}
	if task.ChainTime.Unix() <= 0 {
		return DeliveryView{}, errors.New("a delivery round needs the checkpoint's chain time")
	}
	now := task.ChainTime
	if !now.Before(task.ResponseDeadline) {
		return DeliveryView{}, ErrTaskDeadlinePassed
	}
	directory := c.outboxDir(record.RequestHash)
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return DeliveryView{}, err
	}
	if err := checkPrivateDir(directory); err != nil {
		return DeliveryView{}, err
	}
	generations, err := c.generations(record.RequestHash)
	if err != nil {
		return DeliveryView{}, err
	}
	view := DeliveryView{}
	var current generationRecord
	if len(generations) == 0 || !now.Before(time.Unix(generations[len(generations)-1].CreatedUnix, 0).Add(TaskResendInterval)) {
		next := 1
		if len(generations) > 0 {
			next = generations[len(generations)-1].Generation + 1
		}
		current, err = c.sealGeneration(ctx, task, next, now)
		if err != nil {
			return DeliveryView{}, err
		}
		if err := writeJSON(c.generationPath(record.RequestHash, next), current, true); err != nil {
			return DeliveryView{}, err
		}
		view.Sealed = true
		if err := c.pruneGenerations(record.RequestHash, append(generations, current)); err != nil {
			return DeliveryView{}, err
		}
	} else {
		current = generations[len(generations)-1]
	}
	view.Generation, view.Envelopes = current.Generation, len(current.Envelopes)
	if uint64(now.Unix()) < current.ExpiresAtUnix {
		c.depositGeneration(ctx, &current)
		if err := writeJSON(c.generationPath(record.RequestHash, current.Generation), current, false); err != nil {
			return view, err
		}
		resealed, err := c.resealConflicts(&current)
		if err != nil {
			return view, err
		}
		if resealed {
			// The fresh envelopes are journaled before their first deposit.
			if err := writeJSON(c.generationPath(record.RequestHash, current.Generation), current, false); err != nil {
				return view, err
			}
			c.depositGeneration(ctx, &current)
			if err := writeJSON(c.generationPath(record.RequestHash, current.Generation), current, false); err != nil {
				return view, err
			}
		}
	}
	for _, envelope := range current.Envelopes {
		for _, state := range envelope.Relays {
			if state == relayAccepted {
				view.Delivered++
				break
			}
		}
	}
	if view.Delivered < view.Envelopes {
		return view, ErrNoRelayAccepted
	}
	return view, nil
}

func (c *Carrier) generationPath(requestHash string, generation int) string {
	return filepath.Join(c.outboxDir(requestHash), fmt.Sprintf("%08d.json", generation))
}

// generations lists a purchase's journaled generations, oldest first.
func (c *Carrier) generations(requestHash string) ([]generationRecord, error) {
	entries, err := os.ReadDir(c.outboxDir(requestHash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []generationRecord
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		var record generationRecord
		if err := readJSON(filepath.Join(c.outboxDir(requestHash), entry.Name()), &record); err != nil {
			return nil, err
		}
		if record.Schema != generationSchema || record.RequestHash != requestHash ||
			fmt.Sprintf("%08d.json", record.Generation) != entry.Name() {
			return nil, errors.New("a journaled task generation is not this purchase's")
		}
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Generation < out[j].Generation })
	return out, nil
}

// pruneGenerations keeps the newest maxGenerations generations.
func (c *Carrier) pruneGenerations(requestHash string, generations []generationRecord) error {
	for len(generations) > maxGenerations {
		if err := os.Remove(c.generationPath(requestHash, generations[0].Generation)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		generations = generations[1:]
	}
	return nil
}

// sealGeneration builds, signs and seals one generation of the task.
func (c *Carrier) sealGeneration(ctx context.Context, task TaskDelivery, number int, now time.Time) (generationRecord, error) {
	record := task.Record
	if record.RequestID == nil || record.CallTransactionLT == 0 || len(record.CallTransactionHex) != 64 {
		return generationRecord{}, errors.New("the purchase's call is not admitted with its transaction")
	}
	packageBytes, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil {
		return generationRecord{}, errors.New("the journaled Quote package is not Base64")
	}
	binding, err := taskBinding(record)
	if err != nil {
		return generationRecord{}, err
	}
	// A card covering the response deadline is preferred; only when none
	// does is the best card valid now used, with the envelope expiry capped
	// by its key retention.
	providerCard, err := c.ProviderCard(ctx, record.CapabilityID, task.ProviderAgentID, task.ResponseDeadline)
	if errors.Is(err, ErrNoProviderCard) {
		providerCard, err = c.ProviderCard(ctx, record.CapabilityID, task.ProviderAgentID, now)
	}
	if err != nil {
		return generationRecord{}, err
	}
	cover, err := buyerCardWindow(record, task.RetentionSeconds)
	if err != nil {
		return generationRecord{}, err
	}
	buyerCard, err := c.BuyerCard(ctx, cover)
	if err != nil {
		return generationRecord{}, err
	}
	message, err := railwork.EncodeTask(railwork.Task{Header: railwork.TaskHeader{BuyerAgentID: c.config.BuyerAgentID,
		BuyerWallet: record.BuyerWallet, CapabilityID: record.CapabilityID, CapabilityVersion: record.CapabilityVersion,
		ExecutionID: record.ExecutionID, ExecutionNonce: task.ExecutionNonce, RequestID: *record.RequestID,
		CallLT: record.CallTransactionLT, CallHash: record.CallTransactionHex}, Package: packageBytes,
		Archive: task.Archive, BuyerKeyCard: buyerCard})
	if err != nil {
		return generationRecord{}, fmt.Errorf("the task does not encode: %w", err)
	}
	frames, err := railwork.EncodeMessageFrames(railwork.KindTask, binding, message)
	if err != nil {
		return generationRecord{}, err
	}
	expires := envelopeExpiry(task.ResponseDeadline, now, providerCard.Card.NotAfterUnix)
	generation, err := c.sealFrames(ctx, record, providerCard, frames, now, expires)
	if err != nil {
		return generationRecord{}, err
	}
	generation.Generation = number
	return generation, nil
}

// sealFrames signs each frame of one message into its own packet from the
// buyer to the card's Agent and seals it to the card, every envelope
// expiring at expires.
func (c *Carrier) sealFrames(ctx context.Context, record buyersdk.CallRecord, providerCard buyersdk.VerifiedProviderCard,
	frames [][]byte, now time.Time, expires uint64) (generationRecord, error) {
	generation := generationRecord{Schema: generationSchema, RequestHash: record.RequestHash,
		CreatedUnix: now.Unix(), ExpiresAtUnix: expires, ProviderKeyID: hex.EncodeToString(providerCard.Key.KeyID[:]),
		ProviderAgentID:   providerCard.Key.AgentID,
		ProviderPublicKey: base64.StdEncoding.EncodeToString(providerCard.Key.PublicKey),
		Relays:            append([]string(nil), providerCard.Card.Relays...)}
	for index, frame := range frames {
		var nonce [32]byte
		if err := c.config.Random(nonce[:]); err != nil {
			return generationRecord{}, err
		}
		packet, err := agentpacket.Sign(ctx, c.config.Signer, c.config.Controller, agentpacket.Packet{
			SenderAgentID: c.config.BuyerAgentID, RecipientAgentID: providerCard.Key.AgentID, CapabilityID: record.CapabilityID,
			QuoteCommitment: record.QuoteCommitment, Sequence: uint64(now.UnixNano()) + uint64(index), Nonce: nonce,
			Payload: frame, CreatedAtUnix: uint64(now.Unix()), SenderKeyID: c.config.ControllerKeyID})
		if err != nil {
			return generationRecord{}, fmt.Errorf("the packet controller cannot sign a packet: %w", err)
		}
		raw, err := agentpacket.EncodeJSON(packet)
		if err != nil {
			return generationRecord{}, err
		}
		var secret [agentpacketseal.AckSecretSize]byte
		if err := c.config.Random(secret[:]); err != nil {
			return generationRecord{}, err
		}
		envelope, err := agentpacketseal.Seal(providerCard.Key, secret, raw, expires)
		if err != nil {
			return generationRecord{}, err
		}
		generation.Envelopes = append(generation.Envelopes, envelopeDelivery{
			EnvelopeBase64: base64.StdEncoding.EncodeToString(envelope),
			PacketBase64:   base64.StdEncoding.EncodeToString(raw), Relays: map[string]string{}})
	}
	return generation, nil
}

// envelopeExpiry is a task envelope's expiry: the response deadline, at
// most MaxPacketLifetime after signing, and never past the provider card's
// not_after plus the key-retention window, so no relay holds an envelope
// the provider can no longer open.
func envelopeExpiry(deadline, now time.Time, cardNotAfterUnix uint64) uint64 {
	expires := uint64(deadline.Unix())
	if limit := uint64(now.Add(MaxPacketLifetime).Unix()); expires > limit {
		expires = limit
	}
	// An overflowing sum is a bound past every representable expiry.
	if limit, ok := checkedAddUnix(cardNotAfterUnix, keyRetentionWindow); ok && expires > limit {
		expires = limit
	}
	return expires
}

// checkedAddUnix adds a duration to a Unix time, reporting overflow.
func checkedAddUnix(unix uint64, add time.Duration) (uint64, bool) {
	seconds := uint64(add / time.Second)
	if unix > math.MaxUint64-seconds {
		return 0, false
	}
	return unix + seconds, true
}

// resealConflicts re-seals, under a fresh acknowledgement secret and so a
// fresh envelope ID, every envelope that no relay accepted and at least one
// relay answered 409 to (relay 8.6). The packet JSON is unchanged; the
// recipient's inbox deduplicates the packet whichever envelope delivers it.
// It reports whether any envelope was replaced.
func (c *Carrier) resealConflicts(generation *generationRecord) (bool, error) {
	var key agentpacketseal.RecipientKey
	resealed := false
	for index := range generation.Envelopes {
		envelope := &generation.Envelopes[index]
		accepted, conflict := false, false
		for _, state := range envelope.Relays {
			accepted = accepted || state == relayAccepted
			conflict = conflict || state == relayConflict
		}
		if accepted || !conflict {
			continue
		}
		if key.PublicKey == nil {
			var err error
			if key, err = generation.recipientKey(); err != nil {
				return resealed, err
			}
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(envelope.PacketBase64)
		if err != nil {
			return resealed, errors.New("a journaled task envelope has no packet to re-seal")
		}
		var secret [agentpacketseal.AckSecretSize]byte
		if err := c.config.Random(secret[:]); err != nil {
			return resealed, err
		}
		sealed, err := agentpacketseal.Seal(key, secret, raw, generation.ExpiresAtUnix)
		if err != nil {
			return resealed, err
		}
		envelope.EnvelopeBase64 = base64.StdEncoding.EncodeToString(sealed)
		envelope.Relays = map[string]string{}
		resealed = true
	}
	return resealed, nil
}

// recipientKey is the journaled provider key of a generation, checked
// against its key ID.
func (g generationRecord) recipientKey() (agentpacketseal.RecipientKey, error) {
	public, err := base64.StdEncoding.Strict().DecodeString(g.ProviderPublicKey)
	if err != nil {
		return agentpacketseal.RecipientKey{}, errors.New("a journaled task generation's provider key is not Base64")
	}
	derived, err := agentpacketseal.KeyID(public)
	if err != nil || hex.EncodeToString(derived[:]) != g.ProviderKeyID {
		return agentpacketseal.RecipientKey{}, errors.New("a journaled task generation's provider key does not match its key ID")
	}
	return agentpacketseal.RecipientKey{AgentID: g.ProviderAgentID, KeyID: derived, PublicKey: public}, nil
}

// taskBinding is the frame binding of the purchase's request.
func taskBinding(record buyersdk.CallRecord) (railwork.Binding, error) {
	var binding railwork.Binding
	account, found := strings.CutPrefix(record.Actor, "0:")
	actor, err := hex.DecodeString(account)
	if !found || err != nil || len(actor) != 32 {
		return binding, errors.New("the purchase's actor is not a workchain-0 raw address")
	}
	request, err := hex.DecodeString(record.RequestHash)
	if err != nil || len(request) != 32 {
		return binding, errors.New("the purchase's request hash is not 64 hex")
	}
	copy(binding.ActorAccount[:], actor)
	copy(binding.RequestHash[:], request)
	binding.RequestID = *record.RequestID
	return binding, nil
}

// depositGeneration deposits every envelope not yet accepted or abandoned
// at every relay of the generation's card, in card order.
func (c *Carrier) depositGeneration(ctx context.Context, generation *generationRecord) {
	for index := range generation.Envelopes {
		envelope := &generation.Envelopes[index]
		raw, err := base64.StdEncoding.Strict().DecodeString(envelope.EnvelopeBase64)
		if err != nil {
			continue
		}
		for _, relay := range generation.Relays {
			if envelope.Relays[relay] != "" {
				continue
			}
			client, err := c.config.RelayClient(relay)
			if err != nil {
				continue
			}
			call, cancel := context.WithTimeout(ctx, DepositTimeout)
			outcome, err := client.Deposit(call, raw)
			cancel()
			switch {
			case err != nil:
				// The envelope itself was refused before sending; no relay
				// will take it.
				envelope.Relays[relay] = relayAbandoned
			case outcome.Accepted():
				envelope.Relays[relay] = relayAccepted
			case outcome.Result == agentpacketrelay.DepositConflict:
				envelope.Relays[relay] = relayConflict
			case outcome.Result == agentpacketrelay.DepositRejected:
				envelope.Relays[relay] = relayAbandoned
			}
		}
	}
}
