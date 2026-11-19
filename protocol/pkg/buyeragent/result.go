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

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

// Result acceptance (MCP_BUYER_ADAPTER_V1 section 7.3; frames 5.3, 5.4,
// 7.2 and 11.1).
const (
	// ResultRequestInterval is how often a result-request is sent again
	// while the respond is finalized and no result is accepted.
	ResultRequestInterval = 21600 * time.Second
	// AckLifetime is an ack packet's lifetime (frames 2.3).
	AckLifetime = 3600 * time.Second
	// MaxFailedDeliveries bounds the failing result deliveries examined per
	// purchase; later ones are discarded unexamined.
	MaxFailedDeliveries = 16
)

// ResultRound is what one result round needs about a responded purchase.
type ResultRound struct {
	Record           buyersdk.CallRecord
	ProviderAgentID  string
	Receipt          railwork.ReceiptBinding
	ResponseHash     [32]byte
	ResponseDeadline time.Time
	RetentionSeconds uint64
	// ChainTime is the finalized checkpoint's chain time, the round's
	// clock.
	ChainTime time.Time
}

// ResultView is the outcome of one result round.
type ResultView struct {
	// Accepted reports a stored, accepted result; ResponseHash is its hash.
	Accepted     bool   `json:"accepted"`
	ResponseHash string `json:"response_hash,omitempty"`
	// Examined counts the complete deliveries this round examined.
	Examined int `json:"examined"`
	// FailedDeliveries counts the deliveries that failed acceptance;
	// Exhausted reports that MaxFailedDeliveries is reached.
	FailedDeliveries int  `json:"failed_deliveries"`
	Exhausted        bool `json:"exhausted,omitempty"`
	// AckSent and ResultRequested report the messages a relay accepted
	// this round.
	AckSent         bool `json:"ack_sent,omitempty"`
	ResultRequested bool `json:"result_requested,omitempty"`
	// RetentionEnded reports that the result's retention has ended.
	RetentionEnded bool `json:"retention_ended,omitempty"`
}

// receivedRecord is a purchase's receiving state.
type receivedRecord struct {
	Schema      string `json:"schema"`
	RequestHash string `json:"request_hash"`
	// AcceptedResponseHash is set once a result is accepted; its Receipt
	// is kept here and its artifact next to this record.
	AcceptedResponseHash string `json:"accepted_response_hash,omitempty"`
	ReceiptBase64        string `json:"receipt_boc_base64,omitempty"`
	AcceptedUnix         int64  `json:"accepted_unix,omitempty"`
	// AckDue reports an ack to send: after acceptance and after every
	// redelivery.
	AckDue                bool  `json:"ack_due,omitempty"`
	LastAckUnix           int64 `json:"last_ack_unix,omitempty"`
	LastResultRequestUnix int64 `json:"last_result_request_unix,omitempty"`
	FailedDeliveries      int   `json:"failed_deliveries,omitempty"`
}

const receivedSchema = "tos.service.mcp-buyer.received.v1"

func (c *Carrier) receivedPath(requestHash string) string {
	return receivedPathAt(c.config.StateDir, requestHash)
}

func receivedPathAt(stateDir, requestHash string) string {
	return filepath.Join(stateDir, "received", requestHash+".json")
}

// ArtifactPath is where an accepted result's artifact is kept.
func (c *Carrier) ArtifactPath(requestHash string) string {
	return artifactPathAt(c.config.StateDir, requestHash)
}

func artifactPathAt(stateDir, requestHash string) string {
	return filepath.Join(stateDir, "received", requestHash+".artifact")
}

func (c *Carrier) readReceived(requestHash string) (receivedRecord, error) {
	return readReceivedAt(c.config.StateDir, requestHash)
}

func readReceivedAt(stateDir, requestHash string) (receivedRecord, error) {
	record := receivedRecord{Schema: receivedSchema, RequestHash: requestHash}
	err := readJSON(receivedPathAt(stateDir, requestHash), &record)
	if errors.Is(err, os.ErrNotExist) {
		return receivedRecord{Schema: receivedSchema, RequestHash: requestHash}, nil
	}
	if err != nil {
		return record, err
	}
	if record.Schema != receivedSchema || record.RequestHash != requestHash {
		return record, errors.New("a receiving record names another purchase")
	}
	return record, nil
}

// ReceiveResult runs one result round for a purchase whose respond is
// finalized (section 7.3). Until the result's retention ends:
//   - every complete delivery in the purchase's inbox is examined:
//     railwork.CheckResultFrom (the purchase's provider and binding), then
//     railwork.ValidateResult against the finalized response hash. A
//     provider card the result carries is learned under relay 6.4 whether
//     or not the result passes.
//   - a failing delivery is discarded and counted, never ending the
//     purchase; after MaxFailedDeliveries the rest are discarded
//     unexamined.
//   - the first passing delivery is stored durably and accepted; an ack
//     (frames 5.3) is then sent, and sent again for every later delivery.
//   - with no accepted result a result-request (frames 5.4) is sent at
//     once, then at most every ResultRequestInterval.
//
// The round's clock is round.ChainTime. Ack and result-request carry the
// buyer card and are sealed to a provider card valid now; one no relay
// accepted is sent again in the next round.
func (c *Carrier) ReceiveResult(ctx context.Context, round ResultRound) (view ResultView, err error) {
	record := round.Record
	if err := checkRequestHash(record.RequestHash); err != nil {
		return view, err
	}
	if round.ChainTime.Unix() <= 0 || round.ResponseHash == ([32]byte{}) || round.ProviderAgentID == "" {
		return view, errors.New("a result round needs the chain time, the finalized response hash and the provider")
	}
	binding, err := taskBinding(record)
	if err != nil {
		return view, err
	}
	now := round.ChainTime
	// Retention end is response_deadline + retention_seconds (frames 11.3).
	deadline := round.ResponseDeadline.Unix()
	if deadline <= 0 || round.RetentionSeconds > math.MaxInt64/2 || uint64(deadline) > math.MaxInt64/2 {
		return view, errors.New("the result retention is out of range")
	}
	retentionEnd := uint64(deadline) + round.RetentionSeconds
	state, err := c.readReceived(record.RequestHash)
	if err != nil {
		return view, err
	}
	defer func() {
		view.Accepted = state.AcceptedResponseHash != ""
		view.ResponseHash = state.AcceptedResponseHash
		view.FailedDeliveries = state.FailedDeliveries
		view.Exhausted = view.Exhausted || state.FailedDeliveries >= MaxFailedDeliveries
	}()
	if uint64(now.Unix()) >= retentionEnd {
		view.RetentionEnded = true
		return view, c.clearInbox(record.RequestHash)
	}
	messages, err := c.inboxMessages(record.RequestHash)
	if err != nil {
		return view, err
	}
	sort.Strings(messages)
	for _, digest := range messages {
		if err := c.examine(ctx, round, binding, digest, now, &state, &view); err != nil {
			return view, err
		}
	}
	if state.AcceptedResponseHash != "" {
		if state.AckDue {
			sent, err := c.sendAck(ctx, round, binding, now)
			if err != nil {
				return view, err
			}
			if sent {
				state.AckDue, state.LastAckUnix, view.AckSent = false, now.Unix(), true
				if err := writeJSON(c.receivedPath(record.RequestHash), state, false); err != nil {
					return view, err
				}
			}
		}
		return view, nil
	}
	// With none sent yet the last request is the Unix epoch, long past.
	if !now.Before(time.Unix(state.LastResultRequestUnix, 0).Add(ResultRequestInterval)) {
		sent, err := c.sendResultRequest(ctx, round, binding, now, retentionEnd)
		if err != nil {
			return view, err
		}
		if sent {
			state.LastResultRequestUnix, view.ResultRequested = now.Unix(), true
			if err := writeJSON(c.receivedPath(record.RequestHash), state, false); err != nil {
				return view, err
			}
		}
	}
	return view, nil
}

// examine handles one inbox message: an incomplete one waits; a complete
// one is accepted, counted as failing, or answered with the ack again.
func (c *Carrier) examine(ctx context.Context, round ResultRound, binding railwork.Binding, digest string, now time.Time,
	state *receivedRecord, view *ResultView) error {
	requestHash := round.Record.RequestHash
	if state.AcceptedResponseHash != "" {
		// A redelivery after acceptance is answered with the ack again.
		state.AckDue = true
		if err := writeJSON(c.receivedPath(requestHash), *state, false); err != nil {
			return err
		}
		return c.discardMessage(requestHash, digest)
	}
	if state.FailedDeliveries >= MaxFailedDeliveries {
		view.Exhausted = true
		return c.discardMessage(requestHash, digest)
	}
	message, complete, err := c.assemble(round, digest)
	if err != nil {
		return err
	}
	if !complete {
		return nil
	}
	view.Examined++
	result, err := message.check(round, binding)
	if result != nil && len(result.ProviderKeyCard) != 0 {
		// A card from the purchase's own provider is taken under relay 6.4;
		// one that fails verification is not used and does not decide the
		// result.
		_, _ = c.LearnProviderCard(ctx, buyersdk.ProviderCardFromResult, round.Record.CapabilityID, result.ProviderKeyCard)
	}
	if err == nil {
		err = railwork.ValidateResult(*result, round.Receipt, round.ResponseHash)
	}
	if err != nil {
		state.FailedDeliveries++
		if err := writeJSON(c.receivedPath(requestHash), *state, false); err != nil {
			return err
		}
		return c.discardMessage(requestHash, digest)
	}
	// The artifact is durable before the record names it accepted.
	if err := writePrivate(c.ArtifactPath(requestHash), result.Artifact, false); err != nil {
		return err
	}
	state.AcceptedResponseHash = hex.EncodeToString(round.ResponseHash[:])
	state.ReceiptBase64 = base64.StdEncoding.EncodeToString(result.Receipt)
	state.AcceptedUnix, state.AckDue = now.Unix(), true
	if err := writeJSON(c.receivedPath(requestHash), *state, false); err != nil {
		return err
	}
	return c.discardMessage(requestHash, digest)
}

// assembledMessage is a joined inbox message, or the reason it does not
// join.
type assembledMessage struct {
	message railwork.Message
	joinErr error
}

// check runs CheckResultFrom on a joined message; a message that did not
// join fails like a result that does not pass.
func (m assembledMessage) check(round ResultRound, binding railwork.Binding) (*railwork.Result, error) {
	if m.joinErr != nil {
		return nil, m.joinErr
	}
	result, err := railwork.CheckResultFrom(m.message, round.ProviderAgentID, binding)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// assemble reads an inbox message's frames. It reports whether the frame
// set is complete; a complete set that does not join carries its join
// error.
func (c *Carrier) assemble(round ResultRound, digest string) (assembledMessage, bool, error) {
	directory := filepath.Join(c.inboxDir(round.Record.RequestHash), digest)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return assembledMessage{}, false, err
	}
	packet := railwork.PacketFields{CapabilityID: round.Record.CapabilityID, QuoteCommitment: round.Record.QuoteCommitment}
	var assembly *railwork.Assembly
	complete := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".frame") || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		raw, err := readPrivate(filepath.Join(directory, entry.Name()))
		if err != nil {
			return assembledMessage{}, false, err
		}
		frame, err := railwork.DecodeFrame(raw)
		if err == nil && fmt.Sprintf("%02d.frame", frame.Index) != entry.Name() {
			err = errors.New("a stored frame is not at its index")
		}
		if err == nil && assembly == nil {
			assembly, err = railwork.NewAssembly(round.ProviderAgentID, packet, frame)
			complete = err == nil && frame.Count == 1
		} else if err == nil {
			complete, err = assembly.Add(packet, frame)
		}
		if err != nil {
			// Stored frames that do not belong together never join.
			return assembledMessage{joinErr: err}, true, nil
		}
	}
	if assembly == nil || !complete {
		return assembledMessage{}, false, nil
	}
	message, err := assembly.Message()
	return assembledMessage{message: message, joinErr: err}, true, nil
}

func (c *Carrier) discardMessage(requestHash, digest string) error {
	if !messageDirPattern.MatchString(digest) {
		return errors.New("invalid inbox message name")
	}
	return os.RemoveAll(filepath.Join(c.inboxDir(requestHash), digest))
}

// clearInbox drops a purchase's inbox once its retention has ended.
func (c *Carrier) clearInbox(requestHash string) error {
	messages, err := c.inboxMessages(requestHash)
	if err != nil {
		return err
	}
	for _, digest := range messages {
		if err := c.discardMessage(requestHash, digest); err != nil {
			return err
		}
	}
	return nil
}

// sendAck sends the ack of the accepted result, carrying the buyer card.
func (c *Carrier) sendAck(ctx context.Context, round ResultRound, binding railwork.Binding, now time.Time) (bool, error) {
	buyerCard, err := c.roundBuyerCard(ctx, round)
	if err != nil {
		return false, err
	}
	message, err := railwork.EncodeAck(round.ResponseHash, buyerCard)
	if err != nil {
		return false, err
	}
	return c.sendMessage(ctx, round, railwork.KindResultAck, binding, message, now, now.Add(AckLifetime))
}

// sendResultRequest asks the provider for the result again, carrying the
// buyer card (relay 6.4, "Buyer, after the respond").
func (c *Carrier) sendResultRequest(ctx context.Context, round ResultRound, binding railwork.Binding, now time.Time,
	retentionEnd uint64) (bool, error) {
	buyerCard, err := c.roundBuyerCard(ctx, round)
	if err != nil {
		return false, err
	}
	message, err := railwork.EncodeResultRequest(buyerCard)
	if err != nil {
		return false, err
	}
	return c.sendMessage(ctx, round, railwork.KindResultRequest, binding, message, now, time.Unix(int64(retentionEnd), 0))
}

func (c *Carrier) roundBuyerCard(ctx context.Context, round ResultRound) ([]byte, error) {
	cover, err := buyerCardWindow(round.Record, round.RetentionSeconds)
	if err != nil {
		return nil, err
	}
	return c.BuyerCard(ctx, cover)
}

// sendMessage seals one message to a provider card valid now and deposits
// it at every relay of the card, re-sealing an envelope a 409 refused once
// (relay 8.6). It reports whether every envelope is held by a relay. The
// envelopes are not journaled: a message no relay took is built afresh in
// the next round.
func (c *Carrier) sendMessage(ctx context.Context, round ResultRound, kind railwork.Kind, binding railwork.Binding,
	message []byte, now, deadline time.Time) (bool, error) {
	record := round.Record
	providerCard, err := c.ProviderCard(ctx, record.CapabilityID, round.ProviderAgentID, now)
	if errors.Is(err, ErrNoProviderCard) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	frames, err := railwork.EncodeMessageFrames(kind, binding, message)
	if err != nil {
		return false, err
	}
	expires := envelopeExpiry(deadline, now, providerCard.Card.NotAfterUnix)
	generation, err := c.sealFrames(ctx, record, providerCard, frames, now, expires)
	if err != nil {
		return false, err
	}
	c.depositGeneration(ctx, &generation)
	resealed, err := c.resealConflicts(&generation)
	if err != nil {
		return false, err
	}
	if resealed {
		c.depositGeneration(ctx, &generation)
	}
	for _, envelope := range generation.Envelopes {
		accepted := false
		for _, state := range envelope.Relays {
			accepted = accepted || state == relayAccepted
		}
		if !accepted {
			return false, nil
		}
	}
	return true, nil
}
