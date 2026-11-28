package buyeragent

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

const (
	PollInterval     = agentcarrier.PollInterval
	RelayCallTimeout = 30 * time.Second
	MaxOpenMessages  = 8
)

// InboundPurchase is what admits a frame to a purchase's inbox: the
// purchase's provider, Capability, Accepted Quote and frame binding.
type InboundPurchase struct {
	ProviderAgentID string
	CapabilityID    string
	QuoteCommitment string
	Binding         railwork.Binding
}

// PurchaseLookup finds the purchase of a request hash. Not found is a
// permanent refusal of the frame; an error is transient.
type PurchaseLookup func(requestHash string) (InboundPurchase, bool, error)

// PollView is the outcome of one polling pass.
type PollView struct {
	// Relays counts the relays listed in this pass.
	Relays int `json:"relays"`
	// Stored counts frames durably stored (a duplicate included), Refused
	// envelopes refused for good, Acknowledged acknowledgements the relays
	// accepted.
	Stored       int `json:"stored"`
	Refused      int `json:"refused"`
	Acknowledged int `json:"acknowledged"`
	// Next is when the next relay is due.
	Next time.Time `json:"next"`
}

var errInboxFull = errors.New("the purchase's inbox holds the most messages it may")

// Poll lets the rail lane verify and open envelopes. Its Store callback
// admits the signed result to the purchase before the lane acknowledges it.
func (c *Carrier) Poll(ctx context.Context, lookup PurchaseLookup) (PollView, []error) {
	if lookup == nil {
		return PollView{}, []error{errors.New("polling needs a purchase lookup")}
	}
	view, err := c.lane.Poll(context.WithValue(ctx, purchaseLookupKey{}, lookup))
	out := PollView{Relays: view.Listed, Stored: view.Stored, Refused: view.Refused,
		Acknowledged: view.Acknowledged, Next: view.Next}
	if out.Next.IsZero() {
		out.Next = c.config.Now().Add(PollInterval)
	}
	if err != nil {
		return out, []error{err}
	}
	return out, nil
}

// RunPoll polls until ctx ends, each pass when the next relay is due and
// at least every PollInterval; report receives each pass's failures. It
// needs no MCP session.
func (c *Carrier) RunPoll(ctx context.Context, lookup PurchaseLookup, report func([]error)) {
	var reportMu sync.Mutex
	reportFailures := func(failures []error) {
		if report != nil && len(failures) > 0 && ctx.Err() == nil {
			reportMu.Lock()
			defer reportMu.Unlock()
			report(failures)
		}
	}
	var waiting sync.WaitGroup
	if lookup != nil {
		waiting.Go(func() { c.waitForMailbox(context.WithValue(ctx, purchaseLookupKey{}, lookup)) })
	}
	waiting.Go(func() {
		ticker := time.NewTicker(PollInterval)
		defer ticker.Stop()
		nextPrune := time.Time{}
		for ctx.Err() == nil {
			var failures []error
			if _, err := c.publisher.Publish(ctx); err != nil {
				failures = append(failures, err)
			}
			if now := c.config.Now(); !now.Before(nextPrune) {
				if err := errors.Join(c.lane.Prune(ctx), c.scheduler.Prune(ctx), c.credentials.Prune(ctx)); err != nil {
					failures = append(failures, err)
				}
				nextPrune = now.Add(5 * time.Minute)
			}
			reportFailures(failures)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	defer waiting.Wait()
	for {
		view, failures := c.Poll(ctx, lookup)
		reportFailures(failures)
		wait := view.Next.Sub(c.config.Now())
		if wait < time.Second {
			wait = time.Second
		}
		if wait > PollInterval {
			wait = PollInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// waitForMailbox keeps one bounded long poll outstanding, rotating to
// another configured relay when the preferred one cannot answer.
func (c *Carrier) waitForMailbox(ctx context.Context) {
	index := 0
	for ctx.Err() == nil {
		_, err := c.lane.Wait(ctx, c.config.Relays[index], 25)
		if err != nil {
			index = (index + 1) % len(c.config.Relays)
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// permanentError marks a packet refused for good (relay 8.5 steps 4 and 5).
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

func permanent(err error) error { return permanentError{err: err} }

func isPermanent(err error) bool {
	var target permanentError
	return errors.As(err, &target)
}

// storeResultPacket admits a verified result for an active purchase and writes
// the frame durably before the transport can acknowledge it.
func (c *Carrier) storeResultPacket(packet agentpacket.Packet, lookup PurchaseLookup) error {
	frame, err := railwork.DecodeFrame(packet.Payload)
	if err != nil {
		return permanent(err)
	}
	requestHash := hex.EncodeToString(frame.Binding.RequestHash[:])
	purchase, found, err := lookup(requestHash)
	if err != nil {
		return err
	}
	if !found {
		return permanent(errors.New("the frame names no purchase of this buyer"))
	}
	if frame.Kind != railwork.KindResult || packet.SenderAgentID != purchase.ProviderAgentID || frame.Binding != purchase.Binding {
		return permanent(errors.New("the frame is not a result from the purchase's provider for its request"))
	}
	if err := railwork.CheckPacketFields(packet.CapabilityID, packet.QuoteCommitment, purchase.CapabilityID,
		purchase.QuoteCommitment, railwork.RefusalResultNotAccepted); err != nil {
		return permanent(err)
	}
	if err := c.storeFrame(requestHash, frame, packet.Payload); err != nil {
		// A full inbox is transient: the envelope stays unacknowledged at
		// the relay and is taken on a later pass once the inbox has room.
		if errors.Is(err, railwork.ErrFrameConflict) {
			return permanent(err)
		}
		return err
	}
	return nil
}

func (c *Carrier) inboxDir(requestHash string) string {
	return filepath.Join(c.config.StateDir, "inbox", requestHash)
}

var messageDirPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// storeFrame stores one admitted frame durably under its message digest.
// The same bytes again are a duplicate and succeed; other bytes for a held
// index are a frame conflict.
func (c *Carrier) storeFrame(requestHash string, frame railwork.Frame, raw []byte) error {
	c.inboxMu.Lock()
	defer c.inboxMu.Unlock()
	inbox := c.inboxDir(requestHash)
	if err := makePrivateDir(inbox); err != nil {
		return err
	}
	message := filepath.Join(inbox, hex.EncodeToString(frame.MessageDigest[:]))
	if _, err := os.Lstat(message); errors.Is(err, os.ErrNotExist) {
		held, err := c.inboxMessages(requestHash)
		if err != nil {
			return err
		}
		if len(held) >= MaxOpenMessages {
			return errInboxFull
		}
	}
	if err := makePrivateDir(message); err != nil {
		return err
	}
	path := filepath.Join(message, fmt.Sprintf("%02d.frame", frame.Index))
	existing, err := readPrivate(path)
	if err == nil {
		if !bytes.Equal(existing, raw) {
			return railwork.ErrFrameConflict
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writePrivate(path, raw, true)
}

// inboxMessages lists the message directories of a purchase's inbox.
func (c *Carrier) inboxMessages(requestHash string) ([]string, error) {
	entries, err := os.ReadDir(c.inboxDir(requestHash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() && messageDirPattern.MatchString(entry.Name()) {
			out = append(out, entry.Name())
		}
	}
	return out, nil
}

// makePrivateDir creates an owner-only directory, or checks an existing
// one.
func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return checkPrivateDir(path)
}
