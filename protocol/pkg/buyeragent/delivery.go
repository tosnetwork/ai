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
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
)

var (
	ErrTaskDeadlinePassed = errors.New("the task's response deadline has passed")
	ErrNoRelayAccepted    = errors.New("no relay accepted the task yet")
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
	// Generation counts the retained rail generations, or zero before sealing.
	Generation int `json:"generation"`
	// Sealed reports that this round created the durable signed packet plan.
	Sealed bool `json:"sealed"`
	// Envelopes is the number of envelopes in the generation, one per
	// frame; Delivered counts those at least one relay accepted.
	Envelopes int `json:"envelopes"`
	Delivered int `json:"delivered"`
}

// packetPlan keeps the signed packets stable across partial queue writes and
// restarts. The rail lane owns all envelopes and relay retry state.
type packetPlan struct {
	Name        string   `json:"name"`
	RequestHash string   `json:"request_hash"`
	Deadline    uint64   `json:"deadline"`
	FrameCount  int      `json:"frame_count"`
	Packets     [][]byte `json:"packets,omitempty"`
}

func (c *Carrier) DeliverTask(ctx context.Context, task TaskDelivery) (DeliveryView, error) {
	if err := checkRequestHash(task.Record.RequestHash); err != nil {
		return DeliveryView{}, err
	}
	if task.ChainTime.Unix() <= 0 {
		return DeliveryView{}, errors.New("a delivery round needs the checkpoint's chain time")
	}
	if !task.ChainTime.Before(task.ResponseDeadline) {
		return DeliveryView{}, ErrTaskDeadlinePassed
	}
	return c.sendFrames(ctx, task.Record, task.ProviderAgentID, railwork.KindTask, 0,
		task.ChainTime, task.ResponseDeadline, func() (railwork.Binding, []byte, error) {
			message, err := c.taskMessage(ctx, task)
			if err != nil {
				return railwork.Binding{}, nil, err
			}
			binding, err := taskBinding(task.Record)
			return binding, message, err
		})
}

func (c *Carrier) sendFrames(ctx context.Context, record buyersdk.CallRecord, peer string, kind railwork.Kind,
	repeat int64, now, deadline time.Time, build func() (railwork.Binding, []byte, error)) (DeliveryView, error) {
	if err := checkRequestHash(record.RequestHash); err != nil {
		return DeliveryView{}, err
	}
	c.deliveryMu.Lock()
	defer c.deliveryMu.Unlock()
	dir := filepath.Join(c.config.StateDir, "outbox-v2", record.RequestHash)
	if err := makePrivateDir(dir); err != nil {
		return DeliveryView{}, err
	}
	name := fmt.Sprintf("%d-%d", kind, repeat)
	path := filepath.Join(dir, name+".json")
	var plan packetPlan
	view := DeliveryView{}
	err := readJSON(path, &plan)
	if errors.Is(err, os.ErrNotExist) {
		binding, message, err := build()
		if err != nil {
			return view, err
		}
		frames, err := railwork.EncodeMessageFrames(kind, binding, message)
		if err != nil {
			return view, err
		}
		plan.Name, plan.RequestHash, plan.Deadline = name, record.RequestHash, uint64(deadline.Unix())
		plan.FrameCount = len(frames)
		for index, frame := range frames {
			var nonce [32]byte
			if err := c.config.Random(nonce[:]); err != nil {
				return view, err
			}
			packet, err := agentpacket.Sign(ctx, c.config.Signer, c.config.Controller, agentpacket.Packet{
				SenderAgentID: c.config.BuyerAgentID, RecipientAgentID: peer, CapabilityID: record.CapabilityID,
				QuoteCommitment: record.QuoteCommitment, Sequence: uint64(now.UnixNano()) + uint64(index), Nonce: nonce,
				Payload: frame, CreatedAtUnix: uint64(now.Unix()), SenderKeyID: c.config.ControllerKeyID})
			if err != nil {
				return view, err
			}
			raw, err := agentpacket.EncodeJSON(packet)
			if err != nil {
				return view, err
			}
			plan.Packets = append(plan.Packets, raw)
		}
		if err := writeJSON(path, plan, true); err != nil {
			return view, err
		}
		view.Sealed = true
	} else if err != nil {
		return view, err
	}
	if plan.Name != name || plan.RequestHash != record.RequestHash || plan.FrameCount < 1 || plan.FrameCount > railwork.MaxChunks ||
		(len(plan.Packets) != 0 && len(plan.Packets) != plan.FrameCount) {
		return view, agentcarrier.ErrStorage
	}
	view.Envelopes = plan.FrameCount
	if len(plan.Packets) != 0 {
		binding, err := taskBinding(record)
		if err != nil {
			return view, err
		}
		for index, raw := range plan.Packets {
			packet, err := agentpacket.DecodeJSON(raw)
			frame, frameErr := railwork.DecodeFrame(packet.Payload)
			if err != nil || frameErr != nil || packet.SenderAgentID != c.config.BuyerAgentID || packet.RecipientAgentID != peer ||
				packet.CapabilityID != record.CapabilityID || packet.QuoteCommitment != record.QuoteCommitment ||
				frame.Kind != kind || frame.Binding != binding || int(frame.Index) != index || int(frame.Count) != plan.FrameCount {
				return view, agentcarrier.ErrStorage
			}
			id := fmt.Sprintf("%s/%s/%d", record.RequestHash, name, index)
			if _, err := c.lane.Queue(ctx, id, raw, plan.Deadline); err != nil {
				return view, err
			}
		}
		// After the lane owns all frames, keep only the list of delivery
		// IDs derivable from this count and drop duplicate packet bytes.
		plan.Packets = nil
		if err := writeJSON(path, plan, false); err != nil {
			return view, err
		}
	}
	cardTime := now
	if kind == railwork.KindTask {
		cardTime = deadline
	}
	card, err := c.ProviderCard(ctx, record.CapabilityID, peer, cardTime)
	if errors.Is(err, ErrNoProviderCard) && !cardTime.Equal(now) {
		card, err = c.ProviderCard(ctx, record.CapabilityID, peer, now)
	}
	if err != nil && !errors.Is(err, ErrNoProviderCard) {
		return view, err
	}
	providerCardHeld := err == nil
	route := agentcarrier.Route{CardPacket: card.PacketJSON}
	for index := range plan.FrameCount {
		if !providerCardHeld {
			break
		}
		id := fmt.Sprintf("%s/%s/%d", record.RequestHash, name, index)
		carriage, err := c.scheduler.Advance(ctx, id, route)
		if status, statusErr := c.lane.Status(ctx, id); statusErr == nil {
			view.Generation = max(view.Generation, status.Generations)
		}
		if carriage.Copies > 0 {
			view.Delivered++
		}
		if err != nil && !errors.Is(err, agentcarrier.ErrNoRoute) && !errors.Is(err, agentcarrier.ErrUnavailable) {
			return view, err
		}
	}
	if view.Delivered != view.Envelopes {
		return view, ErrNoRelayAccepted
	}
	return view, nil
}

func (c *Carrier) taskMessage(ctx context.Context, task TaskDelivery) ([]byte, error) {
	record := task.Record
	if record.RequestID == nil || record.CallTransactionLT == 0 || len(record.CallTransactionHex) != 64 {
		return nil, errors.New("the purchase's call is not admitted with its transaction")
	}
	packageBytes, err := base64.StdEncoding.Strict().DecodeString(record.PackageBase64)
	if err != nil {
		return nil, errors.New("the journaled Quote package is not Base64")
	}
	cover, err := buyerCardWindow(record, task.RetentionSeconds)
	if err != nil {
		return nil, err
	}
	buyerCard, err := c.BuyerCard(ctx, cover)
	if err != nil {
		return nil, err
	}
	grant, err := c.issueContact(ctx, task.ProviderAgentID)
	if err != nil {
		return nil, err
	}
	message, err := railwork.EncodeTask(railwork.Task{Header: railwork.TaskHeader{BuyerAgentID: c.config.BuyerAgentID,
		BuyerWallet: record.BuyerWallet, CapabilityID: record.CapabilityID, CapabilityVersion: record.CapabilityVersion,
		ExecutionID: record.ExecutionID, ExecutionNonce: task.ExecutionNonce, RequestID: *record.RequestID,
		CallLT: record.CallTransactionLT, CallHash: record.CallTransactionHex, Contact: grant}, Package: packageBytes,
		Archive: task.Archive, BuyerKeyCard: buyerCard})
	if err != nil {
		return nil, fmt.Errorf("the task does not encode: %w", err)
	}
	return message, nil
}

func checkedAddUnix(unix uint64, add time.Duration) (uint64, bool) {
	seconds := uint64(add / time.Second)
	if unix > math.MaxUint64-seconds {
		return 0, false
	}
	return unix + seconds, true
}

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
	if record.RequestID == nil {
		return binding, errors.New("the purchase has no admitted request ID")
	}
	binding.RequestID = *record.RequestID
	return binding, nil
}
