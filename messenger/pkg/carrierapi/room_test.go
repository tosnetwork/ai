package carrierapi

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

var roomID = "room_" + strings.Repeat("c", 64)

func roomAgent(index int) string { return fmt.Sprintf("agent_%064x", index+1) }

func maximalCards(count int) []RoomCard {
	cards := make([]RoomCard, count)
	for index := range cards {
		cards[index] = RoomCard{AgentID: roomAgent(index),
			CardBase64: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", relayframe.MaxCardBytes)))}
	}
	return cards
}

// carrier.room-cards names a room and 1..31 distinct cards to admit, or
// 1..31 distinct Agents to forget; carrier.withdraw names a recipient and an
// idempotency key; neither carries a frame.
func TestRoomCardsAndWithdrawRequestsAreStrict(t *testing.T) {
	valid := []Request{
		{Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: maximalCards(MaxRoomCards)},
		{Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsForget, ForgetAgentIDs: []string{agentA, agentB}},
		{Schema: RequestSchema, Op: OpWithdraw, RecipientAgentID: agentA, IdempotencyKey: keyOne},
	}
	for _, request := range valid {
		if err := ValidateRequest(request); err != nil {
			t.Fatalf("%s: %v", request.Op, err)
		}
	}
	// The largest valid request fits the message bound.
	if encoded, err := encodeRequest(valid[0]); err != nil || len(encoded) > int(MaxMessageBytes) {
		t.Fatalf("maximal room-cards request: %d %v", len(encoded), err)
	}
	oversizedCard := maximalCards(1)
	oversizedCard[0].CardBase64 = base64.StdEncoding.EncodeToString(make([]byte, relayframe.MaxCardBytes+1))
	invalid := map[string]Request{
		"no room":         {Schema: RequestSchema, Op: OpRoomCards, RoomCardsAction: RoomCardsAdmit, RoomCards: maximalCards(1)},
		"no action":       {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCards: maximalCards(1)},
		"no cards":        {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit},
		"32 cards":        {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: maximalCards(MaxRoomCards + 1)},
		"oversized card":  {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: oversizedCard},
		"empty card":      {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: []RoomCard{{AgentID: agentA}}},
		"duplicate card":  {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: append(maximalCards(1), maximalCards(1)...)},
		"admit forgets":   {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: maximalCards(1), ForgetAgentIDs: []string{agentA}},
		"forget nothing":  {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsForget},
		"forget twice":    {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsForget, ForgetAgentIDs: []string{agentA, agentA}},
		"cards frame":     {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsForget, ForgetAgentIDs: []string{agentA}, FrameBase64: frameBase64()},
		"withdraw no key": {Schema: RequestSchema, Op: OpWithdraw, RecipientAgentID: agentA},
		"withdraw frame":  {Schema: RequestSchema, Op: OpWithdraw, RecipientAgentID: agentA, IdempotencyKey: keyOne, FrameBase64: frameBase64()},
		"withdraw room":   {Schema: RequestSchema, Op: OpWithdraw, RecipientAgentID: agentA, IdempotencyKey: keyOne, RoomID: roomID},
		"carry room":      {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyOne, ExpiresAtUnix: 1, FrameBase64: frameBase64(), RoomID: roomID},
	}
	for name, request := range invalid {
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Each operation has its own answers: room-cards applied (naming refused
// cards), withdraw withdrawn or ignored; refused cards belong only there.
func TestRoomCardsAndWithdrawAnswers(t *testing.T) {
	for _, test := range []struct {
		op       Op
		response Response
		valid    bool
	}{
		{OpRoomCards, Response{Schema: ResponseSchema, Result: ResultApplied}, true},
		{OpRoomCards, Response{Schema: ResponseSchema, Result: ResultApplied, RefusedAgentIDs: []string{agentA}}, true},
		{OpRoomCards, Response{Schema: ResponseSchema, Result: ResultApplied, RefusedAgentIDs: []string{"agent_bad"}}, false},
		{OpRoomCards, Withdrawn(), false},
		{OpRoomCards, Retry(), true},
		{OpWithdraw, Withdrawn(), true},
		{OpWithdraw, Response{Schema: ResponseSchema, Result: ResultIgnored}, true},
		{OpWithdraw, Carried(3600), false},
		{OpWithdraw, Refusal(CodeNoPeerCard), true},
		{OpDeliveryAck, Response{Schema: ResponseSchema, Result: ResultApplied, RefusedAgentIDs: []string{agentA}}, false},
		{OpDeliver, Withdrawn(), false},
		// A kind-3 object or stored part admitted.
		{OpDeliver, Response{Schema: ResponseSchema, Result: ResultAdmitted}, true},
	} {
		if err := ValidateResponse(test.op, test.response); (err == nil) != test.valid {
			t.Fatalf("%s %+v: %v, want valid=%v", test.op, test.response, err, test.valid)
		}
	}
}

// Kind 3 holds at most 16 of a peer's 24 chat envelopes: at least 8 stay
// for copies, acks and evidence.
func TestPeerCapHoldsKindThreeToSixteenOfTwentyFour(t *testing.T) {
	if MaxPeerEnvelopes != 24 || MaxPeerRoomEnvelopes != 16 {
		t.Fatal("the per-peer caps differ from section 7")
	}
	for _, test := range []struct {
		kind        uint8
		total, room int
		allowed     bool
	}{
		{relayframe.KindRoom, 0, 0, true},
		{relayframe.KindRoom, 15, 15, true},
		{relayframe.KindRoom, 16, 16, false},
		{relayframe.KindCopy, 16, 16, true},
		{relayframe.KindDeliveryAck, 23, 16, true},
		{relayframe.KindCopy, 24, 16, false},
		{relayframe.KindRoom, 20, 10, true},
		{relayframe.KindRoom, 24, 10, false},
		{relayframe.KindCopy, 3, 4, false},
		{relayframe.KindCopy, -1, 0, false},
	} {
		if got := PeerCapAllows(test.kind, test.total, test.room); got != test.allowed {
			t.Fatalf("kind %d at %d/%d: %v", test.kind, test.total, test.room, got)
		}
	}
}

func TestRoomCardsAndWithdrawOverTheSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "carrier.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	handler := &recordingHandler{}
	server, err := NewServer(handler, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	client, err := NewClient(path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.RoomCards(ctx, roomID, maximalCards(MaxRoomCards))
	if err != nil || response.Result != ResultApplied || len(response.RefusedAgentIDs) != 1 || response.RefusedAgentIDs[0] != roomAgent(1) {
		t.Fatalf("admit: %+v %v", response, err)
	}
	if response, err := client.ForgetRoomCards(ctx, roomID, []string{agentA}); err != nil || response.Result != ResultApplied {
		t.Fatalf("forget: %+v %v", response, err)
	}
	if response, err := client.Withdraw(ctx, agentA, keyOne); err != nil || response.Result != ResultWithdrawn {
		t.Fatalf("withdraw: %+v %v", response, err)
	}
	if response, err := client.Withdraw(ctx, agentA, keyTwo); err != nil || response.Result != ResultIgnored {
		t.Fatalf("withdraw of nothing: %+v %v", response, err)
	}
	if response, err := client.Withdraw(ctx, agentB, keyOne); err != nil || response.Result != ResultRetry {
		t.Fatalf("a mismatched withdraw answer: %+v %v", response, err)
	}
}
