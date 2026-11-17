package carrierapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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
		{Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: maximalCards(MaxRoomCards)},
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
		"no room":         {Schema: RequestSchema, Op: OpRoomCards, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: maximalCards(1)},
		"no action":       {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCards: maximalCards(1)},
		"no cards":        {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd},
		"32 cards":        {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: maximalCards(MaxRoomCards + 1)},
		"oversized card":  {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: oversizedCard},
		"empty card":      {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: []RoomCard{{AgentID: agentA}}},
		"duplicate card":  {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: append(maximalCards(1), maximalCards(1)...)},
		"admit forgets":   {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomEndsAtUnix: testRoomEnd, RoomCards: maximalCards(1), ForgetAgentIDs: []string{agentA}},
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
	end := uint64(time.Now().Add(24 * time.Hour).Unix())
	response, err := client.RoomCards(ctx, roomID, end, maximalCards(MaxRoomCards))
	if err != nil || response.Result != ResultApplied || len(response.RefusedAgentIDs) != 1 || response.RefusedAgentIDs[0] != roomAgent(1) {
		t.Fatalf("admit: %+v %v", response, err)
	}
	if len(handler.carried) != 1 || handler.carried[0].RoomEndsAtUnix != end {
		t.Fatalf("the carrier was not handed the room end: %+v", handler.carried)
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

// testRoomEnd is a room end the codec accepts; no clock bounds it there.
const testRoomEnd uint64 = 1_800_000_000

// The room end belongs to a room-cards admission only: an admission needs
// one, and a forget or any other operation that names one is refused.
func TestRoomEndIsNamedByAdmissionsOnly(t *testing.T) {
	admit := Request{Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit, RoomCards: maximalCards(1)}
	if err := ValidateRequest(admit); !errors.Is(err, ErrRoomEnd) {
		t.Fatalf("an admission without a room end: %v", err)
	}
	for _, end := range []uint64{1, testRoomEnd, math.MaxUint64} {
		admit.RoomEndsAtUnix = end
		if err := ValidateRequest(admit); err != nil {
			t.Fatalf("an admission ending at %d: %v", end, err)
		}
	}
	invalid := map[string]Request{
		"forget":       {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsForget, ForgetAgentIDs: []string{agentA}},
		"no action":    {Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCards: maximalCards(1)},
		"withdraw":     {Schema: RequestSchema, Op: OpWithdraw, RecipientAgentID: agentA, IdempotencyKey: keyOne},
		"carry":        {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyOne, ExpiresAtUnix: 1, FrameBase64: frameBase64()},
		"deliver":      {Schema: RequestSchema, Op: OpDeliver, PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
		"delivery-ack": {Schema: RequestSchema, Op: OpDeliveryAck, PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
	}
	for name, request := range invalid {
		if name != "no action" {
			if err := ValidateRequest(request); err != nil {
				t.Fatalf("%s without a room end: %v", name, err)
			}
		}
		request.RoomEndsAtUnix = testRoomEnd
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("%s naming a room end was accepted", name)
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequest(encoded); err == nil {
			t.Fatalf("%s naming a room end decoded", name)
		}
	}
}

// A room end lies at most 30 days and 1 h past the clock; an end already
// past is valid (the carrier's sweep drops it).
func TestValidateRoomEndBoundsTheEndByTheClock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	latest := uint64(now.Unix()) + MaxRoomLifetimeSeconds + RoomEndSlackSeconds
	if MaxRoomLifetimeSeconds != 30*24*3600 || RoomEndSlackSeconds != 3600 {
		t.Fatal("the room end bounds differ from D18 and the largest clock skew")
	}
	for _, test := range []struct {
		end   uint64
		now   time.Time
		valid bool
	}{
		{latest, now, true},
		{latest + 1, now, false},
		{latest - 1, now, true},
		{uint64(now.Unix()), now, true},
		{1, now, true},
		{0, now, false},
		{math.MaxUint64, now, false},
		{1, time.Time{}, false},
		{1, time.Unix(-1, 0), false},
		{1<<62 + MaxRoomLifetimeSeconds + RoomEndSlackSeconds, time.Unix(1<<62, 0), true},
		{1<<62 + MaxRoomLifetimeSeconds + RoomEndSlackSeconds + 1, time.Unix(1<<62, 0), false},
	} {
		if err := ValidateRoomEnd(test.end, test.now); (err == nil) != test.valid {
			t.Fatalf("end %d at %v: %v, want valid=%v", test.end, test.now, err, test.valid)
		}
	}
}

// The carrier drops an admission at the room end plus the slack.
func TestRoomAdmissionDropsAtTheEndPlusTheSlack(t *testing.T) {
	for _, test := range []struct {
		end, at uint64
		ok      bool
	}{
		{testRoomEnd, testRoomEnd + 3600, true},
		{1, 3601, true},
		{math.MaxUint64 - 3600, math.MaxUint64, true},
		{math.MaxUint64 - 3599, 0, false},
		{0, 0, false},
	} {
		if at, ok := RoomAdmissionDropAtUnix(test.end); at != test.at || ok != test.ok {
			t.Fatalf("end %d: %d %v", test.end, at, ok)
		}
	}
}

// Both ends that own a clock bound the room end: the client sends nothing
// beyond it, and the server hands its handler nothing beyond it.
func TestRoomEndBeyondTheClockIsRefusedAtBothEnds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	latest := uint64(now.Unix()) + MaxRoomLifetimeSeconds + RoomEndSlackSeconds
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
	server.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	client, err := NewClient(path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }
	for _, end := range []uint64{0, latest + 1} {
		if _, err := client.RoomCards(ctx, roomID, end, maximalCards(1)); !errors.Is(err, ErrRoomEnd) {
			t.Fatalf("the client sent an admission ending at %d: %v", end, err)
		}
	}
	if response, err := client.RoomCards(ctx, roomID, latest, maximalCards(1)); err != nil || response.Result != ResultApplied {
		t.Fatalf("an admission at the latest end: %+v %v", response, err)
	}
	if len(handler.carried) != 1 || handler.carried[0].RoomEndsAtUnix != latest {
		t.Fatalf("the carrier was handed: %+v", handler.carried)
	}
	// A client whose clock runs ahead is caught by the server.
	beyond, err := json.Marshal(Request{Schema: RequestSchema, Op: OpRoomCards, RoomID: roomID, RoomCardsAction: RoomCardsAdmit,
		RoomEndsAtUnix: latest + 1, RoomCards: maximalCards(1)})
	if err != nil {
		t.Fatal(err)
	}
	if op, response := server.Handle(ctx, beyond); op != OpRoomCards || response.Result != ResultRefused || response.Code != CodeInvalidRequest {
		t.Fatalf("the server took an admission beyond its clock: %s %+v", op, response)
	}
	if len(handler.carried) != 1 {
		t.Fatalf("the handler saw an admission beyond the clock: %+v", handler.carried)
	}
}
