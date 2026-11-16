package carrierapi

import (
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	agentA = "agent_" + strings.Repeat("a", 64)
	keyOne = "idem_" + strings.Repeat("1", 64)
	keyTwo = "idem_" + strings.Repeat("2", 64)
)

func frameBase64() string { return base64.StdEncoding.EncodeToString([]byte("frame")) }

func TestRequestValidationIsPerOperation(t *testing.T) {
	valid := []Request{
		{Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyOne, ExpiresAtUnix: 1, FrameBase64: frameBase64()},
		{Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyTwo, WithdrawIdempotencyKey: keyOne,
			ExpiresAtUnix: 1, FrameBase64: frameBase64()},
		{Schema: RequestSchema, Op: OpDeliver, PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
		{Schema: RequestSchema, Op: OpDeliveryAck, PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
	}
	for _, request := range valid {
		if err := ValidateRequest(request); err != nil {
			t.Fatalf("%+v: %v", request, err)
		}
	}
	invalid := map[string]Request{
		"schema":          {Schema: "other", Op: OpDeliver, PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
		"op":              {Schema: RequestSchema, Op: "carrier.other", PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
		"empty frame":     {Schema: RequestSchema, Op: OpDeliver, PacketSenderAgentID: agentA},
		"bad base64":      {Schema: RequestSchema, Op: OpDeliver, PacketSenderAgentID: agentA, FrameBase64: "@@"},
		"oversized frame": {Schema: RequestSchema, Op: OpDeliver, PacketSenderAgentID: agentA, FrameBase64: base64.StdEncoding.EncodeToString(make([]byte, 190_465))},
		"carry no key":    {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, ExpiresAtUnix: 1, FrameBase64: frameBase64()},
		"carry bad key":   {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: "idem_X", ExpiresAtUnix: 1, FrameBase64: frameBase64()},
		"carry self withdraw": {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyOne,
			WithdrawIdempotencyKey: keyOne, ExpiresAtUnix: 1, FrameBase64: frameBase64()},
		"carry no expiry":   {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyOne, FrameBase64: frameBase64()},
		"carry with sender": {Schema: RequestSchema, Op: OpCarry, RecipientAgentID: agentA, IdempotencyKey: keyOne, ExpiresAtUnix: 1, PacketSenderAgentID: agentA, FrameBase64: frameBase64()},
		"deliver no sender": {Schema: RequestSchema, Op: OpDeliver, FrameBase64: frameBase64()},
		"deliver with key":  {Schema: RequestSchema, Op: OpDeliver, PacketSenderAgentID: agentA, IdempotencyKey: keyOne, FrameBase64: frameBase64()},
	}
	for name, request := range invalid {
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestResponseValidationIsPerOperation(t *testing.T) {
	ack := Response{Schema: ResponseSchema, Result: ResultAck, AckFrameBase64: frameBase64(), AckOutcome: "accepted"}
	for _, test := range []struct {
		op       Op
		response Response
		valid    bool
	}{
		{OpCarry, Response{Schema: ResponseSchema, Result: ResultCarried}, true},
		{OpCarry, Retry(), true},
		{OpCarry, Refusal(CodePeerCap), true},
		{OpCarry, ack, false},
		{OpDeliver, ack, true},
		{OpDeliver, Response{Schema: ResponseSchema, Result: ResultAdmitted}, true},
		{OpDeliver, Response{Schema: ResponseSchema, Result: ResultCarried}, false},
		{OpDeliver, Response{Schema: ResponseSchema, Result: ResultAck, AckOutcome: "accepted"}, false},
		{OpDeliver, Response{Schema: ResponseSchema, Result: ResultAck, AckFrameBase64: frameBase64(), AckOutcome: "delivered"}, false},
		{OpDeliveryAck, Response{Schema: ResponseSchema, Result: ResultApplied}, true},
		{OpDeliveryAck, Response{Schema: ResponseSchema, Result: ResultAdmitted}, false},
		{OpDeliveryAck, Response{Schema: ResponseSchema, Result: ResultRefused, Code: "made-up"}, false},
		{OpDeliveryAck, Response{Schema: ResponseSchema, Result: ResultApplied, Code: CodePeerCap}, false},
		{OpDeliveryAck, Response{Result: ResultApplied}, false},
	} {
		err := ValidateResponse(test.op, test.response)
		if (err == nil) != test.valid {
			t.Fatalf("%s %+v: err=%v", test.op, test.response, err)
		}
	}
}

type recordingHandler struct {
	carried []Request
}

func (h *recordingHandler) Carry(_ context.Context, request Request, frame []byte) Response {
	h.carried = append(h.carried, request)
	if string(frame) != "frame" {
		return Refusal(CodeFrameMalformed)
	}
	return Response{Result: ResultCarried}
}

func (h *recordingHandler) Deliver(context.Context, string, []byte) Response { return NotServed() }

func (h *recordingHandler) DeliveryAck(context.Context, string, []byte) Response {
	return Response{Result: ResultCarried}
}

func TestSocketRoundTripIsBoundedAndChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "carrier.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	handler := &recordingHandler{}
	server, err := NewServer(handler, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	defer listener.Close()
	client, err := NewClient(path, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Carry(ctx, agentA, keyTwo, keyOne, 10, []byte("frame"))
	if err != nil || response.Result != ResultCarried {
		t.Fatalf("carry: %+v %v", response, err)
	}
	if len(handler.carried) != 1 || handler.carried[0].WithdrawIdempotencyKey != keyOne {
		t.Fatalf("carried: %+v", handler.carried)
	}
	if response, err := client.Deliver(ctx, agentA, []byte("frame")); err != nil || response.Code != CodeOperationNotServedHere {
		t.Fatalf("deliver on a carrier: %+v %v", response, err)
	}
	// A handler answer that does not belong to the operation becomes retry.
	if response, err := client.DeliveryAck(ctx, agentA, []byte("frame")); err != nil || response.Result != ResultRetry {
		t.Fatalf("mismatched answer: %+v %v", response, err)
	}
	if _, err := client.Carry(ctx, agentA, "idem_bad", "", 10, []byte("frame")); err == nil {
		t.Fatal("an invalid request was sent")
	}
	if _, err := NewClient("relative.sock", time.Second); err == nil {
		t.Fatal("relative socket path accepted")
	}
	if _, err := NewServer(handler, time.Hour); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
	if _, response := server.Handle(ctx, []byte(`{"schema":"x"}`)); response.Code != CodeInvalidRequest {
		t.Fatalf("invalid request body: %+v", response)
	}
}

// slowHandler records how many handlers run at once and whether each saw
// the per-connection deadline.
type slowHandler struct {
	mutex      sync.Mutex
	running    int
	maximum    int
	noDeadline int
}

func (h *slowHandler) Carry(ctx context.Context, _ Request, _ []byte) Response {
	h.mutex.Lock()
	h.running++
	if h.running > h.maximum {
		h.maximum = h.running
	}
	if _, ok := ctx.Deadline(); !ok {
		h.noDeadline++
	}
	h.mutex.Unlock()
	time.Sleep(50 * time.Millisecond)
	h.mutex.Lock()
	h.running--
	h.mutex.Unlock()
	return Response{Result: ResultCarried}
}

func (h *slowHandler) Deliver(context.Context, string, []byte) Response     { return NotServed() }
func (h *slowHandler) DeliveryAck(context.Context, string, []byte) Response { return NotServed() }

func TestServerBoundsConcurrentHandlersAndTheirTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "carrier.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	handler := &slowHandler{}
	server, err := NewServer(handler, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	client, err := NewClient(path, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	failures := make(chan error, 3*MaxConcurrentHandlers)
	for index := 0; index < 3*MaxConcurrentHandlers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			response, err := client.Carry(ctx, agentA, keyOne, "", 10, []byte("frame"))
			if err != nil || response.Result != ResultCarried {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatalf("a queued request failed: %v", err)
	}
	if handler.maximum > MaxConcurrentHandlers || handler.maximum == 0 {
		t.Fatalf("%d handlers ran at once, cap %d", handler.maximum, MaxConcurrentHandlers)
	}
	if handler.noDeadline != 0 {
		t.Fatalf("%d handlers ran without the connection deadline", handler.noDeadline)
	}
}
