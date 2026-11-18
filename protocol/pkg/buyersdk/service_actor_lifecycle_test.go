package buyersdk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakeLifecycle struct {
	mu      sync.Mutex
	intents []LifecycleIntent
	err     error
	panics  bool
	// submission is what custody reports about the message it signed.
	submission LifecycleSubmission
}

func (f *fakeLifecycle) SendLifecycle(_ context.Context, intent LifecycleIntent) (LifecycleSubmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.intents = append(f.intents, intent)
	if f.panics {
		panic("a defect inside custody during a lifecycle send")
	}
	return f.submission, f.err
}

var lifecycleEndpoints = vetter{endpoints: []string{"https://a.example/jsonRPC", "https://b.example/jsonRPC",
	"https://c.example/jsonRPC"}}

func TestTheLifecycleSenderNamesTheOperationRequestAndDestination(t *testing.T) {
	for _, operation := range []string{LifecycleExpire, LifecycleClaimRefund, LifecycleSweep} {
		sender, calls := testSender(t, validConfig, lifecycleEndpoints, nil)
		sender.runWithPath = func(_ context.Context, args ...string) ([]byte, error) {
			*calls = append(*calls, args)
			return []byte("OK Service Actor " + operation + " message submitted to " + saActor + "\n"), nil
		}
		intent := LifecycleIntent{Operation: operation, Actor: saActor, RequestID: 3, QueryID: 9, Destination: saBuyer}
		if _, err := sender.SendLifecycle(context.Background(), intent); err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		want := fmt.Sprintf("agent service send --operation %s --address %s --from buyer --query-id 9 --request-id 3",
			operation, saActor)
		if operation == LifecycleClaimRefund {
			want += " --destination " + saBuyer
		}
		if got := strings.Join((*calls)[0], " "); got != want+" --yes" {
			t.Fatalf("argv\n got %s\nwant %s --yes", got, want)
		}
	}
	silent, _ := testSender(t, validConfig, lifecycleEndpoints, nil)
	silent.runWithPath = func(context.Context, ...string) ([]byte, error) { return []byte("nothing"), nil }
	if _, err := silent.SendLifecycle(context.Background(), LifecycleIntent{Operation: LifecycleExpire, Actor: saActor,
		RequestID: 3, QueryID: 9}); err == nil || errors.Is(err, ErrCallNotStarted) {
		t.Fatalf("an unreported lifecycle send was not ambiguous: %v", err)
	}
	for name, intent := range map[string]LifecycleIntent{
		"unknown operation":           {Operation: "respond", Actor: saActor, QueryID: 9},
		"claim without a destination": {Operation: LifecycleClaimRefund, Actor: saActor, QueryID: 9},
		"zero query id":               {Operation: LifecycleExpire, Actor: saActor},
	} {
		started, calls := testSender(t, validConfig, lifecycleEndpoints, nil)
		if _, err := started.SendLifecycle(context.Background(), intent); !errors.Is(err, ErrCallNotStarted) || len(*calls) != 0 {
			t.Errorf("%s was handed to custody: %v", name, err)
		}
	}
	unverified, calls := testSender(t, validConfig, vetter{endpoints: lifecycleEndpoints.endpoints,
		bad: map[string]bool{"https://a.example/jsonRPC": true}}, nil)
	if _, err := unverified.SendLifecycle(context.Background(), LifecycleIntent{Operation: LifecycleExpire, Actor: saActor,
		RequestID: 3, QueryID: 9}); !errors.Is(err, ErrCallNotStarted) || len(*calls) != 0 {
		t.Fatalf("a send through an unverified endpoint started: %v", err)
	}
}

const announcedLine = "Wallet message seqno=7 valid_until=2000000120 hash=sha256:" +
	"abababababababababababababababababababababababababababababababab"

// The sender reports the wallet message tosctl announced, on success and on
// an ambiguous outcome alike.
func TestTheLifecycleSenderReportsTheAnnouncedWalletMessage(t *testing.T) {
	want := LifecycleSubmission{Announced: true, Seqno: 7, ValidUntilUnix: 2_000_000_120, MessageHash: strings.Repeat("ab", 32)}
	for name, run := range map[string]func(context.Context, ...string) ([]byte, error){
		"submitted": func(context.Context, ...string) ([]byte, error) {
			return []byte(announcedLine + "\nOK Service Actor expire message submitted to " + saActor + "\n"), nil
		},
		"ambiguous": func(context.Context, ...string) ([]byte, error) {
			return []byte(announcedLine + "\nwallet message sha256:ab may have been submitted\n"), errors.New("exit status 1")
		},
	} {
		sender, _ := testSender(t, validConfig, lifecycleEndpoints, nil)
		sender.runWithPath = run
		got, _ := sender.SendLifecycle(context.Background(), LifecycleIntent{Operation: LifecycleExpire, Actor: saActor,
			RequestID: 3, QueryID: 9})
		if got != want {
			t.Errorf("%s: reported %+v", name, got)
		}
	}
}

// Exactly one well-formed line is trusted; anything else announces
// nothing.
func TestOnlyOneWellFormedWalletMessageLineIsTrusted(t *testing.T) {
	if got := parseWalletMessage([]byte("x\n" + announcedLine + "\r\ny")); !got.Announced || got.Seqno != 7 {
		t.Fatalf("a well-formed line was not read: %+v", got)
	}
	for name, output := range map[string]string{
		"no line":            "OK Service Actor expire message submitted",
		"two lines":          announcedLine + "\n" + announcedLine,
		"no expiry":          strings.Replace(announcedLine, "valid_until=2000000120", "valid_until=none", 1),
		"zero expiry":        strings.Replace(announcedLine, "valid_until=2000000120", "valid_until=0", 1),
		"seqno over 32 bits": strings.Replace(announcedLine, "seqno=7", "seqno=4294967296", 1),
		"uppercase hash":     strings.Replace(announcedLine, "abab", "ABAB", 1),
		"short hash":         announcedLine[:len(announcedLine)-2],
		"inside a line":      "error: " + announcedLine,
	} {
		if got := parseWalletMessage([]byte(output)); got.Announced {
			t.Errorf("%s: announced %+v", name, got)
		}
	}
}

// admitted prepares, calls and lands a call, and resolves it to admitted.
func admitted(t *testing.T, f *buyerFixture) CallRecord {
	t.Helper()
	ctx := context.Background()
	record, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(1), digest32(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.Call(ctx, record.RequestHash); err != nil {
		t.Fatal(err)
	}
	f.land(t, record, 0, true)
	if report, err := f.buyer.Resolve(ctx, record.RequestHash); err != nil || report.Phase != PhaseAdmitted {
		t.Fatalf("resolve: %+v %v", report, err)
	}
	return record
}

func TestLifecycleSendsAreJournaledAndAlwaysRefundTheBuyer(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	lifecycle := &fakeLifecycle{}
	f.buyer.config.Lifecycle = lifecycle
	ctx := context.Background()
	unadmitted, err := f.buyer.Prepare(ctx, f.request, f.pkg, digest32(3), digest32(4))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.buyer.SendLifecycle(ctx, unadmitted.RequestHash, LifecycleExpire); err == nil {
		t.Fatal("a call that was never admitted got a lifecycle send")
	}
	record := admitted(t, f)
	sent, err := f.buyer.SendLifecycle(ctx, record.RequestHash, LifecycleClaimRefund)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent.Lifecycle) != 1 || sent.Lifecycle[0].Phase != PhaseSubmitted || sent.Lifecycle[0].Operation != LifecycleClaimRefund {
		t.Fatalf("journaled %+v", sent.Lifecycle)
	}
	intent := lifecycle.intents[0]
	if intent.Destination != saBuyer || intent.Actor != record.Actor || intent.RequestID != 0 || intent.QueryID == 0 ||
		intent.QueryID == record.QueryID {
		t.Fatalf("intent %+v", intent)
	}
	if _, err := f.buyer.SendLifecycle(ctx, record.RequestHash, "respond"); err == nil {
		t.Fatal("an unknown operation was sent")
	}
	lifecycle.err = errors.New("tosctl exited after submitting")
	ambiguous, err := f.buyer.SendLifecycle(ctx, record.RequestHash, LifecycleExpire)
	if err == nil || ambiguous.Lifecycle[1].Phase != PhaseAmbiguous {
		t.Fatalf("an ambiguous lifecycle send: %+v %v", ambiguous.Lifecycle, err)
	}
	lifecycle.err = ErrCallNotStarted
	notStarted, err := f.buyer.SendLifecycle(ctx, record.RequestHash, LifecycleSweep)
	if !errors.Is(err, ErrCallNotStarted) || notStarted.Lifecycle[2].Phase != PhasePrepared {
		t.Fatalf("a send custody never started: %+v %v", notStarted.Lifecycle, err)
	}
	f.buyer.config.Lifecycle = nil
	if _, err := f.buyer.SendLifecycle(ctx, record.RequestHash, LifecycleExpire); !errors.Is(err, ErrNoLifecycleSender) {
		t.Fatalf("a buyer without a lifecycle sender sent: %v", err)
	}
}

// A panic or a crash during a lifecycle send leaves its entry ambiguous,
// as for the call.
func TestAnInterruptedLifecycleSendIsAmbiguous(t *testing.T) {
	f := newBuyerFixture(t, defaultLimits())
	lifecycle := &fakeLifecycle{panics: true}
	f.buyer.config.Lifecycle = lifecycle
	record := admitted(t, f)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the planted panic did not reach the caller")
			}
		}()
		_, _ = f.buyer.SendLifecycle(context.Background(), record.RequestHash, LifecycleSweep)
	}()
	stored, err := f.buyer.Journal().Read(record.RequestHash)
	if err != nil || len(stored.Lifecycle) != 1 || stored.Lifecycle[0].Phase != PhaseAmbiguous {
		t.Fatalf("after a panic: %+v %v", stored.Lifecycle, err)
	}
	if _, err := f.buyer.Journal().Transition(record.RequestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		r.Lifecycle = append(r.Lifecycle, LifecycleSend{Operation: LifecycleExpire, QueryID: 1, Phase: PhaseSending})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenServiceActorJournal(f.dir, saNow)
	if err != nil {
		t.Fatal(err)
	}
	stored, err = reopened.Read(record.RequestHash)
	if err != nil || stored.Lifecycle[1].Phase != PhaseAmbiguous || stored.Phase != PhaseAdmitted {
		t.Fatalf("after a restart: %+v %v", stored, err)
	}
}
