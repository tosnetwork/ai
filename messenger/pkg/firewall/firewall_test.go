package firewall

import (
	"strings"
	"testing"
)

const baseUnix = uint64(1_800_000_000)

func testOrigin(seed string) Origin {
	return Origin{
		AgentID:        "agent_" + strings.Repeat(seed, 64),
		EndpointID:     "mep_" + strings.Repeat(seed, 64),
		DeviceID:       "dev_" + strings.Repeat(seed, 64),
		EventID:        "evt_" + strings.Repeat(seed, 64),
		ConversationID: "conv_" + strings.Repeat(seed, 64),
		Kind:           "text",
		ReceivedAtUnix: baseUnix,
	}
}

func testAction(effect Effect, origins ...Origin) Action {
	return Action{Effect: effect, Summary: "do the thing", DerivedFrom: origins}
}

// The same action is judged differently depending on whether something a
// stranger sent contributed to it. That difference is the whole point.
func TestReceivedContentIsHeldToATighterCeiling(t *testing.T) {
	policy := Default()

	ownWork, err := Evaluate(policy, testAction(EffectToolCall))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if ownWork.Outcome != Allow {
		t.Fatalf("the Agent's own tool call was stopped: %+v", ownWork)
	}

	prompted, err := Evaluate(policy, testAction(EffectToolCall, testOrigin("1")))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if prompted.Outcome != RequireOwnerApproval {
		t.Fatalf("a tool call a stranger's message led to ran unattended: %+v", prompted)
	}
	if len(prompted.Provenance) != 1 {
		t.Fatalf("the owner would not be told what caused it: %+v", prompted)
	}
}

// Replying is what a messenger is. An Agent that needed a person for every
// answer would not be an Agent.
func TestRepliesRunUnattended(t *testing.T) {
	decision, err := Evaluate(Default(), testAction(EffectMessage, testOrigin("2")))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Outcome != Allow {
		t.Fatalf("answering a message required a person: %+v", decision)
	}
}

// A key authorises whatever it signs, and a configuration change can remove
// this check. No policy may permit either unattended.
func TestNoPolicyCanReachAKeyOrTheConfiguration(t *testing.T) {
	for _, ceiling := range []Effect{EffectKeyUse, EffectConfiguration} {
		policy := Policy{UnattendedCeiling: ceiling, OwnInitiativeCeiling: EffectConfiguration}
		if err := policy.Validate(); err == nil {
			t.Fatalf("a policy raised the unattended ceiling to %q", ceiling)
		}
	}
	if err := (Policy{UnattendedCeiling: EffectMessage, OwnInitiativeCeiling: EffectConfiguration}).Validate(); err == nil {
		t.Fatal("a policy let the runtime reconfigure the installation")
	}
	// Even own-initiative configuration goes to the owner.
	decision, err := Evaluate(Default(), testAction(EffectConfiguration))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Outcome != RequireOwnerApproval {
		t.Fatalf("the runtime reconfigured the installation: %+v", decision)
	}
}

// Received content cannot be trusted further than the Agent's own initiative.
func TestUnattendedCeilingCannotExceedOwnInitiative(t *testing.T) {
	policy := Policy{UnattendedCeiling: EffectToolCall, OwnInitiativeCeiling: EffectMessage}
	if err := policy.Validate(); err == nil {
		t.Fatal("received content was trusted further than the Agent itself")
	}
}

func TestMalformedActionsAreRefused(t *testing.T) {
	duplicate := testOrigin("3")
	cases := map[string]Action{
		"unknown effect":   {Effect: "delete-everything", Summary: "x"},
		"no summary":       {Effect: EffectMessage},
		"summary too long": {Effect: EffectMessage, Summary: strings.Repeat("x", MaxSummaryBytes+1)},
		"broken origin":    {Effect: EffectMessage, Summary: "x", DerivedFrom: []Origin{{}}},
		"same event twice": {Effect: EffectMessage, Summary: "x", DerivedFrom: []Origin{duplicate, duplicate}},
		"too much lineage": {Effect: EffectMessage, Summary: "x", DerivedFrom: tooManyOrigins()},
	}
	for name, action := range cases {
		t.Run(name, func(t *testing.T) {
			decision, err := Evaluate(Default(), action)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Outcome != Refuse {
				t.Fatalf("expected %q to be refused, got %+v", name, decision)
			}
		})
	}
}

func tooManyOrigins() []Origin {
	origins := make([]Origin, 0, MaxProvenance+1)
	for index := 0; index <= MaxProvenance; index++ {
		origin := testOrigin("1")
		origin.EventID = "evt_" + strings.Repeat("0", 62) + string([]byte{
			"0123456789abcdef"[index>>4], "0123456789abcdef"[index&0xf],
		})
		origins = append(origins, origin)
	}
	return origins
}

// Two renderings of one approval prompt must read the same way, or an owner
// comparing them would see a difference that is not there.
func TestProvenanceIsOrderedStably(t *testing.T) {
	first, second := testOrigin("1"), testOrigin("2")
	forward, err := Evaluate(Default(), testAction(EffectToolCall, first, second))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	backward, err := Evaluate(Default(), testAction(EffectToolCall, second, first))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for index := range forward.Provenance {
		if forward.Provenance[index].EventID != backward.Provenance[index].EventID {
			t.Fatal("the approval prompt depended on the order the runtime listed its sources")
		}
	}
}

// A retired effect name is refused like any unknown effect, whatever the
// policy, so it cannot come back with a meaning nobody reviewed.
func TestRetiredEffectsAreRefused(t *testing.T) {
	if len(RetiredEffects) == 0 {
		t.Fatal("the retired effect list is empty")
	}
	for _, effect := range RetiredEffects {
		if Known(effect) {
			t.Fatalf("retired effect %q is recognised again", effect)
		}
		decision, err := Evaluate(Default(), Action{Effect: effect, Summary: "buy the transcription"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if decision.Outcome != Refuse {
			t.Fatalf("retired effect %q was not refused: %+v", effect, decision)
		}
		if err := (Policy{UnattendedCeiling: EffectMessage, OwnInitiativeCeiling: effect}).Validate(); err == nil {
			t.Fatalf("a policy accepted retired effect %q as a ceiling", effect)
		}
	}
}

func TestActionIdentifierCommitsToolIdempotencyKey(t *testing.T) {
	first := Action{Effect: EffectToolCall, Summary: "invoke scanner",
		IdempotencyKey: "idem_" + strings.Repeat("a", 64)}
	second := first
	second.IdempotencyKey = "idem_" + strings.Repeat("b", 64)
	firstID, err := ActionID(first)
	if err != nil {
		t.Fatalf("first id: %v", err)
	}
	secondID, err := ActionID(second)
	if err != nil {
		t.Fatalf("second id: %v", err)
	}
	if firstID == secondID {
		t.Fatal("distinct tool invocations derived one action identifier")
	}
	if _, err := ActionID(Action{Effect: EffectToolCall, Summary: "invoke scanner", IdempotencyKey: "bad"}); err == nil {
		t.Fatal("a malformed idempotency key was accepted")
	}
}

func TestPhysicalIOAlwaysRequiresExactLocalOneShotApproval(t *testing.T) {
	action := Action{
		Effect: EffectPhysicalIO, Summary: "read local temperature sensor",
		IdempotencyKey: "idem_" + strings.Repeat("a", 64),
		Physical: &PhysicalOperation{CapabilityID: "cap_" + strings.Repeat("b", 64),
			Tool: "i2c", Operation: "read",
			ArgumentsDigest: "sha256:16384135fc236bb03583cf3024b9fb573cc1ae45f908a98d0601d2ab45f8cfbe",
			ArgumentsJSON:   `{"action":"read"}`},
	}
	policy := Policy{UnattendedCeiling: EffectMessage, OwnInitiativeCeiling: EffectPhysicalIO}
	decision, err := Evaluate(policy, action)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Outcome != RequireOwnerApproval {
		t.Fatalf("decision = %+v", decision)
	}
	base, err := ActionID(action)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []Action{action, action, action, action}
	for i := range mutations {
		physical := *action.Physical
		mutations[i].Physical = &physical
	}
	mutations[0].Physical.CapabilityID = "cap_" + strings.Repeat("d", 64)
	mutations[1].Physical.Tool = "spi"
	mutations[2].Physical.Operation = "write"
	mutations[2].Physical.ArgumentsDigest = "sha256:cb9d4afeff142ea54a6895aab73ba70eabad5e43caaf2c4fb7aa6c48a160a197"
	mutations[2].Physical.ArgumentsJSON = `{"action":"write"}`
	mutations[3].Physical.ArgumentsDigest = "sha256:fc8d3bb5fdbbf709135d031562103a482a000d9f0385762020409ca235915f85"
	mutations[3].Physical.ArgumentsJSON = `{"action":"read","length":2}`
	for _, mutation := range mutations {
		got, err := ActionID(mutation)
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Fatalf("physical substitution retained action ID: %+v", mutation.Physical)
		}
	}
}

func TestPhysicalIOShapeFailsClosed(t *testing.T) {
	valid := Action{Effect: EffectPhysicalIO, Summary: "raw I/O",
		IdempotencyKey: "idem_" + strings.Repeat("a", 64),
		Physical: &PhysicalOperation{CapabilityID: "cap_" + strings.Repeat("b", 64), Tool: "i2c",
			Operation: "read", ArgumentsDigest: "sha256:16384135fc236bb03583cf3024b9fb573cc1ae45f908a98d0601d2ab45f8cfbe",
			ArgumentsJSON: `{"action":"read"}`}}
	cases := []Action{valid, valid, valid, valid, valid, valid, valid, valid, valid}
	cases[0].Physical = nil
	cases[1].IdempotencyKey = ""
	for i := 2; i < len(cases); i++ {
		clone := *valid.Physical
		cases[i].Physical = &clone
	}
	cases[2].Physical.CapabilityID = "cap_short"
	cases[3].Physical.Operation = "../../write"
	cases[4].Effect = EffectToolCall
	cases[5].Physical.ArgumentsDigest = "sha256:" + strings.Repeat("f", 64)
	cases[6].Physical.ArgumentsJSON = `{ "action": "read" }`
	cases[7].Physical.ArgumentsJSON = `{"action":"write"}`
	cases[8].Physical.ArgumentsJSON = strings.Repeat("x", MaxPhysicalArgumentsBytes+1)
	for _, candidate := range cases {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("accepted malformed action: %+v", candidate)
		}
	}
}
