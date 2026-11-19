package localapi

import (
	"bytes"
	"strings"
	"testing"
)

// The mandate operations are retired. No principal may perform them, the
// request validator does not know them, and no owner can sign for them.
func TestRetiredOperationsAreRefused(t *testing.T) {
	if len(RetiredOperations) == 0 {
		t.Fatal("the retired operation list is empty")
	}
	for _, operation := range RetiredOperations {
		if _, known := operations[operation]; known {
			t.Fatalf("retired operation %q is recognised again", operation)
		}
		for _, principal := range []Principal{PrincipalRuntime, PrincipalOwner} {
			if Permits(principal, operation) {
				t.Fatalf("principal %q may perform retired operation %q", principal, operation)
			}
		}
		if Deciding(operation) {
			t.Fatalf("retired operation %q is an owner decision", operation)
		}
		if _, err := DecisionBytes(Request{Op: operation}, strings.Repeat("a", 64)); err == nil {
			t.Fatalf("an owner preimage was built for retired operation %q", operation)
		}
	}
}

func TestAdmissionInviteDecisionCommitsScopeAndExpiry(t *testing.T) {
	request := Request{
		Op: OpCreateAdmissionInvite, Challenge: strings.Repeat("a", 64),
		InvitedAgentID: "agent_" + strings.Repeat("b", 64), InviteExpiresAtUnix: 1_900_000_000,
	}
	original, err := DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	changedAgent := request
	changedAgent.InvitedAgentID = "agent_" + strings.Repeat("c", 64)
	changedExpiry := request
	changedExpiry.InviteExpiresAtUnix++
	for name, changed := range map[string]Request{"agent": changedAgent, "expiry": changedExpiry} {
		encoded, err := DecisionBytes(changed, changed.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(original, encoded) {
			t.Fatalf("%s substitution retained owner signature preimage", name)
		}
	}
}
