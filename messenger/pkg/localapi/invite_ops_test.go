package localapi

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/fault"
)

const presentedToken = "invite_" + "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

func presentRequest(token string, expires uint64) Request {
	return Request{Op: OpPresentInvite, InviteRecipientAgentID: senderID, InviteToken: token, InviteExpiresAtUnix: expires}
}

// invites.present and contacts.remove are owner decisions: the runtime is
// refused even with an owner-shaped signature, and the owner's signature
// commits the exact token.
func TestInviteOperationsAreOwnerOnlyAndSigned(t *testing.T) {
	h := newHarness(t)
	expires := uint64(h.clock.Add(time.Hour).Unix())
	for _, request := range []Request{presentRequest(presentedToken, expires), {Op: OpRemoveContact, ContactAgentID: senderID}} {
		if response := h.runtimeAttempt(t, request); response.OK || response.Code != fault.CodeClassNotDelegated {
			t.Fatalf("runtime %s: %+v", request.Op, response)
		}
		if Permits(PrincipalRuntime, request.Op) || !Permits(PrincipalOwner, request.Op) || !Deciding(request.Op) {
			t.Fatalf("%s is not an owner decision", request.Op)
		}
	}

	// A signature over one token does not authorize another.
	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	signed := presentRequest(presentedToken, expires)
	signature, err := SignDecision(signed, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatal(err)
	}
	changed := presentRequest("invite_"+strings.Repeat("B", 43), expires)
	changed.Challenge, changed.OwnerSignature = issued.Challenge, signature
	if response := h.callAs(t, PrincipalOwner, changed); response.OK || response.Code != fault.CodeNotAuthentic {
		t.Fatalf("a signature over another token was accepted: %+v", response)
	}
	if _, found, _ := h.journal.PresentedInviteFor(senderID, h.clock); found {
		t.Fatal("a refused presentation stored a token")
	}
	if response := h.owner(t, presentRequest(presentedToken, expires)); !response.OK {
		t.Fatalf("present: %+v", response)
	}
	if token, found, err := h.journal.PresentedInviteFor(senderID, h.clock); err != nil || !found || token != presentedToken {
		t.Fatalf("presented: %v %v", found, err)
	}
	// An invalid presentation is the owner's input error, not an internal one.
	if response := h.owner(t, presentRequest(presentedToken, uint64(h.clock.Unix()))); response.OK || response.Code != fault.CodePayloadMalformed {
		t.Fatalf("expired presentation: %+v", response)
	}
	if response := h.owner(t, Request{Op: OpRemoveContact, ContactAgentID: senderID}); response.OK || response.Code != fault.CodePayloadMalformed {
		t.Fatalf("removing a contact that is none: %+v", response)
	}
}
