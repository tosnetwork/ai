package directory

import (
	"time"

	"github.com/tosnetwork/ai/messenger/internal/ids"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/group"
)

// The CheckPeer pin of a room member (sections 2.5, 11.2).
//
// Kind 3 is content, so a room object is sealed and re-deposited to a member
// only after CheckPeer passes on that member's stored evidence, and a
// received object's part-0 evidence is checked the same way. Neither side
// has a 1:1 session pin for a member that is no contact; the pin is the
// Endpoint and device of the member's MLS leaf, as the leaf's
// DeviceCredential bound them. CheckPeer then requires the evidence to be a
// live finalized delegation of that Endpoint whose current set still holds
// that device, so a member whose device a newer descriptor removed, or whose
// Endpoint was withdrawn on chain, gets nothing.

// LeafPin returns the pin of a member from its leaf's DeviceCredential. The
// credential must be the member's own and inside its validity window: an
// expired credential refuses the member's objects not-authentic (D15).
func LeafPin(memberAgentID string, credential group.DeviceCredential, now time.Time) (Pin, error) {
	if !ids.Agent.MatchString(memberAgentID) {
		return Pin{}, fault.New(fault.CodeSenderMismatch, "invalid room member Agent identifier")
	}
	if credential.AgentID != memberAgentID {
		return Pin{}, fault.New(fault.CodeSenderMismatch, "the leaf credential names another Agent than the member")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Pin{}, fault.New(fault.CodeInternal, "invalid leaf pin time")
	}
	if credential.IssuedAtUnix == 0 || credential.ExpiresAtUnix <= credential.IssuedAtUnix {
		return Pin{}, fault.New(fault.CodeNotAuthentic, "the leaf credential has no validity window")
	}
	seconds := uint64(now.Unix())
	if seconds < credential.IssuedAtUnix || seconds >= credential.ExpiresAtUnix {
		return Pin{}, fault.New(fault.CodeNotAuthentic, "the leaf credential is outside its validity window")
	}
	pin := Pin{EndpointID: credential.EndpointID, DeviceID: credential.DeviceID}
	if err := validatePin(pin); err != nil {
		return Pin{}, fault.New(fault.CodeNotAuthentic, "the leaf credential names no Endpoint and device")
	}
	return pin, nil
}
