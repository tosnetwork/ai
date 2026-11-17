package railwork

import (
	"crypto/sha256"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
	"google.golang.org/protobuf/proto"
)

// Provider names the provider a task must be admitted by: its network, its
// own Agent and the Capability version it offers.
type Provider struct {
	Network      *nativev1.NetworkDomain
	AgentID      string
	CapabilityID string
	Version      string
}

// Admission is a task that passed the checks of section 7.1 that need no
// chain access (items 1 to 4), with the values the finalized-state check
// (item 5) and the frame binding check (item 6) use. Every value is derived
// from the task and its Quote package, never taken from the buyer's word.
type Admission struct {
	Message Message
	Task    Task
	Package *nativev1.QuoteProposalPackageV1
	Quote   *quoteexchange.Validated
	// QuoteHash and QuoteCommitment are the Accepted Quote's cell hash and
	// its tvm-cell-sha256 text.
	QuoteHash       [32]byte
	QuoteCommitment string
	ExecutionID     [32]byte
	SourceDigest    [32]byte
	InputDigest     [32]byte
	// RequestHash is the request hash of section 6.3: the one the paid call
	// must carry.
	RequestHash [32]byte
	// Actor is the quoted Service Actor's raw address.
	Actor string
}

// Slot is the provider's at-most-once execution slot of a request
// (section 7.1 item 7).
type Slot struct {
	QuoteCommitment string
	Actor           string
	RequestID       uint64
}

// Slot is the admission's execution slot.
func (a *Admission) Slot() Slot {
	return Slot{QuoteCommitment: a.QuoteCommitment, Actor: a.Actor, RequestID: a.Task.Header.RequestID}
}

func notAdmitted(reason string) error {
	return refuse(RefusalTaskNotAdmitted, reason)
}

func (p Provider) valid() bool {
	return p.Network != nil && agentIDPattern.MatchString(p.AgentID) && capabilityPattern.MatchString(p.CapabilityID) &&
		p.Version != "" && len(p.Version) <= MaxCapabilityVersionBytes
}

// CheckTask decodes a complete task message and runs section 7.1 items 1
// to 4: the sender is the task's buyer and the frames name the header's
// request; the Quote package validates for this provider, Capability,
// version and the buyer's wallet; the Quote delivers to this provider as
// Agent Packets and admits the archive's size; the execution ID opens to the
// buyer Agent. A malformed task is refused as message-invalid, any other
// failure as task-not-admitted. It reads no chain state: the caller must
// still establish item 5 from one finalized checkpoint, then call
// CheckVerifiedBinding (item 6) and claim the slot once (item 7).
func (p Provider) CheckTask(message Message) (*Admission, error) {
	if !p.valid() {
		return nil, ErrInvalidInput
	}
	if message.Kind != KindTask {
		return nil, notAdmitted("the message is not a task")
	}
	task, err := DecodeTask(message.Body)
	if err != nil {
		return nil, err
	}
	header := task.Header
	if message.SenderAgentID != header.BuyerAgentID {
		return nil, notAdmitted("the task comes from another Agent than its buyer")
	}
	if message.Binding.RequestID != header.RequestID {
		return nil, notAdmitted("the task frames name another request than the header")
	}
	pkg := &nativev1.QuoteProposalPackageV1{}
	if err = proto.Unmarshal(task.Package, pkg); err != nil || pkg.GetProposal() == nil {
		return nil, notAdmitted("the task Quote package does not decode")
	}
	proposal := pkg.GetProposal()
	if proposal.GetCapabilityId() != p.CapabilityID || proposal.GetCapabilityVersion() != p.Version ||
		proposal.GetProviderAgentId() != p.AgentID {
		return nil, notAdmitted("the Quote names another provider, Capability or version")
	}
	validated, err := quoteexchange.ValidatePortable(p.Network, &nativev1.RequestQuoteProposalRequest{
		CapabilityId: header.CapabilityID, CapabilityVersion: header.CapabilityVersion, BuyerAddress: header.BuyerWallet,
	}, pkg)
	if err != nil {
		return nil, refuseWith(RefusalTaskNotAdmitted, "the Quote package does not validate", err)
	}
	recipient, err := validated.TransportBinding.AgentPacketRecipient()
	if err != nil || recipient != p.AgentID {
		return nil, notAdmitted("the Quote does not deliver work to this provider as Agent Packets")
	}
	if uint64(len(task.Archive)) > uint64(validated.TransportBinding.MaxRequestBytes) ||
		len(task.Archive) > MaxInlineInputBytes {
		return nil, notAdmitted("the source archive exceeds the quoted request bound")
	}
	executionID, ok := decodeHex32(header.ExecutionID)
	if !ok {
		return nil, notAdmitted("invalid execution ID")
	}
	nonce, ok := decodeHex32(header.ExecutionNonce)
	if !ok {
		return nil, notAdmitted("invalid execution nonce")
	}
	committed, err := ExecutionID(header.BuyerAgentID, nonce)
	if err != nil || committed != executionID {
		return nil, notAdmitted("the execution ID does not commit to the task's buyer Agent")
	}
	quoteHash, commitment, err := QuoteCommitment(p.Network, validated.Proposal)
	if err != nil {
		return nil, refuseWith(RefusalTaskNotAdmitted, "the Accepted Quote does not build", err)
	}
	sourceDigest := sha256.Sum256(task.Archive)
	inputDigest := InputDigest(sourceDigest)
	requestHash, err := RequestHash(quoteHash, executionID, inputDigest)
	if err != nil {
		return nil, refuseWith(RefusalTaskNotAdmitted, "the request hash does not build", err)
	}
	return &Admission{
		Message: message, Task: task, Package: pkg, Quote: validated,
		QuoteHash: quoteHash, QuoteCommitment: commitment, ExecutionID: executionID,
		SourceDigest: sourceDigest, InputDigest: inputDigest, RequestHash: requestHash,
		Actor: validated.Rail.Actor,
	}, nil
}

// CheckVerifiedBinding is section 7.1 item 6: the task's frames must be
// bound to the actor and request hash that finalized state verified. The
// caller passes the values its finalized-state check established.
func (a *Admission) CheckVerifiedBinding(verifiedActor string, verifiedRequestHash [32]byte) error {
	if a == nil {
		return ErrInvalidInput
	}
	if !walletPattern.MatchString(verifiedActor) || verifiedRequestHash == ([32]byte{}) {
		return ErrInvalidInput
	}
	if a.Message.Binding.RequestHash != verifiedRequestHash || a.Message.Binding.Actor() != verifiedActor {
		return notAdmitted("the task frames are bound to another request than the verified one")
	}
	return nil
}

// FrameBindingMatchesQuote reports whether the task's frames carry the
// request hash and actor derived from the task and its Quote. It is the
// item 6 comparison against derived rather than verified values, available
// before any slot is claimed (section 15, Q3).
func (a *Admission) FrameBindingMatchesQuote() bool {
	return a != nil && a.Message.Binding.RequestHash == a.RequestHash && a.Message.Binding.Actor() == a.Actor
}
