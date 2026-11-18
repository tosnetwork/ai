package railwork

import (
	"bytes"
)

// Message is a complete, digest-checked rail message from one verified
// sender (the Agent Packet's sender_agent_id).
type Message struct {
	SenderAgentID string
	Kind          Kind
	Binding       Binding
	MessageDigest [32]byte
	Body          []byte
	// Packet is the capability_id and quote_commitment every frame of the
	// message arrived with (section 2.1).
	Packet PacketFields
}

// PacketFields are the Agent Packet fields a frame arrived with: the
// purchased Capability and the Accepted Quote commitment (section 2.1).
// The sender sets them; the receiver compares them with the request
// (Admission.CheckPacketFields, CheckPacketFields).
type PacketFields struct {
	CapabilityID    string
	QuoteCommitment string
}

func (p PacketFields) valid() bool {
	return capabilityPattern.MatchString(p.CapabilityID) && quoteCommitmentPattern.MatchString(p.QuoteCommitment)
}

// Identity is how a receiver identifies a message (section 9): frames of
// the same identity assemble into one message, and a fresh delivery of the
// same bytes has the same identity.
type Identity struct {
	SenderAgentID string
	Kind          Kind
	Binding       Binding
	MessageDigest [32]byte
}

// IdentityOf is the identity of a frame from a verified sender.
func IdentityOf(senderAgentID string, frame Frame) Identity {
	return Identity{SenderAgentID: senderAgentID, Kind: frame.Kind, Binding: frame.Binding, MessageDigest: frame.MessageDigest}
}

// Assembly collects the frames of one message in memory. A runtime that
// must survive a crash between acknowledging a packet and processing its
// message stores frames durably instead (section 9); the refusal rules are
// the same. One Assembly holds one message: bounding how many open
// assemblies a receiver keeps (OpenFox keeps at most 8 per sender and 64 in
// total, refused as inbox-full) is the caller's job. It records the packet
// fields of the first frame and refuses a later frame whose packet names
// others (section 3.3).
type Assembly struct {
	identity Identity
	packet   PacketFields
	total    uint32
	chunks   [][]byte
	held     int
}

// NewAssembly starts an assembly with its first frame and the packet fields
// it arrived with.
func NewAssembly(senderAgentID string, packet PacketFields, first Frame) (*Assembly, error) {
	if !agentIDPattern.MatchString(senderAgentID) {
		return nil, refuse(RefusalPacketInvalid, "the sender is not an Agent ID")
	}
	if !packet.valid() {
		return nil, refuse(RefusalPacketInvalid, "the packet does not name a Capability and an Accepted Quote")
	}
	if err := validateFrame(first); err != nil {
		return nil, err
	}
	assembly := &Assembly{
		identity: IdentityOf(senderAgentID, first), packet: packet, total: first.TotalLength,
		chunks: make([][]byte, first.Count),
	}
	if _, err := assembly.Add(packet, first); err != nil {
		return nil, err
	}
	return assembly, nil
}

// Identity is the identity of the assembled message.
func (a *Assembly) Identity() Identity {
	return a.identity
}

// Packet is the packet fields the assembly's frames arrived with.
func (a *Assembly) Packet() PacketFields {
	return a.packet
}

// Add stores one frame and the packet fields it arrived with, and reports
// whether every index is now held. A repeated frame with the same bytes
// changes nothing; one with other bytes for a held index, or arriving in a
// packet that names other fields, is refused as frame-conflict.
func (a *Assembly) Add(packet PacketFields, frame Frame) (bool, error) {
	if a == nil || a.chunks == nil {
		return false, refuse(RefusalJoinInvalid, "no assembly")
	}
	if packet != a.packet {
		return false, refuse(RefusalFrameConflict, "the frame's packet names another Capability or Accepted Quote")
	}
	if err := validateFrame(frame); err != nil {
		return false, err
	}
	if IdentityOf(a.identity.SenderAgentID, frame) != a.identity || frame.TotalLength != a.total ||
		int(frame.Count) != len(a.chunks) {
		return false, refuse(RefusalJoinInvalid, "the frame belongs to another message")
	}
	if held := a.chunks[frame.Index]; held != nil {
		if !bytes.Equal(held, frame.Data) {
			return false, refuse(RefusalFrameConflict, "a frame differs from the held frame of its index")
		}
		return a.held == len(a.chunks), nil
	}
	a.chunks[frame.Index] = bytes.Clone(frame.Data)
	a.held++
	return a.held == len(a.chunks), nil
}

// Message joins a complete assembly. A set whose bytes do not hash to the
// message digest is refused as join-invalid; the receiver discards it and
// waits for a fresh delivery.
func (a *Assembly) Message() (Message, error) {
	if a == nil || a.chunks == nil {
		return Message{}, refuse(RefusalJoinInvalid, "no assembly")
	}
	frames := make([]Frame, 0, len(a.chunks))
	for index, chunk := range a.chunks {
		if chunk == nil {
			return Message{}, refuse(RefusalJoinInvalid, "the frame set is incomplete")
		}
		frames = append(frames, Frame{
			Kind: a.identity.Kind, Binding: a.identity.Binding, MessageDigest: a.identity.MessageDigest,
			TotalLength: a.total, Index: uint8(index), Count: uint8(len(a.chunks)), Data: chunk,
		})
	}
	body, err := JoinFrames(frames)
	if err != nil {
		return Message{}, err
	}
	return Message{
		SenderAgentID: a.identity.SenderAgentID, Kind: a.identity.Kind, Binding: a.identity.Binding,
		MessageDigest: a.identity.MessageDigest, Body: body, Packet: a.packet,
	}, nil
}
