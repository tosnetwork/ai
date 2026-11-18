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
// total, refused as inbox-full) is the caller's job.
type Assembly struct {
	identity Identity
	total    uint32
	chunks   [][]byte
	held     int
}

// NewAssembly starts an assembly with its first frame.
func NewAssembly(senderAgentID string, first Frame) (*Assembly, error) {
	if !agentIDPattern.MatchString(senderAgentID) {
		return nil, refuse(RefusalPacketInvalid, "the sender is not an Agent ID")
	}
	if err := validateFrame(first); err != nil {
		return nil, err
	}
	assembly := &Assembly{
		identity: IdentityOf(senderAgentID, first), total: first.TotalLength,
		chunks: make([][]byte, first.Count),
	}
	if _, err := assembly.Add(first); err != nil {
		return nil, err
	}
	return assembly, nil
}

// Identity is the identity of the assembled message.
func (a *Assembly) Identity() Identity {
	return a.identity
}

// Add stores one frame and reports whether every index is now held. A
// repeated frame with the same bytes changes nothing; one with other bytes
// for a held index is refused as frame-conflict.
func (a *Assembly) Add(frame Frame) (bool, error) {
	if a == nil || a.chunks == nil {
		return false, refuse(RefusalJoinInvalid, "no assembly")
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
		MessageDigest: a.identity.MessageDigest, Body: body,
	}, nil
}
