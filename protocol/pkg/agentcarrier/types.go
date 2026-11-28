// Package agentcarrier carries opaque, signed packets over V2 relays. Business
// admission and durable inbox processing belong to the lane, not the carrier.
package agentcarrier

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type Kind string

const (
	Rail Kind = "rail"
	Chat Kind = "chat"
)
const (
	MaxKeys           = 16
	DefaultOutbox     = 256
	MaxOutbox         = 4096
	MaxRecordBytes    = 2 << 20
	MaxPacketBytes    = agentpacketseal.MaxEnvelopeBytes
	MaxPollRelays     = 32
	MaxEnvelopeMemory = 8192
	KeyLifetime       = 7 * 24 * time.Hour
	SuccessorLead     = 48 * time.Hour
	KeyRetention      = 24*time.Hour + 300*time.Second
	CallTimeout       = 30 * time.Second
	PollInterval      = 15 * time.Second
)

var (
	ErrConfig           = errors.New("carrier-config")
	ErrStorage          = errors.New("carrier-storage")
	ErrCapacity         = errors.New("carrier-capacity")
	ErrConflict         = errors.New("carrier-conflict")
	ErrNoRoute          = errors.New("no-route")
	ErrPeerRevoked      = errors.New("peer-revoked")
	ErrTransportRevoked = errors.New("transport-revoked")
	ErrUnavailable      = errors.New("carrier-unavailable")
	ErrRefused          = errors.New("packet-refused")
	ErrExpired          = errors.New("retention-exceeded")
)

// Relay deliberately has the V2 signatures. The retired client cannot satisfy
// it. A factory must return a transport with bounded calls and no redirects.
type Relay interface {
	Describe(context.Context) (agentpacketrelay.V2Description, error)
	Deposit(context.Context, []byte, []byte, ed25519.PrivateKey) error
	List(context.Context, string, []byte, ed25519.PrivateKey) ([]agentpacketrelay.V2MailboxEntry, error)
	ListWait(context.Context, string, []byte, ed25519.PrivateKey, int) ([]agentpacketrelay.V2MailboxEntry, error)
	Fetch(context.Context, string, [32]byte, []byte, ed25519.PrivateKey) ([]byte, error)
	Acknowledge(context.Context, string, [32]byte) error
}

var _ Relay = (*agentpacketrelay.V2Client)(nil)

type Credential struct {
	Wire   []byte
	Holder ed25519.PrivateKey
}

// Credentials are supplied by the credential manager. Part 1 does not issue,
// persist or refresh them. A missing contact credential means stranger deposit.
type Credentials interface {
	Owner(context.Context, string) (Credential, error)
	Contact(context.Context, string, string) (Credential, bool, error)
	DropContact(context.Context, string, string) error
}

// CardVerifier must call the finalized key-card verifier and honor ctx. It is
// run at every use; no serialized "verified" flag is trusted after restart.
type CardVerifier func(context.Context, []byte, time.Time) (agentpacketseal.RecipientKey, agentpacketseal.KeyCard, error)
type CardSigner func(context.Context, agentpacketseal.KeyCard) ([]byte, error)

// PacketVerifier applies finalized packet verification. Only ErrRefused marks
// a permanent refusal; read failures are transient. Store must return nil only
// after its durable inbox write (a durable duplicate is success).
type PacketVerifier func(context.Context, agentpacket.Packet) error
type Inbox func(context.Context, []byte) error

type Config struct {
	StateDir     string
	AgentID      string
	Kind         Kind
	Relays       []string
	Delegation   []byte
	Verifier     *agenttransport.Verifier
	HintPolicy   agenttransport.HintPolicy
	VerifyObject agenttransport.ObjectVerifier
	Credentials  Credentials
	Relay        func(string) (Relay, error)
	SignCard     CardSigner
	VerifyCard   CardVerifier
	VerifyPacket PacketVerifier
	Store        Inbox
	Now          func() time.Time
	OutboxLimit  int
}

type OwnCard struct {
	Packet []byte
	Card   agentpacketseal.KeyCard
}

// Raw routes, never a card's relay list, are the only outbound routing input.
type Route struct {
	HintRecord []byte
	CardPacket []byte
}
type DeliveryView struct {
	State       string
	Code        string
	Generations int
}
type AttemptResult struct {
	Accepted        bool
	RelayTTLSeconds uint64
	Code            string
}
type PollView struct {
	Listed, Stored, Refused, Acknowledged int
	Code                                  string
}
