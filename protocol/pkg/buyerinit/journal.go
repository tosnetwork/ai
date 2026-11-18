package buyerinit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

// JournalSchema names the init journal.
const JournalSchema = "tos.service.mcp-buyer.init-journal.v1"

const (
	initDirectory  = "init"
	journalFile    = "journal.json"
	policyFile     = "agent-policy.json"
	lockFile       = "init.lock"
	maxJournalSize = 1 << 20
)

// Step states. A step is "sending" from the moment before its message is
// handed to tosctl, so a crash at any later point leaves a record that says
// a message may be in flight.
const (
	stepPending   = ""
	stepSending   = "sending"
	stepFinalized = "finalized"
)

// ChainStep is what the journal knows about one chain message.
type ChainStep struct {
	State       string `json:"state,omitempty"`
	StartedUnix int64  `json:"started_unix,omitempty"`
	Attempts    int    `json:"attempts,omitempty"`
	Checkpoint  uint64 `json:"finalized_checkpoint,omitempty"`
}

func (s ChainStep) sent() bool { return s.State != stepPending || s.Attempts > 0 }

// Identity holds the inputs that determine the buyer's on-chain identity.
type Identity struct {
	NetworkID        string `json:"network_id"`
	GenesisRootHash  string `json:"genesis_root_hash"`
	GenesisFileHash  string `json:"genesis_file_hash"`
	RegistryCodeHash string `json:"registry_code_hash"`
	Wallet           string `json:"wallet"`
	WalletAddress    string `json:"wallet_address"`
	Controller       string `json:"packet_controller"`
	ControllerKeyID  string `json:"packet_controller_key_id"`
}

// Journal is the durable record of init. The Agent nonce is stored before
// the registration is built and the registration before it is sent, so a
// re-run after a crash rebuilds and resolves the same Agent.
type Journal struct {
	Schema       string                            `json:"schema"`
	UpdatedUnix  int64                             `json:"updated_unix"`
	Identity     Identity                          `json:"identity"`
	AgentNonce   string                            `json:"agent_nonce,omitempty"`
	Registration *buyersdk.SignedAgentRegistration `json:"registration,omitempty"`
	Activation   ChainStep                         `json:"activation"`
	Agent        ChainStep                         `json:"agent"`
}

// registered reports whether the journal may already have put an Agent on
// chain.
func (j *Journal) registered() bool { return j.Agent.sent() || j.Registration != nil }

func journalPath(stateDir string) string { return filepath.Join(stateDir, initDirectory, journalFile) }

// loadJournal reads the journal; a missing one is empty.
func loadJournal(stateDir string) (*Journal, error) {
	raw, err := readPrivateFile(journalPath(stateDir), maxJournalSize)
	if errors.Is(err, os.ErrNotExist) {
		return &Journal{Schema: JournalSchema}, nil
	}
	if err != nil {
		return nil, err
	}
	journal := &Journal{}
	if err := jsonstrict.Decode(raw, journal); err != nil {
		return nil, fmt.Errorf("the init journal does not decode strictly: %w", err)
	}
	if journal.Schema != JournalSchema {
		return nil, errors.New("the init journal has another schema")
	}
	if journal.Registration != nil && journal.Registration.Validate() != nil {
		return nil, errors.New("the init journal holds an invalid registration")
	}
	return journal, nil
}

func saveJournal(stateDir string, journal *Journal, now time.Time) error {
	journal.Schema, journal.UpdatedUnix = JournalSchema, now.Unix()
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return errors.New("encode the init journal")
	}
	return writePrivateFile(journalPath(stateDir), encoded)
}
