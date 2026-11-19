// Package purchaseevidence verifies one Service Actor purchase from public
// inputs and quorum-finalized state, and defines the evidence bundle a buyer
// exports for that verification.
//
// The verification signs nothing and needs no key. It reads, at one
// finalized checkpoint, the actor account (which must run the pinned release
// code), the actor's complete transaction history replayed and reconciled
// with its state and getters, and each selected request's call and outcome
// (respond, or expire, claim_refund or sweep). Files the buyer supplies, a
// Receipt, an artifact and an evidence bundle, are untrusted: each is
// checked against finalized state and the Receipt, never believed.
package purchaseevidence

import (
	"errors"
	"fmt"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// Schemas of the documents this package reads and writes.
const (
	BundleSchema  = "tos.service.purchase-evidence.v1"
	VerdictSchema = "tos.service.purchase-verdict.v1"
)

// Bounds of the inputs a verification reads.
const (
	// MaxBundleBytes bounds an evidence bundle file.
	MaxBundleBytes = 8 << 20
	// MaxSelected bounds the requests one verification selects.
	MaxSelected = 64
	// MaxLifecycleEntries bounds the journaled lifecycle sends of a bundle.
	MaxLifecycleEntries = 64
)

// Evidence file names in an exported bundle directory.
const (
	BundleFile   = "evidence.json"
	ReceiptFile  = "receipt.boc"
	ArtifactFile = "artifact.tar"
)

// NetworkTuple is the network a document is bound to.
type NetworkTuple struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

// Tool names the build that wrote a document.
type Tool struct {
	Name        string `json:"name"`
	Module      string `json:"module,omitempty"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSModified bool   `json:"vcs_modified,omitempty"`
	GoVersion   string `json:"go_version,omitempty"`
}

// Bundle is a purchase's evidence as its buyer exports it (schema
// BundleSchema). It holds no secret: no key, seed, vault URL, token,
// confirmation code, execution nonce or idempotency key, and not the buyer's
// source, only its digest. Every value in it is a claim the verification
// checks against finalized state, the Quote and the Receipt.
type Bundle struct {
	Schema       string       `json:"schema"`
	Tool         Tool         `json:"tool"`
	ExportedUnix int64        `json:"exported_unix"`
	Network      NetworkTuple `json:"network"`
	// The buyer's endpoints and quorum are deliberately absent: they are
	// the buyer's private configuration, and a verifier brings its own.
	RegistryCodeHash string  `json:"registry_code_hash"`
	ActorCodeHash    string  `json:"actor_code_hash"`
	Actor            string  `json:"actor"`
	BuyerWallet      string  `json:"buyer_wallet"`
	BuyerAgentID     string  `json:"buyer_agent_id"`
	Offer            Offer   `json:"offer"`
	Quote            Quote   `json:"quote"`
	Request          Request `json:"request"`
	Journal          Journal `json:"journal"`
	Result           Result  `json:"result"`
	Budget           Budget  `json:"budget"`
	// Finalized is the buyer's own verification at export, absent when
	// none was made.
	Finalized *Finalized `json:"finalized,omitempty"`
}

// Offer is the verified offer the purchase was prepared against.
type Offer struct {
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	ManifestDigest    string `json:"manifest_digest"`
	ToolchainDigest   string `json:"toolchain_digest"`
	ProviderAgentID   string `json:"provider_agent_id"`
	RetentionSeconds  uint64 `json:"retention_seconds"`
}

// Quote is the Quote package the buyer accepted and what it commits to.
type Quote struct {
	// PackageBase64 is the deterministic protobuf QuoteProposalPackageV1.
	PackageBase64            string `json:"package_base64"`
	RequestBuyerAddress      string `json:"request_buyer_address"`
	AcceptedQuoteBOC         string `json:"accepted_quote_boc"`
	QuoteCommitment          string `json:"quote_commitment"`
	TermsHash                string `json:"terms_hash"`
	PolicyVersion            uint32 `json:"policy_version"`
	PriceNanoTOS             string `json:"price_nanotos"`
	StorageFeeNanoTOS        string `json:"storage_fee_nanotos"`
	PaymentNanoTOS           string `json:"payment_nanotos"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	ExpiresAtUnixSeconds     uint64 `json:"expires_at_unix_seconds"`
	AttestorKeyID            string `json:"attestor_key_id"`
}

// Request is the request commitment of the call.
type Request struct {
	RequestHash string `json:"request_hash"`
	ExecutionID string `json:"execution_id"`
	InputDigest string `json:"input_digest"`
	// SourceDigest is the sha256:<hex> digest of the source archive.
	SourceDigest string `json:"source_digest"`
	SourceBytes  int    `json:"source_bytes"`
}

// Journal is what the buyer's call journal records of the purchase.
type Journal struct {
	Phase           string              `json:"phase"`
	QueryID         string              `json:"query_id"`
	CreatedUnix     int64               `json:"created_unix"`
	SentUnix        int64               `json:"sent_unix,omitempty"`
	RequestID       *uint64             `json:"request_id,omitempty"`
	CallTransaction *toschain.ActorTxID `json:"call_transaction,omitempty"`
	ExitCode        int32               `json:"exit_code,omitempty"`
	Lifecycle       []LifecycleEntry    `json:"lifecycle,omitempty"`
}

// LifecycleEntry is one journaled expire, claim_refund or sweep send.
type LifecycleEntry struct {
	Operation   string `json:"operation"`
	QueryID     string `json:"query_id"`
	Phase       string `json:"phase"`
	SentUnix    int64  `json:"sent_unix"`
	MessageHash string `json:"message_hash,omitempty"`
}

// Result is the result the buyer accepted, if any.
type Result struct {
	Accepted     bool        `json:"accepted"`
	AcceptedUnix int64       `json:"accepted_unix,omitempty"`
	ResponseHash string      `json:"response_hash,omitempty"`
	Receipt      *FileDigest `json:"receipt_file,omitempty"`
	Artifact     *FileDigest `json:"artifact_file,omitempty"`
	// Members are the artifact's output.log and report.json.
	Members        []FileDigest `json:"artifact_members,omitempty"`
	ResultDigest   string       `json:"result_digest,omitempty"`
	ArtifactDigest string       `json:"artifact_digest,omitempty"`
	ReportDigest   string       `json:"report_digest,omitempty"`
}

// FileDigest names a file by its SHA-256 and size.
type FileDigest struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// Budget is the buyer's spending policy at export.
type Budget struct {
	WindowSeconds     int64  `json:"window_seconds"`
	MaxCalls          int    `json:"max_calls"`
	MaxPerCallNanoTOS string `json:"max_per_call_nanotos"`
	MaxWindowNanoTOS  string `json:"max_window_nanotos"`
	MaxUnconfirmed    int    `json:"max_unconfirmed"`
	MaxLifecycleSends int    `json:"max_lifecycle_sends_per_window"`
}

// Finalized is the request as one finalized checkpoint showed it.
type Finalized struct {
	Checkpoint Checkpoint    `json:"checkpoint"`
	Request    RequestReport `json:"request"`
}

// DecodeBundle decodes an evidence bundle strictly: unknown fields,
// duplicate keys and trailing data are refused, and so is a document over
// its bounds or of another schema.
func DecodeBundle(raw []byte) (*Bundle, error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return nil, errors.New("the evidence bundle is outside its bounds")
	}
	var bundle Bundle
	if err := jsonstrict.Decode(raw, &bundle); err != nil {
		return nil, fmt.Errorf("the evidence bundle does not decode strictly: %w", err)
	}
	if bundle.Schema != BundleSchema {
		return nil, errors.New("the evidence bundle names another schema")
	}
	if len(bundle.Journal.Lifecycle) > MaxLifecycleEntries || len(bundle.Result.Members) > 2 {
		return nil, errors.New("the evidence bundle is outside its bounds")
	}
	return &bundle, nil
}
