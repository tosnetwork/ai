package provideragent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// Library is the part of the rail node library the agent calls besides the
// pause functions, which act on the state directory directly. Every call
// reloads the rail configuration, so an offer applied by the agent is seen
// at once. Tests replace it; Rail is the real one.
type Library interface {
	Config() (servicebridge.NodeConfig, error)
	Status(ctx context.Context, now time.Time) (*servicebridge.ProviderStatus, error)
	Preflight(ctx context.Context) *servicebridge.PreflightReport
	Offer(ctx context.Context, in servicebridge.OfferInput) (*servicebridge.OfferResult, error)
	Withdraw(ctx context.Context, in servicebridge.WithdrawInput) (*servicebridge.WithdrawResult, error)
	Withdrawals() ([]servicebridge.WithdrawalRecord, error)
	ProviderRecords() ([]servicebridge.ProviderRecord, error)
	WalletBalance(ctx context.Context) (servicebridge.WalletBalance, error)
	DescribeOffer(ctx context.Context, offerPath string) (*OfferDescription, error)
	OfferFile(offerPath string) ([]byte, error)
}

// OfferDescription is the offer the node keeps, checked against finalized
// state at one checkpoint (section 4.7).
type OfferDescription struct {
	CapabilityID         string                          `json:"capability_id"`
	CapabilityVersion    string                          `json:"capability_version"`
	ProviderAgentID      string                          `json:"provider_agent_id"`
	Actor                string                          `json:"actor"`
	ManifestDigest       string                          `json:"manifest_digest"`
	ToolchainDigest      string                          `json:"toolchain_digest"`
	Limits               nativecore.SoftwareWorkLimitsV1 `json:"limits"`
	RetentionSeconds     uint64                          `json:"retention_seconds"`
	AttestorKeyID        string                          `json:"attestor_key_id"`
	Policy               *FinalizedPolicy                `json:"finalized_policy"`
	OfferFileSHA256      string                          `json:"offer_file_sha256"`
	KeyCardNotBefore     uint64                          `json:"key_card_not_before_unix,omitempty"`
	KeyCardNotAfter      uint64                          `json:"key_card_not_after_unix,omitempty"`
	Checkpoint           uint64                          `json:"checkpoint"`
	UntrustedName        string                          `json:"untrusted_name"`
	UntrustedDescription string                          `json:"untrusted_description"`
}

// FinalizedPolicy is the actor's policy as finalized state holds it.
type FinalizedPolicy struct {
	PriceNanoTOS             string `json:"price_nanotos"`
	StorageFeeNanoTOS        string `json:"storage_fee_nanotos"`
	CleanupBountyNanoTOS     string `json:"cleanup_bounty_nanotos"`
	ResponseSLASeconds       uint32 `json:"response_sla_seconds"`
	RefundClaimWindowSeconds uint32 `json:"refund_claim_window_seconds"`
	PolicyVersion            uint32 `json:"policy_version"`
	TermsHash                string `json:"terms_hash"`
	Active                   bool   `json:"active"`
	OpenAccess               bool   `json:"open_access"`
}

// errNotOffered reports a node whose offer is not published yet.
var errNotOffered = errors.New("the node has no published offer")

// Rail is the real Library over one rail configuration file.
type Rail struct {
	Path string
	// Report receives the library's diagnostic lines (previews, progress).
	Report func(line string)
}

// Config implements Library.
func (r Rail) Config() (servicebridge.NodeConfig, error) { return servicebridge.LoadNodeConfig(r.Path) }

func (r Rail) env() servicebridge.SetupEnv { return servicebridge.SetupEnv{Report: r.Report} }

// Status implements Library: the status report with a finalized read.
func (r Rail) Status(ctx context.Context, now time.Time) (*servicebridge.ProviderStatus, error) {
	config, err := r.Config()
	if err != nil {
		return nil, err
	}
	if config.Provider == nil {
		return nil, errNotOffered
	}
	chain, err := servicebridge.OpenStatusChain(config)
	if err != nil {
		chain = servicebridge.UnavailableStatusChain(fmt.Errorf("open the finalized reader: %w", err))
	}
	return servicebridge.ReadProviderStatus(ctx, config, chain, now)
}

// Preflight implements Library.
func (r Rail) Preflight(ctx context.Context) *servicebridge.PreflightReport {
	if c, err := r.Config(); err == nil && c.Token != nil && c.Provider == nil {
		return servicebridge.TokenPreflight(ctx, c, servicebridge.TokenEnv{SetupEnv: r.env()})
	}
	return servicebridge.RunPreflight(ctx, r.Path, servicebridge.PreflightEnv{})
}

// Offer implements Library.
func (r Rail) Offer(ctx context.Context, in servicebridge.OfferInput) (*servicebridge.OfferResult, error) {
	in.RailConfigPath = r.Path
	return servicebridge.RunOffer(ctx, in, r.env())
}

// Withdraw implements Library.
func (r Rail) Withdraw(ctx context.Context, in servicebridge.WithdrawInput) (*servicebridge.WithdrawResult, error) {
	in.RailConfigPath = r.Path
	return servicebridge.RunWithdraw(ctx, in, r.env())
}

// Withdrawals implements Library.
func (r Rail) Withdrawals() ([]servicebridge.WithdrawalRecord, error) {
	config, err := r.Config()
	if err != nil {
		return nil, err
	}
	return servicebridge.ReadWithdrawals(config.StateDir)
}

// ProviderRecords implements Library.
func (r Rail) ProviderRecords() ([]servicebridge.ProviderRecord, error) {
	config, err := r.Config()
	if err != nil {
		return nil, err
	}
	if config.Provider == nil {
		return nil, nil
	}
	return servicebridge.ReadProviderRecords(config.StateDir)
}

func (r Rail) session(ctx context.Context, config servicebridge.NodeConfig) (*toschain.ServiceActorSession, error) {
	chain, err := servicebridge.OpenStatusChain(config)
	if err != nil {
		return nil, err
	}
	reader, ok := chain.(servicebridge.ReaderStatusChain)
	if !ok || reader.Reader == nil {
		return nil, errors.New("the finalized reader did not open")
	}
	return reader.Reader.Begin(ctx)
}

// WalletBalance implements Library: the owner wallet's balance at a
// strict-majority finalized checkpoint.
func (r Rail) WalletBalance(ctx context.Context) (servicebridge.WalletBalance, error) {
	config, err := r.Config()
	if err != nil {
		return servicebridge.WalletBalance{}, err
	}
	session, err := r.session(ctx, config)
	if err != nil {
		return servicebridge.WalletBalance{}, errors.New(servicebridge.RedactEndpoints(err.Error(), config.RPCEndpoints))
	}
	return servicebridge.ReadWalletBalance(ctx, session, config.WalletAddress)
}

// offerPathOf is where the node's offer file is: the provider section's
// record of it, else the operator's configured path, else the library's
// default.
func offerPathOf(config servicebridge.NodeConfig, configured string) string {
	if config.Provider != nil && config.Provider.OfferFile != "" {
		return config.Provider.OfferFile
	}
	if configured != "" {
		return configured
	}
	return filepath.Join(config.StateDir, "setup", "offer.json")
}

// maxOfferFileBytes bounds the offer file the agent hands out.
const maxOfferFileBytes = 256 << 10

// OfferFile implements Library: the offer file's bytes, after it decodes.
func (r Rail) OfferFile(offerPath string) ([]byte, error) {
	config, err := r.Config()
	if err != nil {
		return nil, err
	}
	if config.Provider == nil {
		return nil, errNotOffered
	}
	path := offerPathOf(config, offerPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxOfferFileBytes {
		return nil, errors.New("the offer file is not a bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := servicebridge.DecodeOfferFile(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// DescribeOffer implements Library.
func (r Rail) DescribeOffer(ctx context.Context, offerPath string) (*OfferDescription, error) {
	config, err := r.Config()
	if err != nil {
		return nil, err
	}
	raw, err := r.OfferFile(offerPath)
	if err != nil {
		return nil, err
	}
	offer, err := servicebridge.DecodeOfferFile(raw)
	if err != nil {
		return nil, err
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(offer.ManifestCBOR)
	if err != nil {
		return nil, fmt.Errorf("the offer's manifest does not decode: %w", err)
	}
	if len(manifest.Settlement.ActorAccountID) != 32 {
		return nil, errors.New("the offer's manifest names no actor")
	}
	sum := sha256.Sum256(raw)
	description := &OfferDescription{CapabilityID: offer.CapabilityID, CapabilityVersion: offer.Version,
		ProviderAgentID: offer.ProviderAgentID, Actor: "0:" + hex.EncodeToString(manifest.Settlement.ActorAccountID),
		ManifestDigest: offer.ManifestDigest, ToolchainDigest: manifest.ToolchainDigest, Limits: manifest.Limits,
		RetentionSeconds: manifest.RetentionSeconds, AttestorKeyID: manifest.ExecutionSignerAuthorization,
		OfferFileSHA256: hex.EncodeToString(sum[:]), UntrustedName: manifest.Name,
		UntrustedDescription: manifest.Description}
	if len(offer.KeyCard) > 0 {
		notBefore, notAfter, cardErr := servicebridge.OfferKeyCardWindow(offer.KeyCard, offer.ProviderAgentID)
		if cardErr != nil {
			return nil, cardErr
		}
		description.KeyCardNotBefore, description.KeyCardNotAfter = notBefore, notAfter
	}
	session, err := r.session(ctx, config)
	if err != nil {
		return nil, errors.New(servicebridge.RedactEndpoints(err.Error(), config.RPCEndpoints))
	}
	description.Checkpoint = session.Checkpoint()
	if err := checkFinalizedCapability(ctx, session, offer); err != nil {
		return nil, err
	}
	account, found, err := session.ReadActor(ctx, description.Actor)
	if err != nil {
		return nil, errors.New(servicebridge.RedactEndpoints(err.Error(), config.RPCEndpoints))
	}
	if !found || account == nil || account.Data == nil {
		return nil, fmt.Errorf("%w: the actor is not in finalized state", servicebridge.ErrOfferMismatch)
	}
	policy := account.Data.Policy
	terms, err := nativecore.ServiceActorTermsHash(nativecore.TermsOfPolicy(policy))
	if err != nil {
		return nil, err
	}
	description.Policy = &FinalizedPolicy{PriceNanoTOS: bigText(policy.PricePerCall),
		StorageFeeNanoTOS: bigText(policy.StorageFee), CleanupBountyNanoTOS: bigText(policy.CleanupBounty),
		ResponseSLASeconds: policy.ResponseSLA, RefundClaimWindowSeconds: policy.RefundClaimWindow,
		PolicyVersion: policy.PolicyVersion, TermsHash: hex.EncodeToString(terms[:]), Active: account.Data.Active,
		OpenAccess: policy.OpenAccess}
	return description, nil
}

// checkFinalizedCapability requires the offered version to be live in
// finalized state, owned by the offer's provider and committed to the
// offer's manifest.
func checkFinalizedCapability(ctx context.Context, session *toschain.ServiceActorSession, offer servicebridge.Offer) error {
	state, found, err := session.ResolveRegistry(ctx, offer.CapabilityID)
	if err != nil {
		return fmt.Errorf("read the Capability: %w", err)
	}
	capability := state.GetCapability()
	if !found || capability == nil || capability.GetTombstoned() ||
		capability.GetOwnerAgentId() != offer.ProviderAgentID {
		return fmt.Errorf("%w: the Capability is not live and owned by the provider", servicebridge.ErrOfferMismatch)
	}
	for _, version := range capability.GetVersions() {
		if version.GetVersion() == offer.Version && !version.GetRevoked() &&
			version.GetManifestDigest() == offer.ManifestDigest {
			return nil
		}
	}
	return fmt.Errorf("%w: the offered version is not live with this manifest", servicebridge.ErrOfferMismatch)
}
