package agentguarantor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

// The quote → offer part of the signed history: a published service profile,
// a signed quote request on an authorized underlying Agreement, the coverage
// Agreement, the exposure-admission receipt and the firm offer, so that
// VerifyFirmOffer runs in this package's own tests.
//
// It stands beside the claim history rather than under it: the claim history
// still rests on its stand-in activation. An acceptance request, an
// acceptance receipt, non-activation evidence and activation evidence are
// built on the firm offer (signed_history_offer_binding_test.go,
// signed_history_nonactivation_release_test.go,
// signed_history_offer_followups_test.go) and verified by the unreplaced
// verifiers. The offer's issuance action is not built: the
// offer and reservation identities and the exposure receipt's action digests
// are well-formed values. A verifier cannot recompute them from the offer,
// and holds the receipt's eligibility proofs to them.

const (
	// signedOfferIssuedAt is when the quote is answered: before the coverage
	// starts, and the time every offer here is verified at.
	signedOfferIssuedAt    = signedHistoryStart - 600
	signedOfferReorgWindow = 60
)

const (
	signedOfferAnchorRefusal   = "final deadline differs from the hard-effect deadline"
	signedOfferTerminalRefusal = "terminal resolution deadline exceeds the requester's maximum"
	signedOfferLateRefusal     = "late-recovery deadline or window exceeds the requester's maximum"
)

// signedOfferKey is the deterministic publication and Agreement key of an
// Agent.
func signedOfferKey(agentID string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("signed-history-agent-key:" + agentID))
	return ed25519.NewKeyFromSeed(seed[:])
}

// signedOfferKeys pins one publication and Agreement key per Agent. It is the
// publication resolver and the Agreement key resolver of an offer.
type signedOfferKeys map[string]ed25519.PublicKey

func (keys signedOfferKeys) authorize(agentID string, publicKey ed25519.PublicKey) error {
	if pinned, found := keys[agentID]; !found || !pinned.Equal(publicKey) {
		return testError("the key is not the Agent's pinned key")
	}
	return nil
}

func (keys signedOfferKeys) AuthorizeAgentOperationKey(agentID string, _ ProfileRefV1, publicKey ed25519.PublicKey,
	_ time.Time, proof []byte) error {
	if len(proof) == 0 {
		return errTestAuthority
	}
	return keys.authorize(agentID, publicKey)
}

func (keys signedOfferKeys) AuthorizeIntentKey(agentID string, publicKey ed25519.PublicKey, _ time.Time) error {
	return keys.authorize(agentID, publicKey)
}

// signedOfferAgreements serves complete underlying Agreements by body digest.
type signedOfferAgreements map[string]agentcommerce.AgentAgreement

func (agreements signedOfferAgreements) ResolveUnderlyingAgreement(bodyDigest string) (agentcommerce.AgentAgreement, error) {
	agreement, found := agreements[bodyDigest]
	if !found {
		return agentcommerce.AgentAgreement{}, testError("underlying Agreement is not held")
	}
	return agreement, nil
}

// signedOfferInputs is what one quote → offer history may vary before it is
// signed. The defaults give an offer VerifyFirmOffer accepts.
type signedOfferInputs struct {
	// terms are the offered terms before their digests of the profile, the
	// request and the Agreement are set.
	terms     CoverageTermsV1
	requested RequestedCoverageTermsV1
	// agreementExpiresAt is the coverage Agreement's expiry; by default the
	// terms' final deadline.
	agreementExpiresAt uint64
	// collateralLockUntil, when not zero, makes the terms collateral-attested
	// with collateral locked until then, releasable from the final deadline
	// plus signedOfferReorgWindow.
	collateralLockUntil uint64
	// requestSigner signs the quote request; by default the requester.
	requestSigner string
	// requestProfile is the profile the quote request is signed under; by
	// default the fixed native Agent authorization profile.
	requestProfile *ProfileRefV1
	// publisher is the Agent whose key signs the service profile publication;
	// by default the Guarantor.
	publisher string
	// reserved is the exposure the receipt reserves; by default the terms'
	// maximum aggregate payout.
	reserved AtomicAmountV1
	// admittedAt is when the exposure is admitted and its eligibility proofs
	// are frozen; by default the offer's valid-from time.
	admittedAt uint64
	// receiptProfile and offerProfile are the profiles the Guarantor signs
	// the exposure receipt and the firm offer under; by default the service
	// profile's exposure authorization profile.
	receiptProfile, offerProfile *ProfileRefV1
	// The hooks below, when given, vary one object after its defaults are
	// set and before its digest is taken or it is signed.
	//
	// requestedTerms varies the requested terms after any collateral
	// selection is copied into them.
	requestedTerms func(*RequestedCoverageTermsV1)
	// requestBody varies the quote request body.
	requestBody func(*CoverageQuoteRequestBodyV1)
	// offeredTerms varies the offered terms after their profile, request and
	// underlying Agreement digests and their coverage ID are set.
	offeredTerms func(*CoverageTermsV1)
	// eligibility varies what the exposure receipt's eligibility proofs bind.
	eligibility func(*signedOfferEligibility)
	// eligibilitySet varies the built eligibility proof set, which must stay
	// sorted and well-formed.
	eligibilitySet func(*AuthorityAdmissionEligibilityProofSetV1)
	// receiptBody varies the exposure receipt body.
	receiptBody func(*ProviderExposureAdmissionReceiptBodyV1)
	// offerBody varies the firm offer body.
	offerBody func(*FirmCoverageOfferBodyV1)
	// agreement varies the coverage Agreement body before its authorization
	// targets are computed.
	agreement func(*agentcommerce.AgentAgreementBody)
}

// signedOfferEligibility is what the eligibility proofs frozen with an
// exposure admission bind: the admitted action, the input envelope, the
// re-resolved subjects, the object kind and body, the required scope, the
// resolver profile, the admission domain and the admission time.
type signedOfferEligibility struct {
	actionDigest, inputDigest string
	subjects                  []string
	kind, bodyDigest          string
	scopeDigest, domainID     string
	profile                   ProfileRefV1
	at                        uint64
}

// signedOffer is a signed firm offer with everything VerifyFirmOffer takes.
type signedOffer struct {
	offer      AuthorizedFirmCoverageOfferV1
	request    AuthorizedCoverageQuoteRequestV1
	agreement  agentcommerce.AgentAgreementBody
	resolver   signedHistoryResolver
	keys       signedOfferKeys
	underlying signedOfferAgreements
}

// verify runs VerifyFirmOffer at the time the offer was issued. The Agreement
// evidence verifier is the released Agent-signature verifier over the pinned
// keys, not a permissive stand-in.
func (signed signedOffer) verify() error {
	return VerifyFirmOffer(signed.offer, signed.request, signed.agreement, signed.resolver, signed.keys, signed.underlying,
		agentcommerce.AgentSignatureEvidenceVerifier{Resolver: signed.keys}, signedHistoryTime(signedOfferIssuedAt))
}

// signedOfferFinalDeadline is the deadline the Agreement anchors: the
// late-recovery terminal deadline with a late contingency, otherwise the
// terminal resolution deadline.
func signedOfferFinalDeadline(terms CoverageTermsV1) uint64 {
	if terms.LateRecoveryTerminalDeadlineUnix != 0 {
		return terms.LateRecoveryTerminalDeadlineUnix
	}
	return terms.TerminalResolutionDeadlineUnix
}

func signedOfferAgentSubject(agentID string) agentcommerce.AgreementAuthoritySubject {
	return agentcommerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: agentID}
}

func signedOfferAgreementAmount(amount AtomicAmountV1) *agentcommerce.AgreementAmount {
	return &agentcommerce.AgreementAmount{AssetNamespace: amount.Asset.AssetNamespace,
		AssetIdentifier: amount.Asset.AssetIdentifier, AmountAtomic: amount.AmountAtomic, Unit: amount.Asset.Unit}
}

// offerCollateral is a collateral-attested profile compatible with the claim
// profile the terms select, and collateral terms under it that cover the
// maximum aggregate payout, locked until lockUntil and releasable from the
// terms' final deadline plus the reorg window.
func (history *signedHistory) offerCollateral(terms CoverageTermsV1, lockUntil uint64) (CollateralProfileV1, CollateralTermsV1) {
	t := history.t
	authority := CollateralAuthorizationBindingV1{AuthorizationProfile: testRef("1", "custody-authority"),
		AuthorizationSubjects: []string{"agent:custodian"}, AuthorizationQuorumRule: "all"}
	transition := CollateralTransitionProfileV1{TransitionKind: "payout", SuccessorDerivationProfile: testRef("2", "successor"),
		AdapterProfile: testRef("3", "custody-adapter"), AdapterRequestContentType: "application/vnd.tos.collateral-request.v1+cbor",
		AdapterRequestProfile: testRef("4", "request"), MaximumAdapterRequestBytes: 4096,
		AdapterEvidenceContentType: "application/vnd.tos.collateral-evidence.v1+cbor", AdapterEvidenceProfile: testRef("5", "evidence"),
		AuthorizationSubjectSource: "custodian", CustodianAuthorizationBinding: &authority,
		PermittedPriorStates: []string{"encumbered", "partially_consumed"}, PermittedResultingStates: []string{"depleted", "partially_consumed"},
		PrerequisiteEvidenceRoles: []string{"terminal-decision"}, AuthorizedClaimDecisionBinding: "required",
		PayoutDestinationBinding: "agreement_fixed"}
	transitionDigest, err := CollateralTransitionProfileDigestV1(transition)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := CollateralControlDisclosureV1{SchemaVersion: 1, CustodyAdapterProfile: transition.AdapterProfile,
		AdapterOperatorSubjects: []string{"agent:custodian"}, CustodianControllerRootSubjects: []string{"root:custodian"},
		DeclaredGuarantorControlRelationship: "control_undetermined"}
	profile := CollateralProfileV1{ProfileID: "collateral-profile:test", ProfileVersion: 1,
		AssuranceLevel: AssuranceCollateralAttested, Asset: terms.CoverageAsset, CustodyAdapterProfile: transition.AdapterProfile,
		CollateralControlDisclosure: disclosure, TransitionProfiles: []CollateralTransitionProfileV1{transition},
		CompatibleClaimProfileDigests: []string{terms.SelectedClaimProfileDigest}, ExclusiveAllocationRequired: true,
		MinimumCollateralizationPPM: 1_000_000, MaximumEvidenceAgeSeconds: 60}
	profileDigest, err := Digest("tos.service.agent-guarantor-collateral-profile.v1", profile)
	if err != nil {
		t.Fatal(err)
	}
	return profile, CollateralTermsV1{PositionID: "position:one", SelectedCollateralProfileDigest: profileDigest,
		AssuranceLevel: AssuranceCollateralAttested, Asset: terms.CoverageAsset, Amount: terms.MaximumAggregatePayout,
		CollateralPrincipalSubject: "agent:principal", CustodyAdapterProfile: transition.AdapterProfile,
		CollateralControlDisclosure: disclosure, PositionIdentityProfile: testRef("7", "position"),
		TransitionBindings: []CollateralTransitionBindingV1{{TransitionProfileDigest: transitionDigest, TransitionProfile: transition,
			AuthorizationBinding: authority}}, ContractOrAccountDigest: testDigest("8"),
		ExclusiveAllocationRequired: true, LockByUnix: terms.CoverageStartsAtUnix, LockUntilUnix: lockUntil,
		ReleaseNotBeforeUnix: signedOfferFinalDeadline(terms) + signedOfferReorgWindow, ReorgWindowSeconds: signedOfferReorgWindow,
		FinalityProfile: testRef("9", "finality"), MaximumEvidenceAgeSeconds: 60}
}

// offerServiceProfile is a service profile that supports the terms through
// claimProfile and, when given, collateralProfile.
func (history *signedHistory) offerServiceProfile(terms CoverageTermsV1, claimProfile ClaimProfileV1,
	collateralProfile *CollateralProfileV1) ServiceProfileV1 {
	asset := terms.CoverageAsset
	profile := ServiceProfileV1{SchemaVersion: 1, ProfileID: "profile:guarantor", Revision: 1,
		ProviderAgentID: terms.GuarantorAgentID, AuthorityDomainDigest: terms.StageActionAuthorityBinding.AuthorityDomainDigest,
		CoverageCapabilities: []CoverageCapabilityV1{{Category: terms.CoverageCategory,
			BenefitKinds: []BenefitKind{terms.BenefitKind}, SupportedUnderlyingProfiles: []ProfileRefV1{testRef("a", "underlying")},
			SupportedClaimProfiles: []ProfileRefV1{terms.ClaimEvidenceProfile}, SupportedAssets: []AssetIdentityV1{asset},
			CoverageRanges: []AtomicRangeV1{{Minimum: AtomicAmountV1{Asset: asset, AmountAtomic: "1"},
				Maximum: AtomicAmountV1{Asset: asset, AmountAtomic: "10000"}}},
			FeeRanges: []AtomicRangeV1{{Minimum: AtomicAmountV1{Asset: asset, AmountAtomic: "1"},
				Maximum: AtomicAmountV1{Asset: asset, AmountAtomic: "1000"}}},
			MaximumCoverageSeconds:    terms.CoverageEndsAtUnix - terms.CoverageStartsAtUnix,
			MaximumClaimWindowSeconds: terms.ClaimFilingEndsAtUnix - terms.CoverageEndsAtUnix,
			JurisdictionPolicy:        PolicyRefV1{ContentType: "text/plain", ContentDigest: testDigest("b"), ContentSize: 10}}},
		ClaimProfiles: []ClaimProfileV1{claimProfile}, PayoutAdapterProfiles: []ProfileRefV1{terms.SelectedPayoutAdapterProfile},
		AdmissionLimits: AdmissionLimitsV1{MaximumQuoteReservations: 10, MaximumActiveCoverages: 10, MaximumActiveClaims: 20,
			MaximumActivePerCoveredParty: 5, MaximumActivationAttemptsPerCoverage: 4, MaximumQuoteRequestsPerWindow: 20,
			QuoteRequestWindowSeconds: 60, MaximumAcceptanceProcessingGraceSeconds: 60},
		Endpoints: ServiceEndpointsV1{QuoteRoute: "https://guarantor.example/quote",
			AcceptanceRoute: "https://guarantor.example/accept", ClaimRoute: "https://guarantor.example/claim",
			ResolveRoute: "https://guarantor.example/resolve", EvidenceRoute: "https://guarantor.example/evidence"},
		ExposureAuthorityID: "authority:guarantor", ExposureAuthorizationProfile: terms.LifecycleAuthorizationProfile,
		LifecycleAuthorityID: "authority:guarantor", LifecycleAuthorizationProfile: terms.LifecycleAuthorizationProfile,
		PolicyRevision: 1, CreatedAtUnix: signedOfferIssuedAt - 60, ExpiresAtUnix: signedOfferIssuedAt + 30*24*60*60}
	if collateralProfile != nil {
		profile.CollateralProfiles = []CollateralProfileV1{*collateralProfile}
	}
	return profile
}

// publishServiceProfile is the one-revision publication artifact of profile:
// a PUBLICATION/POST operation signed with publisher's key, whose Intent
// payload describes the profile's canonical bytes.
func (history *signedHistory) publishServiceProfile(profile ServiceProfileV1, publisher string) GuarantorServiceProfileArtifactV1 {
	t := history.t
	profileDigest, err := ServiceProfileDigest(profile)
	if err != nil {
		t.Fatalf("signed-history service profile is invalid: %v", err)
	}
	profileBytes, err := Canonical(profile)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256(profileBytes)
	payload := agentcommerce.AgentIntentPayload{DiscoveryCard: agentcommerce.DiscoveryCard{Summary: "Bounded guarantor service",
		IntentModes: []agentcommerce.IntentMode{agentcommerce.IntentOffer}, SubjectClasses: []agentcommerce.SubjectClass{agentcommerce.SubjectService},
		TaxonomyPaths: []string{"tos.taxonomy.v1/service/guarantor"},
		Keywords:      []agentcommerce.IntentKeyword{{Text: "guarantor", Language: "en"}},
		ValueState:    agentcommerce.ValueNegotiable, Schedule: agentcommerce.IntentSchedule{Flexibility: "ongoing"}},
		DetailDescriptor: agentcommerce.ContentDescriptor{ContentType: ServiceProfileContentType,
			ContentDigest: "sha256:" + hex.EncodeToString(contentHash[:]), ContentSize: uint64(len(profileBytes))},
		ReplyRoutes: []agentcommerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: profile.ProviderAgentID}}}
	payloadBytes, err := Canonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadProfile := ProfileRefV1{ProfileURI: ServiceIntentPayloadProfileURI, ProfileVersion: 1, ProfileDigest: testDigest("d")}
	payloadDigest, err := agentcommerce.AgentOperationPayloadDigest(payloadProfile, payloadBytes)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := agentcommerce.SignAgentOperationV1(agentcommerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test",
		OpcodeNamespace: ServiceIntentOpcodeNamespace, OpcodeName: ServiceIntentOpcodeName, OpcodeVersion: 1,
		OperationID: "operation:guarantor-profile:1", ActorAgentID: profile.ProviderAgentID,
		AuthorizationRef: testRef("e", "publication-authority"), AudienceDescriptor: "public:indexable",
		ObjectID: profile.ProfileID, OrderingDomain: "publication:" + profile.ProfileID, Sequence: profile.Revision,
		CreatedAtUnix: profile.CreatedAtUnix, NotBeforeUnix: profile.CreatedAtUnix, ExpiresAtUnix: profile.ExpiresAtUnix,
		PayloadProfile: payloadProfile, PayloadDigest: payloadDigest, PayloadSize: uint64(len(payloadBytes))},
		profile.ProviderAgentID, signedOfferKey(publisher), signedHistoryProof)
	if err != nil {
		t.Fatal(err)
	}
	operationDigest, err := agentcommerce.AgentOperationEnvelopeDigestV1(operation)
	if err != nil {
		t.Fatal(err)
	}
	artifact := GuarantorServiceProfileArtifactV1{SchemaVersion: ServiceProfileArtifactSchemaV1,
		SelectedServiceIntentOperationDigest: operationDigest, SelectedServiceProfileDigest: profileDigest,
		Revisions: []GuarantorServiceProfileRevisionArtifactV1{{SchemaVersion: 1, ServiceIntentOperationDigest: operationDigest,
			ServiceIntentOperation: operation, IntentPayload: payload, ServiceProfile: profile}}}
	if _, err := ServiceProfileArtifactDigestV1(artifact); err != nil {
		t.Fatalf("signed-history service profile artifact is malformed: %v", err)
	}
	return artifact
}

// underlyingAgreement is the Agreement whose covered obligations the covered
// party owes the beneficiary, with the covered party's signed acceptance.
func (history *signedHistory) underlyingAgreement(terms CoverageTermsV1) (agentcommerce.AgentAgreement, string) {
	t := history.t
	covered := signedOfferAgentSubject(terms.CoveredPartyAgentID)
	body, err := agentcommerce.PrepareAgreementTargets(agentcommerce.AgentAgreementBody{SchemaVersion: 1,
		AgreementID: "agreement:underlying", Version: 1, NetworkContext: "tos:test",
		Participants: []agentcommerce.AgreementParticipant{{AgentID: terms.BeneficiaryAgentID, Roles: []string{"customer"}},
			{AgentID: terms.CoveredPartyAgentID, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("covered exchange"),
		Obligations: []agentcommerce.AgreementObligation{{ObligationID: terms.CoveredObligationIDs[0], Kind: "service",
			ObligorAgentID: terms.CoveredPartyAgentID, BeneficiaryAgentID: terms.BeneficiaryAgentID,
			SubjectContentType: "text/plain", Subject: []byte("deliver the exchange"), ConfidentialityPolicy: "participants",
			CancellationPolicy: "mutual", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"predicate:underlying-covered"}}},
		AuthorizationPredicates: []agentcommerce.AgreementAuthorizationPredicate{{PredicateID: "predicate:underlying-covered",
			AuthoritySubject: covered, ObligationIDs: []string{terms.CoveredObligationIDs[0]},
			EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature, EvidenceProfileVersion: 1,
			EvidenceProfileDigest: agentcommerce.AgentSignatureProfileDigest(), ExpiresAtUnix: terms.CoverageEndsAtUnix}},
		ValidFromUnix: signedOfferIssuedAt - 60, ExpiresAtUnix: terms.CoverageEndsAtUnix})
	if err != nil {
		t.Fatalf("signed-history underlying Agreement is invalid: %v", err)
	}
	digest, err := agentcommerce.AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	predicate := body.AuthorizationPredicates[0]
	acceptance, err := agentcommerce.SignAgreementAcceptance(agentcommerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
		AgreementVersion: body.Version, AgreementBodyDigest: digest, AcceptingSubject: covered,
		PredicateIDs:                    []string{predicate.PredicateID},
		EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
		ExpiresAtUnix:                   body.ExpiresAtUnix}, signedOfferKey(terms.CoveredPartyAgentID))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := agentcommerce.AgentSignatureEvidence(body, acceptance)
	if err != nil {
		t.Fatal(err)
	}
	return agentcommerce.AgentAgreement{Body: body, AuthorizationEvidence: []agentcommerce.AgreementAuthorizationEvidence{evidence}}, digest
}

// coverageAgreement is the coverage Agreement body the offer is made on,
// expiring at expiresAt: the coverage, payout template and premium
// obligations, the collateral obligation when the terms name one, and the
// Guarantor's predicate under the firm-offer evidence profile.
func (history *signedHistory) coverageAgreement(terms CoverageTermsV1, expiresAt uint64,
	change func(*agentcommerce.AgentAgreementBody)) agentcommerce.AgentAgreementBody {
	t := history.t
	agentSignature := agentcommerce.AgentSignatureProfileDigest()
	firmOffer := FirmOfferAgreementEvidenceProfileV1()
	adapter := terms.SelectedPayoutAdapterProfile.ProfileURI
	guarantorObligations := []string{history.obligation, terms.PayoutTemplate.AgreementObligationID}
	obligations := []agentcommerce.AgreementObligation{
		{ObligationID: history.obligation, Kind: "coverage", ObligorAgentID: terms.GuarantorAgentID,
			BeneficiaryAgentID: terms.BeneficiaryAgentID, SubjectContentType: "text/plain", Subject: []byte("guarantee the covered exchange"),
			ConfidentialityPolicy: "participants", CancellationPolicy: "mutual", DisputePolicy: "evidence",
			AuthorizationPredicateIDs: []string{"predicate:guarantor"}},
		{ObligationID: terms.PayoutTemplate.AgreementObligationID, Kind: "guarantor.payout.template",
			ObligorAgentID: terms.GuarantorAgentID, BeneficiaryAgentID: terms.BeneficiaryAgentID, SubjectContentType: "text/plain",
			Subject: []byte("conditional coverage payout"), Amount: signedOfferAgreementAmount(terms.MaximumAggregatePayout),
			ConfidentialityPolicy: "participants", CancellationPolicy: "coverage-terms", DisputePolicy: "evidence",
			SettlementAdapterURI: adapter, SettlementParameters: []byte("beneficiary-wallet"),
			AuthorizationPredicateIDs: []string{"predicate:beneficiary", "predicate:guarantor"}},
		{ObligationID: terms.PremiumObligationIDs[0], Kind: CoverageFeeObligationKindV1, ObligorAgentID: terms.CoveredPartyAgentID,
			BeneficiaryAgentID: terms.GuarantorAgentID, DependsOnObligationIDs: []string{history.obligation},
			SubjectContentType: "text/plain", Subject: []byte("coverage premium"),
			Amount:                signedOfferAgreementAmount(AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "100"}),
			ConfidentialityPolicy: "participants", CancellationPolicy: "before-activation", DisputePolicy: "evidence",
			SettlementAdapterURI: adapter, SettlementParameters: []byte("premium-destination"),
			AuthorizationPredicateIDs: []string{"predicate:covered"}}}
	if terms.CollateralObligationID != "" {
		guarantorObligations = append([]string{terms.CollateralObligationID}, guarantorObligations...)
		obligations = append(obligations, agentcommerce.AgreementObligation{ObligationID: terms.CollateralObligationID,
			Kind: "collateral", ObligorAgentID: terms.GuarantorAgentID, BeneficiaryAgentID: terms.BeneficiaryAgentID,
			SubjectContentType: "text/plain", Subject: []byte("lock the coverage collateral"), ConfidentialityPolicy: "participants",
			CancellationPolicy: "coverage-terms", DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"predicate:guarantor"}})
	}
	unprepared := agentcommerce.AgentAgreementBody{SchemaVersion: 1,
		AgreementID: "agreement:coverage", Version: 1, NetworkContext: "tos:test",
		Participants: []agentcommerce.AgreementParticipant{{AgentID: terms.BeneficiaryAgentID, Roles: []string{"beneficiary"}},
			{AgentID: terms.CoveredPartyAgentID, Roles: []string{"covered"}}, {AgentID: terms.GuarantorAgentID, Roles: []string{"guarantor"}}},
		TermsContentType: "text/plain", Terms: []byte("fixed benefit coverage"), Obligations: obligations,
		AuthorizationPredicates: []agentcommerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:beneficiary", AuthoritySubject: signedOfferAgentSubject(terms.BeneficiaryAgentID),
				ObligationIDs: []string{terms.PayoutTemplate.AgreementObligationID}, EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: agentSignature, ExpiresAtUnix: expiresAt},
			{PredicateID: "predicate:covered", AuthoritySubject: signedOfferAgentSubject(terms.CoveredPartyAgentID),
				ObligationIDs: []string{terms.PremiumObligationIDs[0]}, EvidenceProfileURI: agentcommerce.EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: agentSignature, ExpiresAtUnix: expiresAt},
			{PredicateID: "predicate:guarantor", AuthoritySubject: signedOfferAgentSubject(terms.GuarantorAgentID),
				ObligationIDs: guarantorObligations, EvidenceProfileURI: firmOffer.ProfileURI,
				EvidenceProfileVersion: uint32(firmOffer.ProfileVersion), EvidenceProfileDigest: firmOffer.ProfileDigest,
				ExpiresAtUnix: expiresAt}},
		ValidFromUnix: signedOfferIssuedAt - 60, ExpiresAtUnix: expiresAt}
	if change != nil {
		change(&unprepared)
	}
	body, err := agentcommerce.PrepareAgreementTargets(unprepared)
	if err != nil {
		t.Fatalf("signed-history coverage Agreement is invalid: %v", err)
	}
	return body
}

// quoteRequest is the requester's signed quote request for requested under
// the published profile, on the underlying Agreement.
func (history *signedHistory) quoteRequest(terms CoverageTermsV1, requested RequestedCoverageTermsV1, profileDigest,
	intentDigest, underlyingDigest, signer string, signingProfile ProfileRefV1,
	change func(*CoverageQuoteRequestBodyV1)) AuthorizedCoverageQuoteRequestV1 {
	t := history.t
	requestedDigest, err := RequestedCoverageTermsDigest(requested)
	if err != nil {
		t.Fatalf("signed-history requested terms are invalid: %v", err)
	}
	body := CoverageQuoteRequestBodyV1{SchemaVersion: 1, RequestID: "request:coverage", ServiceIntentDigest: intentDigest,
		ServiceProfileDigest: profileDigest, RequesterAgentID: terms.CoveredPartyAgentID, GuarantorAgentID: terms.GuarantorAgentID,
		CoveredPartyAgentID: terms.CoveredPartyAgentID, BeneficiaryAgentID: terms.BeneficiaryAgentID,
		ClaimantSubjects: terms.PermittedClaimantSubjects, UnderlyingAgreementBodyDigest: underlyingDigest,
		CoveredObligationIDs: terms.CoveredObligationIDs, RequestedTermsDigest: requestedDigest,
		MaximumFee:             AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "100"},
		SelectedAssuranceLevel: requested.SelectedAssuranceLevel, SelectedClaimProfileDigest: requested.SelectedClaimProfileDigest,
		SelectedDecisionProfile: terms.DecisionProfile, SelectedCollateralProfileDigest: requested.SelectedCollateralProfileDigest,
		SelectedPayoutAdapterProfile: requested.SelectedPayoutAdapterProfile,
		CreatedAtUnix:                signedOfferIssuedAt - 30, ExpiresAtUnix: signedOfferIssuedAt + 600}
	if change != nil {
		change(&body)
	}
	bodyDigest, err := Digest("tos.service.agent-guarantor-quote-request-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizedCoverageQuoteRequestV1{Body: body, RequestedTerms: requested,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(signer, signingProfile,
			"coverage-quote-request", bodyDigest, "tos.service.agent-guarantor-quote-request-signature.v1", body.CreatedAtUnix)}}
	if _, err := QuoteRequestDigest(request); err != nil {
		t.Fatalf("signed-history quote request is malformed: %v", err)
	}
	return request
}

// exposureReceipt is the Guarantor-signed exposure-admission receipt that
// reserves inputs.reserved for the offered terms on the coverage Agreement.
// offerID stands for the issuance authority instance. Its eligibility proofs
// re-resolve the parties request names.
func (history *signedHistory) exposureReceipt(terms CoverageTermsV1, profile ServiceProfileV1, profileDigest, requestDigest,
	agreementDigest, termsDigest, offerID string, request CoverageQuoteRequestBodyV1, inputs signedOfferInputs,
	expiresAt uint64) AuthorizedProviderExposureAdmissionReceiptV1 {
	t, reserved := history.t, inputs.reserved
	scope := ProviderExposureReservationScopeV1{SchemaVersion: 1, OwnerID: "owner:guarantor", GuarantorAgentID: terms.GuarantorAgentID,
		CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: history.obligation, CoverageAsset: terms.CoverageAsset,
		MaximumAggregatePayout: terms.MaximumAggregatePayout, SelectedAssuranceLevel: terms.SelectedAssuranceLevel,
		PolicyBucketDigest: testDigest("1"), CorrelationBucketDigest: testDigest("2"), DefaultLiabilityDisposition: "retain",
		ReservationExpiresAtUnix: expiresAt}
	scopeDigest, err := ExposureReservationScopeDigestV1(scope)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := ProviderExposureAdmissionDescriptorV1{SchemaVersion: 1, GuarantorAgentID: terms.GuarantorAgentID,
		ServiceProfileDigest: profileDigest, QuoteRequestDigest: requestDigest, CoverageID: terms.CoverageID,
		CoverageVersion: terms.CoverageVersion, CoverageAgreementBodyDigest: agreementDigest, CoverageTermsDigest: termsDigest,
		ReservationScope: scope, ReservationScopeDigest: scopeDigest, ReservedExposure: reserved,
		CollateralCredit:   AtomicAmountV1{Asset: terms.CoverageAsset, AmountAtomic: "0"},
		PolicyBucketDigest: scope.PolicyBucketDigest, CorrelationBucketDigest: scope.CorrelationBucketDigest,
		BasePortfolioRevision: 1, ReservationExpiresAtUnix: expiresAt}
	descriptorDigest, err := ExposureAdmissionDescriptorDigestV1(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	reservationID, err := ReservationIDV1(terms.GuarantorAgentID, offerID, descriptorDigest)
	if err != nil {
		t.Fatal(err)
	}
	fenceDigest, err := agentcommerce.WriterFenceDigest(history.fence)
	if err != nil {
		t.Fatal(err)
	}
	actionDigest, stableActionID, exactRequestDigest := testDigest("3"), testDigest("4"), testDigest("5")
	parties := map[string]struct{}{request.RequesterAgentID: {}, request.CoveredPartyAgentID: {}, request.BeneficiaryAgentID: {}}
	subjects := make([]string, 0, len(parties))
	for party := range parties {
		subjects = append(subjects, party)
	}
	admissionDomain, err := FirmOfferAdmissionDomainIDV1(offerID)
	if err != nil {
		t.Fatal(err)
	}
	bound := signedOfferEligibility{actionDigest: actionDigest, inputDigest: requestDigest, subjects: subjects,
		kind: "firm-offer-issuance", bodyDigest: exactRequestDigest, scopeDigest: profile.AuthorityDomainDigest,
		domainID: admissionDomain, profile: profile.ExposureAuthorizationProfile, at: inputs.admittedAt}
	if inputs.eligibility != nil {
		inputs.eligibility(&bound)
	}
	eligibility := history.eligibility(bound.actionDigest, bound.inputDigest, bound.subjects, bound.kind, bound.bodyDigest,
		bound.scopeDigest, bound.profile, bound.domainID, 1, bound.at)
	if inputs.eligibilitySet != nil {
		inputs.eligibilitySet(&eligibility)
	}
	eligibilityDigest, err := AuthorityAdmissionEligibilityProofSetDigestV1(eligibility)
	if err != nil {
		t.Fatal(err)
	}
	body := ProviderExposureAdmissionReceiptBodyV1{SchemaVersion: 1, AuthorityID: profile.ExposureAuthorityID,
		GuarantorAgentID: terms.GuarantorAgentID, DescriptorDigest: descriptorDigest, AuthorizedActionDigest: actionDigest,
		ReservationID: reservationID, StableActionID: stableActionID, ExactRequestDigest: exactRequestDigest, WriterGeneration: 1,
		WriterFenceDigest: fenceDigest, BasePortfolioRevision: 1, AdmittedPortfolioRevision: 2, ReservedExposure: reserved,
		State: "reserved", AdmittedAtUnix: inputs.admittedAt, ExpiresAtUnix: expiresAt,
		AuthorityAdmissionEligibilityProofSetDigest: eligibilityDigest}
	if inputs.receiptBody != nil {
		inputs.receiptBody(&body)
	}
	bodyDigest, err := Digest("tos.service.agent-guarantor-exposure-receipt-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	signingProfile := profile.ExposureAuthorizationProfile
	if inputs.receiptProfile != nil {
		signingProfile = *inputs.receiptProfile
	}
	receipt := AuthorizedProviderExposureAdmissionReceiptV1{Body: body, Descriptor: descriptor,
		AuthorityAdmissionEligibilityProofSet: eligibility,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(terms.GuarantorAgentID, signingProfile,
			"exposure-admission-receipt", bodyDigest, "tos.service.agent-guarantor-exposure-receipt-signature.v1", signedOfferIssuedAt)}}
	if _, err := ExposureAdmissionReceiptDigestV1(receipt); err != nil {
		t.Fatalf("signed-history exposure receipt is malformed: %v", err)
	}
	return receipt
}

// quoteToOffer signs one quote → offer history on the history's terms, with
// the late-recovery contingency or without it. change, when given, varies the
// inputs before anything is signed; every digest downstream of a varied input
// is recomputed, so a varied offer differs from an accepted one only in what
// change changed.
func (history *signedHistory) quoteToOffer(late bool, change func(*signedOfferInputs)) signedOffer {
	t := history.t
	terms := history.terms
	terms.StageActionAuthorityBinding.Stages = append([]GuarantorStageActionAuthorityV1(nil), terms.StageActionAuthorityBinding.Stages...)
	if !late {
		terms.LateIngressRecoveryWindowSeconds, terms.LateIngressRecoveryDeadlineUnix = 0, 0
		terms.LateRecoveryTerminalDeadlineUnix = 0
	}
	// The offered grace is the published maximum of offerServiceProfile.
	terms.AcceptanceProcessingGraceSeconds = 60
	claimProfile := testClaimProfileFor(t, &terms)
	requested := testRequestedTerms(t, terms)
	requested.MaximumLateRecoveryTerminalDeadlineUnix = terms.LateRecoveryTerminalDeadlineUnix
	requested.MaximumLateIngressRecoveryWindowSeconds = terms.LateIngressRecoveryWindowSeconds
	inputs := signedOfferInputs{terms: terms, requested: requested, agreementExpiresAt: signedOfferFinalDeadline(terms),
		requestSigner: terms.CoveredPartyAgentID, publisher: terms.GuarantorAgentID, reserved: terms.MaximumAggregatePayout,
		admittedAt: signedOfferIssuedAt}
	if change != nil {
		change(&inputs)
	}
	terms, requested = inputs.terms, inputs.requested
	var collateralProfile *CollateralProfileV1
	if inputs.collateralLockUntil != 0 {
		profile, collateral := history.offerCollateral(terms, inputs.collateralLockUntil)
		collateralProfile = &profile
		terms.SelectedAssuranceLevel, terms.SelectedCollateralProfileDigest = collateral.AssuranceLevel, collateral.SelectedCollateralProfileDigest
		terms.CollateralObligationID, terms.CollateralTerms = "obligation:collateral", &collateral
		requested.SelectedAssuranceLevel, requested.SelectedCollateralProfileDigest = terms.SelectedAssuranceLevel, terms.SelectedCollateralProfileDigest
	}
	if inputs.requestedTerms != nil {
		inputs.requestedTerms(&requested)
	}
	keys := signedOfferKeys{}
	for _, agentID := range []string{terms.GuarantorAgentID, terms.CoveredPartyAgentID, terms.BeneficiaryAgentID} {
		keys[agentID] = signedOfferKey(agentID).Public().(ed25519.PublicKey)
	}
	profile := history.offerServiceProfile(terms, claimProfile, collateralProfile)
	artifact := history.publishServiceProfile(profile, inputs.publisher)
	profileDigest, intentDigest := artifact.SelectedServiceProfileDigest, artifact.SelectedServiceIntentOperationDigest
	underlying, underlyingDigest := history.underlyingAgreement(terms)
	requestProfile := NativeAgentAuthorizationProfileV1()
	if inputs.requestProfile != nil {
		requestProfile = *inputs.requestProfile
	}
	request := history.quoteRequest(terms, requested, profileDigest, intentDigest, underlyingDigest, inputs.requestSigner,
		requestProfile, inputs.requestBody)
	requestDigest, err := QuoteRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	agreement := history.coverageAgreement(terms, inputs.agreementExpiresAt, inputs.agreement)
	agreementDigest, err := agentcommerce.AgreementBodyDigest(agreement)
	if err != nil {
		t.Fatal(err)
	}
	terms.ServiceProfileDigest, terms.QuoteRequestDigest, terms.UnderlyingAgreementBodyDigest = profileDigest, requestDigest, underlyingDigest
	if terms.CoverageID, err = CoverageID(terms.GuarantorAgentID, requestDigest); err != nil {
		t.Fatal(err)
	}
	ingressDomain, err := ClaimIngressStateDomainDigestV1(agreementDigest, history.obligation)
	if err != nil {
		t.Fatal(err)
	}
	for index := range terms.StageActionAuthorityBinding.Stages {
		if terms.StageActionAuthorityBinding.Stages[index].Stage == "claim_submission_ingress" {
			terms.StageActionAuthorityBinding.Stages[index].AdmissionStateDomainDigest = ingressDomain
		}
	}
	if inputs.offeredTerms != nil {
		inputs.offeredTerms(&terms)
	}
	termsDigest, err := CoverageTermsDigest(terms)
	if err != nil {
		t.Fatalf("signed-history offered terms are invalid: %v", err)
	}
	offerID, err := Digest("tos.test.signed-history-offer-id.v1", requestDigest)
	if err != nil {
		t.Fatal(err)
	}
	acceptBy, grace := uint64(signedOfferIssuedAt+300), terms.AcceptanceProcessingGraceSeconds
	receipt := history.exposureReceipt(terms, profile, profileDigest, requestDigest, agreementDigest, termsDigest, offerID,
		request.Body, inputs, acceptBy+grace)
	receiptDigest, err := ExposureAdmissionReceiptDigestV1(receipt)
	if err != nil {
		t.Fatal(err)
	}
	evidenceProfile := FirmOfferAgreementEvidenceProfileV1()
	var targets []GuarantorSatisfiedPredicateTargetV1
	for _, predicate := range agreement.AuthorizationPredicates {
		if predicate.AuthoritySubject.SubjectIdentifier == terms.GuarantorAgentID {
			targets = append(targets, GuarantorSatisfiedPredicateTargetV1{PredicateID: predicate.PredicateID,
				TargetProjectionDigest: predicate.EvidenceTargetProjectionDigest})
		}
	}
	body := FirmCoverageOfferBodyV1{SchemaVersion: 1, OfferID: offerID, OfferVersion: 1, QuoteRequestDigest: requestDigest,
		ServiceIntentDigest: intentDigest, ServiceProfileDigest: profileDigest, CoverageID: terms.CoverageID,
		CoverageVersion: terms.CoverageVersion, GuarantorAgentID: terms.GuarantorAgentID,
		CoveredPartyAgentID: terms.CoveredPartyAgentID, BeneficiaryAgentID: terms.BeneficiaryAgentID,
		UnderlyingAgreementBodyDigest: underlyingDigest, CoveredObligationIDs: terms.CoveredObligationIDs,
		CoverageTermsDigest: termsDigest, CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: history.obligation,
		PremiumObligationIDs: terms.PremiumObligationIDs, CollateralObligationID: terms.CollateralObligationID,
		PayoutTemplateObligationID: terms.PayoutTemplate.AgreementObligationID, GuarantorPredicateTargets: targets,
		GuarantorEvidenceProfile: evidenceProfile, ExposureAdmissionReceiptDigest: receiptDigest,
		ReservationID: receipt.Body.ReservationID, MaxAcceptances: 1, ValidFromUnix: signedOfferIssuedAt, AcceptByUnix: acceptBy,
		AcceptanceProcessingGraceSeconds: grace, WithdrawalPolicy: "forbidden", ExpiresAtUnix: acceptBy + grace,
		RequiredExtensions: terms.RequiredExtensions, OptionalExtensions: terms.OptionalExtensions}
	if inputs.offerBody != nil {
		inputs.offerBody(&body)
	}
	bodyDigest, err := Digest("tos.service.agent-guarantor-firm-offer-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	offerProfile := profile.ExposureAuthorizationProfile
	if inputs.offerProfile != nil {
		offerProfile = *inputs.offerProfile
	}
	offer := AuthorizedFirmCoverageOfferV1{Body: body, CoverageTerms: terms, ExposureAdmissionReceipt: receipt,
		AuthorizedQuoteRequest: request, ServiceProfileArtifact: artifact,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(terms.GuarantorAgentID, offerProfile,
			"firm-coverage-offer", bodyDigest, "tos.service.agent-guarantor-firm-offer-signature.v1", signedOfferIssuedAt)}}
	if _, err := FirmOfferDigest(offer); err != nil {
		t.Fatalf("signed-history firm offer is malformed: %v", err)
	}
	return signedOffer{offer: offer, request: request, agreement: agreement, resolver: history.resolver, keys: keys,
		underlying: signedOfferAgreements{underlyingDigest: underlying}}
}

// signedOfferCase is one varied offer and the refusal it must meet; an empty
// refusal means the offer must be accepted.
type signedOfferCase struct {
	name    string
	late    bool
	change  func(*signedOfferInputs)
	refusal string
}

// checkSignedOffers signs each case's offer and runs VerifyFirmOffer on it.
func checkSignedOffers(t *testing.T, cases []signedOfferCase) {
	t.Helper()
	history := newSignedHistory(t)
	for _, test := range cases {
		name := test.name + " (no late contingency)"
		if test.late {
			name = test.name + " (late contingency)"
		}
		err := history.quoteToOffer(test.late, test.change).verify()
		if test.refusal == "" && err != nil {
			t.Errorf("%s: the firm offer was refused: %v", name, err)
		}
		if test.refusal != "" && (err == nil || !strings.Contains(err.Error(), test.refusal)) {
			t.Errorf("%s: got %v, want a refusal containing %q", name, err, test.refusal)
		}
	}
}

// TestSignedHistoryFirmOfferFinalDeadlineIsTheHardEffectAnchor: through
// VerifyFirmOffer, a signed firm offer is accepted when its terms' final
// deadline equals the hard-effect deadline and refused when the two are one
// second apart. The final deadline is the late-recovery terminal deadline
// with a late contingency and the terminal resolution deadline without one.
// The hard-effect deadline is the coverage Agreement's expiry for unsecured
// terms, and for collateralized terms the earlier of that expiry and the
// collateral lock's end less the reorg window.
//
// Collateralized terms whose final deadline is after the lock's end less the
// reorg window never reach the anchor: valid terms keep the final deadline
// plus the reorg window no later than the release guard, which is no later
// than the lock's end. That direction is refused by ValidateCoverageTerms.
func TestSignedHistoryFirmOfferFinalDeadlineIsTheHardEffectAnchor(t *testing.T) {
	const reorg = signedOfferReorgWindow
	lockedLong := func(in *signedOfferInputs) { in.collateralLockUntil = signedOfferFinalDeadline(in.terms) + reorg + 600 }
	lockedToFinal := func(in *signedOfferInputs) {
		in.collateralLockUntil = signedOfferFinalDeadline(in.terms) + reorg
		in.agreementExpiresAt += 100
	}
	var cases []signedOfferCase
	for _, late := range []bool{true, false} {
		cases = append(cases,
			signedOfferCase{"unsecured, Agreement expiring at the final deadline", late, nil, ""},
			signedOfferCase{"unsecured, Agreement expiring one second after the final deadline", late,
				func(in *signedOfferInputs) { in.agreementExpiresAt++ }, signedOfferAnchorRefusal},
			signedOfferCase{"unsecured, Agreement expiring one second before the final deadline", late,
				func(in *signedOfferInputs) { in.agreementExpiresAt-- }, signedOfferAnchorRefusal},
			signedOfferCase{"collateral locked past the Agreement's expiry at the final deadline", late, lockedLong, ""},
			signedOfferCase{"collateral locked past the Agreement's expiry one second after the final deadline", late,
				func(in *signedOfferInputs) { lockedLong(in); in.agreementExpiresAt++ }, signedOfferAnchorRefusal},
			signedOfferCase{"collateral locked past the Agreement's expiry one second before the final deadline", late,
				func(in *signedOfferInputs) { lockedLong(in); in.agreementExpiresAt-- }, signedOfferAnchorRefusal},
			signedOfferCase{"collateral lock less the reorg window at the final deadline, before the Agreement's expiry", late,
				lockedToFinal, ""},
			signedOfferCase{"collateral lock less the reorg window one second after the final deadline", late,
				func(in *signedOfferInputs) { lockedToFinal(in); in.collateralLockUntil++ }, signedOfferAnchorRefusal},
			signedOfferCase{"collateral lock less the reorg window at the final deadline, Agreement expiring one second before it", late,
				func(in *signedOfferInputs) {
					lockedToFinal(in)
					in.agreementExpiresAt = signedOfferFinalDeadline(in.terms) - 1
				}, signedOfferAnchorRefusal})
	}
	// With a late contingency the anchored deadline is the late-recovery
	// terminal deadline, not the terminal resolution deadline before it.
	cases = append(cases, signedOfferCase{"unsecured, Agreement expiring at the terminal resolution deadline", true,
		func(in *signedOfferInputs) { in.agreementExpiresAt = in.terms.TerminalResolutionDeadlineUnix }, signedOfferAnchorRefusal})
	checkSignedOffers(t, cases)
}

// TestSignedHistoryFirmOfferStaysWithinTheRequestMaxima: through
// VerifyFirmOffer, a signed firm offer is accepted with its terminal
// resolution deadline, late-recovery terminal deadline and late-ingress
// window each exactly at the quote request's maximum, and refused with any
// one of them a second over it. A request with zero late maxima admits no
// late contingency.
func TestSignedHistoryFirmOfferStaysWithinTheRequestMaxima(t *testing.T) {
	checkSignedOffers(t, []signedOfferCase{
		{"terminal resolution deadline at the request maximum", false, nil, ""},
		{"terminal resolution deadline one second over the request maximum", false,
			func(in *signedOfferInputs) { in.requested.MaximumTerminalResolutionDeadlineUnix-- }, signedOfferTerminalRefusal},
		{"every deadline and the window at the request maxima", true, nil, ""},
		{"terminal resolution deadline one second over the request maximum", true,
			func(in *signedOfferInputs) { in.requested.MaximumTerminalResolutionDeadlineUnix-- }, signedOfferTerminalRefusal},
		{"late-recovery terminal deadline one second over the request maximum", true,
			func(in *signedOfferInputs) { in.requested.MaximumLateRecoveryTerminalDeadlineUnix-- }, signedOfferLateRefusal},
		{"late-ingress window one second over the request maximum", true,
			func(in *signedOfferInputs) { in.requested.MaximumLateIngressRecoveryWindowSeconds-- }, signedOfferLateRefusal},
		{"late contingency against a request for none", true,
			func(in *signedOfferInputs) {
				in.requested.MaximumLateRecoveryTerminalDeadlineUnix, in.requested.MaximumLateIngressRecoveryWindowSeconds = 0, 0
			}, signedOfferLateRefusal},
	})
}

// TestSignedHistoryFirmOfferRefusesUnauthorizedParts: a firm offer is refused
// when its quote request is not signed by the requester, when its service
// profile is published under a key that is not the Guarantor's, and when its
// exposure receipt reserves less than the terms' maximum aggregate payout;
// in each the offer itself is signed by the Guarantor over consistent digests.
func TestSignedHistoryFirmOfferRefusesUnauthorizedParts(t *testing.T) {
	checkSignedOffers(t, []signedOfferCase{
		{"quote request signed by another Agent", true,
			func(in *signedOfferInputs) { in.requestSigner = "agent:other" }, `"agent:covered" is missing`},
		{"service profile published under another Agent's key", true,
			func(in *signedOfferInputs) { in.publisher = "agent:other" }, "service profile publication operation does not verify"},
		{"exposure receipt reserving one unit under the maximum aggregate payout", true,
			func(in *signedOfferInputs) { in.reserved.AmountAtomic = "999" }, "exposure receipt is not bound to the offer"},
	})
}
