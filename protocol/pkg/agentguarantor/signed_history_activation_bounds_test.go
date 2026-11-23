package agentguarantor

import "testing"

// The times an activation may be admitted at, on signed history: no earlier
// than the acceptance it consumes and no later than the activation cutoff,
// which is the coverage start.

// activationAt is the Guarantor-signed activation of the accepted coverage,
// admitted at at and otherwise the history's own.
func (history *signedHistory) activationAt(signed signedOffer, acceptance AuthorizedCoverageAcceptanceReceiptV1,
	at uint64) AuthorizedCoverageActivationEvidenceV1 {
	prior := history.vary
	history.vary.activatedAt = at
	evidence := history.offerActivation(signed, acceptance)
	history.vary = prior
	if evidence.Body.ActivatedAtUnix != at || evidence.StageActionAdmissionEvidence.Body.AdmittedAtUnix != at {
		history.t.Fatalf("the activation is admitted at %d and states %d, want %d",
			evidence.StageActionAdmissionEvidence.Body.AdmittedAtUnix, evidence.Body.ActivatedAtUnix, at)
	}
	return evidence
}

// collateralControl is the Guarantor-signed collateral-control evidence of the
// terms' control disclosure on the coverage Agreement of digest agreement,
// observed at observedAt and expiring at expiresAt.
func (history *signedHistory) collateralControl(terms CoverageTermsV1, agreement string,
	observedAt, expiresAt uint64) AuthorizedCollateralControlEvidenceV1 {
	t, disclosure := history.t, terms.CollateralTerms.CollateralControlDisclosure
	disclosureDigest, err := CollateralControlDisclosureDigestV1(disclosure)
	if err != nil {
		t.Fatal(err)
	}
	body := CollateralControlEvidenceBodyV1{SchemaVersion: 1, CoverageAgreementBodyDigest: agreement,
		CollateralObligationID: terms.CollateralObligationID, SelectedCollateralProfileDigest: terms.SelectedCollateralProfileDigest,
		CollateralControlDisclosureDigest: disclosureDigest, CustodyAdapterProfile: disclosure.CustodyAdapterProfile,
		AdapterOperatorSubjects:              disclosure.AdapterOperatorSubjects,
		CustodianControllerRootSubjects:      disclosure.CustodianControllerRootSubjects,
		DeclaredGuarantorControlRelationship: disclosure.DeclaredGuarantorControlRelationship,
		ObservedAtUnix:                       observedAt, ExpiresAtUnix: expiresAt}
	bodyDigest, err := Digest("tos.service.agent-guarantor-collateral-control-evidence-body.v1", body)
	if err != nil {
		t.Fatal(err)
	}
	evidence := AuthorizedCollateralControlEvidenceV1{Body: body,
		Authorizations: []ProfileQualifiedObjectAuthorizationV1{history.signObjectAs(terms.GuarantorAgentID,
			terms.LifecycleAuthorizationProfile, "collateral-control-evidence", bodyDigest,
			"tos.service.agent-guarantor-collateral-control-evidence-signature.v1", observedAt)}}
	if _, err := CollateralControlEvidenceDigestV1(evidence); err != nil {
		t.Fatalf("signed-history collateral control evidence is malformed: %v", err)
	}
	return evidence
}

// collateralizedActivation is the activation of the accepted collateralized
// coverage, one second after its acceptance, on its collateral prerequisites:
// the custodian-signed lock of the whole position, admitted and finalized at
// lockedAt, and the Guarantor's collateral-control evidence, observed at
// lockedAt and expiring at controlExpiresAt. Both are named by descriptor and
// held by the offer's resolver.
func (history *signedHistory) collateralizedActivation(signed signedOffer, acceptance AuthorizedCoverageAcceptanceReceiptV1,
	lockedAt, controlExpiresAt uint64) AuthorizedCoverageActivationEvidenceV1 {
	t, terms, agreement := history.t, signed.offer.CoverageTerms, signed.offer.Body.CoverageAgreementBodyDigest
	policy := terms.SelectedCollateralProfileDigest
	lock := history.collateralEvidence(terms, collateralTransition{kind: "lock", agreement: agreement, purpose: "collateral-lock",
		prior: CollateralLockPending,
		prerequisite: []CanonicalGuarantorEvidenceItemV1{carriedEvidenceItem("application/vnd.tos.collateral-deposit.v1+cbor",
			testDigest("2"), []byte("deposit"), policy)},
		admittedAt: lockedAt, finalizedAt: lockedAt})
	lockDigest, err := CollateralEvidenceDigestV1(lock)
	if err != nil {
		t.Fatal(err)
	}
	control := history.collateralControl(terms, agreement, lockedAt, controlExpiresAt)
	controlDigest, err := CollateralControlEvidenceDigestV1(control)
	if err != nil {
		t.Fatal(err)
	}
	lockItem, lockWire := prerequisiteItem(t, CollateralEvidenceContentTypeV1, policy, lock, lockDigest)
	controlItem, controlWire := prerequisiteItem(t, CollateralControlEvidenceContentTypeV1, policy, control, controlDigest)
	signed.resolver.evidence[lockDigest], signed.resolver.evidence[controlDigest] = lockWire, controlWire
	items := []CanonicalGuarantorEvidenceItemV1{lockItem, controlItem}
	sortEvidenceItems(t, items)
	prior := history.vary
	history.vary.activationPrerequisites = &CanonicalGuarantorEvidenceSetV1{SchemaVersion: 1,
		Purpose: "coverage-activation-collateral", ContextDigest: agreement, Items: items}
	evidence := history.offerActivation(signed, acceptance)
	history.vary = prior
	return evidence
}

// TestSignedHistoryCollateralizedActivationIsJudgedAtItsActivationTime: the
// collateral prerequisites of an activation are current at the activation
// time, not at the verifier's present. Activation evidence of a collateralized
// coverage, built in full on a signed offer with a custodian-signed lock at
// the limit of its permitted age and collateral-control evidence that expires
// a second after the activation, is accepted by the unreplaced verifier at its
// activation time and ten years later, long after both prerequisites have
// aged out. The same activation on a lock that was a second too old when the
// coverage was activated, or on control evidence that expired at the instant
// of the activation, is refused at its activation time and ten years later,
// as is an activation that carries no prerequisites.
func TestSignedHistoryCollateralizedActivationIsJudgedAtItsActivationTime(t *testing.T) {
	const lacking = "collateral activation lacks exact allocation, control, or operational-independence proof"
	history := offerPhaseHistory(t)
	transitionAuthority, err := derivedAuxiliaryStageAuthorityV1(history.terms.StageActionAuthorityBinding,
		"collateral_transition", "payout_execution")
	if err != nil {
		t.Fatal(err)
	}
	history.useOfferPhaseFence(transitionAuthority.OperationActionKind)
	signed := history.quoteToOffer(true, signedOfferCollateralized)
	terms := signed.offer.CoverageTerms
	if terms.CollateralTerms == nil {
		t.Fatal("the signed offer is not collateralized")
	}
	acceptance := history.acceptanceReceipt(signed)
	activatedAt, maximumAge := acceptance.Body.AcceptedAtUnix+1, terms.CollateralTerms.MaximumEvidenceAgeSeconds
	verify := func(evidence AuthorizedCoverageActivationEvidenceV1, at uint64) error {
		if evidence.Body.ActivatedAtUnix != activatedAt {
			t.Fatalf("the coverage is activated at %d, want %d", evidence.Body.ActivatedAtUnix, activatedAt)
		}
		return VerifyCoverageActivationEvidenceV1(evidence, signed.offer, signedOfferAgreementVerifier{signed}, signed.resolver,
			history.fenceResolver, signedHistoryFinality{}, signedHistoryTime(at))
	}
	for _, test := range []struct {
		name                       string
		lockedAt, controlExpiresAt uint64
		carried                    bool
		want                       string
	}{
		{"an activation on a lock at its maximum age and control evidence expiring a second later",
			activatedAt - maximumAge, activatedAt + 1, true, ""},
		{"an activation on a lock a second over its maximum age",
			activatedAt - maximumAge - 1, activatedAt + 1, true, lacking},
		{"an activation on control evidence that expires at the activation",
			activatedAt - maximumAge, activatedAt, true, lacking},
		{"an activation that carries no collateral prerequisites", 0, 0, false,
			"collateralized coverage lacks finalized lock evidence"},
	} {
		evidence := history.offerActivation(signed, acceptance)
		if test.carried {
			evidence = history.collateralizedActivation(signed, acceptance, test.lockedAt, test.controlExpiresAt)
		}
		expectVerdict(t, test.name+", verified at its activation time", verify(evidence, activatedAt), test.want)
		expectVerdict(t, test.name+", verified ten years later", verify(evidence, activatedAt+signedHistoryLater), test.want)
	}
}

// TestSignedHistoryActivationIsBetweenItsAcceptanceAndTheCoverageStart: V1
// forbids retroactive activation. Activation evidence built in full on a
// signed offer is accepted when it is admitted at the instant of its
// acceptance and when it is admitted at the coverage start, and refused when
// it is admitted a second before the acceptance or a second after the coverage
// start. The four differ in the activation time alone, and each is verified
// ten years later, so the refusal is of the activation and not of its age.
func TestSignedHistoryActivationIsBetweenItsAcceptanceAndTheCoverageStart(t *testing.T) {
	history := offerPhaseHistory(t)
	signed := history.quoteToOffer(true, nil)
	acceptance := history.acceptanceReceipt(signed)
	acceptedAt, startsAt := acceptance.Body.AcceptedAtUnix, signed.offer.CoverageTerms.CoverageStartsAtUnix
	if acceptedAt >= startsAt {
		t.Fatalf("the offer is accepted at %d, not before the coverage starts at %d", acceptedAt, startsAt)
	}
	for _, test := range []struct {
		name string
		at   uint64
		want string
	}{
		{"an activation admitted at the instant of its acceptance", acceptedAt, ""},
		{"an activation admitted a second before its acceptance", acceptedAt - 1,
			"coverage activation is admitted before the acceptance it stands on"},
		{"an activation admitted at the coverage start", startsAt, ""},
		{"an activation admitted a second after the coverage start", startsAt + 1,
			"coverage activation is admitted after the activation cutoff, the coverage start"},
	} {
		evidence := history.activationAt(signed, acceptance, test.at)
		expectVerdict(t, test.name, VerifyCoverageActivationEvidenceV1(evidence, signed.offer, signedOfferAgreementVerifier{signed},
			signed.resolver, history.fenceResolver, nil, signedHistoryTime(startsAt+signedHistoryLater)), test.want)
	}
}
