package agentguarantor

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentcommerce"
)

const maxCollateralAdapterEvidenceBytes = 256 << 10

// CollateralAdapterFinalityVerifier is the owner-enabled, profile-specific
// trust boundary which turns Adapter bytes into a verified finalized state
// transition. A digest-shaped evidence blob is never sufficient by itself.
type CollateralAdapterFinalityVerifier interface {
	VerifyCollateralAdapterFinalityV1(request CollateralAdapterRequestV1, evidence CollateralAdapterEvidenceV1,
		result CollateralPositionStateV1, finalityReference string, finalizedAt time.Time,
		terms CollateralTermsV1) error
}

func collateralFinalityVerifierFromResolverV1(resolver AuthorityKeyResolver) CollateralAdapterFinalityVerifier {
	verifier, _ := resolver.(CollateralAdapterFinalityVerifier)
	return verifier
}

var collateralTransitionRulesV1 = map[string]struct {
	prior, result []string
	decision      string
	destination   string
}{
	"lock":                {[]string{"lock_pending", "unproven"}, []string{"locked"}, "forbidden", "forbidden"},
	"encumber":            {[]string{"locked"}, []string{"encumbered"}, "forbidden", "forbidden"},
	"payout":              {[]string{"encumbered", "partially_consumed"}, []string{"depleted", "partially_consumed"}, "required", "agreement_fixed"},
	"release":             {[]string{"encumbered", "locked", "partially_consumed"}, []string{"released"}, "forbidden", "forbidden"},
	"reorg":               {[]string{"encumbered", "locked", "partially_consumed"}, []string{"reorged"}, "forbidden", "forbidden"},
	"position_impairment": {[]string{"encumbered", "locked", "partially_consumed", "reorged"}, []string{"defaulted"}, "forbidden", "forbidden"},
	"payout_default":      {[]string{"encumbered", "partially_consumed"}, []string{"defaulted"}, "required", "agreement_fixed"},
}

func CollateralControlDisclosureDigestV1(value CollateralControlDisclosureV1) (string, error) {
	if err := ValidateCollateralControlDisclosureV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-collateral-control-disclosure.v1", value)
}

func ValidateCollateralControlDisclosureV1(value CollateralControlDisclosureV1) error {
	if value.SchemaVersion != 1 || agentcommerce.ValidateProfileRefV1(value.CustodyAdapterProfile) != nil ||
		!sortedUnique(value.AdapterOperatorSubjects, 64, validID) ||
		!sortedUnique(value.CustodianControllerRootSubjects, 64, validID) {
		return errors.New("Guarantor collateral control disclosure is invalid")
	}
	switch value.DeclaredGuarantorControlRelationship {
	case "third_party_control_asserted":
		if value.ControlResolutionProfile == nil || value.DisclosureEvidenceProfile == nil ||
			agentcommerce.ValidateProfileRefV1(*value.ControlResolutionProfile) != nil ||
			agentcommerce.ValidateProfileRefV1(*value.DisclosureEvidenceProfile) != nil ||
			QuorumThresholdMustFailV1(value.DisclosureAuthorityQuorumRule, value.DisclosureAuthoritySubjects) ||
			value.MaximumDisclosureEvidenceAgeSeconds == 0 {
			return errors.New("third-party collateral control disclosure lacks authority evidence")
		}
	case "guarantor_controlled", "shared_control", "control_undetermined":
		if value.ControlResolutionProfile != nil || value.DisclosureEvidenceProfile != nil ||
			len(value.DisclosureAuthoritySubjects) != 0 || value.DisclosureAuthorityQuorumRule != "" ||
			value.MaximumDisclosureEvidenceAgeSeconds != 0 {
			return errors.New("collateral control disclosure carries forbidden third-party evidence fields")
		}
	default:
		return errors.New("collateral control relationship is unsupported")
	}
	if len(value.AdapterOperatorSubjects) == 0 || len(value.CustodianControllerRootSubjects) == 0 {
		return errors.New("collateral control roots are empty")
	}
	return nil
}

func CollateralTransitionProfileDigestV1(value CollateralTransitionProfileV1) (string, error) {
	if err := ValidateCollateralTransitionProfileV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-collateral-transition-profile.v1", value)
}

func ValidateCollateralTransitionProfileV1(value CollateralTransitionProfileV1) error {
	rule, found := collateralTransitionRulesV1[value.TransitionKind]
	if !found || agentcommerce.ValidateProfileRefV1(value.SuccessorDerivationProfile) != nil ||
		agentcommerce.ValidateProfileRefV1(value.AdapterProfile) != nil ||
		!validContentType(value.AdapterRequestContentType) || agentcommerce.ValidateProfileRefV1(value.AdapterRequestProfile) != nil ||
		value.MaximumAdapterRequestBytes == 0 || value.MaximumAdapterRequestBytes > 256<<10 ||
		!validContentType(value.AdapterEvidenceContentType) || agentcommerce.ValidateProfileRefV1(value.AdapterEvidenceProfile) != nil ||
		!equalStrings(value.PermittedPriorStates, rule.prior) || !equalStrings(value.PermittedResultingStates, rule.result) ||
		value.AuthorizedClaimDecisionBinding != rule.decision || value.PayoutDestinationBinding != rule.destination ||
		!sortedUniqueAllowEmpty(value.PrerequisiteEvidenceRoles, 32, func(v string) bool { return validToken(v, 128) }) {
		return errors.New("Guarantor collateral transition profile is invalid")
	}
	switch value.AuthorizationSubjectSource {
	case "custodian":
		if value.CustodianAuthorizationBinding == nil || validateCollateralAuthorizationBinding(*value.CustodianAuthorizationBinding) != nil {
			return errors.New("custodian collateral transition lacks an authorization binding")
		}
	case "independent_execution_quorum":
		if value.CustodianAuthorizationBinding != nil {
			return errors.New("independent collateral transition carries a custodian binding")
		}
	default:
		return errors.New("collateral transition authority source is unsupported")
	}
	return nil
}

func validateCollateralAuthorizationBinding(value CollateralAuthorizationBindingV1) error {
	if agentcommerce.ValidateProfileRefV1(value.AuthorizationProfile) != nil ||
		QuorumThresholdMustFailV1(value.AuthorizationQuorumRule, value.AuthorizationSubjects) {
		return errors.New("collateral authorization binding is invalid")
	}
	return nil
}

func CollateralTransitionBindingDigestV1(value CollateralTransitionBindingV1) (string, error) {
	profileDigest, err := CollateralTransitionProfileDigestV1(value.TransitionProfile)
	if err != nil || profileDigest != value.TransitionProfileDigest || validateCollateralAuthorizationBinding(value.AuthorizationBinding) != nil {
		return "", errors.New("Guarantor collateral transition binding is invalid")
	}
	if value.TransitionProfile.AuthorizationSubjectSource == "custodian" {
		left, _ := guarantorCodec.Marshal(value.AuthorizationBinding)
		right, _ := guarantorCodec.Marshal(*value.TransitionProfile.CustodianAuthorizationBinding)
		if !bytes.Equal(left, right) {
			return "", errors.New("collateral transition substituted its custodian authorization")
		}
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-collateral-transition-binding.v1", value)
}

// validateCollateralTransitionBindingOfTermsV1 requires a transition binding
// a request or an action presents to be, byte for byte, one of the bindings
// the collateral terms carry. A binding is well formed on its own (its profile
// digest and its custodian authorization are consistent with each other), so
// without this a transition could be made, and its evidence authorized, under
// a binding of the presenter's choosing: another Adapter, another evidence
// profile or other authorization subjects than the Agreement fixed.
func validateCollateralTransitionBindingOfTermsV1(binding CollateralTransitionBindingV1, terms CollateralTermsV1) error {
	for _, agreed := range terms.TransitionBindings {
		if equalCanonical(agreed, binding) {
			return nil
		}
	}
	return errors.New("Guarantor collateral transition binding is not one of the Agreement's transition bindings")
}

func ValidateCollateralTermsV1(value CollateralTermsV1) error {
	if !validID(value.PositionID) || !validDigest(value.SelectedCollateralProfileDigest) ||
		(value.AssuranceLevel != AssuranceCollateralAttested && value.AssuranceLevel != AssuranceIndependentlyEnforced) ||
		agentcommerce.ValidateAssetIdentityV1(value.Asset) != nil || validateAmount(value.Amount, true) != nil ||
		value.Amount.Asset != value.Asset || !validID(value.CollateralPrincipalSubject) ||
		agentcommerce.ValidateProfileRefV1(value.CustodyAdapterProfile) != nil ||
		ValidateCollateralControlDisclosureV1(value.CollateralControlDisclosure) != nil ||
		value.CollateralControlDisclosure.CustodyAdapterProfile != value.CustodyAdapterProfile ||
		agentcommerce.ValidateProfileRefV1(value.PositionIdentityProfile) != nil || len(value.TransitionBindings) == 0 ||
		len(value.TransitionBindings) > len(collateralTransitionRulesV1) || !validDigest(value.ContractOrAccountDigest) ||
		!value.ExclusiveAllocationRequired || value.LockByUnix == 0 || value.LockUntilUnix < value.LockByUnix ||
		value.ReleaseNotBeforeUnix > value.LockUntilUnix || agentcommerce.ValidateProfileRefV1(value.FinalityProfile) != nil ||
		value.MaximumEvidenceAgeSeconds == 0 {
		return errors.New("Guarantor collateral terms are invalid")
	}
	previous := ""
	for _, binding := range value.TransitionBindings {
		if _, err := CollateralTransitionBindingDigestV1(binding); err != nil || binding.TransitionProfile.TransitionKind <= previous {
			return errors.New("Guarantor collateral transition bindings are invalid or unsorted")
		}
		previous = binding.TransitionProfile.TransitionKind
	}
	if value.AssuranceLevel == AssuranceIndependentlyEnforced {
		if value.IndependentExecutionProfile == nil || agentcommerce.ValidateProfileRefV1(*value.IndependentExecutionProfile) != nil ||
			QuorumThresholdMustFailV1(value.IndependentExecutionQuorumRule, value.IndependentExecutionAuthoritySubjects) ||
			!validDigest(value.NetworkDomainDigest) || !validDigest(value.AdapterCodeDigest) {
			return errors.New("independently enforceable collateral terms are incomplete")
		}
		for _, binding := range value.TransitionBindings {
			if binding.TransitionProfile.AuthorizationSubjectSource == "independent_execution_quorum" &&
				(binding.AuthorizationBinding.AuthorizationProfile != *value.IndependentExecutionProfile ||
					!equalStrings(binding.AuthorizationBinding.AuthorizationSubjects, value.IndependentExecutionAuthoritySubjects) ||
					binding.AuthorizationBinding.AuthorizationQuorumRule != value.IndependentExecutionQuorumRule) {
				return errors.New("independent collateral transition authority differs from terms")
			}
		}
	} else if value.IndependentExecutionProfile != nil || len(value.IndependentExecutionAuthoritySubjects) != 0 ||
		value.IndependentExecutionQuorumRule != "" || value.NetworkDomainDigest != "" || value.AdapterCodeDigest != "" {
		return errors.New("attested collateral terms carry independent enforcement fields")
	}
	return nil
}

func CollateralPositionStateDigestV1(value CollateralPositionStateV1) (string, error) {
	if err := ValidateCollateralPositionStateV1(value); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-collateral-position-state.v1", value)
}

func ValidateCollateralPositionStateV1(value CollateralPositionStateV1) error {
	if value.SchemaVersion != 1 || !validDigest(value.CoverageAgreementBodyDigest) ||
		!validToken(value.CollateralObligationID, 128) || !validID(value.PositionID) || !validDigest(value.PositionDigest) ||
		!validDigest(value.CoverageBindingDigest) || value.StateRevision == 0 || !validCollateralStatus(value.Status) ||
		agentcommerce.ValidateAssetIdentityV1(value.Asset) != nil || validateAmount(value.AllocatedAmount, true) != nil ||
		validateAmount(value.CumulativeConsumed, false) != nil || validateAmount(value.CumulativeReleased, false) != nil ||
		validateAmount(value.CumulativeImpaired, false) != nil || validateAmount(value.RemainingAmount, false) != nil {
		return errors.New("Guarantor collateral position state is invalid")
	}
	for _, amount := range []AtomicAmountV1{value.AllocatedAmount, value.CumulativeConsumed, value.CumulativeReleased, value.CumulativeImpaired, value.RemainingAmount} {
		if amount.Asset != value.Asset {
			return errors.New("Guarantor collateral position has mixed assets")
		}
	}
	total := new(big.Int)
	for _, amount := range []AtomicAmountV1{value.CumulativeConsumed, value.CumulativeReleased, value.CumulativeImpaired, value.RemainingAmount} {
		parsed, _ := new(big.Int).SetString(amount.AmountAtomic, 10)
		total.Add(total, parsed)
	}
	allocated, _ := new(big.Int).SetString(value.AllocatedAmount.AmountAtomic, 10)
	if total.Cmp(allocated) != 0 {
		return errors.New("Guarantor collateral position accounting does not balance")
	}
	return nil
}

func validCollateralStatus(value CollateralStatus) bool {
	switch value {
	case CollateralUnproven, CollateralLockPending, CollateralLocked, CollateralEncumbered,
		CollateralPayoutPending, CollateralPartiallyConsumed, CollateralDepleted,
		CollateralReleasePending, CollateralReleased, CollateralAmbiguous, CollateralReorged, CollateralDefaulted:
		return true
	default:
		return false
	}
}

func validContentType(value string) bool {
	return len(value) > 0 && len(value) <= 256 && !bytes.ContainsAny([]byte(value), "\x00\r\n")
}

func CollateralAdapterRequestDigestV1(value CollateralAdapterRequestV1, binding CollateralTransitionBindingV1,
	terms CollateralTermsV1) (string, error) {
	if err := ValidateCollateralAdapterRequestV1(value, binding, terms); err != nil {
		return "", err
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-collateral-adapter-request.v1", value)
}

func ValidateCollateralAdapterRequestV1(value CollateralAdapterRequestV1, binding CollateralTransitionBindingV1,
	terms CollateralTermsV1) error {
	bindingDigest, bindingErr := CollateralTransitionBindingDigestV1(binding)
	stateDigest, stateErr := CollateralPositionStateDigestV1(value.ExpectedPositionState)
	if bindingErr != nil || stateErr != nil || ValidateCollateralTermsV1(terms) != nil || value.SchemaVersion != 1 ||
		value.AdapterProfile != binding.TransitionProfile.AdapterProfile ||
		value.AdapterRequestProfile != binding.TransitionProfile.AdapterRequestProfile ||
		value.CoverageAgreementBodyDigest != value.ExpectedPositionState.CoverageAgreementBodyDigest ||
		value.CollateralObligationID != value.ExpectedPositionState.CollateralObligationID ||
		value.CollateralPositionID != terms.PositionID || value.CollateralPositionID != value.ExpectedPositionState.PositionID ||
		value.TransitionBindingDigest != bindingDigest || value.TransitionKind != binding.TransitionProfile.TransitionKind ||
		value.ExpectedStateDigest != stateDigest || value.Asset != terms.Asset || value.Asset != value.ExpectedPositionState.Asset ||
		validateAmount(value.Amount, true) != nil || value.Amount.Asset != value.Asset ||
		!validDigest(value.PrerequisiteEvidenceSetDigest) {
		return errors.New("Guarantor collateral Adapter request is invalid")
	}
	if err := validateCollateralTransitionBindingOfTermsV1(binding, terms); err != nil {
		return err
	}
	if !containsString(binding.TransitionProfile.PermittedPriorStates, collateralStateToken(value.ExpectedPositionState.Status)) {
		return errors.New("Guarantor collateral Adapter request uses an impermissible prior state")
	}
	needsDecision := value.TransitionKind == "payout" || value.TransitionKind == "payout_default"
	if needsDecision {
		if !validDigest(value.PayoutDestinationDigest) || !validDigest(value.AgreementPaymentRequestDigest) ||
			!validID(value.ObligationInstanceID) || !validDigest(value.AuthorizedClaimDecisionEnvelopeDigest) {
			return errors.New("Guarantor collateral payout request lacks an exact payment binding")
		}
	} else if value.PayoutDestinationDigest != "" || value.AgreementPaymentRequestDigest != "" ||
		value.ObligationInstanceID != "" || value.AuthorizedClaimDecisionEnvelopeDigest != "" {
		return errors.New("non-payout collateral request carries payment fields")
	}
	encoded, err := guarantorCodec.Marshal(value)
	if err != nil || uint64(len(encoded)) > binding.TransitionProfile.MaximumAdapterRequestBytes {
		return errors.New("complete Guarantor collateral Adapter request exceeds its bound")
	}
	return nil
}

func collateralStateToken(value CollateralStatus) string {
	return string(bytes.ToLower([]byte(value)))
}

func ValidateCollateralTransitionActionBodyV1(value CollateralTransitionActionBodyV1, terms CollateralTermsV1,
	allowCompositePayout bool) error {
	bindingDigest, bindingErr := CollateralTransitionBindingDigestV1(value.TransitionBinding)
	requestDigest, requestErr := CollateralAdapterRequestDigestV1(value.AdapterRequest, value.TransitionBinding, terms)
	evidenceDigest, evidenceErr := CanonicalGuarantorEvidenceSetDigestV1(value.PrerequisiteEvidenceSet)
	_ = requestDigest
	if bindingErr != nil || requestErr != nil || evidenceErr != nil || value.SchemaVersion != 1 ||
		!validDigest(value.CoverageAgreementBodyDigest) || !validToken(value.ObligationID, 128) ||
		value.CoverageAgreementBodyDigest != value.AdapterRequest.CoverageAgreementBodyDigest ||
		value.ObligationID != value.AdapterRequest.CollateralObligationID || value.CollateralPositionID != terms.PositionID ||
		value.TransitionKind != value.TransitionBinding.TransitionProfile.TransitionKind ||
		value.ExpectedStateRevision != value.AdapterRequest.ExpectedPositionState.StateRevision ||
		value.ExpectedStateDigest != value.AdapterRequest.ExpectedStateDigest || value.Asset != terms.Asset ||
		value.Asset != value.AdapterRequest.Asset || value.Amount != value.AdapterRequest.Amount ||
		value.PayoutDestinationDigest != value.AdapterRequest.PayoutDestinationDigest ||
		value.AdapterRequest.TransitionBindingDigest != bindingDigest ||
		value.AdapterRequest.PrerequisiteEvidenceSetDigest != evidenceDigest {
		return errors.New("Guarantor collateral transition action is invalid")
	}
	if value.TransitionKind == "payout" && !allowCompositePayout {
		return errors.New("collateral payout requires the atomic settlement composite")
	}
	return nil
}

func ApplyCollateralAdapterTransitionV1(request CollateralAdapterRequestV1,
	binding CollateralTransitionBindingV1, terms CollateralTermsV1) (CollateralPositionStateV1, error) {
	if err := ValidateCollateralAdapterRequestV1(request, binding, terms); err != nil {
		return CollateralPositionStateV1{}, err
	}
	current := request.ExpectedPositionState
	result := current
	result.StateRevision++
	amount, _ := new(big.Int).SetString(request.Amount.AmountAtomic, 10)
	remaining, _ := new(big.Int).SetString(current.RemainingAmount.AmountAtomic, 10)
	consumed, _ := new(big.Int).SetString(current.CumulativeConsumed.AmountAtomic, 10)
	released, _ := new(big.Int).SetString(current.CumulativeReleased.AmountAtomic, 10)
	impaired, _ := new(big.Int).SetString(current.CumulativeImpaired.AmountAtomic, 10)
	switch request.TransitionKind {
	case "lock":
		result.Status = CollateralLocked
	case "encumber":
		result.Status = CollateralEncumbered
	case "payout":
		if amount.Cmp(remaining) > 0 {
			return CollateralPositionStateV1{}, errors.New("collateral payout exceeds remaining allocation")
		}
		remaining.Sub(remaining, amount)
		consumed.Add(consumed, amount)
		result.Status = CollateralPartiallyConsumed
		if remaining.Sign() == 0 {
			result.Status = CollateralDepleted
		}
	case "release":
		released.Add(released, remaining)
		remaining.SetUint64(0)
		result.Status = CollateralReleased
	case "reorg":
		result.Status = CollateralReorged
	case "position_impairment", "payout_default":
		if amount.Cmp(remaining) > 0 {
			return CollateralPositionStateV1{}, errors.New("collateral impairment exceeds remaining allocation")
		}
		remaining.Sub(remaining, amount)
		impaired.Add(impaired, amount)
		result.Status = CollateralDefaulted
	default:
		return CollateralPositionStateV1{}, errors.New("unsupported collateral transition")
	}
	result.CumulativeConsumed.AmountAtomic = consumed.String()
	result.CumulativeReleased.AmountAtomic = released.String()
	result.CumulativeImpaired.AmountAtomic = impaired.String()
	result.RemainingAmount.AmountAtomic = remaining.String()
	if !containsString(binding.TransitionProfile.PermittedResultingStates, collateralStateToken(result.Status)) ||
		ValidateCollateralPositionStateV1(result) != nil {
		return CollateralPositionStateV1{}, errors.New("collateral successor violates its transition profile")
	}
	return result, nil
}

func CollateralAdapterEvidenceDigestV1(value CollateralAdapterEvidenceV1) (string, error) {
	if !validContentType(value.ContentType) || agentcommerce.ValidateProfileRefV1(value.EvidenceProfile) != nil ||
		!validDigest(value.TransitionBindingDigest) || !validDigest(value.AdapterProfileDigest) ||
		collateralTransitionRulesV1[value.TransitionKind].prior == nil || !validDigest(value.AdapterRequestDigest) ||
		value.PriorStateRevision == 0 || value.ResultingStateRevision != value.PriorStateRevision+1 ||
		!validDigest(value.ExpectedStateDigest) || !validDigest(value.ResultingStateDigest) {
		return "", errors.New("Guarantor collateral Adapter evidence is invalid")
	}
	switch value.Representation {
	case "inline":
		if len(value.CanonicalEvidenceBytes) == 0 || len(value.CanonicalEvidenceBytes) > maxCollateralAdapterEvidenceBytes || value.ImmutableDescriptor != nil {
			return "", errors.New("inline collateral evidence representation is invalid")
		}
	case "content_addressed":
		if len(value.CanonicalEvidenceBytes) != 0 || value.ImmutableDescriptor == nil ||
			validateImmutableEvidenceDescriptor(*value.ImmutableDescriptor) != nil {
			return "", errors.New("content-addressed collateral evidence representation is invalid")
		}
	default:
		return "", errors.New("collateral evidence representation is unsupported")
	}
	return guarantorCodec.Digest("tos.service.agent-guarantor-collateral-adapter-evidence.v1", value)
}

func validateImmutableEvidenceDescriptor(value ImmutableEvidenceDescriptorV1) error {
	if !validContentType(value.ContentType) || !validDigest(value.ContentDigest) || value.ContentSize == 0 ||
		value.ContentSize > MaxCanonicalObjectBytes || !validDigest(value.RetrievalPolicyDigest) {
		return errors.New("immutable Guarantor evidence descriptor is invalid")
	}
	return nil
}

func CollateralEvidenceDigestV1(value AuthorizedCollateralEvidenceV1) (string, error) {
	if value.Body.SchemaVersion != 1 || len(value.Authorizations) == 0 || len(value.Authorizations) > MaxAuthorizations {
		return "", errors.New("authorized Guarantor collateral evidence is invalid")
	}
	return guarantorCodec.Digest(CollateralDomain, value)
}

// validateCollateralReleaseGuardV1 holds a release transition to the
// Agreement's earliest-release guard: its stage action is admitted, and its
// Adapter evidence finalized, no earlier than release_not_before_unix. The
// terms place that guard after the final deadline and its reorg window, so a
// release that respects it cannot remove collateral a payout may still need.
// No other transition kind releases the position, so none is held to it.
func validateCollateralReleaseGuardV1(transitionKind string, finalizedAtUnix, admittedAtUnix uint64,
	terms CollateralTermsV1) error {
	if transitionKind != "release" {
		return nil
	}
	if admittedAtUnix < terms.ReleaseNotBeforeUnix {
		return errors.New("Guarantor collateral release is admitted before the Agreement's release guard")
	}
	if finalizedAtUnix < terms.ReleaseNotBeforeUnix {
		return errors.New("Guarantor collateral release is finalized before the Agreement's release guard")
	}
	return nil
}

// terminalClaimSetContentTypeV1 is the media type of an authorized terminal
// claim set, as an evidence item names it.
const terminalClaimSetContentTypeV1 = GuarantorMediaTypePrefixV1 + "terminal-claim-set.v1+cbor"

// collateralReleasePrerequisitePurposeV1 is the purpose of the prerequisite
// evidence set of a release transition.
const collateralReleasePrerequisitePurposeV1 = "collateral-release"

// collateralReleaseTerminalClaimSetV1 is the digest of the authorized terminal
// claim set a release transition is made against, as its action commits it:
// collateral is released only against the coverage's closed claim cut. The
// prerequisite evidence set has the release purpose and the action's coverage
// Agreement as context, and names exactly one terminal claim set, through a
// descriptor of that media type and of the item's own envelope digest, so the
// digest the action commits is the digest the set is retrieved by.
//
// This is all a holder of the collateral evidence and the terms can check: it
// has no firm offer and no set. VerifyCollateralReleaseEvidenceV1 verifies the
// set itself and ties it to the release.
func collateralReleaseTerminalClaimSetV1(action CollateralTransitionActionBodyV1) (string, error) {
	prerequisites := action.PrerequisiteEvidenceSet
	var named []CanonicalGuarantorEvidenceItemV1
	for _, item := range prerequisites.Items {
		if item.ContentType == terminalClaimSetContentTypeV1 {
			named = append(named, item)
		}
	}
	if len(named) != 1 {
		return "", errors.New("Guarantor collateral release does not name exactly one authorized terminal claim set as its prerequisite")
	}
	if prerequisites.Purpose != collateralReleasePrerequisitePurposeV1 {
		return "", errors.New("Guarantor collateral release prerequisites have another purpose than a collateral release")
	}
	if prerequisites.ContextDigest != action.CoverageAgreementBodyDigest {
		return "", errors.New("Guarantor collateral release prerequisites are of another coverage Agreement than the release")
	}
	item := named[0]
	if item.ImmutableDescriptor == nil || item.ImmutableDescriptor.ContentType != item.ContentType {
		return "", errors.New("Guarantor collateral release names its terminal claim set through a descriptor of another media type")
	}
	if item.ImmutableDescriptor.ContentDigest != item.EvidenceEnvelopeDigest {
		return "", errors.New("Guarantor collateral release names its terminal claim set through a descriptor of another object")
	}
	return item.EvidenceEnvelopeDigest, nil
}

// VerifyCollateralReleaseEvidenceV1 verifies the release of a coverage's
// collateral together with the terminal claim set it is made against, for a
// verifier that holds both and the firm offer: the release verifies as
// collateral evidence under the offer's terms, the set verifies as the
// offer's terminal claim set, and the release is of that set. The release
// commits the set's envelope digest, is of the offer's coverage Agreement, and
// is admitted no earlier than the set was created and than the set allows its
// release, so collateral is not released against a claim cut of another
// coverage, an unverifiable one, or one that does not exist yet.
func VerifyCollateralReleaseEvidenceV1(release AuthorizedCollateralEvidenceV1, claimSet AuthorizedTerminalClaimSetEvidenceV1,
	offer AuthorizedFirmCoverageOfferV1, agreementVerifier agentcommerce.AgreementEvidenceVerifier,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver,
	paymentVerifier agentcommerce.PaymentEvidenceVerifier, finalityVerifier CollateralAdapterFinalityVerifier, now time.Time) error {
	if release.CollateralTransitionActionBody.TransitionKind != "release" {
		return errors.New("Guarantor collateral release evidence is of another transition kind")
	}
	if err := VerifyCollateralEvidenceV1(release, offer.CoverageTerms, authorityResolver, fenceResolver, now, finalityVerifier,
		false); err != nil {
		return err
	}
	if err := VerifyTerminalClaimSetV1(claimSet, offer, agreementVerifier, authorityResolver, fenceResolver, paymentVerifier,
		now); err != nil {
		return fmt.Errorf("Guarantor collateral release stands on an invalid terminal claim set: %w", err)
	}
	return bindCollateralReleaseToTerminalClaimSetV1(release, claimSet, offer)
}

// bindCollateralReleaseToTerminalClaimSetV1 ties a verified release to the
// verified terminal claim set it names and to the offer both were verified
// against.
func bindCollateralReleaseToTerminalClaimSetV1(release AuthorizedCollateralEvidenceV1,
	claimSet AuthorizedTerminalClaimSetEvidenceV1, offer AuthorizedFirmCoverageOfferV1) error {
	named, err := collateralReleaseTerminalClaimSetV1(release.CollateralTransitionActionBody)
	if err != nil {
		return err
	}
	setDigest, err := TerminalClaimSetDigestV1(claimSet)
	if err != nil {
		return errors.New("Guarantor collateral release's terminal claim set cannot be digested")
	}
	if named != setDigest {
		return errors.New("Guarantor collateral release names another terminal claim set than the one presented")
	}
	if release.Body.CoverageAgreementBodyDigest != offer.Body.CoverageAgreementBodyDigest {
		return errors.New("Guarantor collateral release is of another coverage Agreement than the firm offer's")
	}
	admittedAt := release.StageActionAdmissionEvidence.Body.AdmittedAtUnix
	if admittedAt < claimSet.Body.ReleaseNotBeforeUnix {
		return errors.New("Guarantor collateral release precedes its terminal claim set's release time")
	}
	if admittedAt < claimSet.Body.CreatedAtUnix {
		return errors.New("Guarantor collateral release precedes the creation of its terminal claim set")
	}
	return nil
}

func VerifyCollateralEvidenceV1(value AuthorizedCollateralEvidenceV1, coverageTerms CoverageTermsV1,
	authorityResolver AuthorityKeyResolver, fenceResolver agentcommerce.FenceAuthorityResolver, now time.Time,
	finalityVerifier CollateralAdapterFinalityVerifier, allowCompositePayout bool) error {
	if coverageTerms.CollateralTerms == nil {
		return errors.New("Guarantor collateral evidence has no accepted collateral terms")
	}
	terms := *coverageTerms.CollateralTerms
	action := value.CollateralTransitionActionBody
	binding := action.TransitionBinding
	// The evidence is of the Agreement's collateral: its transition is made
	// under one of the terms' bindings and for the terms' collateral
	// obligation. The terms carry no Agreement digest, so which coverage
	// Agreement the evidence names is held by the verifier that has one: the
	// activation it is a prerequisite of, or the release verifier.
	if err := validateCollateralTransitionBindingOfTermsV1(binding, terms); err != nil {
		return err
	}
	if action.ObligationID != coverageTerms.CollateralObligationID {
		return errors.New("Guarantor collateral evidence is of another obligation than the Agreement's collateral obligation")
	}
	if authorityResolver == nil || fenceResolver == nil || finalityVerifier == nil || ValidateCoverageTerms(coverageTerms) != nil ||
		ValidateCollateralTransitionActionBodyV1(action, terms, allowCompositePayout) != nil {
		return errors.New("Guarantor collateral evidence context is invalid")
	}
	body := value.Body
	if err := validateCollateralReleaseGuardV1(action.TransitionKind, body.FinalizedAtUnix,
		value.StageActionAdmissionEvidence.Body.AdmittedAtUnix, terms); err != nil {
		return err
	}
	if action.TransitionKind == "release" {
		if _, err := collateralReleaseTerminalClaimSetV1(action); err != nil {
			return err
		}
	}
	if body.FinalizedAtUnix > ^uint64(0)-terms.MaximumEvidenceAgeSeconds ||
		uint64(now.UTC().Unix()) > body.FinalizedAtUnix+terms.MaximumEvidenceAgeSeconds {
		return errors.New("Guarantor collateral evidence is stale")
	}
	actionBodyDigest, actionBodyErr := guarantorCodec.Digest("tos.service.agent-guarantor-collateral-transition-action-body.v1", action)
	if actionBodyErr != nil {
		return errors.New("Guarantor collateral transition action body cannot be encoded")
	}
	requestDigest, _ := CollateralAdapterRequestDigestV1(action.AdapterRequest, binding, terms)
	adapterEvidenceDigest, adapterErr := CollateralAdapterEvidenceDigestV1(value.AdapterEvidence)
	expectedResult, resultErr := ApplyCollateralAdapterTransitionV1(action.AdapterRequest, binding, terms)
	resultDigest, digestErr := CollateralPositionStateDigestV1(value.ResultingPositionState)
	proofDigest, proofErr := AuthorityAdmissionEligibilityProofSetDigestV1(value.AuthorityAdmissionEligibilityProofSet)
	bindingDigest, _ := CollateralTransitionBindingDigestV1(binding)
	if adapterErr != nil || resultErr != nil || digestErr != nil || proofErr != nil || !equalCanonical(expectedResult, value.ResultingPositionState) ||
		body.CoverageAgreementBodyDigest != action.CoverageAgreementBodyDigest || body.CollateralObligationID != action.ObligationID ||
		body.PositionID != terms.PositionID || body.PositionDigest != value.ResultingPositionState.PositionDigest ||
		body.TransitionBindingDigest != bindingDigest || body.CollateralTransitionActionBodyDigest != actionBodyDigest ||
		body.AdapterProfile != binding.TransitionProfile.AdapterProfile || body.EvidenceProfile != binding.TransitionProfile.AdapterEvidenceProfile ||
		body.EvidenceContentType != binding.TransitionProfile.AdapterEvidenceContentType || body.TransitionKind != action.TransitionKind ||
		body.Amount != action.Amount || body.CumulativeConsumed != value.ResultingPositionState.CumulativeConsumed ||
		body.PriorStateRevision != action.ExpectedStateRevision || body.ResultingStateRevision != action.ExpectedStateRevision+1 ||
		body.ExpectedStateDigest != action.ExpectedStateDigest || body.ResultingStateDigest != resultDigest ||
		body.CoverageBindingDigest != value.ResultingPositionState.CoverageBindingDigest ||
		body.AuthorizedClaimDecisionEnvelopeDigest != action.AdapterRequest.AuthorizedClaimDecisionEnvelopeDigest ||
		body.AgreementPaymentRequestDigest != action.AdapterRequest.AgreementPaymentRequestDigest ||
		body.ObligationInstanceID != action.AdapterRequest.ObligationInstanceID || !validDigest(body.FinalityReference) ||
		body.FinalizedAtUnix == 0 || uint64(now.UTC().Unix()) < body.FinalizedAtUnix || body.AdapterRequestDigest != requestDigest ||
		body.AdapterEvidenceDigest != adapterEvidenceDigest || !validDigest(body.AuthorizedActionDigest) ||
		!validDigest(body.StableActionID) || !validDigest(body.ExactRequestDigest) || body.WriterGeneration == 0 ||
		!validDigest(body.WriterFenceDigest) || body.AuthorityAdmissionEligibilityProofSetDigest != proofDigest ||
		value.AuthorityAdmissionEligibilityProofSet.AdmittedActionDigest != body.AuthorizedActionDigest {
		return errors.New("Guarantor collateral evidence binding is invalid")
	}
	adapter := value.AdapterEvidence
	if adapter.ContentType != body.EvidenceContentType || adapter.EvidenceProfile != body.EvidenceProfile ||
		adapter.TransitionBindingDigest != bindingDigest || adapter.AdapterProfileDigest != body.AdapterProfile.ProfileDigest ||
		adapter.TransitionKind != body.TransitionKind || adapter.AdapterRequestDigest != requestDigest ||
		adapter.PriorStateRevision != body.PriorStateRevision || adapter.ResultingStateRevision != body.ResultingStateRevision ||
		adapter.ExpectedStateDigest != body.ExpectedStateDigest || adapter.ResultingStateDigest != body.ResultingStateDigest {
		return errors.New("Guarantor collateral Adapter evidence differs from its outer body")
	}
	if err := finalityVerifier.VerifyCollateralAdapterFinalityV1(action.AdapterRequest, adapter,
		value.ResultingPositionState, body.FinalityReference, time.Unix(int64(body.FinalizedAtUnix), 0).UTC(), terms); err != nil {
		return errors.New("Guarantor collateral Adapter finality does not verify: " + err.Error())
	}
	fields := map[string]agentcommerce.SemanticValue{
		"owner_id":                  agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.OwnerID),
		"agent_id":                  agentcommerce.ID(value.StageActionAdmissionEvidence.AuthorizedAction.AgentID),
		"agreement_body_digest":     agentcommerce.Digest32(body.CoverageAgreementBodyDigest),
		"obligation_id":             agentcommerce.ID(body.CollateralObligationID),
		"collateral_position_id":    agentcommerce.ID(body.PositionID),
		"transition_binding_digest": agentcommerce.Digest32(bindingDigest),
		"expected_state_revision":   agentcommerce.U64(body.PriorStateRevision),
		"transition_kind":           agentcommerce.Kind(body.TransitionKind),
	}
	bound, err := derivedAuxiliaryStageAuthorityV1(coverageTerms.StageActionAuthorityBinding,
		"collateral_transition", "payout_execution")
	if err != nil {
		return err
	}
	if err := verifyPortableStage(value.StageActionAdmissionEvidence, &bound, action, fields, "collateral_transition",
		body.AuthorizedActionDigest, body.StableActionID, body.ExactRequestDigest, body.WriterGeneration,
		body.WriterFenceDigest, authorityResolver, fenceResolver, now); err != nil {
		return err
	}
	for _, authorization := range value.Authorizations {
		if authorization.ProfileURI != binding.AuthorizationBinding.AuthorizationProfile.ProfileURI ||
			authorization.ProfileVersion != binding.AuthorizationBinding.AuthorizationProfile.ProfileVersion ||
			authorization.ProfileDigest != binding.AuthorizationBinding.AuthorizationProfile.ProfileDigest {
			return errors.New("Guarantor collateral evidence uses a substituted authorization profile")
		}
	}
	bodyDigest, _ := guarantorCodec.Digest("tos.service.agent-guarantor-collateral-evidence-body.v1", body)
	return ValidateAuthorizationQuorumSet(value.Authorizations, "collateral-evidence", bodyDigest,
		"tos.service.agent-guarantor-collateral-evidence-signature.v1",
		binding.AuthorizationBinding.AuthorizationSubjects, binding.AuthorizationBinding.AuthorizationQuorumRule,
		authorityResolver, time.Unix(int64(body.FinalizedAtUnix), 0).UTC())
}
