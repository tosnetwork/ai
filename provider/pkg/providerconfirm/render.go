// Package providerconfirm is the confirmer of the MCP provider adapter
// (spec/docs/MCP_PROVIDER_ADAPTER_V1.md section 5): the program a human runs
// as the custody account, on a terminal no developer-account process
// touches, to read a pending offer, withdrawal or resume and type its
// confirmation code. It renders under the buyer confirmer's rules and
// reuses its escaping, amounts and terminal checks.
package providerconfirm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/tosnetwork/ai/protocol/pkg/buyerconfirm"
	"github.com/tosnetwork/ai/provider/pkg/provideragent/agentapi"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// Fixed headings. No text read from a file can reproduce them unescaped:
// every line break inside a printed string is escaped, so only the
// confirmer starts a line.
const (
	UntrustedHeading = "---- Text read from files, not from TOS: not checked by the provider agent ----"
	UntrustedEnd     = "---- end of text read from files ----"
	ProtocolHeading  = "==== TOS protocol fields, from the provider agent's own records ===="
	// Gutter begins every row of untrusted text, so a terminal's soft wrap
	// never puts that text at the start of a row.
	Gutter = "f| "
	// wrapWidth is the most display columns of untrusted text in one row.
	wrapWidth = 64
	// maxUntrusted bounds each untrusted string, in characters.
	maxUntrusted = 256
)

func field(s string) string { return buyerconfirm.Escape(s, buyerconfirm.MaxProtocolString) }

func tos(nano string) string { return buyerconfirm.TOS(nano) }

func utc(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC") }

// untrustedRows escapes text, collapses its spacing and hard-wraps it
// behind the gutter. Printable ASCII counts one column, every other shown
// character two, so a row is never wider than counted.
func untrustedRows(label, text string) []string {
	collapsed := strings.Join(strings.FieldsFunc(text, func(r rune) bool { return unicode.Is(unicode.Zs, r) }), " ")
	escaped := label + ": " + buyerconfirm.Escape(collapsed, maxUntrusted)
	var rows []string
	var row strings.Builder
	columns := 0
	for _, r := range escaped {
		width := 2
		if r >= 0x20 && r <= 0x7e {
			width = 1
		}
		if columns+width > wrapWidth {
			rows = append(rows, Gutter+row.String())
			row.Reset()
			columns = 0
		}
		row.WriteRune(r)
		columns += width
	}
	return append(rows, Gutter+row.String())
}

// Previews as the agent stores them.
type offerPreview struct {
	Offer        *servicebridge.OfferPreview `json:"offer"`
	PlannedSteps []string                    `json:"planned_steps"`
}

type withdrawPreview struct {
	Withdraw      *servicebridge.WithdrawPreview `json:"withdraw"`
	AmountNanoTOS string                         `json:"amount_nanotos"`
}

type resumePreview struct {
	Marker     *servicebridge.AdmissionPause  `json:"marker"`
	RecordedAs string                         `json:"recorded_as"`
	Preflight  *servicebridge.PreflightReport `json:"preflight"`
}

// Render lays out one presentation (section 5.2): the untrusted block
// first, then a fixed separator, then the protocol fields from the agent's
// own record with the confirmation code last.
func Render(p agentapi.Presentation) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	action := p.Action
	line("Action %s (%s) is waiting for your decision.", field(action.Reference), field(action.Kind))
	line("")
	line("%s", UntrustedHeading)
	for _, item := range []struct{ label, value string }{{"manifest name", p.UntrustedName},
		{"manifest description", p.UntrustedDescription}, {"pause reason", p.UntrustedReason}} {
		if item.value == "" {
			continue
		}
		for _, row := range untrustedRows(item.label, item.value) {
			line("%s", row)
		}
	}
	line("%s", UntrustedEnd)
	line("")
	line("%s", ProtocolHeading)
	line("Action kind:      %s", field(action.Kind))
	switch action.Kind {
	case agentapi.KindOffer:
		renderOffer(line, action.Preview)
	case agentapi.KindWithdraw:
		renderWithdraw(line, action.Preview)
	case agentapi.KindToken:
		line("Token provider action: confirm the exact actor, asset, atomic token amount and nanoTOS value below.")
		if raw, err := json.Marshal(action.Preview); err == nil {
			line("%s", field(string(raw)))
		}
	case agentapi.KindResume:
		renderResume(line, action.Preview)
	default:
		line("This kind is unknown to this confirmer. Do not confirm it.")
	}
	line("")
	line("Network:          %s", field(p.NetworkID))
	line("Provider Agent:   %s", field(p.ProviderAgentID))
	line("Owner wallet:     %s", field(p.OwnerWallet))
	line("Action reference: %s", field(action.Reference))
	line("Preview digest:   %s", field(action.PreviewDigest))
	line("Preview expires:  %s", utc(action.ExpiresUnix))
	line("Confirmation code:  %s (valid until %s)", field(p.Code), utc(p.ValidUntilUnix))
	return b.String()
}

type liner func(format string, args ...any)

func renderOffer(line liner, raw json.RawMessage) {
	var preview offerPreview
	if json.Unmarshal(raw, &preview) != nil || preview.Offer == nil {
		line("The offer preview does not decode. Do not confirm it.")
		return
	}
	offer := preview.Offer
	terms := offer.Terms
	line("Publishes the offer below. After confirmation the node responds to admitted calls on its own.")
	line("Owner wallet:     %s (pays every fee and the values attached below)", field(offer.OwnerWallet))
	line("Provider Agent:   %s at %s", field(offer.ProviderAgentID), field(offer.ProviderAgent))
	line("Actor:            %s", field(offer.Actor))
	line("Actor code hash:  %s", field(offer.ActorCodeHash))
	line("Attestor:         %s, key %s", field(offer.AttestorController), field(offer.AttestorKeyID))
	line("Capability:       %s version %s at %s", field(offer.CapabilityID), field(offer.Version),
		field(offer.CapabilityAddress))
	line("Manifest digest:  %s", field(offer.ManifestDigest))
	line("Metadata hash:    %s", field(offer.MetadataHash))
	line("Proof scheme:     %s", field(offer.ProofSchemeHash))
	for _, missing := range offer.ToBeCreated {
		line("To be created:    %s", field(missing))
	}
	line("")
	price, storage := fmt.Sprint(terms.PriceNano), fmt.Sprint(terms.StorageFeeNano)
	line("Price per call:   %s", tos(price))
	line("Storage fee:      %s", tos(storage))
	line("Cleanup bounty:   %s", tos(fmt.Sprint(terms.CleanupBountyNano)))
	line("Response SLA %ds, refund claim window %ds.", terms.ResponseSLA, terms.RefundClaimWindow)
	line("One answered call pays the provider %s plus the storage fee %s.", tos(price), tos(storage))
	line("A call not answered within the SLA lets the buyer claim the price %s back; the storage fee is kept.", tos(price))
	line("A buyer attaches %s to each call.", tos(offer.BuyerAttachesNano))
	line("")
	line("Deploy funding:   %s (stays in the actor as its reserve)", tos(offer.DeployFundingNano))
	line("Registration:     %s attached", tos(offer.RegistryValueNano))
	line("Policy step:      %s attached", tos(offer.PolicyValueNano))
	line("Total attached:   %s, plus wallet fees", tos(offer.TotalAttachedNano))
	line("Planned steps:    %s", field(strings.Join(preview.PlannedSteps, ", ")))
	line("Note:             %s", field(offer.Note))
}

func renderWithdraw(line liner, raw json.RawMessage) {
	var preview withdrawPreview
	if json.Unmarshal(raw, &preview) != nil || preview.Withdraw == nil {
		line("The withdrawal preview does not decode. Do not confirm it.")
		return
	}
	withdraw := preview.Withdraw
	line("Withdraws credited revenue from the actor to the owner wallet.")
	line("Actor:            %s", field(withdraw.Actor))
	line("Destination:      %s (the owner wallet, fixed by the contract)", field(withdraw.Destination))
	line("Amount:           %s", tos(preview.AmountNanoTOS))
	line("Credited before:  %s", tos(withdraw.CreditedNano))
	line("Credited after:   %s", tos(withdraw.RemainingNano))
	line("Attached:         %s (for fees; the contract returns what is unused)", tos(withdraw.AttachedNano))
	line("Checkpoint:       %d", withdraw.Checkpoint)
}

func renderResume(line liner, raw json.RawMessage) {
	var preview resumePreview
	if json.Unmarshal(raw, &preview) != nil {
		line("The resume preview does not decode. Do not confirm it.")
		return
	}
	line("Removes the pause marker below, so new requests are admitted and the node signs for them again.")
	if preview.Marker == nil {
		line("Marker:           unreadable by this release")
	} else {
		line("Paused since:     %s", utc(preview.Marker.PausedUnix))
		line("Marker origin:    %s", field(preview.Marker.Origin))
	}
	if preview.RecordedAs != "" {
		line("Agent's record:   written for %s", field(preview.RecordedAs))
	}
	if preview.Preflight == nil {
		line("Preflight:        not run")
		return
	}
	line("Preflight:        ok %t", preview.Preflight.OK)
	for _, check := range preview.Preflight.Checks {
		line("  %-6s %s", field(check.Status), field(check.ID))
	}
}
