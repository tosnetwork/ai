// Package buyerconfirm is the confirmer of the MCP buyer adapter
// (spec/docs/MCP_BUYER_ADAPTER_V1.md section 5): the program a human runs
// as the custody account, on a terminal no developer-account process
// touches, to read a prepared purchase and type its confirmation code.
//
// Everything it prints is treated as hostile, even protocol fields, and
// the provider's own text is printed first, apart from everything the
// buyer agent verified.
package buyerconfirm

import (
	"fmt"
	"math/big"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

// Rendering bounds (section 5.2).
const (
	// MaxProviderString bounds one provider string, in characters.
	MaxProviderString = 256
	// MaxProviderBlock bounds the whole provider block, in characters.
	MaxProviderBlock = 4096
	// MaxProtocolString bounds any other printed string, in characters.
	MaxProtocolString = 512

	truncationMark = " ...[truncated]"
)

// Fixed headings. No provider text can reproduce them unescaped: every
// line break inside a printed string is escaped, so only the confirmer
// starts a line.
const (
	ProviderHeading  = "---- Provider-supplied text: written by the provider, not by TOS or the buyer agent ----"
	ProviderEnd      = "---- end of provider-supplied text ----"
	ProtocolHeading  = "==== TOS protocol fields, from the buyer agent's verified records ===="
	SensitiveMarker  = "!! SENSITIVE"
	refundWarningAge = 24 * time.Hour
)

// escaped reports whether r is printed as a visible escape: C0 controls,
// DEL, C1 controls, the bidirectional formatting characters, and the
// invisible separators and joiners that can hide or reorder text.
func escaped(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0x200b && r <= 0x200d, r == 0x2028, r == 0x2029, r == 0xfeff:
		return true
	}
	return false
}

// Escape renders s for a terminal. Invalid UTF-8 becomes U+FFFD; every
// rune escaped() reports becomes a visible \u{XXXX}; and at most limit
// source characters are kept, the rest replaced by a truncation mark.
func Escape(s string, limit int) string {
	var out strings.Builder
	count := 0
	for index := 0; index < len(s); {
		if count == limit {
			out.WriteString(truncationMark)
			break
		}
		// An invalid byte decodes as utf8.RuneError, U+FFFD, which is
		// printed as itself.
		r, size := utf8.DecodeRuneInString(s[index:])
		index += size
		count++
		if escaped(r) {
			fmt.Fprintf(&out, "\\u{%04X}", r)
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// field escapes a protocol field.
func field(s string) string { return Escape(s, MaxProtocolString) }

// DefaultSensitive are the member-name patterns highlighted by default: a
// pattern ending in "/" matches a directory segment, any other one a
// segment's name.
var DefaultSensitive = []string{".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_*", "*secret*", "*token*",
	"*credential*", ".netrc", ".npmrc", ".pypirc", ".git/", ".ssh/", ".gnupg/", ".aws/"}

// Sensitive reports whether a member name matches a pattern.
func Sensitive(name string, patterns []string) bool {
	trimmed := strings.TrimSuffix(name, "/")
	segments := strings.Split(trimmed, "/")
	for _, pattern := range patterns {
		directory := strings.HasSuffix(pattern, "/")
		pattern = strings.ToLower(strings.TrimSuffix(pattern, "/"))
		for index, segment := range segments {
			isDirectory := index < len(segments)-1 || strings.HasSuffix(name, "/")
			if directory && !isDirectory {
				continue
			}
			if matched, err := path.Match(pattern, strings.ToLower(segment)); err == nil && matched {
				return true
			}
		}
	}
	return false
}

// TOS renders a nanoTOS decimal as TOS with its nanoTOS value.
func TOS(nano string) string {
	value, ok := new(big.Int).SetString(nano, 10)
	if !ok || value.Sign() < 0 {
		return field(nano) + " nanoTOS (not a valid amount)"
	}
	whole, fraction := new(big.Int).QuoRem(value, big.NewInt(1_000_000_000), new(big.Int))
	text := whole.String()
	if fraction.Sign() != 0 {
		text += "." + strings.TrimRight(fmt.Sprintf("%09d", fraction.Int64()), "0")
	}
	return text + " TOS (" + value.String() + " nanoTOS)"
}

func duration(seconds uint64) string {
	d := time.Duration(seconds) * time.Second
	days, hours, minutes := d/(24*time.Hour), (d%(24*time.Hour))/time.Hour, (d%time.Hour)/time.Minute
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	return fmt.Sprintf("%dh %dm", hours, minutes)
}

func utc(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC") }

func add(values ...string) string {
	total := new(big.Int)
	for _, value := range values {
		parsed, ok := new(big.Int).SetString(value, 10)
		if !ok {
			return "?"
		}
		total.Add(total, parsed)
	}
	return total.String()
}

// Render lays out one presentation (section 5.2): the provider block
// first, then a fixed separator, then the protocol fields with the
// confirmation code last.
func Render(p buyeragent.Presentation, sensitive []string) string {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	purchase := p.Purchase

	line("Purchase %s is waiting for your decision.", field(purchase.Reference))
	line("")
	line("%s", ProviderHeading)
	budget := MaxProviderBlock
	for _, item := range []struct{ label, value string }{{"name", p.ProviderName}, {"description", p.ProviderDescription}} {
		limit := MaxProviderString
		if budget < limit {
			limit = budget
		}
		if limit <= 0 {
			line("%s: %s", item.label, strings.TrimSpace(truncationMark))
			continue
		}
		budget -= utf8.RuneCountInString(item.value)
		line("%s: %s", item.label, Escape(item.value, limit))
	}
	line("%s", ProviderEnd)
	line("")
	line("%s", ProtocolHeading)
	line("Capability:       %s version %s", field(purchase.CapabilityID), field(purchase.CapabilityVersion))
	line("Provider Agent:   %s", field(p.ProviderAgentID))
	line("Actor (payee):    %s", field(purchase.Actor))
	line("Attestor key:     %s", field(purchase.AttestorKeyID))
	line("Manifest digest:  %s", field(p.ManifestDigest))
	line("")
	line("Price:            %s", TOS(purchase.PriceNanoTOS))
	line("Storage fee:      %s", TOS(purchase.StorageFeeNanoTOS))
	line("Allowance:        %s (its unused part returns)", TOS(p.AllowanceNanoTOS))
	line("Total attached:   %s", TOS(purchase.PaymentNanoTOS))
	line("")
	responseBy := p.NowUnix + int64(p.ResponseSLASeconds)
	refundBy := responseBy + int64(p.RefundClaimWindowSeconds)
	line("What happens if you pay now:")
	line("  - The provider is paid the price and the storage fee only for an attested result before %s.", utc(responseBy))
	line("    A Receipt proves what the provider's attestor signed, not that the work is correct.")
	line("  - Without one, the buyer agent runs expire and claim_refund between %s and %s:", utc(responseBy), utc(refundBy))
	line("    you get the price back; the storage fee %s is not refunded.", TOS(purchase.StorageFeeNanoTOS))
	line("  - If nobody claims by %s, the refund right lapses and a sweep returns the price;", utc(refundBy))
	line("    the sweeper takes the cleanup bounty %s, which is you when your agent sweeps.", TOS(p.CleanupBountyNanoTOS))
	line("  - The result is kept until %s.", utc(responseBy+int64(p.RetentionSeconds)))
	line("Response SLA %s, refund window %s, result retention %s.", duration(uint64(p.ResponseSLASeconds)),
		duration(uint64(p.RefundClaimWindowSeconds)), duration(p.RetentionSeconds))
	if time.Duration(p.RefundClaimWindowSeconds)*time.Second < refundWarningAge {
		line("WARNING: the refund window is shorter than 24 hours. Keep the buyer agent online until %s.", utc(refundBy))
	}
	line("Quote expires:    %s", utc(int64(purchase.QuoteExpiresUnix)))
	line("")
	line("Source archive:   %s, %d bytes, %d members.", field(purchase.SourceDigest), purchase.ArchiveBytes, len(purchase.Members))
	line("The whole archive goes to the provider:")
	flagged := 0
	for _, member := range purchase.Members {
		marker := "  "
		if Sensitive(member.Name, sensitive) {
			marker = SensitiveMarker
			flagged++
		}
		if member.Directory {
			line("  %s [dir] %s", marker, field(member.Name))
			continue
		}
		line("  %s %s (%d bytes)", marker, field(member.Name), member.SizeBytes)
	}
	if flagged > 0 {
		line("%s: %d members match a sensitive-name pattern. Do not pay unless you mean to send them.", SensitiveMarker, flagged)
	}
	line("")
	budgetView := p.Budget
	line("Budget: this payment %s against a per-call limit of %s.", TOS(purchase.PaymentNanoTOS), TOS(budgetView.MaxPerCallNanoTOS))
	line("        window reserved before: %s in %d calls; after: %s in %d calls; limit %s in %d calls.",
		TOS(budgetView.ReservedNanoTOS), budgetView.ReservedCalls, TOS(add(budgetView.ReservedNanoTOS, purchase.PaymentNanoTOS)),
		budgetView.ReservedCalls+1, TOS(budgetView.MaxWindowNanoTOS), budgetView.MaxCalls)
	line("")
	line("Network:          %s", field(p.NetworkID))
	line("Buyer wallet:     %s (pays the call; every refund is paid back to it)", field(p.BuyerWallet))
	line("request_hash:     %s", field(purchase.RequestHash))
	line("terms_hash:       %s", field(purchase.TermsHash))
	line("quote_commitment: %s", field(purchase.QuoteCommitment))
	line("Purchase reference: %s", field(purchase.Reference))
	line("Confirmation code:  %s (valid until %s)", field(p.Code), utc(p.ValidUntilUnix))
	return b.String()
}
