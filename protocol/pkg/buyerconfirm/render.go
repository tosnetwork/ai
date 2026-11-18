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
	"unicode"
	"unicode/utf8"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"golang.org/x/text/unicode/norm"
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

// shown reports whether r is printed as itself. The rule is an allowlist,
// so a character terminals disagree on can never be printed raw:
//   - U+0020 is shown;
//   - a letter, number, punctuation mark or symbol (L*, N*, P*, S*) is
//     shown, except the variation selectors U+FE00 to U+FE0F and U+E0100
//     to U+E01EF;
//   - everything else is escaped: every mark (Mn, Mc, Me), every control,
//     format, private-use, surrogate or unassigned code point (Cc, Cf, Co,
//     Cs, Cn), every other separator (Zl, Zp, and Zs other than U+0020),
//     and the variation selectors.
//
// So no shown rune can be zero width, combine with its neighbour, select
// another presentation, or reorder text.
func shown(r rune) bool {
	if r == ' ' {
		return true
	}
	if (r >= 0xfe00 && r <= 0xfe0f) || (r >= 0xe0100 && r <= 0xe01ef) {
		return false
	}
	return unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S)
}

// Escape renders s for a terminal. It NFC-normalizes s first, so a
// sequence that composes is shown as its one composed character. Invalid
// UTF-8 becomes U+FFFD. Every rune shown() refuses becomes a visible
// \u{XXXX}. At most limit source characters are kept, the rest replaced by
// a truncation mark.
func Escape(s string, limit int) string {
	s = norm.NFC.String(s)
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
		if !shown(r) {
			fmt.Fprintf(&out, "\\u{%04X}", r)
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

// field escapes a protocol field.
func field(s string) string { return Escape(s, MaxProtocolString) }

// Provider text layout. Every provider row is hard-wrapped at a fixed
// display width and starts with a gutter. A terminal's own soft wrap of a
// long line can therefore never put provider text at the start of a row,
// where it could pass for the block's end marker or a protocol field.
const (
	// ProviderWrapWidth is the most display columns of provider text in
	// one row, the gutter not counted.
	ProviderWrapWidth = 64
	// ProviderGutter begins with "p", a strong left-to-right letter. A
	// terminal that lays out each line as its own bidirectional paragraph
	// takes the line's direction from its first strong character, so every
	// provider row, the first and every continuation alike, stays
	// left-to-right with the gutter at column 0. Hebrew or Arabic text in
	// it stays readable but cannot reorder the row so that provider text
	// starts it. A row ends with its last shown character: every control is
	// escaped, so no direction state carries over to the next row.
	ProviderGutter = "p| "
)

// displayWidth is the number of columns r is counted as taking. Printable
// ASCII counts one. Every other shown rune counts two, the most any
// terminal draws for it, so a row is never wider than counted. An escape is
// ASCII and counts its length.
func displayWidth(r rune) int {
	if r >= 0x20 && r <= 0x7e {
		return 1
	}
	return 2
}

// collapseSpaces turns every run of Unicode space separators (category Zs:
// the space, U+00A0, U+2000 to U+200A, U+202F, U+205F, U+3000) into one
// space and trims the ends, so padding cannot push text to a chosen column.
func collapseSpaces(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.Is(unicode.Zs, r) }), " ")
}

// providerRows hard-wraps already escaped text into rows of at most
// ProviderWrapWidth display columns, each behind the gutter.
func providerRows(text string) []string {
	var rows []string
	var row strings.Builder
	columns := 0
	for _, r := range text {
		w := displayWidth(r)
		if columns+w > ProviderWrapWidth {
			rows = append(rows, ProviderGutter+row.String())
			row.Reset()
			columns = 0
		}
		row.WriteRune(r)
		columns += w
	}
	return append(rows, ProviderGutter+row.String())
}

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
			line("%s%s: %s", ProviderGutter, item.label, strings.TrimSpace(truncationMark))
			continue
		}
		value := collapseSpaces(item.value)
		budget -= utf8.RuneCountInString(value)
		for _, row := range providerRows(item.label + ": " + Escape(value, limit)) {
			line("%s", row)
		}
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
