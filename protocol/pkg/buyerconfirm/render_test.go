package buyerconfirm

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
)

func presentation() buyeragent.Presentation {
	return buyeragent.Presentation{
		Purchase: buyeragent.PurchaseView{RequestHash: strings.Repeat("ab", 32), Reference: "abab-abab-abab-abab",
			CapabilityID: "cap_" + strings.Repeat("3", 64), CapabilityVersion: "1.0.0", Actor: "0:" + strings.Repeat("77", 32),
			AttestorKeyID: "mldsa44:" + strings.Repeat("9", 64), PriceNanoTOS: "300000000", StorageFeeNanoTOS: "200000000",
			PaymentNanoTOS: "700000000", TermsHash: strings.Repeat("cd", 32), QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("ef", 32),
			QuoteExpiresUnix: 2_000_001_800, SourceDigest: "sha256:" + strings.Repeat("01", 32), ArchiveBytes: 2560,
			Members: []buyeragent.Member{{Name: "src/", Directory: true}, {Name: "src/main.go", SizeBytes: 13}}},
		NetworkID: "tos-test", BuyerWallet: "0:" + strings.Repeat("21", 32),
		Budget: buyeragent.BudgetView{MaxCalls: 10, MaxPerCallNanoTOS: "1000000000", MaxWindowNanoTOS: "10000000000",
			ReservedNanoTOS: "700000000", ReservedCalls: 1},
		ProviderAgentID: "agent_" + strings.Repeat("4", 64), ManifestDigest: "sha256:" + strings.Repeat("5", 64),
		ProviderName: "build", ProviderDescription: "Builds the source.", ResponseSLASeconds: 3600,
		RefundClaimWindowSeconds: 86_400, RetentionSeconds: 86_400, CleanupBountyNanoTOS: "100000000",
		AllowanceNanoTOS: "200000000", NowUnix: 2_000_000_000, Code: "1234-5678-9abc-def0", ValidUntilUnix: 2_000_000_600,
	}
}

// Every class the spec names is rendered as a visible escape, never raw
// (section 5.2).
func TestEscapeMakesControlsBidiAndInvalidBytesVisible(t *testing.T) {
	cases := map[string]string{
		"escape sequence": "\x1b[2J", "newline": "a\nb", "carriage return": "a\rb", "tab": "a\tb", "NUL": "a\x00b",
		"DEL": "a\x7fb", "C1 next line": "a\u0085b", "C1 CSI": "a\u009bb",
	}
	for name, code := range map[string]rune{"right-to-left override": 0x202e, "left-to-right embedding": 0x202a,
		"first strong isolate": 0x2068, "pop directional isolate": 0x2069, "Arabic letter mark": 0x061c,
		"left-to-right mark": 0x200e, "right-to-left mark": 0x200f, "line separator": 0x2028,
		"paragraph separator": 0x2029, "zero width space": 0x200b, "zero width joiner": 0x200d,
		"byte order mark": 0xfeff} {
		cases[name] = "a" + string(code) + "b"
	}
	for name, input := range cases {
		out := Escape(input, MaxProviderString)
		for _, r := range out {
			if escaped(r) {
				t.Errorf("%s: %q kept a raw %U", name, out, r)
			}
		}
		if !strings.Contains(out, `\u{`) {
			t.Errorf("%s: %q has no visible escape", name, out)
		}
	}
	if out := Escape("a\xffb\xc3", MaxProviderString); out != "a�b�" {
		t.Errorf("invalid UTF-8 rendered as %q", out)
	}
	if out := Escape("plain café text", MaxProviderString); out != "plain café text" {
		t.Errorf("plain text changed to %q", out)
	}
}

func TestEscapeBoundsEachString(t *testing.T) {
	out := Escape(strings.Repeat("é", 300), MaxProviderString)
	if !strings.HasSuffix(out, truncationMark) || utf8.RuneCountInString(strings.TrimSuffix(out, truncationMark)) != 256 {
		t.Fatalf("a 300-character string rendered as %d characters", utf8.RuneCountInString(out))
	}
	if out := Escape(strings.Repeat("a", 256), MaxProviderString); strings.HasSuffix(out, truncationMark) {
		t.Fatal("a string at the bound was truncated")
	}
}

// The provider block comes first, the fixed separator after it, and the
// code is the last line. Provider text that imitates the separator or a
// protocol line stays inside its block on one escaped line.
func TestRenderKeepsProviderTextBeforeAndApartFromTheProtocolFields(t *testing.T) {
	p := presentation()
	p.ProviderName = "x\n" + ProtocolHeading + "\nPrice:            0 TOS\nConfirmation code:  0000-0000-0000-0000"
	p.ProviderDescription = strings.Repeat("d", 5000)
	out := Render(p, DefaultSensitive)
	provider, protocol := strings.Index(out, ProviderHeading), strings.Index(out, "\n"+ProtocolHeading+"\n")
	if provider < 0 || protocol < 0 || provider > protocol || strings.Index(out, ProviderEnd) > protocol {
		t.Fatalf("the blocks are out of order:\n%s", out)
	}
	if strings.Count(out, "\n"+ProtocolHeading) != 1 || strings.Contains(out, "\nPrice:            0 TOS") {
		t.Fatalf("provider text started a line of its own:\n%s", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "Confirmation code:  "+p.Code) {
		t.Fatalf("the last line is %q", last)
	}
	if strings.Contains(out, strings.Repeat("d", MaxProviderString+1)) {
		t.Fatal("a provider string was not bounded")
	}
	for _, want := range []string{"Actor (payee):    " + p.Purchase.Actor, "every refund is paid back to it",
		"0.3 TOS (300000000 nanoTOS)", "is not refunded", "0.1 TOS (100000000 nanoTOS)", "The whole archive goes to the provider"} {
		if !strings.Contains(out, want) {
			t.Errorf("the presentation lacks %q", want)
		}
	}
}

func TestTheProviderBlockIsBoundedAsAWhole(t *testing.T) {
	p := presentation()
	p.ProviderName = strings.Repeat("n", MaxProviderBlock)
	p.ProviderDescription = "visible only if the block has room"
	out := Render(p, nil)
	if strings.Contains(out, p.ProviderDescription) {
		t.Fatal("the provider block exceeded its bound")
	}
}

func TestRenderFlagsSensitiveMembersAndShortRefundWindows(t *testing.T) {
	p := presentation()
	p.Purchase.Members = []buyeragent.Member{{Name: ".env", SizeBytes: 12}, {Name: "keys/id_ed25519", SizeBytes: 400},
		{Name: ".git/", Directory: true}, {Name: "src/main.go", SizeBytes: 13}}
	out := Render(p, DefaultSensitive)
	if strings.Count(out, SensitiveMarker+" ") != 3 || !strings.Contains(out, "3 members match") {
		t.Fatalf("sensitive members were not flagged:\n%s", out)
	}
	if strings.Contains(out, "WARNING: the refund window") {
		t.Fatal("a 24-hour refund window was warned about")
	}
	p.RefundClaimWindowSeconds = 86_399
	if !strings.Contains(Render(p, DefaultSensitive), "WARNING: the refund window is shorter than 24 hours") {
		t.Fatal("a refund window under 24 hours was not warned about")
	}
}

func TestSensitivePatternsMatchSegments(t *testing.T) {
	for name, want := range map[string]bool{".env": true, "app/.env.local": true, "certs/server.pem": true,
		"id_rsa": true, "x/.ssh/config": true, ".git/": true, "src/git/x.go": false, "main.go": false,
		"docs/SECRET_plan.md": true, ".ssh": false} {
		if got := Sensitive(name, DefaultSensitive); got != want {
			t.Errorf("%s: sensitive %v, want %v", name, got, want)
		}
	}
}

func TestTOSRendersExactAmounts(t *testing.T) {
	for nano, want := range map[string]string{"0": "0 TOS (0 nanoTOS)", "1": "0.000000001 TOS (1 nanoTOS)",
		"1500000000": "1.5 TOS (1500000000 nanoTOS)", "340282366920938463463374607431768211455": "340282366920938463463374607431.768211455 TOS (340282366920938463463374607431768211455 nanoTOS)"} {
		if got := TOS(nano); got != want {
			t.Errorf("%s: %s", nano, got)
		}
	}
	if !strings.Contains(TOS("-1"), "not a valid amount") || !strings.Contains(TOS("\x1b"), `\u{001B}`) {
		t.Fatal("an invalid amount was rendered as one")
	}
}
