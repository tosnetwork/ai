package buyerconfirm

import (
	"math/rand"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Runes the rendering tests use.
const (
	fullwidthA    = rune(0xff21) // FULLWIDTH LATIN CAPITAL LETTER A, Lu
	heavyHeart    = rune(0x2764) // HEAVY BLACK HEART, So; with U+FE0F many terminals draw it two wide
	emojiStyle    = rune(0xfe0f) // VARIATION SELECTOR-16
	combiningAcut = rune(0x0301) // COMBINING ACUTE ACCENT, Mn
	plusMinus     = rune(0x00b1) // PLUS-MINUS SIGN, Sm, East Asian ambiguous
)

// testWidth is the test's own column count: printable ASCII is one column,
// any other rune two.
func testWidth(r rune) int {
	if r >= 0x20 && r <= 0x7e {
		return 1
	}
	return 2
}

// allowed is the test's own statement of the allowlist of section 5.2,
// written from the category tables rather than from shown().
func allowed(r rune) bool {
	switch {
	case r == ' ':
		return true
	case r >= 0xfe00 && r <= 0xfe0f, r >= 0xe0100 && r <= 0xe01ef:
		return false
	}
	for _, table := range []*unicode.RangeTable{unicode.Lu, unicode.Ll, unicode.Lt, unicode.Lm, unicode.Lo, unicode.Nd,
		unicode.Nl, unicode.No, unicode.Pc, unicode.Pd, unicode.Ps, unicode.Pe, unicode.Pi, unicode.Pf, unicode.Po,
		unicode.Sm, unicode.Sc, unicode.Sk, unicode.So} {
		if unicode.Is(table, r) {
			return true
		}
	}
	return false
}

// providerBlockRows returns the rows between the provider heading and its
// end marker.
func providerBlockRows(t *testing.T, out string) []string {
	t.Helper()
	lines := strings.Split(out, "\n")
	start, end := -1, -1
	for index, row := range lines {
		if row == ProviderHeading && start < 0 {
			start = index
		}
		if row == ProviderEnd && end < 0 {
			end = index
		}
	}
	if start < 0 || end <= start {
		t.Fatalf("the provider block is not delimited:\n%s", out)
	}
	return lines[start+1 : end]
}

// checkRows requires every provider row to carry the gutter, to hold only
// allowlisted runes, and to fit the wrap width by the test's own count.
func checkRows(t *testing.T, rows []string) {
	t.Helper()
	for _, row := range rows {
		if !strings.HasPrefix(row, ProviderGutter) {
			t.Fatalf("provider row %q has no gutter", row)
		}
		columns := 0
		for _, r := range strings.TrimPrefix(row, ProviderGutter) {
			if !allowed(r) {
				t.Fatalf("provider row %q holds a raw %U", row, r)
			}
			columns += testWidth(r)
		}
		if columns > ProviderWrapWidth {
			t.Fatalf("provider row %q takes %d columns, more than %d", row, columns, ProviderWrapWidth)
		}
	}
}

func render(t *testing.T, description string) []string {
	t.Helper()
	p := presentation()
	p.ProviderName = "build"
	p.ProviderDescription = description
	return providerBlockRows(t, Render(p, nil))
}

// One narrow and 32 wide characters after "description: " fill an
// 80-column row by display width; counted two each, they wrap in time.
func TestWideTextIsCountedTwoColumns(t *testing.T) {
	for _, wide := range []rune{fullwidthA, plusMinus} {
		rows := render(t, "a"+strings.Repeat(string(wide), 32)+"Price: 0.000000001 TOS")
		checkRows(t, rows)
		if len(rows) < 3 {
			t.Fatalf("%U: a description %d columns wide was not wrapped: %q", wide, 13+1+64+22, rows)
		}
	}
}

// The reviewer's case: an emoji with VARIATION SELECTOR-16 is drawn two
// wide. The selector is escaped and the emoji counted two, so the row still
// fits.
func TestAnEmojiPresentationSelectorIsEscapedAndTheEmojiCountedWide(t *testing.T) {
	rows := render(t, "a"+strings.Repeat(string(heavyHeart)+string(emojiStyle), 32)+"Price: 0.000000001 TOS")
	checkRows(t, rows)
	joined := strings.Join(rows, "")
	if strings.ContainsRune(joined, emojiStyle) || !strings.Contains(joined, `\u{FE0F}`) {
		t.Fatalf("the variation selector was not escaped: %q", rows)
	}
}

// Marks are escaped, never stacked over the text or the gutter.
func TestStackedCombiningMarksAreEscaped(t *testing.T) {
	rows := render(t, "e"+strings.Repeat(string(combiningAcut), 200))
	checkRows(t, rows)
	if !strings.Contains(strings.Join(rows, ""), `\u{0301}`) {
		t.Fatalf("the combining marks were not escaped: %q", rows)
	}
}

// NFC composes first: a letter with one combining accent is shown as its
// composed letter, Hangul jamo as their syllable.
func TestTextIsComposedBeforeTheAllowlist(t *testing.T) {
	if got := Escape("e"+string(combiningAcut), 16); got != string(rune(0x00e9)) {
		t.Fatalf("e + U+0301 rendered as %q", got)
	}
	jamo := string([]rune{0x1100, 0x1161})
	if got := Escape(jamo, 16); got != string(rune(0xac00)) {
		t.Fatalf("Hangul jamo rendered as %q", got)
	}
	checkRows(t, render(t, strings.Repeat(jamo, 40)))
}

// Every invisible format character the review found, and the tag
// characters, are escaped.
func TestInvisibleFormatAndTagCharactersAreEscaped(t *testing.T) {
	var invisible []rune
	for r := rune(0x2060); r <= 0x2064; r++ {
		invisible = append(invisible, r)
	}
	invisible = append(invisible, 0x180e, 0x00ad, 0x200b, 0x200c, 0x200d, 0xfeff, 0x202e, 0x061c)
	for r := rune(0xe0000); r <= 0xe007f; r++ {
		invisible = append(invisible, r)
	}
	for _, r := range invisible {
		out := Escape("a"+string(r)+"b", 16)
		if strings.ContainsRune(out, r) || !strings.HasPrefix(out, "a\\u{") {
			t.Errorf("%U rendered as %q", r, out)
		}
	}
}

// Every Unicode space separator collapses like the ASCII space, so wide
// spaces cannot pad text to a chosen column.
func TestEveryUnicodeSpaceCollapses(t *testing.T) {
	for _, space := range []rune{0x0020, 0x00a0, 0x2000, 0x2005, 0x200a, 0x202f, 0x205f, 0x3000} {
		padded := "a" + strings.Repeat(string(space), 40) + "b"
		if got := collapseSpaces(padded); got != "a b" {
			t.Errorf("%U: %q", space, got)
		}
	}
	rows := render(t, "x"+strings.Repeat(string(rune(0x3000)), 31)+ProviderEnd)
	checkRows(t, rows)
	for _, row := range rows {
		if strings.Contains(row, string(rune(0x3000))) {
			t.Fatalf("a wide space survived in row %q", row)
		}
	}
}

// The property the rules exist for: for any input, over the whole BMP and
// the astral planes and with invalid bytes, every provider row carries the
// gutter, holds only allowlisted runes, and fits 64 counted columns.
func TestNoProviderRowEverExceedsTheWidth(t *testing.T) {
	random := rand.New(rand.NewSource(20261118))
	for trial := 0; trial < 3000; trial++ {
		var b strings.Builder
		for index := random.Intn(300); index > 0; index-- {
			switch random.Intn(10) {
			case 0:
				b.WriteByte(byte(random.Intn(256)))
			case 1:
				b.WriteRune(rune(0x10000 + random.Intn(0x100000)))
			case 2:
				b.WriteRune(rune(random.Intn(0x80)))
			default:
				r := rune(random.Intn(0x10000))
				if !utf8.ValidRune(r) {
					r = utf8.RuneError
				}
				b.WriteRune(r)
			}
		}
		checkRows(t, render(t, b.String()))
	}
}

// On a terminal that lays out each line as its own bidirectional
// paragraph, a row's direction follows its first strong character. Every
// provider row, continuation rows that begin with Hebrew or Arabic
// included, must therefore begin with a strong left-to-right ASCII letter,
// so the gutter stays at column 0 and no provider text can start the row.
func TestEveryProviderRowStartsWithAStrongLeftToRightLetter(t *testing.T) {
	for _, rtl := range []rune{0x05d0, 0x0627} { // HEBREW LETTER ALEF, ARABIC LETTER ALEF
		description := strings.Repeat(string(rtl), 100) + " Price: 0.0001 TOS"
		rows := render(t, description)
		checkRows(t, rows)
		continuations := 0
		for index, row := range rows {
			first := row[0]
			if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z') {
				t.Fatalf("%U: provider row %q does not start with a strong left-to-right letter", rtl, row)
			}
			if index > 1 && strings.HasPrefix(strings.TrimPrefix(row, ProviderGutter), string(rtl)) {
				continuations++
			}
		}
		if continuations == 0 {
			t.Fatalf("%U: no continuation row starts with right-to-left text: %q", rtl, rows)
		}
	}
}
