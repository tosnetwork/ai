package buyerconfirm

import (
	"strings"
	"testing"
)

// Runes the width tests use, with the columns a terminal gives them. The
// table is the test's own, independent of displayWidth.
const (
	fullwidthA    = rune(0xff21) // FULLWIDTH LATIN CAPITAL LETTER A: 2
	cjkMiddle     = rune(0x4e2d) // a CJK ideograph: 2
	combiningAcut = rune(0x0301) // COMBINING ACUTE ACCENT: 0
	plusMinus     = rune(0x00b1) // PLUS-MINUS SIGN, East Asian ambiguous: counted 2
)

func tableWidth(t *testing.T, r rune) int {
	t.Helper()
	switch {
	case r == fullwidthA, r == cjkMiddle, r == plusMinus:
		return 2
	case r == combiningAcut:
		return 0
	case r >= 0x20 && r < 0x7f:
		return 1
	}
	t.Fatalf("rune %U is not in the test's width table", r)
	return 0
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

func checkRows(t *testing.T, rows []string) {
	t.Helper()
	for _, row := range rows {
		if !strings.HasPrefix(row, ProviderGutter) {
			t.Fatalf("provider row %q has no gutter", row)
		}
		columns := 0
		for _, r := range strings.TrimPrefix(row, ProviderGutter) {
			columns += tableWidth(t, r)
		}
		if columns > ProviderWrapWidth {
			t.Fatalf("provider row %q takes %d columns, more than %d", row, columns, ProviderWrapWidth)
		}
	}
}

// The reviewer's case: one narrow character and 32 wide ones after
// "description: " fill a whole terminal row by display width. Counting
// characters would leave the rest of the text to soft-wrap to column 0
// without the gutter.
func TestProviderRowsAreWrappedByDisplayWidth(t *testing.T) {
	p := presentation()
	p.ProviderName = "build"
	p.ProviderDescription = "a" + strings.Repeat(string(fullwidthA), 32) + "Price: 0.000000001 TOS"
	rows := providerBlockRows(t, Render(p, nil))
	checkRows(t, rows)
	if len(rows) < 3 {
		t.Fatalf("a description %d columns wide was not wrapped: %q", 13+1+64+22, rows)
	}
	// An ambiguous-width character is counted two columns wide, as some
	// terminals draw it.
	p.ProviderDescription = "a" + strings.Repeat(string(plusMinus), 32) + "Price: 0.000000001 TOS"
	checkRows(t, providerBlockRows(t, Render(p, nil)))
}

// Combining marks take no column: 51 accented letters after
// "description: " fill exactly one 64-column row.
func TestCombiningMarksTakeNoColumn(t *testing.T) {
	p := presentation()
	p.ProviderName = "n"
	p.ProviderDescription = strings.Repeat("e"+string(combiningAcut), 51)
	rows := providerBlockRows(t, Render(p, nil))
	if len(rows) != 2 {
		t.Fatalf("51 accented letters took %d description rows: %q", len(rows)-1, rows)
	}
	checkRows(t, rows)
}

// Mixed wide and combining text is wrapped by display width as well: the
// combining marks take no column and never start a row of their own.
func TestMixedWideAndCombiningTextStaysWithinTheWidth(t *testing.T) {
	p := presentation()
	var b strings.Builder
	for index := 0; index < 60; index++ {
		b.WriteRune('e')
		b.WriteRune(combiningAcut)
		b.WriteRune(cjkMiddle)
	}
	p.ProviderName = "name"
	p.ProviderDescription = b.String()
	rows := providerBlockRows(t, Render(p, nil))
	checkRows(t, rows)
	for _, row := range rows {
		if strings.HasPrefix(row, ProviderGutter+string(combiningAcut)) {
			t.Fatalf("a combining mark starts row %q", row)
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
	p := presentation()
	p.ProviderDescription = "x" + strings.Repeat(string(rune(0x3000)), 31) + ProviderEnd
	for _, row := range strings.Split(Render(p, nil), "\n") {
		if strings.HasPrefix(row, ProviderGutter) && strings.Contains(row, string(rune(0x3000))) {
			t.Fatalf("a wide space survived in row %q", row)
		}
	}
}
