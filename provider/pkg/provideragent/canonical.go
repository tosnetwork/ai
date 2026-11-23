package provideragent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// maxSafeInteger is the largest integer RFC 8785 renders exactly
// (2^53 - 1); every number the agent canonicalizes is an integer, and
// larger amounts travel as decimal strings.
const maxSafeInteger = 1<<53 - 1

// canonicalJSON renders value as RFC 8785 canonical JSON: object members
// sorted by their names' UTF-16 code units, no insignificant whitespace,
// strings with only the escapes the scheme requires. Only integers within
// the safe range are accepted as numbers.
func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var generic any
	if err := decoder.Decode(&generic); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, generic); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(typed))
	case json.Number:
		integer, err := strconv.ParseInt(typed.String(), 10, 64)
		if err != nil || integer > maxSafeInteger || integer < -maxSafeInteger {
			return fmt.Errorf("canonical JSON: %s is not a safe integer", typed.String())
		}
		out.WriteString(strconv.FormatInt(integer, 10))
	case string:
		writeCanonicalString(out, typed)
	case []any:
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, typed[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return errors.New("canonical JSON: unexpected value")
	}
	return nil
}

func utf16Less(a, b string) bool {
	left, right := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return len(left) < len(right)
}

// writeCanonicalString escapes only '"', '\\' and the controls below
// U+0020, the short forms where RFC 8785 has them; every other character is
// written as itself. Invalid UTF-8 cannot occur: the input came from
// json.Marshal, which replaces it.
func writeCanonicalString(out *bytes.Buffer, text string) {
	out.WriteByte('"')
	for index := 0; index < len(text); {
		r, size := utf8.DecodeRuneInString(text[index:])
		index += size
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
				continue
			}
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}
