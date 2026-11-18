// Package buyeragent is the custody-side core of the MCP buyer adapter
// (spec/docs/MCP_BUYER_ADAPTER_V1.md): the agent that holds the call
// journal, re-validates every request a client sends, and confirms a
// payment only on a human decision taken from the custody account.
//
// Nothing a client says is trusted. The MCP server runs in the developer
// account, which the model controls, so every check it makes is repeated
// here on the bytes the agent receives.
package buyeragent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Archive bounds (MCP_BUYER_ADAPTER_V1 section 4.5).
const (
	// MaxArchiveBytes is the inline task bound of the rail work frames.
	MaxArchiveBytes = 1_048_576
	// MaxArchiveEntries bounds the members of one source archive.
	MaxArchiveEntries = 4096
	// MaxMemberNameBytes bounds one member name.
	MaxMemberNameBytes = 255

	blockSize = 512
)

// memberNamePattern is the safe member-name charset: segments of
// [A-Za-z0-9._+-] joined by "/", with an optional trailing "/" that only a
// directory may carry. Segment rules are checked separately.
var memberNamePattern = regexp.MustCompile(`^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*/?$`)

// Member is one entry of a checked source archive.
type Member struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	Directory bool   `json:"directory,omitempty"`
}

// CheckedArchive is a source archive that passed every rule.
type CheckedArchive struct {
	Members []Member
	// Digest is the raw SHA-256 of the archive bytes.
	Digest [32]byte
}

// SourceDigest is the archive's digest in the rail's sha256:<hex> form.
func (c CheckedArchive) SourceDigest() string { return "sha256:" + hex.EncodeToString(c.Digest[:]) }

// ErrArchiveRefused wraps every reason an archive is refused.
var ErrArchiveRefused = errors.New("the source archive is refused")

func archiveError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrArchiveRefused, fmt.Sprintf(format, args...))
}

// CheckSourceArchive parses raw as an uncompressed USTAR archive and refuses
// it unless:
//   - every member is a regular file or a directory with a safe name;
//   - no name repeats and at least one regular file is present;
//   - the size is within its bound;
//   - the bytes are exactly the canonical encoding of the members
//     (PackSourceArchive).
//
// The parse reads raw header blocks itself, so no extension header (PAX,
// GNU long name) can rename a member behind the name shown. The canonical
// comparison leaves no header field, padding byte or trailing block that
// could carry data the member list does not show.
func CheckSourceArchive(raw []byte, maxBytes int) (CheckedArchive, error) {
	if maxBytes <= 0 || maxBytes > MaxArchiveBytes {
		maxBytes = MaxArchiveBytes
	}
	if len(raw) == 0 || len(raw) > maxBytes {
		return CheckedArchive{}, archiveError("its size %d is outside 1 to %d bytes", len(raw), maxBytes)
	}
	if len(raw)%blockSize != 0 {
		return CheckedArchive{}, archiveError("its size is not a whole number of 512-byte blocks")
	}
	var members []Member
	var files []SourceFile
	seen := map[string]bool{}
	regular := 0
	offset := 0
	for {
		if offset+blockSize > len(raw) {
			return CheckedArchive{}, archiveError("it has no end-of-archive marker")
		}
		header := raw[offset : offset+blockSize]
		if isZeroBlock(header) {
			if offset+2*blockSize > len(raw) || !isZeroBlock(raw[offset+blockSize:offset+2*blockSize]) {
				return CheckedArchive{}, archiveError("it has no end-of-archive marker")
			}
			if !isZeroBlock(raw[offset+2*blockSize:]) {
				return CheckedArchive{}, archiveError("it has bytes after the end-of-archive marker")
			}
			break
		}
		if len(members) == MaxArchiveEntries {
			return CheckedArchive{}, archiveError("it has more than %d members", MaxArchiveEntries)
		}
		member, err := parseHeader(header)
		if err != nil {
			return CheckedArchive{}, err
		}
		key := strings.TrimSuffix(member.Name, "/")
		if seen[key] {
			return CheckedArchive{}, archiveError("member %q appears twice", key)
		}
		seen[key] = true
		if !member.Directory {
			regular++
		}
		offset += blockSize
		padded := (member.SizeBytes + blockSize - 1) / blockSize * blockSize
		if padded > int64(len(raw)-offset) {
			return CheckedArchive{}, archiveError("member %q runs past the end of the archive", member.Name)
		}
		files = append(files, SourceFile{Name: member.Name, Directory: member.Directory,
			Content: raw[offset : offset+int(member.SizeBytes)]})
		offset += int(padded)
		members = append(members, member)
	}
	if regular == 0 {
		return CheckedArchive{}, archiveError("it holds no regular file")
	}
	// The members as parsed must re-encode to exactly these bytes, so no
	// header field, padding byte or trailing block carries anything the
	// member list does not show.
	canonical, err := PackSourceArchive(files)
	if err != nil {
		return CheckedArchive{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return CheckedArchive{}, archiveError("it is not in canonical form: a header field, padding or trailing " +
			"bytes differ from the canonical encoding of its members")
	}
	return CheckedArchive{Members: members, Digest: sha256.Sum256(raw)}, nil
}

func isZeroBlock(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// parseHeader decodes one USTAR header block and applies the member rules.
func parseHeader(header []byte) (Member, error) {
	if !bytes.Equal(header[257:263], []byte("ustar\x00")) || !bytes.Equal(header[263:265], []byte("00")) {
		return Member{}, archiveError("a member header is not a USTAR header")
	}
	if err := checkChecksum(header); err != nil {
		return Member{}, err
	}
	name, err := field(header[0:100])
	if err != nil {
		return Member{}, err
	}
	prefix, err := field(header[345:500])
	if err != nil {
		return Member{}, err
	}
	if prefix != "" {
		name = prefix + "/" + name
	}
	linkName, err := field(header[157:257])
	if err != nil {
		return Member{}, err
	}
	if linkName != "" {
		return Member{}, archiveError("member %s names a link target", printable(name))
	}
	size, err := octal(header[124:136])
	if err != nil {
		return Member{}, archiveError("member %s has an invalid size field", printable(name))
	}
	member := Member{Name: name, SizeBytes: size}
	switch header[156] {
	case '0':
	case '5':
		member.Directory = true
		if size != 0 {
			return Member{}, archiveError("directory %s has a size", printable(name))
		}
	default:
		return Member{}, archiveError("member %s is not a regular file or a directory", printable(name))
	}
	if err := checkMemberName(name, member.Directory); err != nil {
		return Member{}, err
	}
	return member, nil
}

// checkMemberName applies the safe-name rules of section 4.5.
func checkMemberName(name string, directory bool) error {
	if len(name) == 0 || len(name) > MaxMemberNameBytes || !memberNamePattern.MatchString(name) {
		return archiveError("member name %s is outside the safe charset or length", printable(name))
	}
	if strings.HasSuffix(name, "/") && !directory {
		return archiveError("regular file %q has a trailing slash", name)
	}
	for _, segment := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if segment == "." || segment == ".." {
			return archiveError("member name %q has a %q segment", name, segment)
		}
	}
	return nil
}

// field reads a NUL-terminated header string; bytes after the NUL must be
// NUL too, so no hidden text follows the name shown.
func field(value []byte) (string, error) {
	end := bytes.IndexByte(value, 0)
	if end < 0 {
		return string(value), nil
	}
	if !isZeroBlock(value[end:]) {
		return "", archiveError("a header field has bytes after its terminator")
	}
	return string(value[:end]), nil
}

// octal reads a USTAR numeric field: octal digits, then NUL or space
// padding. The base-256 extension is refused.
func octal(value []byte) (int64, error) {
	text := strings.TrimRight(string(value), "\x00 ")
	text = strings.TrimLeft(text, " ")
	if text == "" || len(text) > 11 {
		return 0, errors.New("invalid octal field")
	}
	for _, c := range text {
		if c < '0' || c > '7' {
			return 0, errors.New("invalid octal field")
		}
	}
	return strconv.ParseInt(text, 8, 64)
}

func checkChecksum(header []byte) error {
	stored, err := octal(header[148:156])
	if err != nil {
		return archiveError("a member header has an invalid checksum field")
	}
	var sum int64
	for index, b := range header {
		if index >= 148 && index < 156 {
			sum += ' '
			continue
		}
		sum += int64(b)
	}
	if sum != stored {
		return archiveError("a member header checksum does not match")
	}
	return nil
}

// printable renders a refused name for an error message without letting
// its bytes reach a terminal raw.
func printable(name string) string {
	if len(name) > 64 {
		name = name[:64]
	}
	return strconv.QuoteToASCII(name)
}
