package buyeragent

import (
	"fmt"
	"sort"
	"strings"
)

// SourceFile is one member to pack into a canonical source archive.
type SourceFile struct {
	Name      string
	Directory bool
	Content   []byte
}

// PackSourceArchive writes the canonical source archive of files
// (MCP_BUYER_ADAPTER_V1 section 4.5). Members are sorted by name;
// directories carry a trailing "/" and no data. Every header is USTAR with:
// mode 0644 for a file and 0755 for a directory; uid, gid and mtime zero;
// empty link, user and group names; zero device numbers; the name split
// into prefix and name only when it exceeds 100 bytes; and zero bytes 500
// to 511. Member data is padded with zero bytes to a block, and the
// archive ends with exactly two zero blocks.
//
// The canonical form leaves no byte that a member list does not show: a
// header field, a padding byte or a trailing block that differs from it
// would be a channel past the human who reads the member list, so the agent
// accepts only these exact bytes.
func PackSourceArchive(files []SourceFile) ([]byte, error) {
	entries := make([]SourceFile, len(files))
	copy(entries, files)
	for index := range entries {
		if entries[index].Directory {
			if len(entries[index].Content) != 0 {
				return nil, archiveError("directory %s has content", printable(entries[index].Name))
			}
			if !strings.HasSuffix(entries[index].Name, "/") {
				entries[index].Name += "/"
			}
		}
		if err := checkMemberName(entries[index].Name, entries[index].Directory); err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	seen := map[string]bool{}
	size := 2 * blockSize
	for _, entry := range entries {
		key := strings.TrimSuffix(entry.Name, "/")
		if seen[key] {
			return nil, archiveError("member %q appears twice", key)
		}
		seen[key] = true
		size += blockSize + paddedLength(len(entry.Content))
		if size > MaxArchiveBytes {
			return nil, archiveError("the archive would exceed %d bytes", MaxArchiveBytes)
		}
	}
	out := make([]byte, 0, size)
	for _, entry := range entries {
		header, err := canonicalHeader(entry.Name, entry.Directory, int64(len(entry.Content)))
		if err != nil {
			return nil, err
		}
		out = append(out, header...)
		out = append(out, entry.Content...)
		out = append(out, make([]byte, paddedLength(len(entry.Content))-len(entry.Content))...)
	}
	return append(out, make([]byte, 2*blockSize)...), nil
}

func paddedLength(length int) int { return (length + blockSize - 1) / blockSize * blockSize }

// splitName places a member name into the USTAR name and prefix fields. A
// name of at most 100 bytes uses the name field alone; a longer one is
// split at the last "/" that leaves at most 100 bytes after it and at most
// 155 before it.
func splitName(name string) (prefix, base string, err error) {
	if len(name) <= 100 {
		return "", name, nil
	}
	for index := len(name) - 1; index > 0; index-- {
		if name[index] != '/' || index == len(name)-1 {
			continue
		}
		if len(name)-index-1 > 100 {
			break
		}
		if index <= 155 {
			return name[:index], name[index+1:], nil
		}
	}
	return "", "", archiveError("member name %s does not fit the USTAR name fields", printable(name))
}

func canonicalHeader(name string, directory bool, size int64) ([]byte, error) {
	prefix, base, err := splitName(name)
	if err != nil {
		return nil, err
	}
	header := make([]byte, blockSize)
	copy(header[0:100], base)
	mode, flag := "0000644\x00", byte('0')
	if directory {
		mode, flag = "0000755\x00", '5'
	}
	copy(header[100:108], mode)
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	copy(header[124:136], fmt.Sprintf("%011o\x00", size))
	copy(header[136:148], "00000000000\x00")
	header[156] = flag
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	copy(header[329:337], "0000000\x00")
	copy(header[337:345], "0000000\x00")
	copy(header[345:500], prefix)
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, b := range header {
		sum += int64(b)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return header, nil
}
