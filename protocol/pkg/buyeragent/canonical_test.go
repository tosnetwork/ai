package buyeragent

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// fiveByteSource is one 5-byte regular file in canonical form.
func fiveByteSource(t *testing.T) []byte {
	t.Helper()
	archive := buildTar(t, entry{name: "main.go", body: "hello"})
	if _, err := CheckSourceArchive(archive, MaxArchiveBytes); err != nil {
		t.Fatalf("the canonical archive was refused: %v", err)
	}
	return archive
}

func refused(t *testing.T, what string, archive []byte) {
	t.Helper()
	checked, err := CheckSourceArchive(archive, MaxArchiveBytes)
	if !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("%s was accepted with members %+v: %v", what, checked.Members, err)
	}
}

// Data hidden in a member's block padding is refused: the member list shows
// only the member's size.
func TestArchivePaddingBytesAreRefused(t *testing.T) {
	archive := fiveByteSource(t)
	hidden := append([]byte(nil), archive...)
	copy(hidden[blockSize+5:], strings.Repeat("K", 55))
	refused(t, "55 bytes in a file's padding", hidden)
	last := append([]byte(nil), archive...)
	last[2*blockSize-1] = 1
	refused(t, "one byte at the end of a file's padding", last)
}

func TestArchiveOwnerNamesAreRefused(t *testing.T) {
	archive := fiveByteSource(t)
	refused(t, "a user name", patchHeader(t, archive, 0, func(h []byte) { copy(h[265:297], "SECRET-0123456789") }))
	refused(t, "a group name", patchHeader(t, archive, 0, func(h []byte) { copy(h[297:329], "SECRET-0123456789") }))
}

func TestArchiveModesAreRefused(t *testing.T) {
	archive := fiveByteSource(t)
	for _, mode := range []string{"0004777\x00", "0000600\x00", "0000755\x00", "644\x00\x00\x00\x00\x00"} {
		refused(t, "file mode "+strings.TrimRight(mode, "\x00"),
			patchHeader(t, archive, 0, func(h []byte) { copy(h[100:108], mode) }))
	}
}

func TestArchiveTimesIDsAndDevicesAreRefused(t *testing.T) {
	archive := fiveByteSource(t)
	for name, span := range map[string][2]int{"mtime": {136, 148}, "uid": {108, 116}, "gid": {116, 124},
		"devmajor": {329, 337}, "devminor": {337, 345}} {
		refused(t, "a non-zero "+name, patchHeader(t, archive, 0, func(h []byte) {
			field := h[span[0]:span[1]]
			copy(field, strings.Repeat("0", len(field)-2)+"7\x00")
		}))
	}
	refused(t, "a size written with other padding", patchHeader(t, archive, 0, func(h []byte) {
		copy(h[124:136], "        5 \x00\x00")
	}))
}

func TestArchiveHeaderTailIsRefused(t *testing.T) {
	archive := fiveByteSource(t)
	refused(t, "bytes 500 to 511 of a header", patchHeader(t, archive, 0, func(h []byte) { copy(h[500:512], "SECRET") }))
	refused(t, "a checksum written another way", func() []byte {
		out := append([]byte(nil), archive...)
		stored := strings.TrimRight(string(out[148:154]), " \x00")
		copy(out[148:156], "0"+stored+"\x00")
		return out
	}())
}

func TestArchiveTrailingZeroBlocksAreRefused(t *testing.T) {
	archive := fiveByteSource(t)
	refused(t, "one extra zero block", append(append([]byte(nil), archive...), make([]byte, blockSize)...))
	refused(t, "record padding to 10 KiB", append(append([]byte(nil), archive...), make([]byte, 10240-len(archive))...))
}

func TestArchiveMemberOrderAndNamesMustBeCanonical(t *testing.T) {
	refused(t, "members out of order", rawTar(t, entry{name: "b.go", body: "x"}, entry{name: "a.go", body: "y"}))
	refused(t, "a directory without its trailing slash", rawTar(t, entry{name: "a.go", body: "x"},
		entry{name: "d", typeflag: tar.TypeDir}))
	// Both slashes of this 132-byte name could split it; the canonical
	// split is at the last one.
	long := strings.Repeat("p", 50) + "/" + strings.Repeat("q", 20) + "/" + strings.Repeat("r", 60)
	split, err := canonicalHeader(long, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes.TrimRight(split[345:500], "\x00")) != long[:71] || string(bytes.TrimRight(split[0:100], "\x00")) != long[72:] {
		t.Fatalf("the long name was split as %q / %q", bytes.TrimRight(split[345:500], "\x00"), bytes.TrimRight(split[0:100], "\x00"))
	}
	resplit := buildTar(t, entry{name: long, body: "x"})
	refused(t, "a long name split elsewhere", patchHeader(t, resplit, 0, func(h []byte) {
		for index := 0; index < 100; index++ {
			h[index] = 0
		}
		for index := 345; index < 500; index++ {
			h[index] = 0
		}
		copy(h[345:500], long[:50])
		copy(h[0:100], long[51:])
	}))
}

// The reproduced case: one 5-byte file whose header and padding carry a
// user name, a setuid mode, a modification time and 55 bytes of a key.
func TestArchiveHiddenChannelsTogetherAreRefused(t *testing.T) {
	archive := patchHeader(t, fiveByteSource(t), 0, func(h []byte) {
		copy(h[265:297], "SECRET-0123456789")
		copy(h[100:108], "0004777\x00")
		copy(h[136:148], "14727655341\x00")
	})
	copy(archive[blockSize+5:], strings.Repeat("K", 55))
	refused(t, "a 5-byte file with hidden header fields and padding", archive)
}

func TestPackSourceArchiveIsDeterministicAndReadable(t *testing.T) {
	files := []SourceFile{{Name: "src/main.go", Content: []byte("package main\n")}, {Name: "src", Directory: true},
		{Name: "go.mod", Content: []byte("module x\n")}}
	first, err := PackSourceArchive(files)
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := PackSourceArchive([]SourceFile{files[2], files[0], files[1]})
	if err != nil || !bytes.Equal(first, reordered) {
		t.Fatalf("packing depends on input order: %v", err)
	}
	if _, err := CheckSourceArchive(first, MaxArchiveBytes); err != nil {
		t.Fatalf("a packed archive was refused: %v", err)
	}
	reader := tar.NewReader(bytes.NewReader(first))
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Uname != "" || header.Gname != "" || header.ModTime.Unix() != 0 || header.Uid != 0 || header.Gid != 0 {
			t.Fatalf("header %q carries owner or time fields", header.Name)
		}
		names = append(names, header.Name)
	}
	if strings.Join(names, ",") != "go.mod,src/,src/main.go" {
		t.Fatalf("the standard reader sees %v", names)
	}
	if _, err := PackSourceArchive([]SourceFile{{Name: "d", Directory: true, Content: []byte("x")}}); err == nil {
		t.Fatal("a directory with content was packed")
	}
	if _, err := PackSourceArchive([]SourceFile{{Name: "a b.go"}}); err == nil {
		t.Fatal("an unsafe name was packed")
	}
	if _, err := PackSourceArchive([]SourceFile{{Name: "a.go"}, {Name: "a.go"}}); err == nil {
		t.Fatal("a repeated name was packed")
	}
	if _, err := PackSourceArchive([]SourceFile{{Name: "big", Content: make([]byte, MaxArchiveBytes)}}); err == nil {
		t.Fatal("an archive over the bound was packed")
	}
}
