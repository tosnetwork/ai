package buyeragent

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// patchHeader overwrites bytes of the header block at offset and recomputes
// its checksum, so a test can build headers the Go writer would refuse.
func patchHeader(t *testing.T, archive []byte, offset int, edit func(header []byte)) []byte {
	t.Helper()
	out := append([]byte(nil), archive...)
	header := out[offset : offset+blockSize]
	edit(header)
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	var sum int64
	for _, b := range header {
		sum += int64(b)
	}
	copy(header[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return out
}

func setName(name string) func([]byte) {
	return func(header []byte) {
		for index := 0; index < 100; index++ {
			header[index] = 0
		}
		copy(header[0:100], name)
	}
}

func TestASafeArchiveIsAcceptedWithItsMembers(t *testing.T) {
	archive := buildTar(t, entry{name: "src/", typeflag: tar.TypeDir}, entry{name: "src/main.go", body: "package main\n"},
		entry{name: "go.mod", body: "module x\n"})
	checked, err := CheckSourceArchive(archive, MaxArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(checked.Members) != 3 || checked.Members[0].Name != "go.mod" || checked.Members[1].Name != "src/" ||
		!checked.Members[1].Directory || checked.Members[2].Name != "src/main.go" || checked.Members[2].SizeBytes != 13 {
		t.Fatalf("members: %+v", checked.Members)
	}
	if !strings.HasPrefix(checked.SourceDigest(), "sha256:") || len(checked.SourceDigest()) != 71 {
		t.Fatalf("digest %s", checked.SourceDigest())
	}
}

// Every name outside the safe charset, and every unsafe segment, refuses
// the whole archive (MCP_BUYER_ADAPTER_V1 section 4.5).
func TestArchiveMemberNamesOutsideTheSafeCharsetAreRefused(t *testing.T) {
	base := buildTar(t, entry{name: strings.Repeat("a", 40), body: "x"})
	for _, name := range []string{
		"has space.go", "caf\xc3\xa9.go", "evil\xe2\x80\xaeog.exe", "esc\x1b[2J.go", "tab\tname", "back\\slash",
		"quote\".go", "semi;colon", "../escape.go", "a/../b.go", "./a.go", "a/./b.go", "/absolute.go", "a//b.go",
		"file.go/", "dollar$.go", "star*.go", "new\nline",
	} {
		archive := patchHeader(t, base, 0, setName(name))
		if _, err := CheckSourceArchive(archive, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
			t.Errorf("name %q was accepted: %v", name, err)
		}
	}
	long := strings.Repeat("a/", 100) + strings.Repeat("b", 56)
	prefixed := patchHeader(t, base, 0, func(header []byte) {
		setName(long[156:])(header)
		copy(header[345:500], long[:155])
	})
	if _, err := CheckSourceArchive(prefixed, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a %d-byte name was accepted: %v", len(long), err)
	}
	hidden := patchHeader(t, base, 0, func(header []byte) {
		setName("ok.go")(header)
		copy(header[10:], "hidden")
	})
	if _, err := CheckSourceArchive(hidden, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("text after a name's terminator was accepted: %v", err)
	}
}

func TestArchiveEntryTypesOtherThanFilesAndDirectoriesAreRefused(t *testing.T) {
	base := buildTar(t, entry{name: "a.go", body: "x"})
	for _, flag := range []byte{'1', '2', '3', '4', '6', '7', 'x', 'g', 'L', 'K', 0} {
		archive := patchHeader(t, base, 0, func(header []byte) { header[156] = flag })
		if _, err := CheckSourceArchive(archive, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
			t.Errorf("type flag %q was accepted: %v", flag, err)
		}
	}
	linked := patchHeader(t, base, 0, func(header []byte) { copy(header[157:257], "target") })
	if _, err := CheckSourceArchive(linked, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a link name was accepted: %v", err)
	}
	var pax bytes.Buffer
	writer := tar.NewWriter(&pax)
	if err := writer.WriteHeader(&tar.Header{Name: "a.go", Size: 1, Mode: 0o644, Format: tar.FormatPAX,
		PAXRecords: map[string]string{"comment": "hidden"}}); err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte("x"))
	writer.Close()
	if _, err := CheckSourceArchive(pax.Bytes(), MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a PAX header was accepted: %v", err)
	}
	gnu := patchHeader(t, base, 0, func(header []byte) { copy(header[257:265], "ustar  \x00") })
	if _, err := CheckSourceArchive(gnu, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a GNU header was accepted: %v", err)
	}
	// Zero padding after the archive gives the directory's claimed data a
	// block to take, so only the directory-size rule refuses it.
	padded := append(buildTar(t, entry{name: "a.go", body: "x"}, entry{name: "d/", typeflag: tar.TypeDir}),
		make([]byte, 2*blockSize)...)
	dirWithSize := patchHeader(t, padded, blockSize*2, func(header []byte) { copy(header[124:136], "00000000001\x00") })
	if _, err := CheckSourceArchive(dirWithSize, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a directory with a size was accepted: %v", err)
	}
}

func TestArchiveDuplicatesCountAndSizeAreBounded(t *testing.T) {
	duplicate := rawTar(t, entry{name: "a.go", body: "x"}, entry{name: "a.go", body: "y"})
	if _, err := CheckSourceArchive(duplicate, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a repeated member was accepted: %v", err)
	}
	dirTwice := rawTar(t, entry{name: "d/", typeflag: tar.TypeDir}, entry{name: "d/", typeflag: tar.TypeDir},
		entry{name: "a.go", body: "x"})
	if _, err := CheckSourceArchive(dirTwice, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a directory named twice was accepted: %v", err)
	}
	onlyDirs := buildTar(t, entry{name: "d/", typeflag: tar.TypeDir})
	if _, err := CheckSourceArchive(onlyDirs, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("an archive without a regular file was accepted: %v", err)
	}
	// The member bound is implied by the size bound (every member takes at
	// least one 512-byte block), so the most members a 1 MiB archive can
	// hold, 2,046 plus the end marker, are accepted.
	var many []entry
	for index := 0; index < MaxArchiveBytes/blockSize-2; index++ {
		many = append(many, entry{name: "d" + strconv.Itoa(index), typeflag: tar.TypeDir})
	}
	many[0] = entry{name: "a.go", body: ""}
	if _, err := CheckSourceArchive(buildTar(t, many...), MaxArchiveBytes); err != nil {
		t.Errorf("%d members were refused: %v", len(many), err)
	}
	small := buildTar(t, entry{name: "a.go", body: "x"})
	if _, err := CheckSourceArchive(small, len(small)); err != nil {
		t.Errorf("an archive at its bound was refused: %v", err)
	}
	if _, err := CheckSourceArchive(small, len(small)-1); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("an archive one byte over its bound was accepted: %v", err)
	}
	if _, err := CheckSourceArchive(nil, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("an empty archive was accepted: %v", err)
	}
}

func TestArchiveEndAndHeaderIntegrityAreChecked(t *testing.T) {
	archive := buildTar(t, entry{name: "a.go", body: "x"})
	trailing := append(append([]byte(nil), archive...), make([]byte, blockSize)...)
	trailing[len(trailing)-1] = 1
	if _, err := CheckSourceArchive(trailing, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("bytes after the end marker were accepted: %v", err)
	}
	if _, err := CheckSourceArchive(archive[:len(archive)-blockSize], MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("an archive without its end marker was accepted: %v", err)
	}
	// A lone zero block is not the end marker: what follows it is still
	// archive content that no member describes.
	members := archive[:len(archive)-2*blockSize]
	junk := make([]byte, blockSize)
	junk[0] = 'j'
	lone := append(append(append(append([]byte(nil), members...), make([]byte, blockSize)...), junk...), make([]byte, 2*blockSize)...)
	if _, err := CheckSourceArchive(lone, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a lone zero block before more content was accepted: %v", err)
	}
	corrupt := append([]byte(nil), archive...)
	corrupt[0] = 'b'
	if _, err := CheckSourceArchive(corrupt, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a header with a wrong checksum was accepted: %v", err)
	}
	big256 := patchHeader(t, archive, 0, func(header []byte) { header[124] = 0x80 })
	if _, err := CheckSourceArchive(big256, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
		t.Errorf("a base-256 size was accepted: %v", err)
	}
}

// A size field that claims more bytes than the archive holds is refused
// with an error, never a panic: the content slice would run past the end.
func TestAMemberSizePastTheEndIsRefusedWithoutAPanic(t *testing.T) {
	archive := buildTar(t, entry{name: "a.go", body: "x"})
	remaining := len(archive) - blockSize
	for _, size := range []int64{int64(remaining) + 1, int64(remaining) + 2048, 0o77777777777} {
		overrun := patchHeader(t, archive, 0, func(header []byte) {
			copy(header[124:136], fmt.Sprintf("%011o\x00", size))
		})
		_, err := CheckSourceArchive(overrun, MaxArchiveBytes)
		if !errors.Is(err, ErrArchiveRefused) || !strings.Contains(err.Error(), "runs past the end") {
			t.Errorf("a %d-byte size over %d remaining bytes: %v", size, remaining, err)
		}
	}
	for _, field := range []string{"-0000000001", "+0000000001"} {
		signed := patchHeader(t, archive, 0, func(header []byte) { copy(header[124:136], field+"\x00") })
		if _, err := CheckSourceArchive(signed, MaxArchiveBytes); !errors.Is(err, ErrArchiveRefused) {
			t.Errorf("a signed size field %q was accepted: %v", field, err)
		}
	}
}
