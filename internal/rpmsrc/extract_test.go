package rpmsrc

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cpioEntry is one file to put in a synthetic newc payload.
type cpioEntry struct {
	name string
	mode uint32
	data []byte
}

// buildCpio writes the "new ASCII" (newc) archive rpm's payload is, with a
// trailer. It is the minimum the extractor parses: a 110-byte hex header, a
// padded name, padded data, and TRAILER!!! to end.
func buildCpio(entries []cpioEntry) []byte {
	var b bytes.Buffer
	write := func(name string, mode uint32, data []byte) {
		name0 := append([]byte(name), 0)
		hdr := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name0), 0)
		b.WriteString(hdr)
		b.Write(name0)
		for (b.Len())%4 != 0 {
			b.WriteByte(0)
		}
		b.Write(data)
		for (b.Len())%4 != 0 {
			b.WriteByte(0)
		}
	}
	for _, e := range entries {
		write(e.name, e.mode, e.data)
	}
	write("TRAILER!!!", 0, nil)
	return b.Bytes()
}

func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The extractor writes exactly the wanted regular files, at their tree-absolute
// paths, and leaves everything else out -- the docs a package ships are not the
// ELF objects the dynsym test opens, and a payload full of them should cost no
// disk here.
func TestExtractELFWritesOnlyWantedRegularFiles(t *testing.T) {
	const regular = cpioFmtReg | 0o755
	payload := gzipBytes(t, buildCpio([]cpioEntry{
		{name: "./usr/lib64/libssl.so.3", mode: regular, data: []byte("ELF-ssl-bytes")},
		{name: "./usr/lib64/libcrypto.so.3", mode: regular, data: []byte("ELF-crypto-bytes")},
		{name: "./usr/share/doc/openssl/README", mode: regular, data: []byte("not wanted")},
		{name: "./usr/bin/openssl", mode: cpioFmtMask&0o120000 | 0o777, data: []byte("symlinkish")}, // not a regular file
	}))

	root := t.TempDir()
	want := []string{"/usr/lib64/libssl.so.3", "/usr/lib64/libcrypto.so.3"}
	if err := extractELF(bytes.NewReader(payload), want, root); err != nil {
		t.Fatalf("extractELF: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "usr/lib64/libssl.so.3"))
	if err != nil {
		t.Fatalf("wanted file missing: %v", err)
	}
	if string(got) != "ELF-ssl-bytes" {
		t.Errorf("libssl content = %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib64/libcrypto.so.3")); err != nil {
		t.Errorf("second wanted file missing: %v", err)
	}

	// A file the header did not classify as ELF is never asked for, so it is
	// never written -- deep mode is not a package unpacker, it is an ELF-object
	// extractor.
	if _, err := os.Stat(filepath.Join(root, "usr/share/doc/openssl/README")); !os.IsNotExist(err) {
		t.Errorf("unwanted doc was extracted (err = %v)", err)
	}
}

// A wanted path the payload does not actually contain is not an error: the
// header is the authority on what the package installs, and the caller's symbol
// test already treats an object it cannot open as proving nothing.
func TestExtractELFToleratesAMissingWantedFile(t *testing.T) {
	payload := gzipBytes(t, buildCpio([]cpioEntry{
		{name: "./usr/lib64/libssl.so.3", mode: cpioFmtReg | 0o755, data: []byte("here")},
	}))
	root := t.TempDir()
	err := extractELF(bytes.NewReader(payload), []string{"/usr/lib64/libssl.so.3", "/usr/lib64/absent.so"}, root)
	if err != nil {
		t.Fatalf("extractELF: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib64/libssl.so.3")); err != nil {
		t.Errorf("present file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "usr/lib64/absent.so")); !os.IsNotExist(err) {
		t.Errorf("absent file should not exist (err = %v)", err)
	}
}

// The compressor is chosen by magic, not by a header tag. gzip is exercised
// end to end above; here the point is that an unknown magic is a clean error
// rather than a panic or a silent empty extraction.
func TestDecompressRejectsUnknownMagic(t *testing.T) {
	_, err := decompress(bytes.NewReader([]byte("this is not a compressed payload")))
	if err == nil {
		t.Fatal("decompress accepted a payload with no recognized magic")
	}
}

// normalizeCpioName is what makes the header's "/usr/bin/x" and the payload's
// "./usr/bin/x" name the same file. If they drifted, every wanted lookup would
// miss and deep mode would silently extract nothing.
func TestNormalizeCpioNameAgreesAcrossHeaderAndPayload(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"./usr/bin/x", "/usr/bin/x"},
		{"/usr/bin/x", "/usr/bin/x"},
		{"usr/bin/x", "/usr/bin/x"},
		{"./usr/lib/../lib64/y", "/usr/lib64/y"},
	} {
		if got := normalizeCpioName(tc.in); got != tc.want {
			t.Errorf("normalizeCpioName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A hostile mirror can set the header's name-length field to any uint32. The
// reader must reject an implausible length rather than make([]byte, namesize)
// on a multi-gigabyte value it will never be able to fill -- a corrupt-input
// OOM is still a denial of service.
func TestReadCpioHeaderRejectsHugeNameSize(t *testing.T) {
	// A 110-byte newc header whose only meaningful field is a 4 GB namesize.
	hdr := make([]byte, 110)
	for i := range hdr {
		hdr[i] = '0'
	}
	copy(hdr[0:6], cpioMagic)
	copy(hdr[94:102], "ffffffff") // namesize
	_, err := readCpioHeader(bytes.NewReader(hdr))
	if err == nil {
		t.Fatal("readCpioHeader accepted a 4 GB name length")
	}
	if !strings.Contains(err.Error(), "implausible cpio name length") {
		t.Errorf("error = %v, want implausible-name-length rejection", err)
	}
}
