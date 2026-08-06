package rpmsrc

// This file is the deep half of --rpm: it decompresses a package's cpio payload
// and writes the ELF objects it carries to a temp directory, so the OS plugin
// can read their dynamic symbol tables. Everything else in this package stops at
// the header; this is the only code that touches the payload, and it runs only
// under --rpm-deep.
//
// What it buys is narrow and worth stating plainly. There is still no filesystem
// and no entrypoint, so the DT_NEEDED closure cannot run and nothing is ever
// linked or ruled out as unreachable. The one test the extracted objects enable
// is the per-object dynsym-absent one: whether the vulnerable function an
// advisory names is exported by anything this package ships. That is a
// not_present verdict an installed scan would also reach, recovered here without
// installing.

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// maxExtractedFile and maxExtractedTotal bound what a payload may write to disk.
//
// The reader that produced this is decompressing attacker-controlled data, so
// the guard is on the decompressed size and not the compressed one: a few
// kilobytes of zstd can claim to expand into gigabytes. The limits are generous
// against real packages -- the largest ELF object in a normal distribution
// package is tens of megabytes -- and exist only to stop a decompression bomb
// from filling the disk.
const (
	maxExtractedFile  = 512 << 20
	maxExtractedTotal = 2 << 30
)

// extractELF decompresses an rpm cpio payload and writes the regular files whose
// tree-absolute path is in want under root, an existing directory.
//
// payload must be positioned at the first byte after the main header, which is
// where ReadFile leaves the reader. Only the files in want are written: they are
// the header's own ELF list, so this extracts exactly the objects the dynsym
// test will open and nothing else -- no docs, no scripts, no symlink chasing.
// Every package in one --rpm run writes under the same root, so the paths land
// where a single DirFS rooted there will find them.
//
// A file in want that the payload does not contain is not an error. The header
// is the authority on what the package installs; a mismatch is a broken package,
// and the caller's symbol test already treats an object it cannot read as
// proving nothing.
func extractELF(payload io.Reader, want []string, root string) error {
	if len(want) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(want))
	for _, p := range want {
		wanted[normalizeCpioName(p)] = true
	}

	dr, err := decompress(payload)
	if err != nil {
		return fmt.Errorf("decompress payload: %w", err)
	}
	// zstd's streaming decoder holds background goroutines until it is closed,
	// and writeWanted returns the moment the last wanted object is written --
	// often long before the payload ends -- so closing here is what keeps a
	// directory scan of hundreds of packages from leaking a decoder each.
	defer dr.Close()
	return writeWanted(dr, wanted, root)
}

// decompress wraps the payload in the reader its magic bytes call for.
//
// rpm records the compressor in a header tag, but the magic is read here instead
// because it needs no tag lookup and cannot disagree with the bytes on the wire.
// The five formats are the ones rpm has shipped: gzip and bzip2 on older
// packages, xz across the RPM distributions for a decade, zstd on Fedora and
// current SUSE, and raw lzma on a few old SUSE builds.
func decompress(r io.Reader) (io.ReadCloser, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(6)
	if err != nil && err != io.EOF {
		return nil, err
	}
	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		return gzip.NewReader(br)
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}):
		xr, err := xz.NewReader(br)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(xr), nil
	case bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		d, err := zstd.NewReader(br)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case bytes.HasPrefix(magic, []byte{'B', 'Z', 'h'}):
		return io.NopCloser(bzip2.NewReader(br)), nil
	case bytes.HasPrefix(magic, []byte{0x5d, 0x00, 0x00}):
		// Raw lzma, no container. ulikunitz/xz reads it through its lzma
		// subpackage; the 13-byte lzma header it needs has not been consumed,
		// because Peek does not advance the reader.
		lr, err := lzma.NewReader(br)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(lr), nil
	default:
		return nil, fmt.Errorf("unrecognized payload compression (magic %x)", magic)
	}
}

// writeWanted walks a decompressed cpio stream and writes the wanted regular
// files under root.
func writeWanted(r io.Reader, wanted map[string]bool, root string) error {
	var total int64
	remaining := len(wanted)
	for remaining > 0 {
		hdr, err := readCpioHeader(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if hdr.name == cpioTrailer {
			break
		}

		name := normalizeCpioName(hdr.name)
		regular := hdr.mode&cpioFmtMask == cpioFmtReg
		if !wanted[name] || !regular {
			if err := discard(r, hdr.paddedSize()); err != nil {
				return err
			}
			continue
		}

		if total += hdr.size; hdr.size > maxExtractedFile || total > maxExtractedTotal {
			return fmt.Errorf("payload extraction exceeded %d bytes, refusing", maxExtractedTotal)
		}
		if err := writeFile(r, hdr, filepath.Join(root, filepath.FromSlash(name))); err != nil {
			return err
		}
		wanted[name] = false
		remaining--
	}
	return nil
}

// writeFile writes one cpio entry's data to dst, then consumes its padding so
// the stream stays aligned for the next header.
func writeFile(r io.Reader, hdr cpioHeader, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(f, r, hdr.size); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return discard(r, hdr.paddedSize()-hdr.size)
}

// cpio "new ASCII" (newc) format, which is what rpm has written for two decades.
// Every field in the 110-byte header is 8 ASCII hex digits.
const (
	cpioMagic   = "070701"
	cpioTrailer = "TRAILER!!!"
	cpioFmtMask = 0o170000
	cpioFmtReg  = 0o100000

	// maxCpioName bounds the name length read from a header before it is
	// allocated. namesize is an attacker-controlled uint32 that can claim up to
	// 4 GB; a real path is bounded by PATH_MAX, so a value past a few kilobytes
	// is a corrupt or hostile payload, not a filename, and must not drive an
	// allocation.
	maxCpioName = 64 << 10
)

type cpioHeader struct {
	mode uint32
	size int64
	name string
}

// paddedSize is the entry's data length rounded up to the 4-byte boundary the
// format pads every section to.
func (h cpioHeader) paddedSize() int64 { return (h.size + 3) &^ 3 }

// readCpioHeader reads one 110-byte newc header and the name that follows it.
func readCpioHeader(r io.Reader) (cpioHeader, error) {
	var raw [110]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return cpioHeader{}, io.EOF
		}
		return cpioHeader{}, err
	}
	if string(raw[:6]) != cpioMagic {
		return cpioHeader{}, fmt.Errorf("bad cpio magic %q", raw[:6])
	}

	mode, err := hexField(raw[14:22])
	if err != nil {
		return cpioHeader{}, err
	}
	size, err := hexField(raw[54:62])
	if err != nil {
		return cpioHeader{}, err
	}
	namesize, err := hexField(raw[94:102])
	if err != nil {
		return cpioHeader{}, err
	}
	if namesize == 0 || namesize > maxCpioName {
		return cpioHeader{}, fmt.Errorf("implausible cpio name length %d", namesize)
	}

	nameBuf := make([]byte, namesize)
	if _, err := io.ReadFull(r, nameBuf); err != nil {
		return cpioHeader{}, err
	}
	// The name is padded so that the 110-byte header plus the name ends on a
	// 4-byte boundary; the file data starts after that padding.
	if pad := (4 - ((110 + int(namesize)) % 4)) % 4; pad > 0 {
		if err := discard(r, int64(pad)); err != nil {
			return cpioHeader{}, err
		}
	}
	name := string(nameBuf)
	if i := strings.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	return cpioHeader{mode: mode, size: int64(size), name: name}, nil
}

func hexField(b []byte) (uint32, error) {
	v, err := strconv.ParseUint(string(b), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("bad cpio hex field %q: %w", b, err)
	}
	return uint32(v), nil
}

// normalizeCpioName makes a cpio or header path comparable: tree-absolute, with
// the leading "./" rpm writes stripped. rpm stores "./usr/bin/x" in the payload
// and "/usr/bin/x" in the header, and these have to agree for the ELF set to
// match.
func normalizeCpioName(name string) string {
	name = strings.TrimPrefix(name, ".")
	if !strings.HasPrefix(name, "/") {
		name = "/" + name
	}
	return path.Clean(name)
}

// discard consumes and drops n bytes, which io.Discard does without allocating a
// buffer per call.
func discard(r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, n)
	return err
}
