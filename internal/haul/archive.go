package haul

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Unpacking a haul.
//
// `hauler store save` writes a zstd-compressed tar by default, but the flag
// that picks the compression is hauler's and a haul someone made another way
// is still a haul, so the format is sniffed from the bytes rather than taken
// from the file name. An extension can be wrong; a magic number is what the
// decoder is going to act on either way.

// maxHaulBytes caps the total uncompressed bytes one haul may write.
//
// Deliberately larger than internal/image's ceiling on a single image, because
// a haul is a fleet: the published examples run to a couple of gigabytes and an
// airgap bundle carrying a whole distribution can be much more than that. Like
// that ceiling it exists for one reason -- a zstd stream that claims to inflate
// to more than any real haul would otherwise be written until the disk is gone
// -- and no honest haul comes near it.
const maxHaulBytes = 128 << 30

// zstdMagic is the zstd frame header. A skippable frame starts 0x184D2A5N,
// which no haul begins with.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// errHaulTooLarge means unpacking hit maxHaulBytes. It is a hard stop rather
// than a truncated tree: a haul missing the blobs the cap cut off would scan
// as an image that could not be read, which reports a tooling limit as if it
// were a fact about the image.
var errHaulTooLarge = errors.New("haul exceeds the unpack size limit")

// unpack writes the archive at src into dest and reports how many entries were
// skipped for not being regular files or directories.
//
// Skipping those is safe in a way that skipping a blob would not be. What is
// in a haul is decided by its index, and the index is JSON naming digests, so
// an entry that is not a file cannot be an artifact hiding from the count --
// at worst it is a blob that will not open, and that surfaces as a loud
// failure when the image it belongs to is extracted. The count is returned
// anyway, because a haul that contains such entries at all is odd enough to
// mention.
func unpack(ctx context.Context, src, dest string) (int, error) {
	f, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	head, err := br.Peek(len(zstdMagic))
	if err != nil && err != io.EOF {
		return 0, err
	}

	var r io.Reader = br
	if bytes.Equal(head, zstdMagic) {
		zr, err := zstd.NewReader(br)
		if err != nil {
			return 0, err
		}
		defer zr.Close()
		r = zr.IOReadCloser()
	}
	return untarInto(ctx, r, dest)
}

func untarInto(ctx context.Context, r io.Reader, dest string) (int, error) {
	root, err := filepath.Abs(dest)
	if err != nil {
		return 0, err
	}

	remaining := int64(maxHaulBytes)
	skipped := 0
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return skipped, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return skipped, nil
		}
		if err != nil {
			return skipped, err
		}

		target, err := safeJoin(root, hdr.Name)
		if err != nil {
			return skipped, err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return skipped, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return skipped, err
			}
			if err := writeFile(tr, target, &remaining); err != nil {
				return skipped, err
			}
		default:
			// A symlink, a device node, a hard link. None of them is part of
			// an OCI layout, and recreating one is how an archive writes
			// through a link to somewhere outside dest.
			skipped++
		}
	}
}

// safeJoin resolves name inside root, refusing anything that climbs out.
//
// A haul is ordinary input from an ordinary tool, but it is also a single file
// that arrives from wherever an airgap transfer came from, and it is unpacked
// by a process that may be running as more than it needs to be. The rule is
// internal/image's: every entry path has to land inside the destination root
// or the unpack fails.
//
// Fails, rather than quietly rewrites. Rooting the name at "/" before cleaning
// it -- the other common shape of this check -- turns "../../etc/passwd" into
// an innocuous relative path and extracts it, which makes an archive built to
// escape indistinguishable from a well-formed one. A haul has no business
// containing either, so both stop the unpack.
func safeJoin(root, name string) (string, error) {
	if strings.Contains(name, `\`) {
		// A backslash is not a separator here, so a name containing one would
		// be treated as a single path element on this platform and as a
		// directory traversal on another. Refuse rather than pick.
		return "", fmt.Errorf("refusing archive entry with a backslash in its name: %q", name)
	}
	if name == "" {
		return "", errors.New("refusing archive entry with an empty name")
	}
	clean := path.Clean(name)
	if clean == "." {
		// The archive root itself, which is what `tar -cf x .` writes as its
		// first entry. It is the destination, already created.
		return root, nil
	}
	if path.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("refusing archive entry outside the unpack root: %q", name)
	}
	target := filepath.Join(root, filepath.FromSlash(clean))
	// Belt and braces: the clean above is the check, and this is the assertion
	// that it did what it claims on whatever platform this is.
	if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing archive entry outside the unpack root: %q", name)
	}
	return target, nil
}

func writeFile(r io.Reader, path string, remaining *int64) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	// One byte past the budget: if the copy actually delivers it, the entry
	// was over the limit rather than exactly at it.
	n, err := io.Copy(f, io.LimitReader(r, *remaining+1))
	if err != nil {
		return err
	}
	if n > *remaining {
		return errHaulTooLarge
	}
	*remaining -= n
	return nil
}
