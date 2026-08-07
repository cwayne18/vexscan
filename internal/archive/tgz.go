// Package archive provides utility functions for working with gzip and tar files.
package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

var (
	gzipMagic      = []byte{0x1f, 0x8b}
	tarMagicUSTAR  = []byte("ustar\x00")   // POSIX, at offset 257
	tarMagicGNU    = []byte("ustar  \x00") // GNU, at 257
	tarMagicOffset = 257
	tarBlockSize   = tarMagicOffset + len(tarMagicGNU)
)

// EnsureDecompressed takes an io.Reader and checks if the data is
// gzip-compressed and/or tar-archived. If it is, it unpacks the data and returns
// a new io.Reader with the unpacked data. Otherwise, it returns the original
// reader. Works with .tar.gz, .gz and .tar data.
func EnsureDecompressed(r io.Reader) (io.Reader, error) {
	// r is consumed after it is read into buf
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}

	var (
		data  = buf.Bytes()
		unGz  *bytes.Buffer
		isTgz bool
	)

	switch {
	case isGzip(data):
		gzr, err := gzip.NewReader(buf)
		if err != nil {
			return nil, err
		}

		unGz = &bytes.Buffer{}
		if _, err := io.Copy(unGz, gzr); err != nil {
			return nil, err
		}

		// if .gz data, we are done. otherwise, if .tar.gz data, we need to untar it
		if !isTar(unGz.Bytes()) {
			return unGz, nil
		}
		isTgz = true
		fallthrough
	case isTar(data):
		tarr := tar.NewReader(buf)
		if isTgz {
			tarr = tar.NewReader(unGz)
		}

		untar := &bytes.Buffer{}
		for {
			if _, err := tarr.Next(); err != nil {
				if errors.Is(err, io.EOF) {
					break // end of archive
				}
				return nil, err
			}
			if untar.Len() > 0 {
				untar.WriteByte('\n')
			}
			if _, err := io.Copy(untar, tarr); err != nil {
				return nil, err
			}
		}
		return untar, nil
	default:
		return buf, nil
	}
}

func isGzip(data []byte) bool {
	return bytes.HasPrefix(data, gzipMagic)
}

func isTar(data []byte) bool {
	if len(data) < tarBlockSize {
		return false
	}
	return (bytes.HasPrefix(data[tarMagicOffset:], tarMagicUSTAR) ||
		bytes.HasPrefix(data[tarMagicOffset:], tarMagicGNU))
}
