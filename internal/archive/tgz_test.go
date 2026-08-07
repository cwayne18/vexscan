package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestEnsureDecompressed(t *testing.T) {
	body := "A long time ago in a galaxy far, far away..."
	tgzData, err := tgzData(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tarData, err := tarData(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gzData, err := gzData(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	strData := bytes.NewBufferString(body)

	for i, r := range []io.Reader{tgzData, tarData, gzData, strData} {
		t.Run(fmt.Sprintf("test case %d", i+1), func(t *testing.T) {
			d, err := EnsureDecompressed(r)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			actual, err := io.ReadAll(d)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(actual) != body {
				t.Errorf("EnsureDecompressed(tgzData) = %q; expected %q", string(actual), body)
			}
		})
	}
}

func tgzData(body string) (io.Reader, error) {
	var (
		buf      = &bytes.Buffer{}
		gz       = gzip.NewWriter(buf)
		tgz      = tar.NewWriter(gz)
		testdata = strings.NewReader(body)
	)
	//nolint:errcheck
	defer func() {
		tgz.Close()
		gz.Close()
	}()

	if err := tgz.WriteHeader(&tar.Header{
		Name: "test.tar.gz",
		Mode: 0o600,
		Size: int64(len(body)),
	}); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tgz, testdata); err != nil {
		return nil, err
	}
	return buf, nil
}

func tarData(body string) (io.Reader, error) {
	var (
		buf      = &bytes.Buffer{}
		tgz      = tar.NewWriter(buf)
		testdata = strings.NewReader(body)
	)
	//nolint:errcheck
	defer func() {
		tgz.Close()
	}()

	if err := tgz.WriteHeader(&tar.Header{
		Name: "test.tar",
		Mode: 0o600,
		Size: int64(len(body)),
	}); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tgz, testdata); err != nil {
		return nil, err
	}
	return buf, nil
}

func gzData(body string) (io.Reader, error) {
	var (
		buf      = &bytes.Buffer{}
		gz       = gzip.NewWriter(buf)
		testdata = strings.NewReader(body)
	)
	if _, err := io.Copy(gz, testdata); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}
