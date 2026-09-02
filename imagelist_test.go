package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseImageList(t *testing.T) {
	got := parseImageList(`
# the fleet
alpine:3.20

  debian:12   # trailing comment
alpine:3.20
ghcr.io/org/app@sha256:abc123
   # comment-only line
`)
	want := []string{"alpine:3.20", "debian:12", "ghcr.io/org/app@sha256:abc123"}
	if !equalStrings(got, want) {
		t.Errorf("parseImageList = %v, want %v", got, want)
	}
}

// A list written on Windows is still a list.
func TestParseImageListHandlesCRLF(t *testing.T) {
	got := parseImageList("alpine:3.20\r\ndebian:12\r\n")
	if !equalStrings(got, []string{"alpine:3.20", "debian:12"}) {
		t.Errorf("parseImageList = %q, want no carriage returns", got)
	}
}

func TestReadImageListFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.txt")
	if err := os.WriteFile(path, []byte("alpine:3.20\n# skip\ndebian:12\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readImageList(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got, []string{"alpine:3.20", "debian:12"}) {
		t.Errorf("readImageList = %v", got)
	}
}

func TestReadImageListFromURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("alpine:3.20\nbusybox:1.36\n"))
	}))
	defer srv.Close()

	got, err := readImageList(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(got, []string{"alpine:3.20", "busybox:1.36"}) {
		t.Errorf("readImageList = %v", got)
	}
}

// A server that answers with anything other than 200 has not published a list,
// and reading its error page as one would scan whatever the words in it parse
// to.
func TestReadImageListRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := readImageList(context.Background(), srv.URL); err == nil {
		t.Error("want an error for a 404, got nil")
	}
}

func TestDedupeKeepsFirstPosition(t *testing.T) {
	got := dedupe([]string{"b", "a", "b", "c", "a"})
	if !equalStrings(got, []string{"b", "a", "c"}) {
		t.Errorf("dedupe = %v, want [b a c]", got)
	}
}
