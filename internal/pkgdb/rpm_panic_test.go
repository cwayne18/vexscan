//go:build !norpm

package pkgdb

import (
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cwayne18/vexscan/internal/target"
)

// panicHeader is an rpm header blob that drives go-rpmdb v0.1.1 into a panic
// rather than an error. hdrblobImport slices the entry list as peList[1:ril]
// (entry.go:170) without checking ril >= 1, so a header whose region trailer
// yields a zero region index-length crashes with "slice bounds out of range
// [1:0]". Databases in the wild carry such headers -- rancher/rancher:v2.15.0
// is one -- and a database we cannot parse must be a scan error, not a crash of
// the whole run.
//
// The bytes are the smallest header that reaches that line: one index entry
// (il=1) that is a HEADERIMMUTABLE region tag with a non-zero offset, and an
// all-zero region trailer so the computed ril is 0. Every field go-rpmdb
// verifies before the slice -- the region tag type and count, the offset range,
// the trailer bounds -- is satisfied; only the final slice is unreachable in a
// well-formed header.
func panicHeader() []byte {
	be := func(v int32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v))
		return b
	}
	var d []byte
	d = append(d, be(1)...)  // il: one index entry
	d = append(d, be(32)...) // dl: data length
	// peList[0]: region tag RPMTAG_HEADERIMMUTABLE(63), RPM_BIN_TYPE(7),
	// offset 16 (non-zero, so ril is not reset to il), count 16.
	d = append(d, be(63)...)
	d = append(d, be(7)...)
	d = append(d, be(16)...)
	d = append(d, be(16)...)
	d = append(d, make([]byte, 16)...) // region data segment
	d = append(d, make([]byte, 16)...) // region trailer, all zero -> ril == 0
	return d
}

// writeSQLiteRPMDB builds a real SQLite rpm database at db within a throwaway
// rootfs, holding blob as its single Packages row. It uses the modernc sqlite
// driver that rpm.go blank-imports, so no new dependency is pulled in.
func writeSQLiteRPMDB(t *testing.T, db string, blob []byte) target.RootFS {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(db, "/")))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`CREATE TABLE Packages (hnum INTEGER PRIMARY KEY, blob BLOB)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(`INSERT INTO Packages (blob) VALUES (?)`, blob); err != nil {
		t.Fatal(err)
	}
	return target.NewDirFS(root)
}

// TestRPMSurvivesAPanickingHeader is the regression guard: a header that makes
// go-rpmdb panic must surface as an error from Read, so one malformed database
// cannot take down the whole scan. Before the recover in listPackages this
// call crashed the test binary outright.
func TestRPMSurvivesAPanickingHeader(t *testing.T) {
	fsys := writeSQLiteRPMDB(t, "/var/lib/rpm/rpmdb.sqlite", panicHeader())
	pkgs, err := (&RPM{}).Read(fsys)
	if err == nil {
		t.Fatalf("a panicking rpm header parsed as an inventory: %+v", pkgs)
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("error does not name the recovered panic: %v", err)
	}
}
