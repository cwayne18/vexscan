package binscan

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"os"
	"sort"
)

// ErrNotGoBinary reports that a file carries no Go build info, so nothing in
// this file can be concluded about it either way.
var ErrNotGoBinary = errors.New("not a Go binary")

// spawnMarkers are the standard-library functions a Go program must link in
// order to start another program, as they appear in the function-name table.
//
// The first two are the chokepoints and the rest are redundant with them. On
// Unix every route out of Go into a new process ends at one of exactly two
// syscall wrappers: syscall.forkExec for fork-then-exec, which is what
// os/exec.Cmd.Start, os.StartProcess and syscall.ForkExec all funnel into, and
// syscall.Exec for the execve-in-place case, which is also where
// golang.org/x/sys/unix.Exec ends up. The higher-level names are matched anyway
// because a match costs nothing and the failure mode of matching too much is a
// taint, while the failure mode of matching too little is a wrong answer.
var spawnMarkers = []string{
	"syscall.forkExec",
	"syscall.Exec",
	"syscall.StartProcess",
	"os.startProcess",
	"os/exec.",
}

// SpawnScan is a Go binary loaded for the question of whether it can start
// another program.
//
// The test is a substring search over the whole file rather than a parse of
// .gopclntab, and that is the conservative direction rather than the lazy one.
// The claim being made is an absence -- "this binary contains no code that
// starts a process" -- and an absence proved over every byte of the file is
// strictly stronger than one proved over the bytes a pclntab parser managed to
// find. A parser that mislocates the table, or does not know a future Go
// version's header, would report an empty function list and turn a binary that
// does exec into one that provably does not. Searching the whole blob cannot
// fail that way: the function-name table is inside the blob, so a name absent
// from the blob is absent from the table. What it costs is precision in the
// other direction -- a marker sitting in an embedded file or a string constant
// reads as a spawn -- and that costs a taint, which is a conclusion withheld
// rather than a conclusion invented.
type SpawnScan struct {
	blob    []byte
	markers []string
	pureGo  bool
}

// ScanSpawn loads the Go binary at a host path and records which
// process-spawning functions it contains. It returns ErrNotGoBinary for
// anything with no Go build info, because the markers are Go symbol names and
// their absence from a C program says only that it is a C program.
func ScanSpawn(hostPath string) (*SpawnScan, error) {
	info, err := buildinfo.ReadFile(hostPath)
	if err != nil || info == nil {
		return nil, ErrNotGoBinary
	}
	blob, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, err
	}

	s := &SpawnScan{blob: blob}
	for _, s2 := range info.Settings {
		if s2.Key == "CGO_ENABLED" {
			s.pureGo = s2.Value == "0"
			break
		}
	}
	for _, m := range spawnMarkers {
		if bytes.Contains(blob, []byte(m)) {
			s.markers = append(s.markers, m)
		}
	}
	sort.Strings(s.markers)
	return s, nil
}

// Markers are the process-spawning functions found, sorted. Empty means none
// of them are in the file.
func (s *SpawnScan) Markers() []string { return s.markers }

// CanSpawn reports that the binary contains code that starts another program.
//
// This direction needs no CGO_ENABLED check. A marker in the file is a marker
// in the file however the binary was linked, so finding one settles the
// positive claim on its own.
func (s *SpawnScan) CanSpawn() bool { return len(s.markers) > 0 }

// CannotSpawn reports that the binary provably starts no other program.
//
// Unlike CanSpawn this requires CGO_ENABLED=0, and the asymmetry is the whole
// point. The markers are Go function names, so their absence rules out the Go
// routes and nothing else; a cgo build can reach execve, system or posix_spawn
// from C, where no Go symbol would record it. A pure-Go build links no C at
// all, so ruling out the Go routes rules out every route the program has.
func (s *SpawnScan) CannotSpawn() bool { return s.pureGo && len(s.markers) == 0 }

// Mentions reports whether a literal string appears anywhere in the binary.
//
// Used to turn a spawn into a list of candidate targets: a program path that
// occurs in the file is one the binary might exec, and rooting it is safe
// because rooting too much only widens the closure. It is not evidence the
// program is executed, and the absence of a path is not evidence it is not --
// Go string constants can be assembled at runtime, and a name resolved through
// PATH never appears as the absolute path at all.
func (s *SpawnScan) Mentions(lit string) bool {
	return lit != "" && bytes.Contains(s.blob, []byte(lit))
}
