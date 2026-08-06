package main

import "testing"

// TestCheckVexOut pins the two things that must be true before a scan runs.
//
// --vex-author is required rather than defaulted because the author of an
// OpenVEX statement is whoever is answerable for it, and a not_affected claim
// is one that tells other people's scanners to stop reporting a vulnerability.
// There is no defensible default for that. The mirror case matters too: an
// author with nowhere to go is a command that did not do what its writer
// thought, so it is an error rather than a silent no-op.
func TestCheckVexOut(t *testing.T) {
	cases := []struct {
		name        string
		dir, author string
		wantErr     bool
	}{
		{name: "neither"},
		{name: "both", dir: "./out", author: "Acme Security"},
		{name: "dir without author", dir: "./out", wantErr: true},
		{name: "author without dir", author: "Acme Security", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkVexOut(tc.dir, tc.author)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkVexOut(%q, %q) = %v, wantErr %v", tc.dir, tc.author, err, tc.wantErr)
			}
		})
	}
}
