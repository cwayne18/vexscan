package main

import "testing"

// TestCheckVexOut pins what must be true before a scan runs.
//
// --vex-author is required rather than defaulted because the author of a VEX
// statement is whoever is answerable for it, and a not_affected claim is one
// that tells other people's scanners to stop reporting a vulnerability. There
// is no defensible default for that. --vex-publisher-namespace is the same
// question in CSAF's terms: the publisher block is mandatory in the format, and
// its namespace is the URI that says who published the advisory.
//
// The mirror cases matter too. A flag with nowhere to go is a command that did
// not do what its writer thought, so an author without --vex-out, or a CSAF
// publisher identity on an OpenVEX run, is an error rather than a silent no-op.
func TestCheckVexOut(t *testing.T) {
	cases := []struct {
		name                         string
		dir, author, format, ns, cat string
		mergeInto                    []string
		wantErr                      bool
	}{
		{name: "neither"},
		{name: "both", dir: "./out", author: "Acme Security"},
		{name: "dir without author", dir: "./out", wantErr: true},
		{name: "author without dir", author: "Acme Security", wantErr: true},

		{name: "explicit openvex", dir: "./out", author: "Acme Security", format: "openvex"},
		{name: "unknown format", dir: "./out", author: "Acme Security", format: "cyclonedx", wantErr: true},

		{
			name: "csaf with a publisher",
			dir:  "./out", author: "Acme Security", format: "csaf",
			ns: "https://acme.example", cat: "vendor",
		},
		{
			name: "csaf defaults its category",
			dir:  "./out", author: "Acme Security", format: "csaf", ns: "https://acme.example",
		},
		{
			name: "csaf without a namespace",
			dir:  "./out", author: "Acme Security", format: "csaf", wantErr: true,
		},
		{
			name: "csaf with a category CSAF does not define",
			dir:  "./out", author: "Acme Security", format: "csaf",
			ns: "https://acme.example", cat: "publisher", wantErr: true,
		},
		{
			name: "publisher identity on an openvex run",
			dir:  "./out", author: "Acme Security", ns: "https://acme.example", wantErr: true,
		},
		{
			name: "publisher identity without a directory",
			ns:   "https://acme.example", wantErr: true,
		},

		// An aggregate is a merged OpenVEX report. CSAF identifies an advisory by
		// document.tracking.id and revises it as a unit, so there is no such
		// thing as a CSAF document holding every product at once -- caught here
		// rather than after the scan.
		{
			name: "merge-into on an openvex run",
			dir:  "./out", author: "Acme Security",
			mergeInto: []string{"reports/rancher.openvex.json"},
		},
		{
			name: "merge-into with an explicit openvex format",
			dir:  "./out", author: "Acme Security", format: "openvex",
			mergeInto: []string{"reports/rancher.openvex.json"},
		},
		{
			name: "merge-into on a csaf run",
			dir:  "./out", author: "Acme Security", format: "csaf", ns: "https://acme.example",
			mergeInto: []string{"reports/rancher.openvex.json"}, wantErr: true,
		},
		{
			name:      "merge-into without a directory",
			mergeInto: []string{"reports/rancher.openvex.json"}, wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := vexOutOptions{
				dir: tc.dir, author: tc.author, format: tc.format,
				pubNS: tc.ns, pubCat: tc.cat, mergeInto: tc.mergeInto,
			}
			if err := checkVexOut(opts); (err != nil) != tc.wantErr {
				t.Fatalf("checkVexOut(%+v) = %v, wantErr %v", opts, err, tc.wantErr)
			}
		})
	}
}
