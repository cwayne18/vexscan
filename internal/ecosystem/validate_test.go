package ecosystem

import "testing"

// A clean verdict is legitimate only when a deterministic method or a real
// (non-SBOM, non-blocking) evidence origin underwrites it. These are the shapes
// the plugins actually emit, and Validate must leave every one of them alone.
func TestValidate_LeavesLegitimateFindingsUntouched(t *testing.T) {
	cases := []struct {
		name string
		f    Finding
	}{
		{"not_present with pclntab method", Finding{
			Status: StatusNotPresent, Justification: "vulnerable_code_not_present", Method: "pclntab"}},
		{"not_present with inventory evidence", Finding{
			Status:   StatusNotPresent,
			Evidence: []Evidence{{Origin: "pydist-inventory", Detail: "no distribution named x"}}}},
		{"not_in_execute_path with closure method", Finding{
			Status: StatusNotInPath, Justification: "vulnerable_code_not_in_execute_path", Method: "elf-needed-closure"}},
		{"linked is never touched even with a taint", Finding{
			Status:   StatusLinked,
			Evidence: []Evidence{{Origin: "elf-needed-closure", Detail: "static-elf", Blocking: true}}}},
		{"undetermined is never touched", Finding{
			Status: StatusUndetermined, Reason: "no_osv_package_mapping"}},
		{"reachable is never touched", Finding{
			Status: StatusReachable, Reachability: "govulncheck: symbol called"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.f.Status
			got, reason := tc.f.Validate()
			if reason != "" {
				t.Fatalf("legitimate finding was corrected: %q", reason)
			}
			if got.Status != before {
				t.Fatalf("status changed %s -> %s with no reason", before, got.Status)
			}
		})
	}
}

// The fail-closed matrix: every documented cannot-decide case must come out
// non-clean. Each row corresponds to a failure mode named in the README's
// "Known limits", encoded here so a regression that lets one of them pass as a
// clean is caught at the unit level rather than on a real image.
func TestValidate_FailClosedMatrix(t *testing.T) {
	cases := []struct {
		name string
		in   Finding
		want Status
	}{
		{
			// Alpine/distroless: a static binary embeds the library while the
			// .so sits unreferenced, so the closure reaches nothing but cannot
			// be trusted. static-elf is a blocking taint.
			name: "static-elf taint on not_in_execute_path",
			in: Finding{Status: StatusNotInPath, Method: "elf-needed-closure",
				Evidence: []Evidence{{Origin: "elf-needed-closure", Detail: "static-elf", Blocking: true}}},
			want: StatusLinked,
		},
		{
			// Debian/ubi9 shell entrypoint: every binary in /usr/bin becomes a
			// root, so unreachability is not a conclusion the closure can draw.
			name: "shell-entrypoint taint on not_present",
			in: Finding{Status: StatusNotPresent, Method: "elf-needed-closure",
				Evidence: []Evidence{{Origin: "elf-needed-closure", Detail: "shell-entrypoint", Blocking: true}}},
			want: StatusLinked,
		},
		{
			// Airflow .pth file runs code at startup and taints globally no
			// matter how well roots are chosen.
			name: "dynamic-import/.pth taint on not_in_execute_path",
			in: Finding{Status: StatusNotInPath, Method: "py-import-graph",
				Evidence: []Evidence{{Origin: "py-import-graph", Detail: "startup .pth taints globally", Blocking: true}}},
			want: StatusLinked,
		},
		{
			// A reconstructed Python file list (no RECORD): "we looked in the
			// wrong place" must never read as "ships no code". The plugin marks
			// this with a blocking taint on a would-be clean.
			name: "reconstructed file list taint",
			in: Finding{Status: StatusNotPresent, Method: "pydist-no-code",
				Evidence: []Evidence{{Origin: "pydist-inventory", Detail: "file list reconstructed, no RECORD", Blocking: true}}},
			want: StatusLinked,
		},
		{
			// A clean resting on nothing but an SBOM component, which names a
			// package and asserts nothing about its code.
			name: "sbom-only origin cannot underwrite a clean",
			in: Finding{Status: StatusNotPresent,
				Evidence: []Evidence{{Origin: OriginSBOM, Detail: "listed in a bill of materials"}}},
			want: StatusUndetermined,
		},
		{
			// A clean with no method and no evidence at all: nothing ran.
			name: "bare clean with no provenance",
			in:   Finding{Status: StatusNotInPath},
			want: StatusUndetermined,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := tc.in.Validate()
			if reason == "" {
				t.Fatalf("guard did not fire on a cannot-decide case (status stayed %s)", got.Status)
			}
			if got.Status != tc.want {
				t.Fatalf("got %s, want %s", got.Status, tc.want)
			}
			if got.Status.clean() {
				t.Fatalf("a cannot-decide case was left clean: %s", got.Status)
			}
			// The correction must be visible, never silent.
			if !hasGuardEvidence(got) {
				t.Fatalf("correction left no false-clean-guard evidence")
			}
		})
	}
}

// The core property, stated directly: after Validate, no clean status may carry
// a blocking taint, and no clean status may lack provenance. This is the
// invariant the whole tool rests on, checked over every combination of the
// inputs that decide it.
func TestValidate_InvariantHolds(t *testing.T) {
	statuses := []Status{StatusNotPresent, StatusNotInPath, StatusLinked, StatusReachable, StatusUndetermined}
	methods := []string{"", "elf-needed-closure"}
	origins := []string{"", OriginSBOM, "pclntab"}
	blockings := []bool{false, true}

	for _, s := range statuses {
		for _, m := range methods {
			for _, o := range origins {
				for _, b := range blockings {
					f := Finding{Status: s, Method: m}
					if o != "" {
						f.Evidence = []Evidence{{Origin: o, Detail: "x", Blocking: b}}
					}
					got, _ := f.Validate()
					if got.Status.clean() {
						if got.blockingTaint() {
							t.Fatalf("clean %s survived with a blocking taint (from %+v)", got.Status, f)
						}
						if !got.hasCleanProvenance() {
							t.Fatalf("clean %s survived with no provenance (from %+v)", got.Status, f)
						}
					}
				}
			}
		}
	}
}

// Validate is idempotent: a corrected finding, run through again, is stable.
func TestValidate_Idempotent(t *testing.T) {
	f := Finding{Status: StatusNotPresent, Method: "elf-needed-closure",
		Evidence: []Evidence{{Origin: "elf-needed-closure", Detail: "static-elf", Blocking: true}}}
	once, _ := f.Validate()
	twice, reason := once.Validate()
	if reason != "" {
		t.Fatalf("second pass corrected an already-corrected finding: %q", reason)
	}
	if twice.Status != once.Status {
		t.Fatalf("not idempotent: %s -> %s", once.Status, twice.Status)
	}
}

func hasGuardEvidence(f Finding) bool {
	for _, e := range f.Evidence {
		if e.Origin == OriginFalseCleanGuard {
			return true
		}
	}
	return false
}
