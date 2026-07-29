package osv

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The fixtures below are verbatim /etc/os-release contents from the official
// images, trimmed to the fields Release parses. The expected ecosystem strings
// were verified against the live api.osv.dev: each one returns advisories,
// and the near-miss spellings noted in the comments return an empty result --
// which is why guessing the suffix rule from the schema is not enough.
func TestReleaseEcosystem(t *testing.T) {
	tests := []struct {
		name    string
		osrel   string
		want    string
		wantErr string
	}{
		{
			name: "debian 12",
			osrel: `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian`,
			// Bare "Debian" answers with records from every release at once.
			want: "Debian:12",
		},
		{
			name: "debian trixie",
			osrel: `PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION_CODENAME=trixie
ID=debian`,
			want: "Debian:13",
		},
		{
			name: "debian sid has no VERSION_ID",
			osrel: `PRETTY_NAME="Debian GNU/Linux trixie/sid"
NAME="Debian GNU/Linux"
ID=debian
VERSION_CODENAME=trixie`,
			// Naming a release the image is not would answer against the wrong
			// version ranges, so this stops instead.
			wantErr: "VERSION_ID",
		},
		{
			name: "ubuntu 24.04 LTS",
			osrel: `PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian`,
			want: "Ubuntu:24.04:LTS",
		},
		{
			name: "ubuntu 22.04 LTS",
			osrel: `PRETTY_NAME="Ubuntu 22.04.5 LTS"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
ID=ubuntu`,
			want: "Ubuntu:22.04:LTS",
		},
		{
			name: "ubuntu interim release drops the LTS suffix",
			osrel: `PRETTY_NAME="Ubuntu 24.10"
VERSION_ID="24.10"
VERSION="24.10 (Oracular Oriole)"
ID=ubuntu`,
			// "Ubuntu:24.10:LTS" finds nothing; the suffix is not decoration.
			want: "Ubuntu:24.10",
		},
		{
			name: "alpine drops the patch level and keeps the v",
			osrel: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.1
PRETTY_NAME="Alpine Linux v3.19"`,
			// "Alpine:3.19" and "Alpine:v3.19.1" both find nothing.
			want: "Alpine:v3.19",
		},
		{
			name: "alpine edge prerelease still yields a major.minor",
			osrel: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.22.0_alpha20250108
PRETTY_NAME="Alpine Linux edge"`,
			want: "Alpine:v3.22",
		},
		{
			name: "rhel maps to the bare family",
			osrel: `NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"`,
			// OSV keys RHEL as "Red Hat:enterprise_linux:9::appstream" and
			// friends -- one ecosystem per repository. CPE_NAME names only the
			// repository the image was built from, so keying on it would drop
			// every appstream advisory. The bare family over-matches across
			// minor versions instead, which only adds candidates.
			want: "Red Hat",
		},
		{
			name: "rocky 9",
			osrel: `NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
PRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"`,
			want: "Rocky Linux:9",
		},
		{
			name: "almalinux 9",
			osrel: `NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
VERSION_ID="9.4"
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"`,
			want: "AlmaLinux:9",
		},
		{
			name: "wolfi",
			osrel: `ID=wolfi
NAME="Wolfi"
PRETTY_NAME="Wolfi"
VERSION_ID="20230201"`,
			want: "Wolfi",
		},
		{
			name: "chainguard",
			osrel: `ID=chainguard
NAME="Chainguard"
PRETTY_NAME="Chainguard"
VERSION_ID="20230214"`,
			want: "Chainguard",
		},
		{
			name: "azure linux drops the minor",
			osrel: `NAME="Microsoft Azure Linux"
VERSION="3.0.20240727"
ID=azurelinux
VERSION_ID="3.0"
PRETTY_NAME="Microsoft Azure Linux 3.0"`,
			// "Azure Linux:3.0" finds nothing; "Azure Linux:3" does.
			want: "Azure Linux:3",
		},
		{
			name: "cbl-mariner is the same ecosystem",
			osrel: `NAME="Common Base Linux Mariner"
VERSION="2.0.20240123"
ID=mariner
VERSION_ID="2.0"`,
			want: "Azure Linux:2",
		},
		{
			name: "openeuler LTS",
			osrel: `NAME="openEuler"
VERSION="24.03 (LTS)"
ID="openEuler"
VERSION_ID="24.03"
PRETTY_NAME="openEuler 24.03 (LTS)"`,
			// "openEuler:24.03" finds nothing; the "-LTS" suffix is required.
			want: "openEuler:24.03-LTS",
		},
		{
			name: "opensuse leap",
			osrel: `NAME="openSUSE Leap"
VERSION="15.6"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.6"
PRETTY_NAME="openSUSE Leap 15.6"`,
			want: "openSUSE:Leap 15.6",
		},
		{
			name: "opensuse tumbleweed",
			osrel: `NAME="openSUSE Tumbleweed"
ID="opensuse-tumbleweed"
VERSION_ID="20240801"
PRETTY_NAME="openSUSE Tumbleweed"`,
			want: "openSUSE:Tumbleweed",
		},
		{
			// The obvious answer, "SUSE:Linux Enterprise Server 15 SP5",
			// carries no records, and neither does its "-LTSS" spelling: SUSE
			// files base packages against the *module* that ships them. Only
			// the bare family matches, and ProductRelease narrows it back.
			name: "sles is the bare family",
			osrel: `NAME="SLES"
VERSION="15-SP5"
VERSION_ID="15.5"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP5"
ID="sles"`,
			want: "SUSE",
		},
		{
			name: "sles for SAP is the bare family too",
			osrel: `NAME="SLES_SAP"
VERSION_ID="12.5"
PRETTY_NAME="SUSE Linux Enterprise Server for SAP Applications 12 SP5"
ID="sles_sap"`,
			want: "SUSE",
		},
		{
			name: "sle micro is the bare family too",
			osrel: `NAME="SLE Micro"
VERSION_ID="5.5"
PRETTY_NAME="SUSE Linux Enterprise Micro 5.5"
ID="sle-micro"`,
			want: "SUSE",
		},
		{
			name: "mageia",
			osrel: `NAME="Mageia"
VERSION="9"
ID=mageia
VERSION_ID=9
PRETTY_NAME="Mageia 9"`,
			want: "Mageia:9",
		},
		{
			name: "alpaquita",
			osrel: `NAME="BellSoft Alpaquita Linux"
ID=alpaquita
VERSION_ID=23
PRETTY_NAME="BellSoft Alpaquita Linux Stream 23 (musl)"`,
			want: "Alpaquita:23",
		},
		{
			name: "minimos",
			osrel: `ID=minimos
NAME="MinimOS"
PRETTY_NAME="MinimOS"
VERSION_ID="20250101"`,
			want: "MinimOS",
		},
		{
			name: "fedora is not an OSV ecosystem",
			osrel: `NAME="Fedora Linux"
VERSION="40 (Container Image)"
ID=fedora
VERSION_ID=40`,
			// OSV publishes no Fedora database. Returning "" and querying with
			// it would answer clean; this stops with a message instead.
			wantErr: "no OSV ecosystem is known",
		},
		{
			name: "centos stream is not an OSV ecosystem",
			osrel: `NAME="CentOS Stream"
VERSION="9"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="9"`,
			wantErr: "no OSV ecosystem is known",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, err := ParseOSRelease(strings.NewReader(tt.osrel))
			if err != nil {
				t.Fatalf("ParseOSRelease: %v", err)
			}

			got, err := rel.Ecosystem()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("Ecosystem() = %q, want an error containing %q", got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Ecosystem() error = %v, want it to contain %q", err, tt.wantErr)
				}
				if got != "" {
					t.Errorf("Ecosystem() returned %q alongside an error; it must return no string at all", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ecosystem(): %v", err)
			}
			if got != tt.want {
				t.Errorf("Ecosystem() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSLEProductRelease(t *testing.T) {
	tests := []struct {
		name  string
		osrel string
		want  string
	}{
		{
			name:  "service pack from the pretty name",
			osrel: "ID=sles\nVERSION_ID=\"15.7\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 15 SP7\"\n",
			want:  "15 SP7",
		},
		{
			// Micro spells its release with a dot, not an SP.
			name:  "dotted release",
			osrel: "ID=sle-micro\nVERSION_ID=\"5.5\"\nPRETTY_NAME=\"SUSE Linux Enterprise Micro 5.5\"\n",
			want:  "5.5",
		},
		{
			name:  "sap applications keeps only the trailing version",
			osrel: "ID=sles_sap\nVERSION_ID=\"12.5\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server for SAP Applications 12 SP5\"\n",
			want:  "12 SP5",
		},
		{
			// The SP spelling has to be reconstructed when PRETTY_NAME is gone.
			name:  "falls back to VERSION_ID",
			osrel: "ID=sles\nVERSION_ID=\"15.7\"\n",
			want:  "15 SP7",
		},
		{
			name:  "sixteen is dotted, not an SP",
			osrel: "ID=sles\nVERSION_ID=\"16.0\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 16.0\"\n",
			want:  "16.0",
		},
		{
			// Every other distribution names its release in the query itself.
			name:  "not applied to other distributions",
			osrel: "ID=debian\nVERSION_ID=\"12\"\n",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, err := ParseOSRelease(strings.NewReader(tt.osrel))
			if err != nil {
				t.Fatal(err)
			}
			if got := rel.ProductRelease(); got != tt.want {
				t.Errorf("ProductRelease() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchesProductRelease(t *testing.T) {
	const release = "15 SP7"
	tests := []struct {
		eco  string
		want bool
	}{
		// The one that matters: gzip on SLES 15 SP7 is filed against the
		// module that ships it, not against the server product.
		{"SUSE:Linux Enterprise Module for Basesystem 15 SP7", true},
		{"SUSE:Linux Enterprise Server 15 SP7", true},
		{"SUSE:Linux Enterprise Server 15 SP7-LTSS", true},
		{"SUSE:Linux Enterprise High Performance Computing 15 SP7-ESPOS", true},

		// A different release of the same product line. These are what make a
		// fully patched SP7 image look vulnerable forever: SLE 16 fixes gzip
		// at 1.13, a version SLE 15 will never ship.
		{"SUSE:Linux Enterprise Server 16.0", false},
		{"SUSE:Linux Enterprise Server 15 SP4-LTSS", false},
		{"SUSE:Linux Micro 6.2", false},
		{"SUSE:Linux Enterprise Micro 5.5", false},

		// "5 SP7" must not match "15 SP7" on a suffix comparison.
		{"SUSE:Linux Enterprise Server 5 SP7", false},
	}
	for _, tt := range tests {
		t.Run(tt.eco, func(t *testing.T) {
			if got := MatchesProductRelease(tt.eco, release); got != tt.want {
				t.Errorf("MatchesProductRelease(%q, %q) = %v, want %v", tt.eco, release, got, tt.want)
			}
		})
	}

	// An empty release narrows nothing, which is what every non-SUSE
	// ecosystem relies on.
	if !MatchesProductRelease("Debian:12", "") {
		t.Error("an empty release must match everything")
	}
}

func TestUnknownDistroIsIdentifiable(t *testing.T) {
	rel, err := ParseOSRelease(strings.NewReader("ID=plan9\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rel.Ecosystem()
	if !errors.Is(err, ErrUnknownDistro) {
		t.Fatalf("error is not ErrUnknownDistro: %v", err)
	}
	// The message has to name what would have worked, or the user is left
	// guessing which spelling of their distro id we wanted.
	if !strings.Contains(err.Error(), "debian") {
		t.Errorf("error does not list the supported ids: %v", err)
	}
}

func TestParseOSRelease(t *testing.T) {
	const osrel = `# a comment

NAME="Ubuntu"
VERSION="24.04.3 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
VERSION_CODENAME=noble
PRETTY_NAME="Ubuntu 24.04.3 LTS"
CPE_NAME="cpe:/o:canonical:ubuntu_linux:24.04"
HOME_URL="https://www.ubuntu.com/"
NOT_A_PAIR
`
	got, err := ParseOSRelease(strings.NewReader(osrel))
	if err != nil {
		t.Fatal(err)
	}
	want := Release{
		ID:              "ubuntu",
		IDLike:          []string{"debian"},
		Version:         "24.04.3 LTS (Noble Numbat)",
		VersionID:       "24.04",
		VersionCodename: "noble",
		PrettyName:      "Ubuntu 24.04.3 LTS",
		CPEName:         "cpe:/o:canonical:ubuntu_linux:24.04",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseOSRelease() = %+v, want %+v", got, want)
	}
}

func TestParseOSReleaseQuoting(t *testing.T) {
	cases := map[string]string{
		`PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`: "Debian GNU/Linux 12 (bookworm)",
		`PRETTY_NAME='Alpine Linux v3.19'`:             "Alpine Linux v3.19",
		`PRETTY_NAME=Wolfi`:                            "Wolfi",
		`PRETTY_NAME="say \"hi\""`:                     `say "hi"`,
		`PRETTY_NAME="a\\b"`:                           `a\b`,
		`PRETTY_NAME='keeps \n literal'`:               `keeps \n literal`,
		`PRETTY_NAME=`:                                 "",
	}
	for line, want := range cases {
		rel, err := ParseOSRelease(strings.NewReader("ID=x\n" + line + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if rel.PrettyName != want {
			t.Errorf("%s -> %q, want %q", line, rel.PrettyName, want)
		}
	}
}

func TestParseOSReleaseWithoutIDIsAnError(t *testing.T) {
	if _, err := ParseOSRelease(strings.NewReader(`PRETTY_NAME="Mystery Linux"`)); err == nil {
		t.Fatal("expected an error for os-release with no ID")
	}
}
