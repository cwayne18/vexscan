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
			name: "sles is refused rather than guessed",
			osrel: `NAME="SLES"
VERSION="15-SP5"
VERSION_ID="15.5"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP5"
ID="sles"`,
			// The obvious answer, "SUSE:Linux Enterprise Server 15 SP5",
			// returns nothing: SLES 15 SP5 advisories are filed under
			// "...15 SP5-LTSS". The suffix tracks the product's support phase,
			// which os-release does not record, so every SLE image past
			// general support would silently scan clean.
			wantErr: "cannot be determined from os-release",
		},
		{
			name: "sles for SAP is refused too",
			osrel: `NAME="SLES_SAP"
VERSION_ID="12.5"
PRETTY_NAME="SUSE Linux Enterprise Server for SAP Applications 12 SP5"
ID="sles_sap"`,
			wantErr: "--ecosystem",
		},
		{
			name: "sle micro is refused for the same reason",
			osrel: `NAME="SLE Micro"
VERSION_ID="5.5"
PRETTY_NAME="SUSE Linux Enterprise Micro 5.5"
ID="sle-micro"`,
			wantErr: "cannot be determined from os-release",
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

func TestSLEIsAmbiguousNotUnknown(t *testing.T) {
	rel, err := ParseOSRelease(strings.NewReader(
		"ID=sles\nVERSION_ID=\"15.5\"\nPRETTY_NAME=\"SUSE Linux Enterprise Server 15 SP5\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rel.Ecosystem()
	if !errors.Is(err, ErrAmbiguousDistro) {
		t.Fatalf("error is not ErrAmbiguousDistro: %v", err)
	}
	if errors.Is(err, ErrUnknownDistro) {
		t.Error("SLE is carried by OSV; it must not report as an unknown distribution")
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
