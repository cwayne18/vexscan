package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// clearPagerEnv unsets every variable pagerCommand consults, so a developer's
// own $PAGER cannot decide whether the suite passes.
func clearPagerEnv(t *testing.T) {
	t.Helper()
	for _, name := range pagerEnvVars {
		if _, ok := os.LookupEnv(name); ok {
			t.Setenv(name, "") // restored by t.Setenv's cleanup
			os.Unsetenv(name)
		}
	}
}

func TestPagerDefaultsToLess(t *testing.T) {
	clearPagerEnv(t)
	if got := pagerCommand(); got != "less" {
		t.Errorf("pagerCommand() = %q, want less", got)
	}
}

func TestPagerPrefersTheMostSpecificVariable(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"system PAGER is honored", map[string]string{"PAGER": "more"}, "more"},
		{"legacy name beats PAGER", map[string]string{"PAGER": "more", "GOMODVEX_PAGER": "bat"}, "bat"},
		{
			"vexscan name wins outright",
			map[string]string{"PAGER": "more", "GOMODVEX_PAGER": "bat", "VEXSCAN_PAGER": "less -S"},
			"less -S",
		},
		{"arguments are preserved", map[string]string{"VEXSCAN_PAGER": "less -S -N"}, "less -S -N"},
		{"surrounding whitespace is not a pager", map[string]string{"VEXSCAN_PAGER": "  less  "}, "less"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearPagerEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if got := pagerCommand(); got != tt.want {
				t.Errorf("pagerCommand() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The behavior envx.Get deliberately does not have: an empty value is a
// decision, not an absence. Without this there is no way to turn paging off
// permanently, which is the whole reason pagerCommand does its own lookup.
func TestAnEmptyPagerVariableTurnsPagingOff(t *testing.T) {
	for _, name := range pagerEnvVars {
		t.Run(name, func(t *testing.T) {
			clearPagerEnv(t)
			t.Setenv(name, "")
			if got := pagerCommand(); got != "" {
				t.Errorf("%s= gave pagerCommand() = %q, want no pager", name, got)
			}
		})
	}
}

// An empty VEXSCAN_PAGER must not fall through to a set PAGER: the specific
// variable saying "off" outranks the general one saying "more".
func TestAnEmptySpecificVariableIsNotAFallThrough(t *testing.T) {
	clearPagerEnv(t)
	t.Setenv("PAGER", "more")
	t.Setenv("VEXSCAN_PAGER", "")
	if got := pagerCommand(); got != "" {
		t.Errorf("pagerCommand() = %q, want no pager", got)
	}
}

func TestLessGetsFRXOnlyWhenItIsBareAndUnconfigured(t *testing.T) {
	tests := []struct {
		name    string
		command string
		lessSet bool
		want    bool
	}{
		{"bare less with no LESS", "less", false, true},
		// Someone with a LESS of their own has already answered this question.
		{"bare less with a LESS already set", "less", true, false},
		// Explicit flags mean the author said what they wanted.
		{"less with arguments", "less -S", false, false},
		{"some other pager", "bat -p", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := pagerEnv(tt.command, []string{"HOME=/root"}, tt.lessSet)
			got := slices.Contains(env, "LESS=FRX")
			if got != tt.want {
				t.Errorf("pagerEnv(%q, lessSet=%v) LESS=FRX present = %v, want %v",
					tt.command, tt.lessSet, got, tt.want)
			}
			// Whatever it decides, it must not lose the caller's environment.
			if !slices.Contains(env, "HOME=/root") {
				t.Errorf("pagerEnv dropped the inherited environment: %v", env)
			}
		})
	}
}

// The report must survive a pager that does not exist -- the failure mode that
// would otherwise turn a forty-second scan into a blank terminal.
func TestPageReportsFailureForAPagerThatIsNotThere(t *testing.T) {
	clearPagerEnv(t)
	t.Setenv("VEXSCAN_PAGER", "vexscan-no-such-pager-exists")
	if page("a report\n") {
		t.Error("page() claimed success for a pager that is not installed; the report would be lost")
	}
}

func TestPageDeclinesWhenPagingIsOff(t *testing.T) {
	clearPagerEnv(t)
	t.Setenv("VEXSCAN_PAGER", "")
	if page("a report\n") {
		t.Error("page() paged despite VEXSCAN_PAGER=")
	}
}

// cat is the pager every machine has, so this exercises the real pipe: start a
// child, write the report to it, and wait for it to finish.
func TestPageWritesTheWholeReportThroughTheChild(t *testing.T) {
	clearPagerEnv(t)
	report := strings.Repeat("CVE-2024-0001  libc6\n", 500)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	t.Setenv("VEXSCAN_PAGER", "cat")

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	ok := page(report)
	os.Stdout = saved
	w.Close()
	got := <-done
	r.Close()

	if !ok {
		t.Fatal("page() failed with cat as the pager")
	}
	if got != report {
		t.Errorf("pager received %d bytes, want %d", len(got), len(report))
	}
}
