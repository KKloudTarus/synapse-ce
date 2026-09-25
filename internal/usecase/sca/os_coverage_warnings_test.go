package sca

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestOSCoverageWarnings pins the structured OS-package coverage warnings, in particular the CentOS Linux 7
// coverage=approximate provenance: an approximated distro is never silent, an unsupported
// distro reads as coverage=unsupported (never clean, never aliased), and the two are distinct signals.
func TestOSCoverageWarnings(t *testing.T) {
	tests := []struct {
		name            string
		pkgs            int
		unsupported     string
		approximate     string
		unresolved      bool
		wantCount       int
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:            "centos 7 approximate",
			pkgs:            12,
			approximate:     "centos-7",
			wantCount:       1,
			wantContains:    []string{"coverage=approximate", "centos-7", "Red Hat 7", "other RPMs"},
			wantNotContains: []string{"coverage=unsupported"},
		},
		{
			name:            "centos stream unsupported",
			pkgs:            8,
			unsupported:     "centos",
			wantCount:       1,
			wantContains:    []string{"coverage=unsupported", "centos", "NOT matched"},
			wantNotContains: []string{"coverage=approximate"},
		},
		{
			name:            "mixed CentOS 7 reports both states",
			pkgs:            2,
			unsupported:     "centos",
			approximate:     "centos-7",
			wantCount:       2,
			wantContains:    []string{"coverage=unsupported", "coverage=approximate", "other RPMs"},
			wantNotContains: []string{"OS advisories were NOT matched"},
		},
		{
			name:         "unresolved release",
			pkgs:         5,
			unresolved:   true,
			wantCount:    1,
			wantContains: []string{"could not be resolved"},
		},
		{
			name:      "fully resolved distro emits nothing",
			pkgs:      20,
			wantCount: 0,
		},
		{
			// The helper must not merge or drop signals when they coexist.
			name:         "all signals set are each surfaced",
			pkgs:         3,
			unsupported:  "centos",
			approximate:  "centos-7",
			unresolved:   true,
			wantCount:    3,
			wantContains: []string{"coverage=unsupported", "coverage=approximate", "could not be resolved"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := osCoverageWarnings(tc.pkgs, tc.unsupported, tc.approximate, tc.unresolved)
			if len(got) != tc.wantCount {
				t.Fatalf("want %d warning(s), got %d: %v", tc.wantCount, len(got), got)
			}
			joined := strings.Join(got, "\n")
			for _, want := range tc.wantContains {
				if !strings.Contains(joined, want) {
					t.Errorf("warnings missing %q; got %v", want, got)
				}
			}
			for _, notWant := range tc.wantNotContains {
				if strings.Contains(joined, notWant) {
					t.Errorf("warnings must not contain %q; got %v", notWant, got)
				}
			}
		})
	}
}

func TestApplyOSCoverageCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name        string
		unsupported string
		unresolved  bool
		wantGap     bool
	}{
		{name: "resolved"},
		{name: "bounded CentOS scope", unsupported: "centos", wantGap: true},
		{name: "unresolved release", unresolved: true, wantGap: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			completeness := ports.Completeness{Confident: true, Warning: "existing warning"}
			gap := applyOSCoverageCompleteness(&completeness, tc.unsupported, tc.unresolved)
			if gap != tc.wantGap || completeness.Confident == tc.wantGap {
				t.Fatalf("gap=%v completeness=%+v", gap, completeness)
			}
			if tc.wantGap && (!strings.Contains(completeness.Warning, "incomplete") || !strings.Contains(completeness.Warning, "existing warning")) {
				t.Fatalf("coverage warning missing from %+v", completeness)
			}
		})
	}
}
