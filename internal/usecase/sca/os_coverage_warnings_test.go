package sca

import (
	"strings"
	"testing"
)

// TestOSCoverageWarnings pins the structured OS-package coverage warnings, in particular the CentOS Linux 7
// coverage=approximate provenance added for #1037: an approximated distro is never silent, an unsupported
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
			wantContains:    []string{"coverage=approximate", "centos-7", "Red Hat 7", "EPEL/SIG/third-party"},
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
			// The cataloger keeps these mutually exclusive, but the helper must not merge or drop signals if
			// they are ever set together: each is surfaced on its own line.
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
