package runtimereach

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func validReport() Report {
	return Report{
		PackageFiles: []PackageFiles{
			{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}},
		},
		Loads:    []LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}},
		Coverage: []CoverageReason{CoverageSensorUnavailable},
	}
}

func TestReportValidateAccepts(t *testing.T) {
	if err := validReport().Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
}

func TestReportValidateRejects(t *testing.T) {
	cases := map[string]func(*Report){
		"empty package name": func(r *Report) { r.PackageFiles[0].Package.Name = "" },
		"empty package ver":  func(r *Report) { r.PackageFiles[0].Package.Version = "" },
		"empty owned path":   func(r *Report) { r.PackageFiles[0].Files[0].Path = "" },
		"empty load path":    func(r *Report) { r.Loads[0].Path = "" },
		"oversize path":      func(r *Report) { r.Loads[0].Path = "/" + strings.Repeat("a", MaxReportPathBytes) },
		"unknown coverage":   func(r *Report) { r.Coverage[0] = CoverageReason("mystery") },
		"relative load path": func(r *Report) { r.Loads[0].Path = "relative/libc.so.6" },
		"relative owned path": func(r *Report) {
			r.PackageFiles[0].Files[0].Path = "usr/lib/libssl.so.3"
		},
		"relative real path": func(r *Report) { r.Loads[0].RealPath = "usr/lib/libssl.so.3" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := validReport()
			mutate(&r)
			if err := r.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}

// TestReportBuildResolvesEndToEnd is the wire→resolution vertical: a validated report builds the Ownership
// index and load slice that Join uses, raising exactly the finding whose loaded package matched.
func TestReportBuildResolvesEndToEnd(t *testing.T) {
	r := validReport()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	ownership, loads := r.Build()
	findings := []FindingPackage{{FindingID: "f-ssl", Package: libssl3()}}
	hits := Join(loads, ownership, findings)
	if len(hits) != 1 || hits[0].FindingID != "f-ssl" || hits[0].Match != MatchFileIdentity {
		t.Fatalf("report build/join = %+v, want one file_identity hit on f-ssl", hits)
	}
}

func TestReportNormalizeSortsAndDropsEmptyPackages(t *testing.T) {
	r := Report{
		PackageFiles: []PackageFiles{
			{Package: PackageRef{Name: "zzz", Version: "1"}, Files: []OwnedFile{{Path: "/z"}}},
			{Package: PackageRef{Name: "empty", Version: "1"}}, // no files -> dropped
			{Package: PackageRef{Name: "aaa", Version: "1"}, Files: []OwnedFile{{Path: "/b"}, {Path: "/a"}}},
		},
		Loads: []LoadEvent{{Path: "/z"}, {Path: "/a"}},
	}
	out := r.Normalize()
	if len(out.PackageFiles) != 2 || out.PackageFiles[0].Package.Name != "aaa" {
		t.Fatalf("normalize packages = %+v", out.PackageFiles)
	}
	if out.PackageFiles[0].Files[0].Path != "/a" {
		t.Fatalf("files not sorted: %+v", out.PackageFiles[0].Files)
	}
	if out.Loads[0].Path != "/a" {
		t.Fatalf("loads not sorted: %+v", out.Loads)
	}
}

func TestReportEmpty(t *testing.T) {
	if !(Report{}).Empty() {
		t.Fatal("zero report must be empty")
	}
	if (Report{PackageFiles: []PackageFiles{{Package: libssl3()}}}).Empty() == false {
		// packages but no loads -> nothing to join -> empty
		t.Fatal("a report with no loads must be empty")
	}
	if validReport().Empty() {
		t.Fatal("a report with packages and loads must not be empty")
	}
}
