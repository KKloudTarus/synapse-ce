package runtimereach

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestJoinRaisesLoadedVulnerableLibrary(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}},
	})
	findings := []FindingPackage{{FindingID: "f-ssl", Package: libssl3()}}
	hits := Join([]LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}, own, findings)
	if len(hits) != 1 || hits[0].FindingID != "f-ssl" || hits[0].Match != MatchFileIdentity {
		t.Fatalf("hits = %+v, want one file_identity hit on f-ssl", hits)
	}
}

func TestJoinMultiVersionRaisesOnlyLoadedVersion(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 300}}}},
		{Package: libssl11(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.1.1", ID: FileID{Device: 64, Inode: 100}}}},
	})
	findings := []FindingPackage{
		{FindingID: "f-v3", Package: libssl3()},
		{FindingID: "f-v1", Package: libssl11()},
	}
	// Only v3 loaded.
	hits := Join([]LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 300}}}, own, findings)
	if len(hits) != 1 || hits[0].FindingID != "f-v3" {
		t.Fatalf("hits = %+v, want only f-v3 raised", hits)
	}
}

func TestJoinBarePathCollisionDoesNotMisattribute(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: PackageRef{Name: "pkg-a", Version: "1"}, Files: []OwnedFile{{Path: "/usr/lib/libcommon.so"}}},
		{Package: PackageRef{Name: "pkg-b", Version: "2"}, Files: []OwnedFile{{Path: "/usr/lib/libcommon.so"}}},
	})
	findings := []FindingPackage{
		{FindingID: "f-a", Package: PackageRef{Name: "pkg-a", Version: "1"}},
		{FindingID: "f-b", Package: PackageRef{Name: "pkg-b", Version: "2"}},
	}
	if hits := Join([]LoadEvent{{Path: "/usr/lib/libcommon.so"}}, own, findings); len(hits) != 0 {
		t.Fatalf("collision produced hits %+v, want none (no misattribution)", hits)
	}
}

func TestJoinManyFindingsOnePackage(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}},
	})
	findings := []FindingPackage{
		{FindingID: "cve-1", Package: libssl3()},
		{FindingID: "cve-2", Package: libssl3()},
	}
	hits := Join([]LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}, own, findings)
	if len(hits) != 2 {
		t.Fatalf("hits = %+v, want both CVEs on the loaded package raised", hits)
	}
	if hits[0].FindingID != "cve-1" || hits[1].FindingID != "cve-2" {
		t.Fatalf("hits not sorted by finding id: %+v", hits)
	}
}

func TestJoinDeduplicatesRepeatedLoadsAndPrefersIdentity(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}}},
	})
	findings := []FindingPackage{{FindingID: "f-ssl", Package: libssl3()}}
	loads := []LoadEvent{
		{Path: "/usr/lib/libssl.so.3"},                                     // unique-path
		{Path: "/usr/lib/libssl.so.3", ID: FileID{Device: 64, Inode: 111}}, // file-identity, stronger
		{Path: "/usr/lib/libssl.so.3"},                                     // unique-path again
	}
	hits := Join(loads, own, findings)
	if len(hits) != 1 {
		t.Fatalf("hits = %+v, want one deduplicated hit", hits)
	}
	if hits[0].Match != MatchFileIdentity {
		t.Fatalf("hit match = %q, want the strongest (file_identity) retained", hits[0].Match)
	}
}

func TestJoinNoFindingForLoadedPackage(t *testing.T) {
	own := NewOwnership([]PackageFiles{
		{Package: PackageRef{Name: "libpng16-16", Version: "1.6"}, Files: []OwnedFile{{Path: "/usr/lib/libpng16.so.16"}}},
	})
	findings := []FindingPackage{{FindingID: "f-ssl", Package: libssl3()}}
	if hits := Join([]LoadEvent{{Path: "/usr/lib/libpng16.so.16"}}, own, findings); len(hits) != 0 {
		t.Fatalf("hits = %+v, want none (loaded package has no finding)", hits)
	}
}

func TestJoinEmptyInputs(t *testing.T) {
	own := NewOwnership([]PackageFiles{{Package: libssl3(), Files: []OwnedFile{{Path: "/usr/lib/libssl.so.3"}}}})
	if hits := Join(nil, own, []FindingPackage{{FindingID: "f", Package: libssl3()}}); hits != nil {
		t.Fatalf("no loads should produce nil, got %+v", hits)
	}
	if hits := Join([]LoadEvent{{Path: "/x"}}, nil, []FindingPackage{{FindingID: "f", Package: libssl3()}}); hits != nil {
		t.Fatalf("nil ownership should produce nil, got %+v", hits)
	}
	var zero shared.ID
	if hits := Join([]LoadEvent{{Path: "/usr/lib/libssl.so.3"}}, own, []FindingPackage{{FindingID: zero, Package: libssl3()}}); hits != nil {
		t.Fatalf("zero finding id should be skipped, got %+v", hits)
	}
}
