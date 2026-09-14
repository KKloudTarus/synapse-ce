package runtimereach

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	dr "github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
)

type fakeFindings struct{ list []finding.Finding }

func (f fakeFindings) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return f.list, nil
}

func scaFinding(id shared.ID, advisory, component, version string) finding.Finding {
	return finding.Finding{ID: id, Kind: finding.KindSCA, DedupKey: vulnerability.DedupKey(advisory, component, version)}
}

func TestFindingPackagesFromDedupKey(t *testing.T) {
	findings := []finding.Finding{
		scaFinding("f1", "CVE-2024-1", "libssl3", "3.0.13-0ubuntu3.4"),
		{ID: "lic", Kind: finding.KindSCA, DedupKey: "license:MIT"},        // no owning package, skipped
		{ID: "sast", Kind: finding.KindSAST, DedupKey: "sast:x"},           // non-SCA, skipped
		{ID: "bad", Kind: finding.KindSCA, DedupKey: "vuln:CVE-x:libfoo:"}, // no version, skipped
	}
	got := FindingPackages(findings)
	if len(got) != 1 {
		t.Fatalf("FindingPackages = %+v, want only the versioned SCA vuln", got)
	}
	if got[0].FindingID != "f1" || got[0].Package != (dr.PackageRef{Name: "libssl3", Version: "3.0.13-0ubuntu3.4"}) {
		t.Fatalf("binding = %+v, want f1 -> libssl3@3.0.13-0ubuntu3.4", got[0])
	}
}

func TestAttributeRaisesLoadedVulnerableLibrary(t *testing.T) {
	findings := fakeFindings{list: []finding.Finding{
		scaFinding("f-ssl", "CVE-2024-1", "libssl3", "3.0.13"),
		scaFinding("f-png", "CVE-2024-2", "libpng16-16", "1.6.43"),
	}}
	c, rec, _ := newCoordinator(t)
	svc, err := NewService(findings, c)
	if err != nil {
		t.Fatal(err)
	}
	own := dr.NewOwnership([]dr.PackageFiles{
		{Package: dr.PackageRef{Name: "libssl3", Version: "3.0.13"}, Files: []dr.OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: dr.FileID{Device: 64, Inode: 111}}}},
		{Package: dr.PackageRef{Name: "libpng16-16", Version: "1.6.43"}, Files: []dr.OwnedFile{{Path: "/usr/lib/libpng16.so.16", ID: dr.FileID{Device: 64, Inode: 222}}}},
	})
	// Only libssl is loaded.
	n, err := svc.Attribute(context.Background(), "eng", own, []dr.LoadEvent{
		{Path: "/usr/lib/libssl.so.3", ID: dr.FileID{Device: 64, Inode: 111}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(rec.proposes) != 1 || rec.proposes[0].subjectID != "f-ssl" {
		t.Fatalf("minted %d for %+v, want only f-ssl raised", n, rec.proposes)
	}
}

func TestAttributeBarePathCollisionDoesNotRaise(t *testing.T) {
	findings := fakeFindings{list: []finding.Finding{
		scaFinding("f-a", "CVE-1", "pkg-a", "1"),
		scaFinding("f-b", "CVE-2", "pkg-b", "2"),
	}}
	c, rec, _ := newCoordinator(t)
	svc, _ := NewService(findings, c)
	own := dr.NewOwnership([]dr.PackageFiles{
		{Package: dr.PackageRef{Name: "pkg-a", Version: "1"}, Files: []dr.OwnedFile{{Path: "/usr/lib/libcommon.so"}}},
		{Package: dr.PackageRef{Name: "pkg-b", Version: "2"}, Files: []dr.OwnedFile{{Path: "/usr/lib/libcommon.so"}}},
	})
	n, err := svc.Attribute(context.Background(), "eng", own, []dr.LoadEvent{{Path: "/usr/lib/libcommon.so"}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(rec.proposes) != 0 {
		t.Fatalf("collision raised %d findings, want 0 (no misattribution)", n)
	}
}

func TestAttributeVersionMismatchIsCleanMiss(t *testing.T) {
	// The finding's package version (from its DedupKey) must match the installed package version the host
	// DB records EXACTLY. A divergent version string (a stale finding, or a producer that normalizes the
	// version differently) is a clean miss, never a wrong raise. This is fail-safe: it under-raises rather
	// than misattributes. It also documents the producer contract: the agent must populate PackageRef from
	// the same version string the SBOM/DedupKey carries, or the join silently yields no hits.
	findings := fakeFindings{list: []finding.Finding{scaFinding("f-ssl", "CVE-2024-1", "libssl3", "3.0.13-0ubuntu3.4")}}
	c, rec, _ := newCoordinator(t)
	svc, _ := NewService(findings, c)
	own := dr.NewOwnership([]dr.PackageFiles{
		// Same name, DIFFERENT version string (missing the distro revision suffix).
		{Package: dr.PackageRef{Name: "libssl3", Version: "3.0.13"}, Files: []dr.OwnedFile{{Path: "/usr/lib/libssl.so.3", ID: dr.FileID{Device: 64, Inode: 111}}}},
	})
	n, err := svc.Attribute(context.Background(), "eng", own, []dr.LoadEvent{{Path: "/usr/lib/libssl.so.3", ID: dr.FileID{Device: 64, Inode: 111}}})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(rec.proposes) != 0 {
		t.Fatalf("version mismatch raised %d findings, want 0 (clean miss, never a wrong raise)", n)
	}
}

func TestAttributeEmptyInputs(t *testing.T) {
	c, _, _ := newCoordinator(t)
	svc, _ := NewService(fakeFindings{}, c)
	if n, err := svc.Attribute(context.Background(), "eng", nil, []dr.LoadEvent{{Path: "/x"}}); err != nil || n != 0 {
		t.Fatalf("nil ownership: n=%d err=%v", n, err)
	}
	own := dr.NewOwnership(nil)
	if n, err := svc.Attribute(context.Background(), "eng", own, nil); err != nil || n != 0 {
		t.Fatalf("no loads: n=%d err=%v", n, err)
	}
}

func TestNewServiceValidatesDeps(t *testing.T) {
	c, _, _ := newCoordinator(t)
	if _, err := NewService(nil, c); err == nil {
		t.Fatal("nil finding reader must error")
	}
	if _, err := NewService(fakeFindings{}, nil); err == nil {
		t.Fatal("nil coordinator must error")
	}
}
