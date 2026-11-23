package sca

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ospkg"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestImageOSInventoryCoverageAndRecovery(t *testing.T) {
	for _, id := range []string{"debian", "wolfi", "unknown-linux"} {
		t.Run(id, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, content string) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			write("etc/os-release", "ID="+id+"\nVERSION_ID=12\n")
			// A pinned language dependency must not hide a missing OS inventory.
			doc := &sbom.SBOM{Components: []sbom.Component{{Name: "app", Version: "1.0.0", PURL: "pkg:npm/app@1.0.0"}}}
			svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
				&fakeAcquirer{dir: t.TempDir(), rootfs: root, image: &sbom.ImageInfo{}}, &fakeDetector{}, staticSBOM{doc: doc}, []ports.DetectionSource{fakeCoverageSource{covered: map[string]bool{"Debian:12": true, "Wolfi": true}, ok: true}}, nil, fakeLic{}, nil)
			svc.SetOSPackageCataloger(ospkg.New())
			scan := func() *ScanResult {
				t.Helper()
				result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			result := scan()
			warning := "OS packages were not inventoried for distro " + id
			if result.Completeness.Confident || !strings.Contains(result.Completeness.Warning, warning) || !strings.Contains(strings.Join(result.SourceWarnings, " "), warning) {
				t.Fatalf("missing OS inventory must be visible: %+v warnings=%v", result.Completeness, result.SourceWarnings)
			}
			partial := false
			for _, outcome := range result.EngineOutcomes {
				if outcome.Engine == "inventory" {
					partial = outcome.Coverage == scanrun.CoveragePartial
				}
			}
			if !partial {
				t.Fatal("missing OS packages must degrade inventory coverage")
			}
			if id == "unknown-linux" {
				return
			}
			if id == "debian" {
				write("var/lib/dpkg/status.d/base-files", "Package: base-files\nVersion: 12.4\nArchitecture: amd64\n")
			} else {
				write("lib/apk/db/installed", "P:glibc\nV:2.39-r0\nA:x86_64\n")
			}
			recovered := scan()
			if !recovered.Completeness.Confident || strings.Contains(recovered.Completeness.Warning, "not inventoried") || strings.Contains(strings.Join(recovered.SourceWarnings, " "), "not inventoried") {
				t.Fatalf("valid package DB did not restore coverage: %+v warnings=%v", recovered.Completeness, recovered.SourceWarnings)
			}
			if len(recovered.SBOM.Components) != 2 {
				t.Fatalf("expected language and OS components: %+v", recovered.SBOM.Components)
			}
		})
	}
}

func TestImageOSInventoryPreservesProducerPackages(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=wolfi\n"), 0644); err != nil {
		t.Fatal(err)
	}
	doc := &sbom.SBOM{Source: "syft", Components: []sbom.Component{{Name: "glibc", Version: "2.39-r0", PURL: "pkg:apk/wolfi/glibc@2.39-r0?arch=x86_64&distro=wolfi"}}}
	svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, nil, nil, nil, nil, nil, nil, nil, ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0, &fakeAcquirer{dir: t.TempDir(), rootfs: root, image: &sbom.ImageInfo{}}, &fakeDetector{}, staticSBOM{doc: doc}, []ports.DetectionSource{fakeCoverageSource{covered: map[string]bool{"Wolfi": true}, ok: true}}, nil, fakeLic{}, nil)
	svc.SetOSPackageCataloger(ospkg.New())
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SBOM.Components) != 1 {
		t.Fatal("expected retained OS package")
	}
	if !result.Completeness.Confident {
		t.Fatalf("producer OS inventory must remain confident: %+v", result.Completeness)
	}
	for _, outcome := range result.EngineOutcomes {
		if outcome.Engine == "inventory" && outcome.Coverage != scanrun.CoverageComplete {
			t.Fatalf("producer inventory degraded: %+v", outcome)
		}
	}
	if strings.Contains(result.Completeness.Warning, "OS packages were not inventoried") || strings.Contains(strings.Join(result.SourceWarnings, " "), "OS packages were not inventoried") {
		t.Fatalf("existing OS inventory incorrectly reported absent: components=%d completeness=%+v", len(result.SBOM.Components), result.Completeness)
	}
}
