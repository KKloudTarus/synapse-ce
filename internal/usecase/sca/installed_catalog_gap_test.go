package sca

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// boundedInstalledCataloger returns a catalog that found packages and did not cover the whole rootfs.
type boundedInstalledCataloger struct {
	report ports.InstalledCatalogReport
}

func (c *boundedInstalledCataloger) CatalogInstalled(ctx context.Context, root string) ([]sbom.Component, error) {
	report, err := c.CatalogInstalledReport(ctx, root)
	return report.Components, err
}

func (c *boundedInstalledCataloger) CatalogInstalledReport(context.Context, string) (ports.InstalledCatalogReport, error) {
	return c.report, nil
}

func installedGapResult(t *testing.T, report ports.InstalledCatalogReport) *ScanResult {
	t.Helper()
	rootfs := t.TempDir()
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()},
		&fakeAcquirer{dir: t.TempDir(), rootfs: rootfs, image: &sbom.ImageInfo{}}, &fakeAudit{}, &fakeDetector{})
	svc.SetInstalledPackageCataloger(&boundedInstalledCataloger{report: report})
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// A catalog that stopped at a bound found real packages and did not look everywhere. The components stand;
// the claim of a complete inventory does not.
func TestTruncatedInstalledCatalogIsNotACompleteInventory(t *testing.T) {
	result := installedGapResult(t, ports.InstalledCatalogReport{
		Components:        []sbom.Component{{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"}},
		Truncated:         true,
		TruncationReasons: []string{"the installed-package component cap was reached, so later packages were not cataloged"},
	})
	if result.Completeness.Confident {
		t.Fatal("a bounded catalog cannot leave the inventory confident")
	}
	outcome, ok := result.engineOutcome("inventory")
	if !ok || outcome.Coverage != scanrun.CoveragePartial || outcome.Reason != scanrun.ReasonAnalysisIncomplete {
		t.Fatalf("inventory outcome %+v, want partial/analysis_incomplete", outcome)
	}
	var warned bool
	for _, w := range result.SourceWarnings {
		if strings.Contains(w, "lower bound") && strings.Contains(w, "component cap") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the warning must name the bound that was reached, got %q", result.SourceWarnings)
	}
}

// Entries the walk could not read are packages that may exist and were never examined, so they count the
// same way a cap does.
func TestUnreadableRootFSEntriesBoundTheInventory(t *testing.T) {
	result := installedGapResult(t, ports.InstalledCatalogReport{
		Components: []sbom.Component{{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"}},
		Unreadable: 3,
	})
	if result.Completeness.Confident {
		t.Fatal("unreadable rootfs entries cannot leave the inventory confident")
	}
	var warned bool
	for _, w := range result.SourceWarnings {
		if strings.Contains(w, "3 root-filesystem entries could not be read") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the warning must count the unreadable entries, got %q", result.SourceWarnings)
	}
}

// A catalog that covered the rootfs within its bounds reports no gap, so the warning stays meaningful.
func TestCompleteInstalledCatalogAddsNoGap(t *testing.T) {
	result := installedGapResult(t, ports.InstalledCatalogReport{
		Components: []sbom.Component{{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"}},
	})
	for _, w := range result.SourceWarnings {
		if strings.Contains(w, "lower bound") {
			t.Fatalf("a complete catalog must add no inventory gap, got %q", result.SourceWarnings)
		}
	}
}
