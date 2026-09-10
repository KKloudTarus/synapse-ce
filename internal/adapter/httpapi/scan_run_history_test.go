package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestMergeScanRunHistoryPreservesLegacyAndAddsNormalizedProvenance(t *testing.T) {
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	sealed := now.Add(time.Minute)
	legacy := []ports.ScanRun{
		{ID: "native-1", EngagementID: "eng-1", CreatedAt: now, Manifest: ports.ScanManifest{ReproScore: 100}, FindingKeys: []string{"finding-a"}},
		{ID: "legacy-1", EngagementID: "eng-1", CreatedAt: now.Add(-time.Hour), Manifest: ports.ScanManifest{ReproScore: 25}, FindingKeys: []string{"finding-old"}},
	}
	normalized := []scanrun.ScanRun{{
		TenantID: shared.ID("tenant-1"), EngagementID: shared.ID("eng-1"), ID: "native-1",
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded,
		CreatedAt: now, SealedAt: &sealed, ManifestHash: "sha256:manifest",
		Lanes: []scanrun.Lane{{LaneKey: "sca"}},
	}}

	got := mergeScanRunHistory(legacy, normalized)
	if len(got) != 2 {
		t.Fatalf("history length = %d, want 2", len(got))
	}
	if got[0].ID != "native-1" || got[0].Provenance != "native" || got[0].TerminalStatus != "succeeded" {
		t.Fatalf("normalized history = %+v", got[0])
	}
	if got[0].Manifest.ReproScore != 100 || len(got[0].FindingKeys) != 1 || got[0].LaneCount != 1 || got[0].SealedAt == nil {
		t.Fatalf("native response did not retain legacy manifest/finding keys and normalized seal data: %+v", got[0])
	}
	if got[1].ID != "legacy-1" || got[1].Provenance != "legacy" || got[1].TerminalStatus != "unknown" {
		t.Fatalf("legacy response = %+v", got[1])
	}
}

func TestScanRunHistoryRetainsExactUploadedSourceAndHidesStorageKeys(t *testing.T) {
	now := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	first := sourcepackage.Package{TenantID: "tenant", EngagementID: "initial", VersionID: "version-1", Filename: "source-v1.zip", Size: 100, SHA256: strings.Repeat("a", 64), CreatedBy: "uploader", CreatedAt: now, AssociatedBy: "uploader", AssociatedAt: now, Locator: "private-locator", ObjectKey: "private-object-key"}
	second := first
	second.EngagementID, second.VersionID, second.Filename, second.SHA256 = "retest", "version-2", "source-v2.zip", strings.Repeat("b", 64)
	runs := []ports.ScanRun{
		{ID: "initial-run", EngagementID: "initial", CreatedAt: now, Manifest: ports.ScanManifest{SourcePackage: &first}},
		{ID: "retest-run", EngagementID: "retest", CreatedAt: now.Add(time.Hour), Manifest: ports.ScanManifest{SourcePackage: &second}},
		{ID: "legacy-run", EngagementID: "initial", CreatedAt: now.Add(-time.Hour)},
	}
	views := mergeScanRunHistory(runs, []scanrun.ScanRun{{ID: "initial-run", EngagementID: "initial", Provenance: scanrun.ProvenanceNative}, {ID: "retest-run", EngagementID: "retest", Provenance: scanrun.ProvenanceNative}})
	if len(views) != 3 || views[0].SourcePackage == nil || views[1].SourcePackage == nil {
		t.Fatalf("source metadata missing from history: %+v", views)
	}
	if views[0].SourcePackage.VersionID != "version-1" || views[0].SourcePackage.Filename != "source-v1.zip" || views[1].SourcePackage.VersionID != "version-2" || views[1].SourcePackage.SHA256 == views[0].SourcePackage.SHA256 {
		t.Fatalf("historical file versions were overwritten: %+v", views)
	}
	if views[2].SourcePackage != nil || views[2].TargetKind != "" {
		t.Fatal("legacy source metadata must not be invented from a later source")
	}
	data, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-locator") || strings.Contains(string(data), "private-object-key") {
		t.Fatal("private storage location exposed in source history")
	}
	manifest, err := json.Marshal(runs[0].Manifest)
	if err != nil {
		t.Fatal(err)
	}
	nativeOnly := mergeScanRunHistory(nil, []scanrun.ScanRun{{ID: "initial-run", EngagementID: "initial", Provenance: scanrun.ProvenanceNative, LegacyManifest: manifest}})
	if len(nativeOnly) != 1 || nativeOnly[0].SourcePackage == nil || nativeOnly[0].SourcePackage.VersionID != first.VersionID {
		t.Fatalf("normalized-only history lost its own immutable source: %+v", nativeOnly)
	}
}
