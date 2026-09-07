package httpapi

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
