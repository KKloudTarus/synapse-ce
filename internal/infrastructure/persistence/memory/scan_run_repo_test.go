package memory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanRunStoreTenantSealingAndIdempotency(t *testing.T) {
	store := NewScanRunStore()
	run := testNativeScanRun(t, "tenant-a", "run-1", "eng-1")
	if err := store.Begin(context.Background(), beginningScanRun(run)); err != nil {
		t.Fatal(err)
	}
	differentStart := beginningScanRun(run)
	differentStart.CreatedAt = differentStart.CreatedAt.Add(time.Second)
	if err := store.Begin(context.Background(), differentStart); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("changed begin timestamp = %v", err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, time.Unix(2, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := store.Seal(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if err := store.Seal(context.Background(), run); err != nil {
		t.Fatalf("idempotent seal: %v", err)
	}
	if _, err := store.Get(context.Background(), "tenant-b", run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get = %v", err)
	}
	got, err := store.Get(context.Background(), "tenant-a", run.ID)
	if err != nil || got.ManifestHash != run.ManifestHash || len(got.Lanes) != 1 {
		t.Fatalf("stored run = %+v, %v", got, err)
	}
	run.Manifest.SBOMSHA256 = strings.Repeat("c", 64)
	if err := store.Seal(context.Background(), run); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered seal = %v", err)
	}
}

func beginningScanRun(run ports.ScanRun) ports.ScanRun {
	run.Manifest = ports.ScanManifest{}
	run.FindingKeys = nil
	run.Lanes = nil
	return run
}

func testNativeScanRun(t *testing.T, tenantID, runID, engagementID string) ports.ScanRun {
	t.Helper()
	started := time.Unix(1, 0).UTC()
	finished := time.Unix(2, 0).UTC()
	target, err := scanrun.CanonicalTarget(scanrun.TargetInput{Kind: scanrun.TargetRepository, Raw: "https://github.com/org/repo", EvaluatedRevision: strings.Repeat("a", 40), SchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	return ports.ScanRun{
		TenantID: tenantID, ID: runID, EngagementID: engagementID, CreatedAt: started,
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
		Manifest: ports.ScanManifest{SBOMSHA256: strings.Repeat("b", 64)}, FindingKeys: []string{"finding-1"},
		Lanes: []scanrun.Lane{{
			Key: "sca", Producer: "synapse-sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
			AuthoritativeFindingKinds: []string{"sca"}, StartedAt: started, FinishedAt: &finished,
			ResultRef: "scan-result/run-1", EvidenceRef: "evidence-1", ResultSHA256: strings.Repeat("b", 64), ManifestSchemaVersion: 1,
			Versions: []scanrun.Version{{Kind: scanrun.VersionTool, Name: "synapse", Version: "v1"}},
			Stages:   []scanrun.Stage{{Key: "pipeline", Status: scanrun.StageSucceeded}},
		}},
	}
}
