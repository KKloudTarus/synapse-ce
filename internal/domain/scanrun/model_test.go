package scanrun_test

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestComputeManifestHash_Determinism(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	laneA := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "sast-primary",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln", "hardcoded_secret"},
		IncludedScope:             []string{"src/", "cmd/"},
		ExcludedScope:             []string{"vendor/", "test/"},
		StartedAt:                 now,
		ResultSHA256:              "result-sha-12345",
		ManifestSchemaVersion:     1,
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
			{VersionKind: scanrun.VersionRulePack, Name: "default-rules", Version: "2026.08"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "parse_ast", Status: scanrun.StageSucceeded, StartedAt: now},
			{StageKey: "eval_rules", Status: scanrun.StageSucceeded, StartedAt: now},
		},
	}

	// Lane B has identical content but with shuffled slice orders
	laneB := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "sast-primary",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"hardcoded_secret", "sast_vuln"}, // shuffled
		IncludedScope:             []string{"cmd/", "src/"},                  // shuffled
		ExcludedScope:             []string{"test/", "vendor/"},              // shuffled
		StartedAt:                 now.Add(5 * time.Minute),                  // execution timestamp does NOT affect semantic hash
		ResultSHA256:              "result-sha-12345",
		ManifestSchemaVersion:     1,
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionRulePack, Name: "default-rules", Version: "2026.08"}, // shuffled
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "eval_rules", Status: scanrun.StageSucceeded, StartedAt: now}, // shuffled
			{StageKey: "parse_ast", Status: scanrun.StageSucceeded, StartedAt: now},
		},
	}

	hashA, err := scanrun.ComputeManifestHash(laneA)
	if err != nil {
		t.Fatalf("compute hash A: %v", err)
	}
	hashB, err := scanrun.ComputeManifestHash(laneB)
	if err != nil {
		t.Fatalf("compute hash B: %v", err)
	}

	if hashA != hashB {
		t.Errorf("manifest hashes must be deterministic and invariant to slice ordering; got hashA=%q, hashB=%q", hashA, hashB)
	}
}

func TestScanRun_CompleteCoverageTrustContract(t *testing.T) {
	now := time.Now().UTC()
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	validLane := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "sast-1",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     1,
		ManifestHash:              "hash123",
		SealedAt:                  &now,
	}

	t.Run("native succeeded sealed run is complete coverage", func(t *testing.T) {
		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "run-1",
			Provenance:            scanrun.ProvenanceNative,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          "hash123",
			SealedAt:              &now,
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{validLane},
		}
		if !run.IsCompleteCoverage() {
			t.Error("expected valid native sealed run to satisfy complete coverage")
		}
	})

	t.Run("legacy run NEVER satisfies complete coverage", func(t *testing.T) {
		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "legacy-run-1",
			Provenance:            scanrun.ProvenanceLegacy,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          "hash123",
			SealedAt:              &now,
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{validLane},
		}
		if run.IsCompleteCoverage() {
			t.Error("legacy scan run must NEVER satisfy complete coverage")
		}
	})

	t.Run("partial or failed run NEVER satisfies complete coverage", func(t *testing.T) {
		for _, status := range []scanrun.TerminalStatus{scanrun.StatusPartial, scanrun.StatusFailed, scanrun.StatusCancelled, scanrun.StatusUnknown} {
			run := scanrun.ScanRun{
				TenantID:              "tenant-1",
				EngagementID:          "eng-1",
				ID:                    "run-1",
				Provenance:            scanrun.ProvenanceNative,
				TerminalStatus:        status,
				ManifestSchemaVersion: 1,
				ManifestHash:          "hash123",
				SealedAt:              &now,
				CreatedAt:             now,
				Lanes:                 []scanrun.Lane{validLane},
			}
			if run.IsCompleteCoverage() {
				t.Errorf("run with status %q must not satisfy complete coverage", status)
			}
		}
	})

	t.Run("empty authoritative finding kinds fails complete coverage", func(t *testing.T) {
		emptyKindsLane := validLane
		emptyKindsLane.AuthoritativeFindingKinds = nil

		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "run-1",
			Provenance:            scanrun.ProvenanceNative,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          "hash123",
			SealedAt:              &now,
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{emptyKindsLane},
		}
		if run.IsCompleteCoverage() {
			t.Error("run with empty authoritative finding kinds must not satisfy complete coverage")
		}
	})

	t.Run("unsealed run fails complete coverage", func(t *testing.T) {
		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "run-1",
			Provenance:            scanrun.ProvenanceNative,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          "hash123",
			SealedAt:              nil, // unsealed
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{validLane},
		}
		if run.IsCompleteCoverage() {
			t.Error("unsealed run must not satisfy complete coverage")
		}
	})
}

func TestScanRun_Validation(t *testing.T) {
	now := time.Now().UTC()
	validRun := scanrun.ScanRun{
		TenantID:       "tenant-1",
		EngagementID:   "eng-1",
		ID:             "run-1",
		Provenance:     scanrun.ProvenanceNative,
		TerminalStatus: scanrun.StatusBuilding,
		CreatedAt:      now,
	}
	if err := validRun.Validate(); err != nil {
		t.Fatalf("valid run validation error: %v", err)
	}

	invalidRuns := []struct {
		name string
		run  scanrun.ScanRun
	}{
		{"missing tenant", scanrun.ScanRun{EngagementID: "e1", ID: "r1", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, CreatedAt: now}},
		{"missing engagement", scanrun.ScanRun{TenantID: "t1", ID: "r1", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, CreatedAt: now}},
		{"missing id", scanrun.ScanRun{TenantID: "t1", EngagementID: "e1", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, CreatedAt: now}},
		{"invalid provenance", scanrun.ScanRun{TenantID: "t1", EngagementID: "e1", ID: "r1", Provenance: "invalid", TerminalStatus: scanrun.StatusBuilding, CreatedAt: now}},
		{"invalid status", scanrun.ScanRun{TenantID: "t1", EngagementID: "e1", ID: "r1", Provenance: scanrun.ProvenanceNative, TerminalStatus: "invalid", CreatedAt: now}},
		{"missing created_at", scanrun.ScanRun{TenantID: "t1", EngagementID: "e1", ID: "r1", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding}},
	}

	for _, tt := range invalidRuns {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("expected ErrValidation, got %v", err)
			}
		})
	}
}
