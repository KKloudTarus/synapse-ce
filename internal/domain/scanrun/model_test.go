package scanrun_test

import (
	"errors"
	"math/rand"
	"strings"
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

func TestComputeManifestHash_RandomizedPermutations(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	baseLane := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "sast-primary",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln", "hardcoded_secret", "iac_misconfig", "dependency_vuln"},
		IncludedScope:             []string{"src/", "cmd/", "pkg/", "internal/"},
		ExcludedScope:             []string{"vendor/", "test/", "docs/", "build/"},
		StartedAt:                 now,
		ResultSHA256:              "result-sha-12345",
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
		Versions: []scanrun.LaneVersion{
			{VersionKind: scanrun.VersionScanner, Name: "semgrep", Version: "1.45.0"},
			{VersionKind: scanrun.VersionRulePack, Name: "default-rules", Version: "2026.08"},
			{VersionKind: scanrun.VersionTool, Name: "synapse-engine", Version: "2.1.0"},
			{VersionKind: scanrun.VersionProfile, Name: "pci-dss", Version: "4.0"},
		},
		Stages: []scanrun.LaneStage{
			{StageKey: "parse_ast", Status: scanrun.StageSucceeded, StartedAt: now},
			{StageKey: "eval_rules", Status: scanrun.StageSucceeded, StartedAt: now},
			{StageKey: "filter_findings", Status: scanrun.StageSucceeded, StartedAt: now},
		},
	}

	canonicalHash, err := scanrun.ComputeManifestHash(baseLane)
	if err != nil {
		t.Fatalf("compute base hash: %v", err)
	}

	rng := rand.New(rand.NewSource(0x708))

	// Run 50 deterministic seeded random permutations
	for i := 0; i < 50; i++ {
		permutedLane := baseLane

		// Shuffle finding kinds
		fk := append([]string(nil), baseLane.AuthoritativeFindingKinds...)
		rng.Shuffle(len(fk), func(a, b int) { fk[a], fk[b] = fk[b], fk[a] })
		permutedLane.AuthoritativeFindingKinds = fk

		// Shuffle scopes
		inc := append([]string(nil), baseLane.IncludedScope...)
		rng.Shuffle(len(inc), func(a, b int) { inc[a], inc[b] = inc[b], inc[a] })
		permutedLane.IncludedScope = inc

		exc := append([]string(nil), baseLane.ExcludedScope...)
		rng.Shuffle(len(exc), func(a, b int) { exc[a], exc[b] = exc[b], exc[a] })
		permutedLane.ExcludedScope = exc

		// Shuffle versions
		vers := append([]scanrun.LaneVersion(nil), baseLane.Versions...)
		rng.Shuffle(len(vers), func(a, b int) { vers[a], vers[b] = vers[b], vers[a] })
		permutedLane.Versions = vers

		// Shuffle stages
		stg := append([]scanrun.LaneStage(nil), baseLane.Stages...)
		rng.Shuffle(len(stg), func(a, b int) { stg[a], stg[b] = stg[b], stg[a] })
		permutedLane.Stages = stg

		h, err := scanrun.ComputeManifestHash(permutedLane)
		if err != nil {
			t.Fatalf("iteration %d: compute hash: %v", i, err)
		}
		if h != canonicalHash {
			t.Fatalf("iteration %d: hash mismatch: got %q, want %q", i, h, canonicalHash)
		}
	}
}

func TestComputeManifestHash_LaneKeyAndStatusSensitivity(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	base := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "sast-primary",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
	}

	baseHash, err := scanrun.ComputeManifestHash(base)
	if err != nil {
		t.Fatalf("compute base hash: %v", err)
	}

	// 1. Changing LaneKey MUST produce a different hash
	diffLaneKey := base
	diffLaneKey.LaneKey = "sast-secondary"
	diffLaneKeyHash, err := scanrun.ComputeManifestHash(diffLaneKey)
	if err != nil {
		t.Fatalf("compute diffLaneKey hash: %v", err)
	}
	if diffLaneKeyHash == baseHash {
		t.Errorf("changing LaneKey must produce different manifest hash; got identical %q", baseHash)
	}

	// 2. Changing TerminalStatus MUST produce a different hash
	diffStatus := base
	diffStatus.TerminalStatus = scanrun.StatusFailed
	diffStatusHash, err := scanrun.ComputeManifestHash(diffStatus)
	if err != nil {
		t.Fatalf("compute diffStatus hash: %v", err)
	}
	if diffStatusHash == baseHash {
		t.Errorf("changing TerminalStatus must produce different manifest hash; got identical %q", baseHash)
	}
}

func TestComputeManifestHash_StageTimeZoneAndPrecisionInvariance(t *testing.T) {
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	instant := time.Date(2026, 8, 31, 10, 0, 0, 123456789, time.UTC)
	finished := instant.Add(time.Second)
	base := scanrun.Lane{
		LaneKey:        "sast-primary",
		Producer:       "synapse-sast",
		TerminalStatus: scanrun.StatusSucceeded,
		Target:         target,
		Stages: []scanrun.LaneStage{{
			StageKey: "scan", Status: scanrun.StageSucceeded,
			StartedAt: instant, FinishedAt: &finished,
		}},
	}

	canonicalHash, err := scanrun.ComputeManifestHash(base)
	if err != nil {
		t.Fatal(err)
	}

	zone := time.FixedZone("UTC+7", 7*60*60)
	zoneEquivalent := base
	zoneFinished := finished.In(zone)
	zoneEquivalent.Stages = []scanrun.LaneStage{{
		StageKey: "scan", Status: scanrun.StageSucceeded,
		StartedAt: instant.In(zone), FinishedAt: &zoneFinished,
	}}
	zoneHash, err := scanrun.ComputeManifestHash(zoneEquivalent)
	if err != nil {
		t.Fatal(err)
	}

	precisionEquivalent := base
	precisionStarted := instant.Truncate(time.Microsecond)
	precisionFinished := finished.Truncate(time.Microsecond)
	precisionEquivalent.Stages = []scanrun.LaneStage{{
		StageKey: "scan", Status: scanrun.StageSucceeded,
		StartedAt: precisionStarted, FinishedAt: &precisionFinished,
	}}
	precisionHash, err := scanrun.ComputeManifestHash(precisionEquivalent)
	if err != nil {
		t.Fatal(err)
	}

	if zoneHash != canonicalHash || precisionHash != canonicalHash {
		t.Fatalf("equivalent stage times must hash identically: canonical=%s zone=%s precision=%s", canonicalHash, zoneHash, precisionHash)
	}
}

func TestComputeRunManifestHash_OrderInvariance(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")

	laneA := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "lane-a",
		Producer:                  "synapse-sast",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"sast_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
	}

	laneB := scanrun.Lane{
		TenantID:                  "tenant-1",
		EngagementID:              "eng-1",
		ScanRunID:                 "run-1",
		LaneKey:                   "lane-b",
		Producer:                  "synapse-sca",
		TerminalStatus:            scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"dep_vuln"},
		StartedAt:                 now,
		ManifestSchemaVersion:     scanrun.CurrentManifestSchemaVersion,
	}

	sliceAB := []scanrun.Lane{laneA, laneB}
	sliceBA := []scanrun.Lane{laneB, laneA}

	hashAB, err := scanrun.ComputeRunManifestHash(sliceAB)
	if err != nil {
		t.Fatalf("compute hash AB: %v", err)
	}

	hashBA, err := scanrun.ComputeRunManifestHash(sliceBA)
	if err != nil {
		t.Fatalf("compute hash BA: %v", err)
	}

	if hashAB != hashBA {
		t.Fatalf("ComputeRunManifestHash must be invariant to slice order; got hashAB=%q, hashBA=%q", hashAB, hashBA)
	}

	// Assert caller input slices were NOT mutated
	if sliceAB[0].LaneKey != "lane-a" || sliceAB[1].LaneKey != "lane-b" {
		t.Errorf("sliceAB was mutated: got [%s, %s]", sliceAB[0].LaneKey, sliceAB[1].LaneKey)
	}
	if sliceBA[0].LaneKey != "lane-b" || sliceBA[1].LaneKey != "lane-a" {
		t.Errorf("sliceBA was mutated: got [%s, %s]", sliceBA[0].LaneKey, sliceBA[1].LaneKey)
	}
}

func TestComputeRunManifestHash_RejectsUnverifiedLaneHash(t *testing.T) {
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	lane := scanrun.Lane{
		LaneKey: "lane-a", Producer: "synapse-sast", TerminalStatus: scanrun.StatusSucceeded,
		Target: target, ManifestHash: strings.Repeat("0", 64),
	}
	if _, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{lane}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unverified lane hash accepted: %v", err)
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
		SealedAt:                  &now,
	}
	validLane.ManifestHash, _ = scanrun.ComputeManifestHash(validLane)
	validRunHash, _ := scanrun.ComputeRunManifestHash([]scanrun.Lane{validLane})

	t.Run("native succeeded sealed run is complete coverage", func(t *testing.T) {
		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "run-1",
			Provenance:            scanrun.ProvenanceNative,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          validRunHash,
			SealedAt:              &now,
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{validLane},
		}
		if !run.IsCompleteCoverage() {
			t.Error("expected valid native sealed run to satisfy complete coverage")
		}
	})

	t.Run("zero lanes fails complete coverage", func(t *testing.T) {
		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "run-1",
			Provenance:            scanrun.ProvenanceNative,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          validRunHash,
			SealedAt:              &now,
			CreatedAt:             now,
			Lanes:                 nil, // zero lanes
		}
		if run.IsCompleteCoverage() {
			t.Error("zero lanes run must not satisfy complete coverage")
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
			ManifestHash:          validRunHash,
			SealedAt:              &now,
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{validLane},
		}
		if run.IsCompleteCoverage() {
			t.Error("legacy scan run must NEVER satisfy complete coverage")
		}
	})

	t.Run("partial or failed run NEVER satisfies complete coverage", func(t *testing.T) {
		for _, status := range []scanrun.TerminalStatus{scanrun.StatusBuilding, scanrun.StatusPartial, scanrun.StatusFailed, scanrun.StatusCancelled, scanrun.StatusUnknown} {
			run := scanrun.ScanRun{
				TenantID:              "tenant-1",
				EngagementID:          "eng-1",
				ID:                    "run-1",
				Provenance:            scanrun.ProvenanceNative,
				TerminalStatus:        status,
				ManifestSchemaVersion: 1,
				ManifestHash:          validRunHash,
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
		emptyKindsLane.ManifestHash, _ = scanrun.ComputeManifestHash(emptyKindsLane)
		emptyKindsRunHash, _ := scanrun.ComputeRunManifestHash([]scanrun.Lane{emptyKindsLane})

		run := scanrun.ScanRun{
			TenantID:              "tenant-1",
			EngagementID:          "eng-1",
			ID:                    "run-1",
			Provenance:            scanrun.ProvenanceNative,
			TerminalStatus:        scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1,
			ManifestHash:          emptyKindsRunHash,
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
			ManifestHash:          validRunHash,
			SealedAt:              nil, // unsealed
			CreatedAt:             now,
			Lanes:                 []scanrun.Lane{validLane},
		}
		if run.IsCompleteCoverage() {
			t.Error("unsealed run must not satisfy complete coverage")
		}
	})

	t.Run("tampered lane facts fail complete coverage", func(t *testing.T) {
		tampered := validLane
		tampered.Producer = "different-producer"
		run := scanrun.ScanRun{
			TenantID: "tenant-1", EngagementID: "eng-1", ID: "run-1",
			Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1, ManifestHash: validRunHash, SealedAt: &now,
			CreatedAt: now, Lanes: []scanrun.Lane{tampered},
		}
		if run.IsCompleteCoverage() {
			t.Error("tampered lane facts must not satisfy complete coverage")
		}
	})

	t.Run("failed pipeline stage fails complete coverage", func(t *testing.T) {
		failedStageLane := validLane
		failedStageLane.Stages = []scanrun.LaneStage{{
			StageKey: "scan", Status: scanrun.StageFailed, StartedAt: now,
		}}
		failedStageLane.ManifestHash, _ = scanrun.ComputeManifestHash(failedStageLane)
		failedStageRunHash, _ := scanrun.ComputeRunManifestHash([]scanrun.Lane{failedStageLane})
		run := scanrun.ScanRun{
			TenantID: "tenant-1", EngagementID: "eng-1", ID: "run-1",
			Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded,
			ManifestSchemaVersion: 1, ManifestHash: failedStageRunHash, SealedAt: &now,
			CreatedAt: now, Lanes: []scanrun.Lane{failedStageLane},
		}
		if run.IsCompleteCoverage() {
			t.Error("failed pipeline stage must not satisfy complete coverage")
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
		{"invalid manifest hash", scanrun.ScanRun{TenantID: "t1", EngagementID: "e1", ID: "r1", Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, ManifestHash: "not-a-sha256", CreatedAt: now}},
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

func TestLaneValidationRejectsUnboundedAndMalformedAttestationFields(t *testing.T) {
	now := time.Now().UTC()
	target, _ := scanrun.CanonicalizeRepositoryTarget("https://github.com/org/repo", "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04")
	base := scanrun.Lane{
		TenantID: "t1", EngagementID: "e1", ScanRunID: "r1", LaneKey: "lane",
		Producer: "producer", TerminalStatus: scanrun.StatusSucceeded, Target: target,
		StartedAt: now, ManifestSchemaVersion: 1,
	}

	invalidDigest := base
	invalidDigest.ResultSHA256 = "not-a-sha256"
	if err := invalidDigest.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("malformed result digest accepted: %v", err)
	}

	oversizedRef := base
	oversizedRef.EvidenceRef = strings.Repeat("x", 4097)
	if err := oversizedRef.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized evidence reference accepted: %v", err)
	}
}
