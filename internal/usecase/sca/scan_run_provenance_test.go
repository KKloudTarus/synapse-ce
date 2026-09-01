package sca

import (
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestNativeSCALaneDerivesCoverageFactsAndRedactsScope(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	item := engagementWithScope(t, "https://github.com/Org/Repo.git")
	item.Scope.OutOfScope = []engdom.Target{{Kind: engdom.TargetURL, Value: "https://user:pass@example.com/private?token=secret&region=us"}}
	result := &ScanResult{
		Target: "https://github.com/Org/Repo.git", SourceCommit: strings.Repeat("a", 40), ScanMode: ScanModeFull,
		Manifest:     ports.ScanManifest{ToolVersions: map[string]string{"synapse": "v1"}, CorrelationVersion: 2, SBOMSHA256: strings.Repeat("b", 64)},
		Findings:     []finding.Finding{{Kind: finding.KindSecret, DedupKey: "secret:1"}},
		Completeness: ports.Completeness{Confident: true}, ReproDigest: strings.Repeat("c", 64),
		DebugEvents: []ports.ScanDebugEvent{{Step: "scan", Status: ports.ScanDebugSucceeded, StartedAt: now}},
	}
	lane, status, err := nativeSCALane(item, "run-1", now, ports.AcquireRequest{Kind: ports.TargetGit, Value: result.Target}, result, "evidence-1", "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if status != scanrun.StatusSucceeded || lane.Target.Canonical != "https://github.com/Org/Repo" || lane.Target.EvaluatedRevision != strings.Repeat("a", 40) {
		t.Fatalf("lane target/status = %+v %s", lane.Target, status)
	}
	if len(lane.Versions) < 2 || len(lane.Stages) != 1 || !containsString(lane.AuthoritativeFindingKinds, "secret") || !containsString(lane.AuthoritativeFindingKinds, "sca") {
		t.Fatalf("derived facts = %+v", lane)
	}
	if joined := strings.Join(lane.ExcludedScope, " "); strings.Contains(joined, "secret") || strings.Contains(joined, "pass") || !strings.Contains(joined, "region=us") {
		t.Fatalf("scope was not redacted/canonicalized: %s", joined)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
