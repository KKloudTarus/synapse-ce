package assessmentcomparison_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	lineagedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	uc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
)

func TestRetestVerificationReaderChoosesNewestDecisionAtLatestSnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	snapshots := memory.NewAssessmentSnapshotRepository()
	first := verificationSnapshot(t, "snapshot-1", "request-1", "run-1", "assessment", now)
	first, _, err := snapshots.CreateFinalizedCAS(ctx, first, 0)
	if err != nil {
		t.Fatal(err)
	}
	second := verificationSnapshot(t, "snapshot-2", "request-2", "run-2", "assessment", now.Add(time.Minute))
	second, _, err = snapshots.CreateFinalizedCAS(ctx, second, 1)
	if err != nil {
		t.Fatal(err)
	}

	lineage := memory.NewFindingLineageRepository()
	fingerprint, err := lineagedom.CanonicalizeFingerprintV1(lineagedom.FingerprintCanonicalInputV1{
		CanonicalizationVersion: lineagedom.CanonicalizationVersionV1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "repo:example", IdentityFields: map[string]lineagedom.CanonicalValue{"rule_id": lineagedom.Text("CVE-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := lineagedom.Identity{
		TenantID: "tenant", CycleID: "cycle", ID: "identity", ProducerKind: "sca", FindingKind: "vulnerability",
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: fingerprint.Fingerprint,
		TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "repo:example", CanonicalIdentityFields: fingerprint.IdentityFields,
		FirstSeenSnapshotID: first.ID, CreatedAt: now,
	}
	observation := func(id shared.ID, snapshotID shared.ID, observedAt time.Time) lineagedom.Observation {
		return lineagedom.Observation{
			TenantID: "tenant", CycleID: "cycle", ID: id, SnapshotID: snapshotID, IdentityID: identity.ID,
			ProducerKind: "sca", FindingKind: "vulnerability", TargetCanonical: "repo:example", SourceFindingID: "finding",
			Severity: shared.SeverityHigh, ScannerProvenance: lineagedom.ScannerProvenance{ToolName: "scanner"}, ObservedAt: observedAt,
		}
	}
	if err := lineage.CreateIdentityWithObservation(ctx, identity, observation("observation-1", first.ID, now)); err != nil {
		t.Fatal(err)
	}
	if err := lineage.AppendObservation(ctx, observation("observation-2", second.ID, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}

	retests := memory.NewRetestRepository()
	older, err := finding.NewRetest("retest-1", "assessment", "finding", finding.RetestStillVulnerable, "", "tester", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	newer, err := finding.NewRetest("retest-2", "assessment", "finding", finding.RetestRemediated, "", "tester", now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := retests.Add(ctx, older); err != nil {
		t.Fatal(err)
	}
	if err := retests.Add(ctx, newer); err != nil {
		t.Fatal(err)
	}

	reader, err := uc.NewRetestVerificationReader(lineage, snapshots, retests)
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := reader.ListEffectiveComparisonVerifications(ctx, "tenant", "cycle", []shared.ID{first.ID, second.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].ID != newer.ID || decisions[0].IdentityID != identity.ID || decisions[0].EffectiveSnapshotID != second.ID || !decisions[0].Remediated {
		t.Fatalf("unexpected effective verification: %+v", decisions)
	}
}

func verificationSnapshot(t *testing.T, id, requestKey, runID string, assessmentID shared.ID, now time.Time) *assessmentsnapshot.Snapshot {
	t.Helper()
	finished := now.Add(time.Second)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	lane := scanrun.Lane{
		TenantID: "tenant", EngagementID: assessmentID, ScanRunID: runID, LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
		AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"}, StartedAt: now, FinishedAt: &finished,
		ResultRef: "result:" + runID, EvidenceRef: "evidence:" + runID,
		ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, SealedAt: &finished,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}, {VersionKind: scanrun.VersionRulePack, Name: "rules", Version: "1"}},
		Stages:   []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now, FinishedAt: &finished}},
	}
	lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatal(err)
	}
	lanes := []scanrun.Lane{lane}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := assessmentsnapshot.NewFinalized("tenant", shared.ID(id), "cycle", assessmentID, assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryStandalone}, requestKey, "operator", now, []assessmentsnapshot.SelectedRun{{
		ID: runID, ManifestHash: manifestHash, Provenance: scanrun.ProvenanceNative,
		TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: lanes,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
