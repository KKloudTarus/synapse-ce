package sca

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	linedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type nativeEvidenceAudit struct{ err error }

func (a *nativeEvidenceAudit) Record(context.Context, ports.AuditEntry) error { return a.err }

func TestNativeAssessmentEvidenceUsesFrozenRunNotMutableFindings(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "native-tenant")
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	clock := fakeClock{t: now.Add(time.Minute)}
	tx := memory.NewTenantTransactionRunner()
	engagements := memory.NewEngagementRepository()
	assessment, _ := engdom.New("assessment", "native-tenant", "Native scan", "", now)
	if err := engagements.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	cycles := memory.NewAssessmentCycleRepository()
	audit := &nativeEvidenceAudit{}
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, tx, idgen.RandomID{}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	cycle, _, err := cycleService.CreateInitialCycle(ctx, cycleuc.CreateInitialCycleInput{TenantID: assessment.TenantID, RootAssessmentID: assessment.ID, Name: "Native cycle", BoundaryKind: cycledom.BoundaryStandalone, Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	runs := memory.NewScanRunStore()
	service := &Service{engagements: engagements, runs: runs, runProvenance: runs, scanRunTransactions: tx, clock: clock, audit: audit}
	v := vulnerability.Vulnerability{ID: "CVE-2026-1234", Component: "example", Version: "1.0.0", Ecosystem: "npm", PackagePURL: "pkg:npm/example@1.0.0", Path: []string{"pkg:npm/root@1.0.0", "pkg:npm/example@1.0.0"}, Severity: shared.SeverityHigh}
	item := finding.Finding{ID: "finding", EngagementID: assessment.ID, Kind: finding.KindSCA, Severity: shared.SeverityHigh, DedupKey: vulnDedupKey(v), Title: "secret text must not enter retained evidence", Audit: shared.Audit{CreatedAt: now}}
	result := &ScanResult{Target: "https://github.com/example/repo", SourceCommit: strings.Repeat("a", 40), ScanMode: ScanModeVulnerabilities, Findings: []finding.Finding{item}, Vulnerabilities: []vulnerability.Vulnerability{v}, ReproDigest: strings.Repeat("b", 64), Completeness: ports.Completeness{Confident: true}, Manifest: ports.ScanManifest{ToolVersions: map[string]string{"scanner": "1.0"}}}
	runID, err := service.persistAssessmentScanRun(ctx, assessment.ID, "native-run", now, ports.AcquireRequest{Value: result.Target}, result, "")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := runs.GetScanRunEvidence(ctx, assessment.TenantID, runID.String())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evidence.Payload), item.Title) {
		t.Fatal("raw finding text leaked into comparison evidence")
	}
	var retained lineageuc.NativeEvidence
	if err := json.Unmarshal(evidence.Payload, &retained); err != nil {
		t.Fatal(err)
	}
	if len(retained.Records) != 1 {
		t.Fatalf("retained %d observations", len(retained.Records))
	}
	fingerprint, err := linedom.CanonicalizeFingerprintV1(retained.Records[0].FingerprintInput)
	if err != nil || fingerprint.Fingerprint == "" {
		t.Fatalf("retained fingerprint invalid: %v", err)
	}
	findings := memory.NewFindingRepository()
	item.Severity = shared.SeverityLow
	if err := findings.Upsert(ctx, []finding.Finding{item}); err != nil {
		t.Fatal(err)
	}
	snapshots := memory.NewAssessmentSnapshotRepository()
	lineageStore := memory.NewFindingLineageRepository()
	lineage, err := lineageuc.NewService(lineageStore, tx, audit, clock, idgen.RandomID{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	projector, err := lineageuc.NewShadowProjector(lineage, cycles, snapshots, findings, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	projector.SetNativeEvidence(runs, runs)
	finalizer, err := snapshotuc.NewService(snapshots, cycles, engagements, runs, tx, idgen.RandomID{}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	finalizer.SetFinalizationObserver(projector)
	snapshot, _, err := finalizer.Finalize(ctx, snapshotuc.FinalizeInput{TenantID: assessment.TenantID, CycleID: cycle.ID, AssessmentID: assessment.ID, SelectedRunIDs: []string{runID.String()}, RequestKey: "snapshot", Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	observations, err := lineageStore.ListObservationsBySnapshot(ctx, assessment.TenantID, cycle.ID, snapshot.ID)
	if err != nil || len(observations) != 1 || observations[0].Severity != shared.SeverityHigh {
		t.Fatalf("snapshot used mutable current rows: %+v err=%v", observations, err)
	}
	if observations[0].EvidenceDigest != evidence.ContentHash {
		t.Fatal("observation not bound to sealed evidence")
	}
	if _, err := runs.GetScanRunEvidence(ctx, "other-tenant", runID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross tenant read=%v", err)
	}

	verification, err := comparisonuc.NewRetestVerificationReader(lineageStore, snapshots, memory.NewRetestRepository())
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := comparisonuc.NewService(memory.NewAssessmentComparisonRepository(), snapshots, cycles, lineageStore, tx, audit, clock, idgen.RandomID{}, verification, nil)
	if err != nil {
		t.Fatal(err)
	}
	expectedVersion := int64(1)
	for index, scenario := range []struct {
		name      string
		empty     bool
		confident bool
		want      cmpdom.Presence
	}{
		{"upgraded-version", false, true, cmpdom.PresenceDetected},
		{"partial-empty", true, false, cmpdom.PresenceNotEvaluated},
		{"complete-empty", true, true, cmpdom.PresenceNotDetected},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			nextClock := fakeClock{t: now.Add(time.Duration(index+3) * time.Minute)}
			service.clock = nextClock
			next := *result
			next.Completeness = ports.Completeness{Confident: scenario.confident}
			if scenario.empty {
				next.Findings = nil
				next.Vulnerabilities = nil
			} else {
				upgraded := v
				upgraded.Version, upgraded.PackagePURL = "2.0.0", "pkg:npm/example@2.0.0"
				upgraded.Path = []string{"pkg:npm/root@2.0.0", "pkg:npm/example@2.0.0"}
				found := item
				found.ID, found.DedupKey = "upgraded-finding", vulnDedupKey(upgraded)
				next.Findings, next.Vulnerabilities = []finding.Finding{found}, []vulnerability.Vulnerability{upgraded}
			}
			nextID, err := service.persistAssessmentScanRun(ctx, assessment.ID, shared.ID(scenario.name), nextClock.t.Add(-time.Second), ports.AcquireRequest{Value: result.Target}, &next, "")
			if err != nil {
				t.Fatal(err)
			}
			finalizer, err := snapshotuc.NewService(snapshots, cycles, engagements, runs, tx, idgen.RandomID{}, nextClock, audit)
			if err != nil {
				t.Fatal(err)
			}
			finalizer.SetFinalizationObserver(projector)
			current, _, err := finalizer.Finalize(ctx, snapshotuc.FinalizeInput{TenantID: assessment.TenantID, CycleID: cycle.ID, AssessmentID: assessment.ID, SelectedRunIDs: []string{nextID.String()}, RequestKey: scenario.name, ExpectedDefaultVersion: expectedVersion, Actor: "tester"})
			if err != nil {
				t.Fatal(err)
			}
			expectedVersion++
			captured, err := lineageStore.ListObservationsBySnapshot(ctx, assessment.TenantID, cycle.ID, current.ID)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.empty && len(captured) != 0 {
				t.Fatal("empty run copied previous evidence")
			}
			if !scenario.empty && (len(captured) != 1 || captured[0].IdentityID != observations[0].IdentityID || captured[0].ComponentVersion != "2.0.0") {
				t.Fatalf("version upgrade forked identity: %+v", captured)
			}
			queued, _, decision, err := comparison.Queue(ctx, comparisonuc.QueueInput{TenantID: assessment.TenantID, BaselineSnapshotID: snapshot.ID, CurrentSnapshotID: current.ID, Mode: cmpdom.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1, Actor: "tester"})
			if err != nil || !decision.Allowed {
				t.Fatalf("queue decision=%+v err=%v", decision, err)
			}
			generated, err := comparison.Generate(ctx, comparisonuc.WorkInput{TenantID: assessment.TenantID, ComparisonID: queued.ID, Actor: "worker"})
			if err != nil || len(generated.Items) != 1 || generated.Items[0].Presence != scenario.want {
				t.Fatalf("presence=%+v err=%v", generated.Items, err)
			}
		})
	}
	audit.err = errors.New("audit unavailable")
	if _, err := service.persistAssessmentScanRun(ctx, assessment.ID, "failed-run", now, ports.AcquireRequest{Value: result.Target}, result, ""); err == nil {
		t.Fatal("audit failure ignored")
	}
	if _, err := runs.GetScanRun(ctx, assessment.TenantID, "failed-run"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("run survived transaction failure: %v", err)
	}
	if _, err := runs.GetScanRunEvidence(ctx, assessment.TenantID, "failed-run"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("evidence survived transaction failure: %v", err)
	}
}
