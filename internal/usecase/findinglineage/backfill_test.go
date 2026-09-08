package findinglineage_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityoccurrence"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFindingLineageBackfillFixtureMatrixReconcilesExactly(t *testing.T) {
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	clock, ids, audit := fixedBackfillClock{now}, &backfillIDs{}, noOpBackfillAudit{}
	snapshots := memory.NewAssessmentSnapshotRepository()
	snapshot := backfillSnapshot(t, now)
	if _, _, err := snapshots.CreateLegacyProjection(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	lineageRepository := memory.NewFindingLineageRepository()
	lineage, err := lineageuc.NewService(lineageRepository, memory.NewTenantTransactionRunner(), audit, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	occurrence := vulnerabilityoccurrence.Occurrence{
		TenantID: "tenant", ID: "occ-1", EngagementID: "assessment", AdvisoryID: "CVE-2026-1",
		ComponentID: "component", SBOMID: "sbom", ComponentFingerprint: "dependency-instance-1",
		Ecosystem: "npm", Package: "left-pad", ComponentVersion: "1.0.0",
	}
	backfillRepository := memory.NewFindingLineageBackfillRepository()
	rows := []ports.FindingLineageBackfillSourceRow{
		backfillSource("f01", finding.KindSCA, "vuln:CVE-2026-1:left-pad:1.0.0", "", "occ-1", now, snapshot),
		backfillSource("f02", finding.KindSAST, "sast:ai:missing-judgment", "sast-rule", "", now, snapshot),
		backfillSource("f03", finding.KindSAST, "cq:sast:go-sql:src/db.go:42", "go-sql", "", now, snapshot),
		backfillSource("f04", finding.KindQuality, "cq:quality:quality-todo:src/app.go:7", "quality-todo", "", now, snapshot),
		backfillSource("f05", finding.KindReliability, "cq:reliability:empty-catch:src/app.go:8", "empty-catch", "", now, snapshot),
		backfillSource("f06", finding.KindSecret, "secret:generic-secret:config/app.env:9", "generic-secret", "", now, snapshot),
		backfillSource("f07", finding.KindMisconfig, "misconfig:terraform-public-instance:main.tf:12", "terraform-public-instance", "", now, snapshot),
		backfillSource("f08", finding.KindSCA, "", "", "", now, snapshot),
		backfillSource("f09", finding.KindManual, "manual:f09", "", "", now, snapshot),
		backfillSource("f10", finding.KindExploitation, "", "", "", now, snapshot),
		backfillSource("f11", finding.KindDAST, "dast:legacy", "", "", now, snapshot),
		backfillSource("f12", finding.KindCloudPosture, "cloud:legacy", "", "", now, snapshot),
	}
	rows[0].AdvisoryID, rows[0].ComponentFingerprint = occurrence.AdvisoryID, occurrence.ComponentFingerprint
	backfillRepository.SetSources("tenant", rows)
	runner, err := lineageuc.NewFindingLineageBackfillRunner(
		lineage, backfillRepository, backfillRepository, snapshots, occurrenceBackfillStore{items: []vulnerabilityoccurrence.Occurrence{occurrence}}, emptyJudgmentStore{}, ids, clock, audit, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunBackfill(context.Background(), lineageuc.FindingLineageBackfillRequest{
		TenantID: "tenant", Actor: "operator", LeaseOwner: "worker-1", BatchSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.ProcessedCount != len(rows) || run.ProcessedCount != run.ObservationCreatedCount+run.ProvisionalCandidateCount+run.SkippedCount {
		t.Fatalf("counts do not reconcile: %+v", run)
	}
	if run.ObservationCreatedCount != 1 || run.ProvisionalCandidateCount != 9 || run.SkippedCount != 2 {
		t.Fatalf("unexpected outcome matrix: %+v", run)
	}
	observations, err := lineageRepository.ListObservationsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := lineageRepository.ListOpenCandidatesBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	skips, err := lineageRepository.ListSkipsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 10 || len(candidates) != 9 || len(skips) != 2 {
		t.Fatalf("persisted outcomes observations=%d candidates=%d skips=%d", len(observations), len(candidates), len(skips))
	}
	for _, observation := range observations {
		if observation.ProducerKind == "secret" && observation.EvidenceDigest != "" {
			t.Fatal("secret backfill persisted an evidence digest")
		}
		if observation.SourceFindingID == "f03" && observation.Location != "src/db.go:42" {
			t.Fatalf("legacy line was not retained in Observation: %+v", observation)
		}
		if observation.SourceFindingID == "f01" && observation.ComponentVersion != "1.0.0" {
			t.Fatalf("occurrence component version was not retained: %+v", observation)
		}
	}
	item, err := backfillRepository.GetFindingLineageBackfillItem(context.Background(), "tenant", run.ID, "f02")
	if err != nil || item.ReasonCode != lineageuc.BackfillReasonMissingTrustedJudgment {
		t.Fatalf("missing Judgment outcome=%+v err=%v", item, err)
	}
	replayed, err := runner.RunBackfill(context.Background(), lineageuc.FindingLineageBackfillRequest{
		TenantID: "tenant", Actor: "operator", LeaseOwner: "worker-2", BatchSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ObservationCreatedCount != run.ObservationCreatedCount || replayed.ProvisionalCandidateCount != run.ProvisionalCandidateCount || replayed.SkippedCount != run.SkippedCount {
		t.Fatalf("idempotent replay changed outcomes first=%+v replay=%+v", run, replayed)
	}
	replayedObservations, _ := lineageRepository.ListObservationsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	replayedCandidates, _ := lineageRepository.ListOpenCandidatesBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	replayedSkips, _ := lineageRepository.ListSkipsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	if len(replayedObservations) != len(observations) || len(replayedCandidates) != len(candidates) || len(replayedSkips) != len(skips) {
		t.Fatalf("idempotent replay duplicated lineage objects observations=%d candidates=%d skips=%d", len(replayedObservations), len(replayedCandidates), len(replayedSkips))
	}
}

func TestFindingLineageBackfillDryRunIsResumableAndWriteFree(t *testing.T) {
	now := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	clock, ids, audit := fixedBackfillClock{now}, &backfillIDs{}, noOpBackfillAudit{}
	snapshots := memory.NewAssessmentSnapshotRepository()
	snapshot := backfillSnapshot(t, now)
	if _, _, err := snapshots.CreateLegacyProjection(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	lineageRepository := memory.NewFindingLineageRepository()
	lineage, _ := lineageuc.NewService(lineageRepository, memory.NewTenantTransactionRunner(), audit, clock, ids, nil)
	backfillRepository := memory.NewFindingLineageBackfillRepository()
	backfillRepository.SetSources("tenant", []ports.FindingLineageBackfillSourceRow{
		backfillSource("f01", finding.KindManual, "manual:f01", "", "", now, snapshot),
		backfillSource("f02", finding.KindDAST, "dast:legacy", "", "", now, snapshot),
	})
	runner, err := lineageuc.NewFindingLineageBackfillRunner(lineage, backfillRepository, backfillRepository, snapshots, occurrenceBackfillStore{}, emptyJudgmentStore{}, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunBackfill(context.Background(), lineageuc.FindingLineageBackfillRequest{
		TenantID: "tenant", Actor: "operator", LeaseOwner: "worker-1", DryRun: true, BatchSize: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.ProcessedCount != 2 || run.ObservationCreatedCount != 1 || run.SkippedCount != 1 {
		t.Fatalf("unexpected dry-run counts: %+v", run)
	}
	observations, _ := lineageRepository.ListObservationsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	skips, _ := lineageRepository.ListSkipsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	if len(observations) != 0 || len(skips) != 0 {
		t.Fatalf("dry run wrote lineage objects observations=%d skips=%d", len(observations), len(skips))
	}
}

func TestFindingLineageBackfillRetainsAllNativeIaCFamiliesForReview(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	clock, ids, audit := fixedBackfillClock{now}, &backfillIDs{}, noOpBackfillAudit{}
	snapshots := memory.NewAssessmentSnapshotRepository()
	snapshot := backfillSnapshot(t, now)
	if _, _, err := snapshots.CreateLegacyProjection(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	repository := memory.NewFindingLineageRepository()
	lineage, err := lineageuc.NewService(repository, memory.NewTenantTransactionRunner(), audit, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewFindingLineageBackfillRepository()
	var rows []ports.FindingLineageBackfillSourceRow
	for index, test := range []struct{ rule, path string }{
		{"dockerfile-run-as-root", "Dockerfile"},
		{"compose-privileged", "compose.yaml"},
		{"gha-permissions-write-all", ".github/workflows/ci.yaml"},
		{"arm-storage-https-only-off", "azure/template.json"},
	} {
		rows = append(rows, backfillSource(shared.ID(fmt.Sprintf("iac-%d", index)), finding.KindMisconfig,
			"misconfig:"+test.rule+":"+test.path+":42", test.rule, "", now, snapshot))
	}
	store.SetSources("tenant", rows)
	runner, err := lineageuc.NewFindingLineageBackfillRunner(lineage, store, store, snapshots, occurrenceBackfillStore{}, emptyJudgmentStore{}, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunBackfill(ctx, lineageuc.FindingLineageBackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "worker", BatchSize: 2})
	if err != nil {
		t.Fatalf("scanner-supported IaC findings aborted backfill: %v", err)
	}
	if run.State != ports.FindingLineageBackfillCompleted || run.ProcessedCount != len(rows) || run.ProvisionalCandidateCount != len(rows) || run.ObservationCreatedCount != 0 || run.SkippedCount != 0 {
		t.Fatalf("scanner-supported findings were discarded or declared fully matched: %+v", run)
	}
	observations, err := repository.ListObservationsBySnapshot(ctx, "tenant", "cycle", snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := repository.ListOpenCandidatesBySnapshot(ctx, "tenant", "cycle", snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != len(rows) || len(candidates) != len(rows) {
		t.Fatalf("provisional evidence was not retained: observations=%d candidates=%d", len(observations), len(candidates))
	}
	for _, row := range rows {
		item, err := store.GetFindingLineageBackfillItem(ctx, "tenant", run.ID, row.FindingID)
		if err != nil || item.Outcome != lineageuc.BackfillOutcomeProvisionalCandidate || item.ReasonCode != "resource_identity_unavailable" {
			t.Fatalf("finding %s did not retain an explicit review outcome: item=%+v err=%v", row.FindingID, item, err)
		}
		found := false
		for _, observation := range observations {
			if observation.SourceFindingID == row.FindingID.String() {
				found = true
				if observation.ProducerKind != "iac" || observation.FindingKind != "misconfig" || !strings.HasSuffix(observation.Location, ":42") || observation.IdentityID.IsZero() {
					t.Fatalf("wrong retained observation: %+v", observation)
				}
			}
		}
		if !found {
			t.Fatalf("finding %s lost its immutable observation", row.FindingID)
		}
	}
	for _, candidate := range candidates {
		if candidate.Reason != "insufficient_anchor" {
			t.Fatalf("unsupported semantic matching must remain needs_review: %+v", candidate)
		}
	}
	replayed, err := runner.RunBackfill(ctx, lineageuc.FindingLineageBackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "replay-worker", BatchSize: 3})
	if err != nil || replayed.ProvisionalCandidateCount != len(rows) || replayed.SkippedCount != 0 {
		t.Fatalf("replay changed backfill outcomes: %+v err=%v", replayed, err)
	}
	observations, err = repository.ListObservationsBySnapshot(ctx, "tenant", "cycle", snapshot.ID)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err = repository.ListOpenCandidatesBySnapshot(ctx, "tenant", "cycle", snapshot.ID)
	if err != nil || len(observations) != len(rows) || len(candidates) != len(rows) {
		t.Fatalf("replay duplicated lineage records: observations=%d candidates=%d err=%v", len(observations), len(candidates), err)
	}
}

func TestFindingLineageBackfillRedactsMalformedSecretBeforePersistence(t *testing.T) {
	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	clock, ids, audit := fixedBackfillClock{now}, &backfillIDs{}, &recordingBackfillAudit{}
	snapshots := memory.NewAssessmentSnapshotRepository()
	snapshot := backfillSnapshot(t, now)
	if _, _, err := snapshots.CreateLegacyProjection(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	lineageRepository := memory.NewFindingLineageRepository()
	lineage, err := lineageuc.NewService(lineageRepository, memory.NewTenantTransactionRunner(), audit, clock, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	backfillRepository := memory.NewFindingLineageBackfillRepository()
	const secret = "password-do-not-persist"
	backfillRepository.SetSources("tenant", []ports.FindingLineageBackfillSourceRow{
		backfillSource("secret-malformed", finding.KindSecret, "secret:generic:https://user:"+secret+"@example.test/repo:9", "generic", "", now, snapshot),
	})
	runner, err := lineageuc.NewFindingLineageBackfillRunner(lineage, backfillRepository, backfillRepository, snapshots, occurrenceBackfillStore{}, emptyJudgmentStore{}, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunBackfill(context.Background(), lineageuc.FindingLineageBackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "worker", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	item, err := backfillRepository.GetFindingLineageBackfillItem(context.Background(), "tenant", run.ID, "secret-malformed")
	if err != nil {
		t.Fatal(err)
	}
	skips, err := lineageRepository.ListSkipsBySnapshot(context.Background(), "tenant", "cycle", snapshot.ID)
	if err != nil || len(skips) != 1 {
		t.Fatalf("skips=%+v err=%v", skips, err)
	}
	persisted := fmt.Sprint(item, skips, audit.entries)
	if strings.Contains(persisted, secret) || item.Outcome != lineageuc.BackfillOutcomeSkipped || item.ReasonCode != lineageuc.BackfillReasonMalformedTrustBoundary {
		t.Fatalf("secret redaction failed persisted=%s item=%+v", persisted, item)
	}
}

func TestFindingLineageBackfillRetriesTransientOccurrenceRead(t *testing.T) {
	now := time.Date(2026, 9, 1, 5, 0, 0, 0, time.UTC)
	clock, ids, audit := fixedBackfillClock{now}, &backfillIDs{}, noOpBackfillAudit{}
	snapshots := memory.NewAssessmentSnapshotRepository()
	snapshot := backfillSnapshot(t, now)
	if _, _, err := snapshots.CreateLegacyProjection(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	lineageRepository := memory.NewFindingLineageRepository()
	lineage, _ := lineageuc.NewService(lineageRepository, memory.NewTenantTransactionRunner(), audit, clock, ids, nil)
	backfillRepository := memory.NewFindingLineageBackfillRepository()
	source := backfillSource("retry-source", finding.KindSCA, "vuln:CVE-2026-9:left-pad:1.0.0", "", "retry-occurrence", now, snapshot)
	backfillRepository.SetSources("tenant", []ports.FindingLineageBackfillSourceRow{source})
	occurrences := &retryOccurrenceStore{item: vulnerabilityoccurrence.Occurrence{
		TenantID: "tenant", ID: "retry-occurrence", EngagementID: "assessment", AdvisoryID: "CVE-2026-9", ComponentID: "component", SBOMID: "sbom",
		ComponentFingerprint: "dependency-instance", Ecosystem: "npm", Package: "left-pad", ComponentVersion: "1.0.0",
	}}
	runner, err := lineageuc.NewFindingLineageBackfillRunner(lineage, backfillRepository, backfillRepository, snapshots, occurrences, emptyJudgmentStore{}, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.RunBackfill(context.Background(), lineageuc.FindingLineageBackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "worker", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if occurrences.attempts != 3 || run.ProvisionalCandidateCount != 1 {
		t.Fatalf("bounded retry attempts=%d run=%+v", occurrences.attempts, run)
	}
}

func backfillSnapshot(t *testing.T, now time.Time) *snapshotdom.Snapshot {
	t.Helper()
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	started := now.Add(-2 * time.Minute)
	finished := now.Add(-time.Minute)
	lane := scanrun.Lane{
		TenantID: "tenant", EngagementID: "assessment", ScanRunID: "run", LaneKey: "sca",
		Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
		AuthoritativeFindingKinds: []string{"vulnerability"}, StartedAt: now.Add(-2 * time.Minute), FinishedAt: &finished,
		ResultRef: "result:run", EvidenceRef: "evidence:run", ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: 1,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}},
		Stages:   []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: started, FinishedAt: &finished}},
		SealedAt: &now,
	}
	lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatal(err)
	}
	lanes := []scanrun.Lane{lane}
	snapshot, err := snapshotdom.NewFinalized("tenant", "snapshot", "cycle", "assessment", snapshotdom.Boundary{Kind: "standalone"}, "request", "operator", now, []snapshotdom.SelectedRun{{
		ID: "run", ManifestHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Provenance: scanrun.ProvenanceLegacy, TerminalStatus: scanrun.StatusSucceeded, Lanes: lanes,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func backfillSource(id shared.ID, kind finding.Kind, dedupKey, ruleKey string, occurrenceID shared.ID, now time.Time, snapshot *snapshotdom.Snapshot) ports.FindingLineageBackfillSourceRow {
	return ports.FindingLineageBackfillSourceRow{
		TenantID: "tenant", AssessmentID: "assessment", CycleID: "cycle", SnapshotID: snapshot.ID, SnapshotContentHash: snapshot.ContentHash, OwnershipValid: true,
		FindingID: id, Kind: kind, RuleKey: ruleKey, DedupKey: dedupKey, OccurrenceID: occurrenceID,
		Severity: shared.SeverityHigh, Reachability: "unknown", CreatedAt: now.Add(-time.Minute), ObservedAt: now.Add(-time.Minute),
	}
}

type fixedBackfillClock struct{ now time.Time }

func (clock fixedBackfillClock) Now() time.Time { return clock.now }

type backfillIDs struct{ next int }

func (ids *backfillIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("generated-%03d", ids.next))
}

type noOpBackfillAudit struct{}

func (noOpBackfillAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type recordingBackfillAudit struct{ entries []ports.AuditEntry }

func (audit *recordingBackfillAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.entries = append(audit.entries, entry)
	return nil
}

type occurrenceBackfillStore struct {
	items []vulnerabilityoccurrence.Occurrence
}

type retryOccurrenceStore struct {
	attempts int
	item     vulnerabilityoccurrence.Occurrence
}

func (store *retryOccurrenceStore) Upsert(context.Context, vulnerabilityoccurrence.Occurrence) (vulnerabilityoccurrence.UpsertResult, error) {
	return vulnerabilityoccurrence.UpsertResult{}, nil
}
func (store *retryOccurrenceStore) Get(context.Context, shared.ID, shared.ID, string, string) (vulnerabilityoccurrence.Occurrence, error) {
	store.attempts++
	if store.attempts < 3 {
		return vulnerabilityoccurrence.Occurrence{}, errors.New("temporary occurrence store outage")
	}
	return store.item, nil
}
func (store *retryOccurrenceStore) ListByEngagement(context.Context, shared.ID, shared.ID, []vulnerabilityoccurrence.State) ([]vulnerabilityoccurrence.Occurrence, error) {
	return []vulnerabilityoccurrence.Occurrence{store.item}, nil
}
func (store *retryOccurrenceStore) ListEvents(context.Context, shared.ID, shared.ID) ([]vulnerabilityoccurrence.Event, error) {
	return nil, nil
}

func (store occurrenceBackfillStore) Upsert(context.Context, vulnerabilityoccurrence.Occurrence) (vulnerabilityoccurrence.UpsertResult, error) {
	return vulnerabilityoccurrence.UpsertResult{}, nil
}
func (store occurrenceBackfillStore) Get(_ context.Context, tenantID, engagementID shared.ID, advisoryID, componentFingerprint string) (vulnerabilityoccurrence.Occurrence, error) {
	for _, item := range store.items {
		if item.TenantID == tenantID && item.EngagementID == engagementID && item.AdvisoryID == advisoryID && item.ComponentFingerprint == componentFingerprint {
			return item, nil
		}
	}
	return vulnerabilityoccurrence.Occurrence{}, shared.ErrNotFound
}
func (store occurrenceBackfillStore) ListByEngagement(_ context.Context, tenantID, engagementID shared.ID, _ []vulnerabilityoccurrence.State) ([]vulnerabilityoccurrence.Occurrence, error) {
	var out []vulnerabilityoccurrence.Occurrence
	for _, item := range store.items {
		if item.TenantID == tenantID && item.EngagementID == engagementID {
			out = append(out, item)
		}
	}
	return out, nil
}
func (store occurrenceBackfillStore) ListEvents(context.Context, shared.ID, shared.ID) ([]vulnerabilityoccurrence.Event, error) {
	return nil, nil
}

type emptyJudgmentStore struct{}

func (emptyJudgmentStore) Save(context.Context, judgment.Judgment) error { return nil }
func (emptyJudgmentStore) ListByEngagement(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return nil, nil
}
func (emptyJudgmentStore) ListBySubject(context.Context, shared.ID, shared.ID) ([]judgment.Judgment, error) {
	return nil, nil
}

type failedBackfillAudit struct{ action string }

func (a failedBackfillAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	if entry.Action == a.action {
		return errors.New("audit unavailable")
	}
	return nil
}
func TestBackfillAuditFailureStopsAndReportsRetainedCheckpoint(t *testing.T) {
	for _, action := range []string{"finding_lineage.backfill_started", "finding_lineage.backfill_batch_committed", "finding_lineage.backfill_completed"} {
		t.Run(action, func(t *testing.T) {
			now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
			ids, clock := &backfillIDs{}, fixedBackfillClock{now}
			snapshots := memory.NewAssessmentSnapshotRepository()
			snapshot := backfillSnapshot(t, now)
			if _, _, err := snapshots.CreateLegacyProjection(context.Background(), snapshot); err != nil {
				t.Fatal(err)
			}
			lineage, err := lineageuc.NewService(memory.NewFindingLineageRepository(), memory.NewTenantTransactionRunner(), noOpBackfillAudit{}, clock, ids, nil)
			if err != nil {
				t.Fatal(err)
			}
			store := memory.NewFindingLineageBackfillRepository()
			store.SetSources("tenant", []ports.FindingLineageBackfillSourceRow{backfillSource("manual", finding.KindManual, "manual:manual", "", "", now, snapshot)})
			runner, err := lineageuc.NewFindingLineageBackfillRunner(lineage, store, store, snapshots, occurrenceBackfillStore{}, emptyJudgmentStore{}, ids, clock, failedBackfillAudit{action}, nil)
			if err != nil {
				t.Fatal(err)
			}
			run, err := runner.RunBackfill(context.Background(), lineageuc.FindingLineageBackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "worker", BatchSize: 1})
			var partial *ports.PartialWriteError
			if !errors.As(err, &partial) || run.ID.IsZero() {
				t.Fatalf("audit failure hidden: run=%+v err=%v", run, err)
			}
			if action == "finding_lineage.backfill_started" && run.ProcessedCount != 0 {
				t.Fatal("backfill continued after start audit failure")
			}
			if action == "finding_lineage.backfill_batch_committed" && run.CheckpointFinding != "manual" {
				t.Fatalf("durable checkpoint lost: %+v", run)
			}
		})
	}
}
