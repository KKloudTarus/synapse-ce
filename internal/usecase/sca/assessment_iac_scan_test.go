package sca

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	linedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/misconfig"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentlifecycle"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The fixtures are inert parser input, never deployed or executed. In particular,
// the real IaC scanner uses New() without opting into Helm or any host command.
func assessmentIaCWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"Dockerfile":               "FROM alpine:latest\nUSER root\n",
		"compose.yaml":             "services:\n  web:\n    image: nginx:latest\n    privileged: true\n",
		".github/workflows/ci.yml": "name: ci\non: pull_request\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
		"azuredeploy.json": `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"fixturestore","location":"eastus","properties":{"allowBlobPublicAccess":true,"supportsHttpsTrafficOnly":false}}]
}`,
		"main.tf":             "resource \"aws_s3_bucket\" \"fixture\" {\n  acl = \"public-read\"\n}\n",
		"cloudformation.yaml": "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  FixtureBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n",
		"pod.yaml":            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: fixture\nspec:\n  containers:\n    - name: app\n      image: nginx:latest\n      securityContext:\n        privileged: true\n",
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

type assessmentIaCAcquirer struct {
	*fakeAcquirer
	commit string
}

func (acquirer *assessmentIaCAcquirer) Acquire(ctx context.Context, request ports.AcquireRequest) (*ports.Workspace, error) {
	workspace, err := acquirer.fakeAcquirer.Acquire(ctx, request)
	if err == nil {
		workspace.Commit = acquirer.commit
	}
	return workspace, err
}

func TestAssessmentIaCMixedScanPersistsAllFamiliesAndNeverInfersFixed(t *testing.T) {
	for _, mode := range []string{"synchronous", "durable-job"} {
		t.Run(mode, func(t *testing.T) {
			ctx := shared.WithTenant(context.Background(), "iac-scan-tenant")
			clock := &fakeClock{t: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
			ids := idgen.RandomID{}
			audit := &fakeAudit{}
			transactions := memory.NewTenantTransactionRunner()
			engagements := memory.NewEngagementRepository()
			assessment, err := engdom.New("iac-assessment", "iac-scan-tenant", "Mixed IaC scan", "", clock.t)
			if err != nil {
				t.Fatal(err)
			}
			request := ports.AcquireRequest{Kind: ports.TargetGit, Value: "https://example.com/fixture/repository.git"}
			assessment.Scope.InScope = []engdom.Target{{Kind: engdom.TargetRepo, Value: request.Value}}
			if err := assessment.Transition(engdom.StatusActive, clock.t); err != nil {
				t.Fatal(err)
			}
			if err := engagements.Create(ctx, assessment); err != nil {
				t.Fatal(err)
			}
			cycles := memory.NewAssessmentCycleRepository()
			cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
			if err != nil {
				t.Fatal(err)
			}
			cycle, _, err := cycleService.CreateInitialCycle(ctx, cycleuc.CreateInitialCycleInput{TenantID: assessment.TenantID, RootAssessmentID: assessment.ID, Name: "Mixed IaC cycle", BoundaryKind: cycledom.BoundaryStandalone, Actor: "tester"})
			if err != nil {
				t.Fatal(err)
			}
			findings := memory.NewFindingRepository()
			runs := memory.NewScanRunStore()
			results := memory.NewScanResultStore()
			jobs := memory.NewScanJobStore()
			evidenceService, err := evidenceuc.NewService(&fakeEvidence{}, nil, audit, clock, ids)
			if err != nil {
				t.Fatal(err)
			}
			acquirer := &assessmentIaCAcquirer{fakeAcquirer: &fakeAcquirer{dir: assessmentIaCWorkspace(t)}, commit: strings.Repeat("a", 40)}
			scanner := misconfig.New()
			rawIaC, err := scanner.ScanConfigs(ctx, acquirer.dir)
			if err != nil || len(rawIaC) == 0 {
				t.Fatalf("fixture scan: findings=%d err=%v", len(rawIaC), err)
			}
			scaFinding := vulnerability.RawFinding{Source: "static", AdvisoryID: "CVE-2026-1234", Component: "fixture-package", Version: "1.0.0", Ecosystem: "npm", PackagePURL: "pkg:npm/fixture-package@1.0.0", Severity: shared.SeverityHigh}
			service := NewService(engagements, findings, memory.NewScanRepository(), results, jobs, runs, evidenceService, ids, ports.Provenance{}, clock, audit, shared.SeverityInfo, 0, acquirer, &fakeDetector{}, staticSBOM{doc: &sbom.SBOM{Components: []sbom.Component{{Name: scaFinding.Component, Version: scaFinding.Version, PURL: scaFinding.PackagePURL}}}}, []ports.DetectionSource{staticVuln{scaFinding}}, nil, fakeLic{}, nil)
			service.SetMisconfigScanner(scanner)
			service.SetScanRunProvenance(runs, transactions)
			snapshots := memory.NewAssessmentSnapshotRepository()
			lineageStore := memory.NewFindingLineageRepository()
			lineage, err := lineageuc.NewService(lineageStore, transactions, audit, clock, ids, nil)
			if err != nil {
				t.Fatal(err)
			}
			projector, err := lineageuc.NewShadowProjector(lineage, cycles, snapshots, findings, func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			projector.SetNativeEvidence(runs, runs)
			finalizer, err := snapshotuc.NewService(snapshots, cycles, engagements, runs, transactions, ids, clock, audit)
			if err != nil {
				t.Fatal(err)
			}
			finalizer.SetFinalizationObserver(projector)
			verification, err := comparisonuc.NewRetestVerificationReader(lineageStore, snapshots, memory.NewRetestRepository())
			if err != nil {
				t.Fatal(err)
			}
			comparisons := memory.NewAssessmentComparisonRepository()
			comparison, err := comparisonuc.NewService(comparisons, snapshots, cycles, lineageStore, transactions, audit, clock, ids, verification, nil)
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := assessmentlifecycle.NewShadowCoordinator(cycles, snapshots, finalizer, comparison, func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			service.SetScanRunObserver(coordinator)
			queue := memory.NewJobQueue(ids, clock.Now)
			if mode == "durable-job" {
				service.SetQueue(queue)
			}
			runScan := func() *ScanResult {
				t.Helper()
				if mode == "synchronous" {
					result, err := service.Scan(ctx, "tester", assessment.ID, request)
					if err != nil {
						t.Fatalf("mixed native Scan failed: %v", err)
					}
					return result
				}
				job, err := service.StartScan(ctx, "tester", assessment.ID, request)
				if err != nil {
					t.Fatal(err)
				}
				queued, err := queue.Claim(ctx, time.Minute, ScanJobKind)
				if err != nil || queued == nil {
					t.Fatalf("claim scan job: %+v err=%v", queued, err)
				}
				if err := service.RunScanJob(ctx, queued.Payload); err != nil {
					t.Fatal(err)
				}
				terminal, err := jobs.GetJob(ctx, job.ID)
				if err != nil || terminal.Status != ports.ScanSucceeded || terminal.Progress != 100 || terminal.Error != "" {
					t.Fatalf("mixed native job must succeed, not merely reach 100%%: %+v err=%v", terminal, err)
				}
				if err := queue.Complete(ctx, queued.ID, queued.Fence); err != nil {
					t.Fatal(err)
				}
				data, err := results.LatestResult(ctx, assessment.ID)
				if err != nil {
					t.Fatal(err)
				}
				var result ScanResult
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatal(err)
				}
				return &result
			}

			result := runScan()
			wantCount := len(rawIaC) + 1 // The unrelated SCA vulnerability must also survive.
			if len(result.Findings) != wantCount || len(result.Vulnerabilities) != 1 {
				t.Fatalf("pipeline lost derived findings: findings=%d want=%d vulnerabilities=%d", len(result.Findings), wantCount, len(result.Vulnerabilities))
			}
			storedFindings, err := findings.ListByEngagement(ctx, assessment.ID)
			if err != nil || len(storedFindings) != wantCount {
				t.Fatalf("persisted findings=%d want=%d err=%v", len(storedFindings), wantCount, err)
			}
			cached, err := results.LatestResult(ctx, assessment.ID)
			if err != nil {
				t.Fatal(err)
			}
			var cachedResult ScanResult
			if err := json.Unmarshal(cached, &cachedResult); err != nil || len(cachedResult.Findings) != wantCount {
				t.Fatalf("persisted scan result lost findings: count=%d err=%v", len(cachedResult.Findings), err)
			}
			baseline, _, err := snapshots.GetDefault(ctx, assessment.TenantID, assessment.ID)
			if err != nil {
				t.Fatalf("scan did not finalize its native snapshot: %v", err)
			}
			var runID string
			for _, dimension := range baseline.Dimensions {
				if dimension.Producer == "iac" {
					if dimension.State != snapshotdom.CoveragePartial {
						t.Fatalf("IaC positive findings incorrectly imply exhaustive coverage: %+v", dimension)
					}
					runID = dimension.RunID
				}
			}
			if runID == "" {
				t.Fatal("snapshot lost the IaC lane")
			}
			retainedRun, err := runs.GetScanRun(ctx, assessment.TenantID, runID)
			if err != nil || retainedRun.Provenance != scanrun.ProvenanceNative || !retainedRun.IsSealed() {
				t.Fatalf("native run is not sealed: %+v err=%v", retainedRun, err)
			}
			evidence, err := runs.GetScanRunEvidence(ctx, assessment.TenantID, runID)
			if err != nil {
				t.Fatal(err)
			}
			var native lineageuc.NativeEvidence
			if err := json.Unmarshal(evidence.Payload, &native); err != nil || len(native.Records) != wantCount {
				t.Fatalf("retained native records=%d want=%d err=%v", len(native.Records), wantCount, err)
			}
			families := []string{"dockerfile", "compose", "github_actions", "arm", "terraform", "cloudformation", "kubernetes"}
			seenFamilies := make(map[string]bool)
			for _, record := range native.Records {
				if record.ProducerKind != "iac" {
					continue
				}
				if !record.ProvisionalIdentity || record.ReviewReason != linedom.ReasonInsufficientAnchor {
					t.Fatalf("unanchored IaC observation must remain provisional for review: %+v", record)
				}
				for _, family := range families {
					if reflect.DeepEqual(record.FingerprintInput.IdentityFields["config_kind"], linedom.Text(family)) {
						seenFamilies[family] = true
					}
				}
			}
			for _, family := range families {
				if !seenFamilies[family] {
					t.Errorf("real scanner family %q is missing from immutable native evidence", family)
				}
			}
			observations, err := lineageStore.ListObservationsBySnapshot(ctx, assessment.TenantID, cycle.ID, baseline.ID)
			if err != nil || len(observations) != wantCount {
				t.Fatalf("snapshot observations=%d want=%d err=%v", len(observations), wantCount, err)
			}
			candidates, err := lineageStore.ListOpenCandidatesBySnapshot(ctx, assessment.TenantID, cycle.ID, baseline.ID)
			if err != nil || len(candidates) < len(rawIaC) {
				t.Fatalf("unanchored IaC findings lost their review candidates: count=%d want >=%d err=%v", len(candidates), len(rawIaC), err)
			}

			// Repeated positive scans must retain review in each Snapshot, even when
			// the source Finding ID and provisional fingerprint match exactly.
			for repeat := 0; repeat < 2; repeat++ {
				clock.t = clock.t.Add(time.Minute)
				runScan()
				next, _, err := snapshots.GetDefault(ctx, assessment.TenantID, assessment.ID)
				if err != nil || next.ID == baseline.ID {
					t.Fatalf("repeat scan did not advance its snapshot: err=%v", err)
				}
				candidates, err := lineageStore.ListOpenCandidatesBySnapshot(ctx, assessment.TenantID, cycle.ID, next.ID)
				if err != nil || len(candidates) < len(rawIaC) {
					t.Fatalf("repeat scan lost provisional review: count=%d want >=%d err=%v", len(candidates), len(rawIaC), err)
				}
				queued, _, _, err := comparison.Queue(ctx, comparisonuc.QueueInput{
					TenantID: assessment.TenantID, BaselineSnapshotID: baseline.ID, CurrentSnapshotID: next.ID,
					Mode: cmpdom.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: comparisonuc.RiskModelVersionV1, Actor: "tester",
				})
				if err != nil {
					t.Fatal(err)
				}
				generated, err := comparison.Generate(ctx, comparisonuc.WorkInput{TenantID: assessment.TenantID, ComparisonID: queued.ID, Actor: "worker"})
				if err != nil {
					t.Fatal(err)
				}
				iacItems := 0
				for _, item := range generated.Items {
					if item.ProducerKind != "iac" {
						continue
					}
					iacItems++
					if item.Presence != cmpdom.PresenceNeedsReview || item.ComparableBaseline || item.FixedBasis != "" {
						t.Errorf("repeated provisional finding became definitive: %+v", item)
					}
				}
				if iacItems != len(rawIaC) {
					t.Fatalf("repeat comparison lost IaC observations: count=%d want=%d", iacItems, len(rawIaC))
				}
				baseline = next
			}

			// Removing config files establishes no exhaustive IaC coverage. The full
			// comparison pipeline must never classify that absence as remediation.
			clock.t = clock.t.Add(time.Minute)
			acquirer.dir, acquirer.commit = t.TempDir(), strings.Repeat("b", 40)
			current := runScan()
			for _, item := range current.Findings {
				if item.Kind == finding.KindMisconfig {
					t.Fatalf("empty scan unexpectedly retained a removed IaC finding: %s", item.ID)
				}
			}
			finalSnapshot, _, err := snapshots.GetDefault(ctx, assessment.TenantID, assessment.ID)
			if err != nil {
				t.Fatal(err)
			}
			queued, created, _, err := comparison.Queue(ctx, comparisonuc.QueueInput{
				TenantID: assessment.TenantID, BaselineSnapshotID: baseline.ID, CurrentSnapshotID: finalSnapshot.ID,
				Mode: cmpdom.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: comparisonuc.RiskModelVersionV1, Actor: "tester",
			})
			if err != nil || created {
				t.Fatalf("empty scan did not auto-queue its comparison: created=%t err=%v", created, err)
			}
			generated, err := comparison.Generate(ctx, comparisonuc.WorkInput{TenantID: assessment.TenantID, ComparisonID: queued.ID, Actor: "worker"})
			if err != nil {
				t.Fatal(err)
			}
			iacItems := 0
			for _, item := range generated.Items {
				if item.ProducerKind != "iac" {
					continue
				}
				iacItems++
				if item.Presence != cmpdom.PresenceNeedsReview && item.Presence != cmpdom.PresenceNotEvaluated {
					t.Errorf("IaC absence falsely resolved: presence=%s fixed_basis=%s", item.Presence, item.FixedBasis)
				}
				if item.FixedBasis != "" || item.ComparableBaseline {
					t.Errorf("partial IaC evidence counted as Fixed: %+v", item)
				}
			}
			if iacItems != len(rawIaC) {
				t.Fatalf("comparison lost IaC observations: count=%d want=%d", iacItems, len(rawIaC))
			}
		})
	}
}
