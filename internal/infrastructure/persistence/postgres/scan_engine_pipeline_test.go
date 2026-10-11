package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	sca "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

func TestScanPipelinePersistsPartialSourceDeadlineEvidence(t *testing.T) {
	ctx, pool := setupScanRunTestDB(t)
	tenantID := shared.ID("pipeline-engine-tenant-" + randHex(t))
	engagementID := shared.ID("pipeline-engine-engagement-" + randHex(t))
	target := "pipeline-engine-target-" + randHex(t)
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenantID.String(), "Pipeline engine tenant"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	eng, err := engagement.New(engagementID, tenantID, "Pipeline engine coverage", "Test client", now)
	if err != nil {
		t.Fatalf("new engagement: %v", err)
	}
	if err := eng.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: target}}, nil, now); err != nil {
		t.Fatalf("set engagement scope: %v", err)
	}
	engagements := NewEngagementRepository(pool)
	if err := engagements.Create(ctx, eng); err != nil {
		t.Fatalf("create engagement: %v", err)
	}

	results := NewScanResultStore(pool)
	runs := NewScanRunStore(pool)
	svc := sca.NewService(
		engagements, nil, nil, results, nil, runs, nil, pipelineTestIDs{}, ports.Provenance{},
		pipelineTestClock{}, pipelineTestAudit{}, shared.SeverityInfo, 100*time.Millisecond,
		pipelineTestAcquirer{target: target}, pipelineTestDetector{}, pipelineTestSBOM{},
		[]ports.DetectionSource{pipelineTestSource{}}, nil, pipelineTestLicenses{}, nil,
	)
	svc.SetScanRunProvenance(runs, NewTenantTransactionRunner(pool))
	svc.SetSASTAnalyzer(pipelineDeadlineSAST{})

	tenantCtx := shared.WithTenant(ctx, tenantID)
	result, err := svc.Scan(tenantCtx, "tester", engagementID, ports.AcquireRequest{Kind: ports.TargetLocal, Value: target})
	if err != nil {
		t.Fatalf("scan with source deadline: %v", err)
	}
	assertPipelineDeadlineOutcome(t, result.EngineOutcomes)
	if result.EngineCoverage.Status != scanrun.CoveragePartial {
		t.Fatalf("returned engine coverage = %+v, want partial", result.EngineCoverage)
	}

	cached, err := results.LatestResult(tenantCtx, engagementID)
	if err != nil {
		t.Fatalf("load cached result: %v", err)
	}
	var persisted sca.ScanResult
	if err := json.Unmarshal(cached, &persisted); err != nil {
		t.Fatalf("decode cached result: %v", err)
	}
	assertPipelineDeadlineOutcome(t, persisted.EngineOutcomes)
	if persisted.EngineCoverage.Status != scanrun.CoveragePartial {
		t.Fatalf("cached engine coverage = %+v, want partial", persisted.EngineCoverage)
	}

	sealed, err := runs.ListScanRuns(tenantCtx, tenantID, engagementID)
	if err != nil {
		t.Fatalf("list sealed scan runs: %v", err)
	}
	if len(sealed) != 1 || !sealed[0].IsSealed() || sealed[0].TerminalStatus != scanrun.StatusPartial {
		t.Fatalf("sealed scan run = %+v, want one partial native record", sealed)
	}
	var lane *scanrun.Lane
	for i := range sealed[0].Lanes {
		if sealed[0].Lanes[i].LaneKey == "sast" {
			lane = &sealed[0].Lanes[i]
			break
		}
	}
	if lane == nil || lane.ManifestSchemaVersion != scanrun.CurrentManifestSchemaVersion || lane.TerminalStatus != scanrun.StatusPartial {
		t.Fatalf("sealed SAST lane = %+v", lane)
	}
	assertPipelineDeadlineOutcome(t, lane.EngineOutcomes)
	if hash, err := scanrun.ComputeRunManifestHash(sealed[0].Lanes); err != nil || hash != sealed[0].ManifestHash {
		t.Fatalf("sealed lane hash = %q, %v; want %q", hash, err, sealed[0].ManifestHash)
	}
}

func assertPipelineDeadlineOutcome(t *testing.T, outcomes []scanrun.EngineOutcome) {
	t.Helper()
	for _, outcome := range outcomes {
		if outcome.Engine == "sast" {
			if outcome.Execution != scanrun.EngineTimedOut || outcome.Coverage != scanrun.CoveragePartial || outcome.Reason != scanrun.ReasonDeadlineExceeded || !outcome.Required {
				t.Fatalf("SAST deadline outcome = %+v", outcome)
			}
			return
		}
	}
	t.Fatal("SAST outcome was not persisted")
}

type pipelineTestClock struct{}

func (pipelineTestClock) Now() time.Time { return time.Now().UTC() }

type pipelineTestIDs struct{}

func (pipelineTestIDs) NewID() shared.ID { return shared.ID("pipeline-engine-run") }

type pipelineTestAudit struct{}

func (pipelineTestAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type pipelineTestAcquirer struct{ target string }

func (a pipelineTestAcquirer) Acquire(context.Context, ports.AcquireRequest) (*ports.Workspace, error) {
	return &ports.Workspace{Dir: a.target, Commit: "e54b4a04e54b4a04e54b4a04e54b4a04e54b4a04", Cleanup: func() error { return nil }}, nil
}

type pipelineTestDetector struct{}

func (pipelineTestDetector) Detect(context.Context, string) ([]ports.DetectedLanguage, error) {
	return []ports.DetectedLanguage{{Name: "Go", Percent: 100}}, nil
}

type pipelineTestSBOM struct{}

func (pipelineTestSBOM) Generate(_ context.Context, target string) (*sbom.SBOM, error) {
	return &sbom.SBOM{TargetRef: target, Source: "test", GeneratorVersion: "test"}, nil
}

type pipelineTestSource struct{}

func (pipelineTestSource) Name() string { return "pipeline-test-source" }

func (pipelineTestSource) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, nil
}

type pipelineTestLicenses struct{}

func (pipelineTestLicenses) Scan(context.Context, *sbom.SBOM) ([]ports.LicenseFinding, error) {
	return nil, nil
}

type pipelineDeadlineSAST struct{}

func (pipelineDeadlineSAST) Name() string { return "pipeline-deadline-sast" }

func (pipelineDeadlineSAST) AnalyzeSource(ctx context.Context, _ string) ([]ports.SASTRawFinding, error) {
	<-ctx.Done()
	return nil, fmt.Errorf("source analysis: %w", ctx.Err())
}
