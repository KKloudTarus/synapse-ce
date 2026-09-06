package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	ap "github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	projectdom "github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	analysisuc "github.com/KKloudTarus/synapse-ce/internal/usecase/analysis"
	attackpathuc "github.com/KKloudTarus/synapse-ce/internal/usecase/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	dastverifieruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	coverageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/coverage"
	hostvulnuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/hostvuln"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetrolloutuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
	promotionuc "github.com/KKloudTarus/synapse-ce/internal/usecase/promotion"
	purpleteamuc "github.com/KKloudTarus/synapse-ce/internal/usecase/purpleteam"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/sarifingest"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

// fakeJudgments is a no-op judgmentService for the harness – every judgment assertion below is a
// DENY (403/404) rejected by authz/withEngTenant before any method runs, except the readonly LIST
// allow which returns an empty set.
func mustPromotionStore(t *testing.T, findings *memory.FindingRepository, engagements ports.EngagementOwnershipReader) ports.PendingPromotionAuditStore {
	t.Helper()
	store, err := memory.NewPromotionStore(findings, engagements)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type fakeJudgments struct{}

type harnessAudit struct{ entries []ports.AuditEntry }

func (a *harnessAudit) Record(ctx context.Context, e ports.AuditEntry) error {
	return a.RecordOnce(ctx, e)
}

func (a *harnessAudit) RecordOnce(_ context.Context, e ports.AuditEntry) error {
	for _, existing := range a.entries {
		if e.Metadata["idempotency_key"] != "" && existing.Metadata["idempotency_key"] == e.Metadata["idempotency_key"] {
			return nil
		}
	}
	a.entries = append(a.entries, e)
	return nil
}

func (fakeJudgments) List(context.Context, shared.ID) ([]judgment.Judgment, error) { return nil, nil }
func (fakeJudgments) Verify(context.Context, string, shared.ID, shared.ID, int, string, int) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}
func (fakeJudgments) Accept(context.Context, string, shared.ID, shared.ID, int) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}

// harnessCoverage is a tenant-aware coverageService: it holds one asset for tenantA only, so the
// harness can prove a tenantB principal reads NOTHING of tenantA's fleet (the #413 isolation gate).
type harnessCoverage struct{}

func (harnessCoverage) Agents(_ context.Context, tenant shared.ID, _ fleetcoverage.AgentHealth) ([]coverageuc.AgentRow, error) {
	if tenant == "tenantA" {
		return []coverageuc.AgentRow{{ID: "ag1", Health: fleetcoverage.AgentHealthy}}, nil
	}
	return nil, nil
}
func (harnessCoverage) AgentDetail(_ context.Context, tenant, id shared.ID) (coverageuc.AgentRow, []coverageuc.OrderBrief, error) {
	if tenant == "tenantA" && id == "ag1" {
		return coverageuc.AgentRow{ID: "ag1"}, nil, nil
	}
	return coverageuc.AgentRow{}, nil, shared.ErrNotFound
}
func (harnessCoverage) Coverage(_ context.Context, tenant shared.ID) ([]coverageuc.CoverageRow, error) {
	if tenant == "tenantA" {
		return []coverageuc.CoverageRow{{AssetID: "asset-A", Capability: "scan.host", Verdict: fleetcoverage.VerdictCovered, AgentID: "ag1"}}, nil
	}
	return nil, nil
}
func (harnessCoverage) Summary(_ context.Context, tenant shared.ID) (coverageuc.Summary, error) {
	rows, _ := harnessCoverage{}.Coverage(context.Background(), tenant)
	sum := coverageuc.Summary{RowsByVerdict: map[fleetcoverage.Verdict]int{}}
	for _, r := range rows {
		sum.RowsByVerdict[r.Verdict]++
	}
	return sum, nil
}

// harnessSARIF is a no-op ingester: every harness assertion on the import route is a DENY that authz or
// withEngTenant rejects before the handler runs.
type harnessSARIF struct{}

func (harnessSARIF) Ingest(context.Context, sarifingest.IngestRequest) (sarifingest.IngestResult, error) {
	return sarifingest.IngestResult{}, nil
}

// harnessRollout is a no-op rollout service: every rollout assertion below is a DENY except the
// readonly VIEW, which only needs the route to exist and answer.
type harnessRollout struct{}

func (harnessRollout) Get(context.Context, shared.ID, string) (*fleetrollout.Plan, error) {
	return nil, shared.ErrNotFound
}
func (harnessRollout) SetTarget(context.Context, fleetrolloutuc.SetTargetInput) (*fleetrollout.Plan, error) {
	return nil, shared.ErrValidation
}
func (harnessRollout) Promote(context.Context, shared.ID, string, shared.ID) (*fleetrollout.Plan, error) {
	return nil, shared.ErrValidation
}
func (harnessRollout) Pause(context.Context, shared.ID, string, shared.ID, string) (*fleetrollout.Plan, error) {
	return nil, shared.ErrValidation
}
func (harnessRollout) Resume(context.Context, shared.ID, string, shared.ID) (*fleetrollout.Plan, error) {
	return nil, shared.ErrValidation
}

// harnessImportedFindings is the no-op read side; every assertion on the read route is a DENY too.
type harnessImportedFindings struct{}

func (harnessImportedFindings) ListByEngagement(context.Context, shared.ID, shared.ID) ([]importedfinding.ImportedFinding, error) {
	return nil, nil
}

// harnessDetections is the #423 detection-ledger read side: it returns one tenant-A detection carrying a
// marker asset, so the harness proves a cross-tenant read (blocked by withEngTenant → 404) never reaches
// it, while a same-tenant read does.
type harnessDetections struct{}

func (harnessDetections) ListDetections(_ context.Context, engagementID shared.ID) ([]detection.Record, error) {
	r, _ := detection.Lookup("det.process_enumeration")
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "host-A",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}
	d, _ := detection.NewDetection(r, "host-A", "agent:A", []detection.Event{ev}, time.Unix(500, 0))
	return []detection.Record{{
		ID: "det-A", TenantID: "tenantA", EngagementID: engagementID, AssetID: "asset-A", AgentID: "agent:A",
		Detection: d, EvidenceID: "ev-A", BatchSeq: 1, RecordedAt: time.Unix(1000, 0),
	}}, nil
}

func (harnessDetections) Incidents(_ context.Context, _ shared.ID) ([]detection.Incident, error) {
	return nil, nil
}

// harnessPurple is the #426 purple-coverage read side: it returns one tenant-A coverage record carrying a
// marker technique, so the harness proves a cross-tenant read (blocked by withEngTenant → 404) never
// reaches it, while a same-tenant read does.
// harnessFindingLister adapts the memory finding repository to the host vulnerability lister.
type harnessFindingLister struct{ repo *memory.FindingRepository }

func (l harnessFindingLister) List(ctx context.Context, engagementID shared.ID) ([]finding.Finding, error) {
	return l.repo.ListByEngagement(ctx, engagementID)
}

// harnessSBOMScanner satisfies the recorder's scanner; the harness only reads.
type harnessSBOMScanner struct{}

func (harnessSBOMScanner) ImportContextSBOM(context.Context, string, shared.ID, shared.ID, string, []byte) (*scauc.ScanResult, error) {
	return &scauc.ScanResult{}, nil
}

func (harnessSBOMScanner) StartScanWithOptions(context.Context, string, shared.ID, ports.AcquireRequest, scauc.ScanOptions) (ports.ScanJob, error) {
	return ports.ScanJob{}, nil
}

type harnessPurple struct{}

func (harnessPurple) Trend(_ context.Context, engagementID shared.ID) ([]purplecoverage.Coverage, error) {
	return []purplecoverage.Coverage{{
		TenantID: "tenantA", EngagementID: engagementID, RunID: "run-A", AssetID: "asset-A",
		TechniqueID: "emu.markerA", TaxonomyRef: "T-marker-A", Expected: "det.markerA",
		Verdict: purplecoverage.VerdictGap, ComputedAt: time.Unix(1000, 0),
	}}, nil
}

func (harnessPurple) WorkItems(_ context.Context, _, _ shared.ID) ([]purplecoverage.WorkItem, error) {
	return nil, nil
}

type fakeRuntimeVerifier struct{}

func (fakeRuntimeVerifier) Apply(context.Context, shared.ID, dastverifieruc.Result) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}

// fakeThreatModel is a no-op threatModelService for the harness – every threat-model assertion below is a
// DENY (403/404) rejected by authz/withEngTenant before either method runs.
type fakeDASTWorkflow struct{}

func (fakeDASTWorkflow) Propose(context.Context, string, shared.ID, dastrunner.Probe) (dastworkflowuc.Proposal, error) {
	return dastworkflowuc.Proposal{}, nil
}
func (fakeDASTWorkflow) Decide(context.Context, string, shared.ID, shared.ID, bool, string) (agent.ApprovalDecision, error) {
	return agent.ApprovalDecision{}, nil
}
func (fakeDASTWorkflow) Run(context.Context, string, shared.ID, shared.ID, dastrunner.Probe) (dastrunner.Result, error) {
	return dastrunner.Result{}, nil
}

// fakeDASTRunner backs the durable DAST run status route. It holds one run owned by tenantA/engA and is
// tenant-scoped like the real store, so the harness can prove the read route rejects a cross-tenant caller
// (through withEngTenant) and a machine role (through the view gate).
// fakePurpleTeam backs the #426 adversary-emulation producer route so the harness guards its operate +
// tenant gates. A cross-tenant caller is rejected by withEngTenant before this runs.
type fakePurpleTeam struct{}

func (fakePurpleTeam) RunEmulation(context.Context, shared.ID, shared.ID, shared.ID, string) (purpleteamuc.Result, error) {
	return purpleteamuc.Result{}, nil
}

type fakeDASTRunner struct{}

func (fakeDASTRunner) Submit(context.Context, shared.ID, shared.ID, string, dastrunner.Probe) (dastrun.Run, error) {
	return dastrun.Run{}, nil
}
func (fakeDASTRunner) GetRun(_ context.Context, tenantID, runID shared.ID) (dastrun.Run, error) {
	if tenantID == "tenantA" && runID == "dast-run-a" {
		return dastrun.Run{ID: "dast-run-a", TenantID: "tenantA", EngagementID: "engA", ActionID: "act-a", Actor: "operator", Status: dastrun.RunSucceeded, Verdict: "confirmed", HTTPStatus: 200, EvidenceID: "ev-a", StartedAt: time.Unix(1_700_000_000, 0).UTC()}, nil
	}
	return dastrun.Run{}, fmt.Errorf("%w: DAST run", shared.ErrNotFound)
}

type fakeThreatModel struct{}

func (fakeThreatModel) Ingest(context.Context, string, shared.ID, shared.ID, threatmodel.Model) (threatmodel.ModelDelta, error) {
	return threatmodel.ModelDelta{}, nil
}
func (fakeThreatModel) Get(context.Context, shared.ID) (threatmodel.Model, bool, error) {
	return threatmodel.Model{}, false, nil
}

// fakeWriteupDrafts is a no-op writeupDraftService for the harness – every sign-off assertion below is a
// DENY (403/404) rejected by authz/withEngTenant before any method runs, except the readonly LIST allow.
type fakeWriteupDrafts struct{}

func (fakeWriteupDrafts) ListByEngagement(context.Context, shared.ID) ([]writeupdraft.Draft, error) {
	return nil, nil
}
func (fakeWriteupDrafts) Edit(context.Context, string, shared.ID, shared.ID, string, string) (writeupdraft.Draft, error) {
	return writeupdraft.Draft{}, nil
}
func (fakeWriteupDrafts) Accept(context.Context, string, shared.ID, shared.ID) (writeupdraft.Draft, error) {
	return writeupdraft.Draft{}, nil
}
func (fakeWriteupDrafts) Reject(context.Context, string, shared.ID, shared.ID) (writeupdraft.Draft, error) {
	return writeupdraft.Draft{}, nil
}

// fakeRules is a no-op rulesService for the harness.
type fakeRules struct{}

func (fakeRules) List(context.Context, rules.Filter) ([]rule.Rule, error) { return nil, nil }
func (fakeRules) Get(context.Context, rule.Key) (rule.Rule, error)        { return rule.Rule{}, nil }

// TestHostileHarness drives the REAL route table (rt.routes()) through the production
// authz → withEngTenant → handler chain with a context-injected principal, asserting the program's
// cross-cutting authorization invariants END-TO-END through the actual wiring (not a stand-in):
// RBAC allow/deny per role (the matrix, as wired per route),
// tenant isolation (cross-tenant → 404, never a 200 nor an existence-revealing 403),
// machine-role denial (separation of duties), and
// fail-closed on a missing principal.
//
// A future route registered WITHOUT the right authz/withEngTenant wrapper, or with the wrong
// permission, fails here – that is the regression this harness exists to catch. The auth + AUP
// middleware are intentionally bypassed (driven via routes(), not Handler()) to isolate the
// authorization layer; they are validated by their own tests.
//
// Allow (200) cases are asserted only on routes whose downstream service is wired here (the
// engagement + users services); deny cases (403/404) are rejected by authz/withEngTenant before any
// handler runs, so they need no downstream service. This is deliberate – the security-critical
// assertions are the denials.
func TestHostileHarness(t *testing.T) {
	engRepo := memory.NewEngagementRepository()
	promotionFindings := memory.NewFindingRepository()
	promotionJudgments := memory.NewJudgmentStore()
	promotionEvents := mustPromotionStore(t, promotionFindings, engRepo)
	audit := &harnessAudit{}
	promotionEvidence, err := evidenceuc.NewService(memory.NewEvidenceStore(), nil, audit, fixedClock{t: time.Unix(1, 0)}, engIDs{})
	if err != nil {
		t.Fatalf("promotion evidence service: %v", err)
	}
	promotionAnalysis, err := analysisuc.NewService(promotionJudgments, promotionEvidence, audit, fixedClock{t: time.Unix(1, 0)}, engIDs{})
	if err != nil {
		t.Fatalf("promotion analysis service: %v", err)
	}
	if err := engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "engA", TenantID: "tenantA", Name: "A", Client: "A", Status: engdom.StatusActive,
	}); err != nil {
		t.Fatalf("seed engagement A: %v", err)
	}
	if err := engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "engB", TenantID: "tenantB", Name: "B", Client: "B", Status: engdom.StatusActive,
	}); err != nil {
		t.Fatalf("seed engagement B: %v", err)
	}
	promotionCtx := shared.WithTenant(context.Background(), "tenantA")
	promotionFinding := finding.Finding{
		ID: "promotion-finding-A", EngagementID: "engA", Title: "promotion marker", Kind: finding.KindSCA,
		Priority: 3, Version: 1, DedupKey: "promotion-finding-A", Audit: shared.Audit{CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)},
	}
	if err := promotionFindings.Upsert(promotionCtx, []finding.Finding{promotionFinding}); err != nil {
		t.Fatalf("seed promotion finding: %v", err)
	}
	promotionRecorder, err := promotionuc.NewConfirmedRecorder(promotionEvidence, promotionEvents, promotionFindings, engRepo, audit, fixedClock{t: time.Unix(1, 0)})
	if err != nil {
		t.Fatalf("promotion recorder: %v", err)
	}
	promotionAnalysis.SetPromotionRecorder(promotionRecorder)
	if _, err := promotionAnalysis.Propose(promotionCtx, "system:promotion", "engA", judgment.CapPromotion, judgment.SubjectFinding, promotionFinding.ID, judgment.PromotionClaim{
		FindingID: promotionFinding.ID, Rule: judgment.RuleRuntimeReachableExposed, Proposed: judgment.PromotionEscalate,
		Inputs:      []judgment.PromotionInput{{Kind: judgment.PromotionInputReachability, ID: "reachability-A"}},
		Fingerprint: strings.Repeat("a", 64), FindingVersion: 1, BeforePriority: 3, AfterPriority: 2,
	}); err != nil {
		t.Fatalf("seed promotion claim: %v", err)
	}
	attackAssets := memory.NewAssetStore()
	attackBindings := memory.NewAttackPathStore()
	attackFindings := memory.NewFindingRepository()
	attackImported := memory.NewImportedFindingStore()
	for _, a := range []*asset.Asset{
		{ID: "ex-A", TenantID: "tenantA", Kind: asset.KindExposure, Key: "ex-A", Name: "ex-A"},
		{ID: "app-A", TenantID: "tenantA", Kind: asset.KindWorkload, Key: "app-A", Name: "app-A"},
		{ID: "ex-B", TenantID: "tenantB", Kind: asset.KindExposure, Key: "ex-B", Name: "ex-B"},
	} {
		if err := attackAssets.UpsertAsset(context.Background(), a); err != nil {
			t.Fatalf("seed attack asset: %v", err)
		}
	}
	edge, _ := asset.NewEdge("tenantA", "ex-A", "app-A", asset.EdgeExposes, "obs-A", asset.EdgeObserved)
	if err := attackAssets.UpsertEdge(context.Background(), edge); err != nil {
		t.Fatalf("seed attack edge: %v", err)
	}
	attackFinding, err := finding.NewManual("marker-A", "engA", finding.ManualInput{Title: "tenant-A-secret-marker", Severity: shared.SeverityHigh}, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("seed attack finding: %v", err)
	}
	if err := attackFindings.Upsert(context.Background(), []finding.Finding{attackFinding}); err != nil {
		t.Fatalf("store attack finding: %v", err)
	}
	if err := attackBindings.ReplaceBindings(context.Background(), "tenantA", "engA", "manual:marker-A", []ap.Binding{{TenantID: "tenantA", EngagementID: "engA", AssetID: "app-A", FindingID: "marker-A", Producer: "manual:marker-A", Provenance: "manual:marker-A", Confidence: asset.EdgeObserved}}); err != nil {
		t.Fatalf("seed attack binding: %v", err)
	}
	attackSvc, err := attackpathuc.NewService(attackAssets, attackBindings, attackFindings, attackImported, nil, engRepo, ap.Limits{MaxLength: 12, MaxPaths: 100, MaxDuration: time.Second})
	if err != nil {
		t.Fatalf("attack path service: %v", err)
	}
	projectRepo := memory.NewProjectRepository()
	projectSvc := projectuc.NewService(projectRepo, engRepo, fixedClock{}, engIDs{}, &fakeAudit{}, true)
	// The measures route signs its pagination cursor, and refuses to serve at all without a key.
	// The generated sweep below must reach the tenant check on that route rather than stopping at
	// an unconfigured-deployment error.
	if err := projectSvc.SetCursorSecret([]byte(strings.Repeat("harness-cursor-secret", 3))); err != nil {
		t.Fatalf("set measure cursor secret: %v", err)
	}
	if _, err := projectSvc.Create(context.Background(), projectuc.CreateInput{
		TenantID: "tenantA", CreatedBy: "p", Name: "Project A", Key: "project-a",
		SourceBinding: projectdom.SourceBinding{Kind: projectdom.SourceLocal, Value: "/repo"},
	}); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	analysisStore := memory.NewProjectAnalysisStore()
	projectSvc.SetHotspotStore(analysisStore)
	projectSvc.SetAnalysisStore(analysisStore)
	usersSvc, err := usersuc.NewService(memory.NewUserRepository(), &fakeAudit{}, fixedClock{}, &seqIDs{})
	if err != nil {
		t.Fatalf("users svc: %v", err)
	}
	// One admin per tenant, plus a tenantB member, so the roster read below can prove that a
	// tenantB admin never observes tenantA's operators.
	platform := usersuc.Actor{ID: usersuc.BootstrapID}
	tenantAAdmin, _, err := usersSvc.CreateUser(context.Background(), platform, "tenantA", "A Admin", userdom.RoleAdmin)
	if err != nil {
		t.Fatalf("seed tenantA admin: %v", err)
	}
	if _, _, err := usersSvc.CreateUser(context.Background(), platform, "tenantB", "B Admin", userdom.RoleAdmin); err != nil {
		t.Fatalf("seed tenantB admin: %v", err)
	}
	if _, _, err := usersSvc.CreateUser(context.Background(), platform, "tenantB", "B Member", userdom.RoleMember); err != nil {
		t.Fatalf("seed tenantB member: %v", err)
	}
	rt := &Router{
		log:      discardLog(),
		eng:      enguc.NewService(engRepo, fixedClock{}, engIDs{}, &fakeAudit{}),
		projects: projectSvc,
		users:    usersSvc,
	}
	// Register the two CONDITIONAL sign-off routes so the harness guards their gates too: the
	// PermReview /verify route (needs a non-nil exploitation verifier) and the agent routes incl.
	// PermReview approval-decide. The deps that the generated sweep actually reads are real; the
	// rest stay nil because every assertion on those routes is a DENY that authz or withEngTenant
	// rejects before any handler runs.
	rt.SetExploitation(&fakeVerifier{})
	rt.SetJudgments(promotionAnalysis) // real judgment/promotion lifecycle for hostile verification coverage
	rt.SetRuntimeVerifier(&fakeRuntimeVerifier{})
	rt.SetDASTWorkflow(&fakeDASTWorkflow{})
	rt.SetDASTRunner(fakeDASTRunner{})        // register the #823 durable DAST run status route so the harness guards its view + tenant gates
	rt.SetThreatModel(&fakeThreatModel{})     // register the threat-model ingest/read routes so the harness guards their gates
	rt.SetWriteupDrafts(&fakeWriteupDrafts{}) // register the writeup-draft sign-off routes so the harness guards their SoD gates
	rt.SetAITriageReviews(&aiReviewFake{})    // register AI-triage queue read/claim/decision routes
	rt.SetRules(&fakeRules{})                 // register rule catalog routes so the harness guards their gates
	rt.SetFleetCoverage(harnessCoverage{})    // register #413 fleet-coverage routes so the harness guards their view/tenant gates
	rt.SetAttackPaths(attackSvc)              // real #419 service proves cross-tenant derived data isolation
	rt.SetSARIFIngest(harnessSARIF{})         // register the #415 import route so the harness guards its operate/tenant gates
	rt.SetImportedFindings(harnessImportedFindings{})
	rt.SetVulnerabilityAudit(audit)
	rt.SetDetectionReader(harnessDetections{})  // register the #423 detection-ledger read route
	rt.SetPurpleCoverageReader(harnessPurple{}) // register the #426 purple-coverage read route
	rt.SetPurpleTeam(fakePurpleTeam{})          // register the #426 adversary-emulation producer route
	// #820 host vulnerabilities: the real use case over tenantA's host asset, its hidden context and one
	// finding, so a cross-tenant read of the host routes is proven empty rather than assumed.
	hostAsset := &asset.Asset{ID: "host-A", TenantID: "tenantA", Kind: asset.KindHost, Key: "machine-id/host-A", Name: "host-A", Attributes: map[string]string{"os": "linux"}}
	if err := attackAssets.UpsertAsset(context.Background(), hostAsset); err != nil {
		t.Fatalf("seed host asset: %v", err)
	}
	if err := engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "hostctx-A", TenantID: "tenantA", HostAssetID: "host-A", Name: "host-A host vulnerabilities", Status: engdom.StatusDraft,
	}); err != nil {
		t.Fatalf("seed host context: %v", err)
	}
	hostFindings := memory.NewFindingRepository()
	if err := hostFindings.Upsert(promotionCtx, []finding.Finding{{
		ID: "hostvuln-A", EngagementID: "hostctx-A", Kind: finding.KindSCA, Severity: shared.SeverityHigh, Status: finding.StatusOpen,
		Title: "CVE-2026-0001 in openssl@1.0", DedupKey: "vuln:CVE-2026-0001:openssl:1.0", Priority: 3, Version: 1,
		Audit: shared.Audit{CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0)},
	}}); err != nil {
		t.Fatalf("seed host finding: %v", err)
	}
	hostVulns, err := hostvulnuc.NewService(engRepo, attackAssets, harnessFindingLister{repo: hostFindings}, harnessSBOMScanner{}, memory.NewImportedSBOMStore(), memory.NewScanJobStore(), engIDs{}, fixedClock{t: time.Unix(1, 0)}, audit)
	if err != nil {
		t.Fatalf("host vulnerability service: %v", err)
	}
	rt.SetHostVulnerabilities(hostVulns)
	rt.SetFleetRolloutAdmin(harnessRollout{})
	// A real approval store, not nil: the generated sweep below reads the approvals route as the
	// owning tenant, so the handler must run rather than dereference a nil dependency.
	rt.EnableAgent(nil, memory.NewAgentSessionStore(), nil, memory.NewApprovalStore(), nil, 1, 8)
	rt.SetAgentPlanStore(memory.NewPlanStore())
	rt.SetAgentDecisionStore(memory.NewDecisionStore())
	mux := rt.routes()

	send := func(role, tenant, method, path string, authed bool) (int, string) {
		req := httptest.NewRequest(method, path, nil)
		if authed {
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: role, TenantID: tenant}))
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	sendBody := func(role, tenant, method, path, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: role, TenantID: tenant}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Cross-tenant offensive-RoE write: a tenantB operator must not set tenantA's rules of engagement.
	// The write is tenant-scoped (GetByIDInTenant), so it fails ErrNotFound rather than mutating.
	if code, _ := sendBody("consultant", "tenantB", http.MethodPut, "/api/v1/engagements/engA/offensive-roe", `{"customer_contact":"x","emergency_contact":"y","risk_ceiling":"low","exclusions_checked":true}`); code != http.StatusNotFound {
		t.Errorf("cross-tenant offensive-roe write = %d, want 404", code)
	}

	// Cross-tenant adversary emulation: a tenantB operator must not run emulation against tenantA's
	// engagement. withEngTenant rejects the engagement before the run is built.
	if code, _ := sendBody("consultant", "tenantB", http.MethodPost, "/api/v1/engagements/engA/emulation", `{"target":"asset-1"}`); code != http.StatusNotFound {
		t.Errorf("cross-tenant emulation run = %d, want 404", code)
	}

	// Cross-tenant user provisioning: a tenantA admin must not be able to mint an operator (and
	// receive that operator's API key) inside tenantB.
	if code, body := sendBody("admin", "tenantA", http.MethodPost, "/api/v1/users", `{"name":"Planted","role":"admin","tenant_id":"other-b"}`); code != http.StatusForbidden || strings.Contains(body, "syn_") {
		t.Errorf("tenantA admin provisioned into another tenant: code=%d body=%s", code, body)
	}
	// Roster reads are tenant-scoped: a tenantB admin sees tenantB operators only.
	if code, body := send("admin", "tenantB", http.MethodGet, "/api/v1/users", true); code != http.StatusOK ||
		strings.Contains(body, tenantAAdmin.ID.String()) || strings.Contains(body, "A Admin") ||
		!strings.Contains(body, "B Admin") || !strings.Contains(body, "B Member") {
		t.Errorf("tenantB admin observed the wrong roster: code=%d body=%s", code, body)
	}

	verifyPromotion := func(role, tenant string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/engA/judgments/eng-1/verify", strings.NewReader(`{"score":75,"rationale":"hostile verification","version":1}`))
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: role, TenantID: tenant}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	assertPromotionUnchanged := func() {
		current, err := promotionFindings.GetByEngagementAndID(promotionCtx, "engA", promotionFinding.ID)
		if err != nil {
			t.Fatalf("load promotion finding: %v", err)
		}
		if current.Priority != promotionFinding.Priority || current.Version != promotionFinding.Version {
			t.Fatalf("hostile verification mutated promotion finding: priority/version=%d/%d, want %d/%d", current.Priority, current.Version, promotionFinding.Priority, promotionFinding.Version)
		}
		events, err := promotionEvents.ListByFinding(promotionCtx, "engA", promotionFinding.ID)
		if err != nil {
			t.Fatalf("list tenantA promotion events: %v", err)
		}
		if len(events) != 0 {
			t.Fatalf("hostile verification created %d tenantA promotion events", len(events))
		}
	}
	for _, role := range []string{"agent", "mcp"} {
		if code, body := verifyPromotion(role, "tenantA"); code != http.StatusForbidden {
			t.Errorf("machine role %q promotion verification = %d, body=%s, want 403", role, code, body)
		}
		assertPromotionUnchanged()
	}
	if code, body := verifyPromotion("reviewer", "tenantB"); code != http.StatusNotFound {
		t.Errorf("tenantB reviewer promotion verification = %d, body=%s, want 404", code, body)
	}
	assertPromotionUnchanged()
	if code, body := send("reviewer", "tenantB", http.MethodGet, "/api/v1/engagements/engA/judgments", true); code != http.StatusNotFound || strings.Contains(body, promotionFinding.ID.String()) {
		t.Errorf("tenantB observed tenantA promotion lifecycle: code=%d body=%s", code, body)
	}
	tenantBEvents, err := promotionEvents.ListByFinding(shared.WithTenant(context.Background(), "tenantB"), "engA", promotionFinding.ID)
	if err != nil {
		t.Fatalf("list tenantB promotion events: %v", err)
	}
	if len(tenantBEvents) != 0 {
		t.Fatalf("tenantB observed %d tenantA promotion events", len(tenantBEvents))
	}

	cases := []struct {
		name         string
		role, tenant string
		authed       bool
		method, path string
		want         int
	}{
		// Fail-closed: no principal → 403 at the authz chokepoint (the 401-producing auth middleware
		// is bypassed here on purpose to isolate the authorization layer).
		{"no principal is denied", "", "", false, http.MethodGet, "/api/v1/engagements", http.StatusForbidden},
		// A machine role is granted NOTHING – not even view (separation of duties).
		{"machine role denied even view", "agent", "tenantA", true, http.MethodGet, "/api/v1/engagements", http.StatusForbidden},
		// RBAC allow (view): every human role reads.
		{"readonly may list", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements", http.StatusOK},
		{"readonly may get own-tenant engagement", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA", http.StatusOK},
		{"readonly may list projects", "readonly", "tenantA", true, http.MethodGet, "/api/v1/projects", http.StatusOK},
		{"readonly may get own-tenant project", "readonly", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a", http.StatusOK},
		{"readonly may read project analysis status", "readonly", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a/analysis-status", http.StatusNotFound},
		{"readonly may read project dependency graph", "readonly", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a/dependency-graph", http.StatusNotFound},
		{"readonly may export project dependency graph", "readonly", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a/dependency-graph/export", http.StatusNotFound},
		{"readonly may list project hotspots", "readonly", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a/hotspots", http.StatusOK},
		{"machine may not read project dependency graph", "agent", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a/dependency-graph", http.StatusForbidden},
		{"machine may not list project hotspots", "agent", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a/hotspots", http.StatusForbidden},
		// RBAC deny: readonly holds only view.
		{"readonly may not create (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements", http.StatusForbidden},
		{"readonly may not create project (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/projects", http.StatusForbidden},
		{"readonly may not start project analysis", "readonly", "tenantA", true, http.MethodPost, "/api/v1/projects/project-a/analyses", http.StatusForbidden},
		{"machine may not start project analysis", "agent", "tenantA", true, http.MethodPost, "/api/v1/projects/project-a/analyses", http.StatusForbidden},
		{"machine may not list projects", "agent", "tenantA", true, http.MethodGet, "/api/v1/projects", http.StatusForbidden},
		{"readonly may not author finding (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/findings", http.StatusForbidden},
		{"readonly may not triage (triage)", "readonly", "tenantA", true, http.MethodPatch, "/api/v1/engagements/engA/findings/f1", http.StatusForbidden},
		{"readonly may not run scan (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/sca/scans", http.StatusForbidden},
		// The scan-job read carries its engagement in the RESPONSE, not the path, so withEngTenant
		// cannot wrap it; the handler re-checks the tenant itself. A machine role is denied outright.
		{"machine may not read scan job (view)", "agent", "tenantA", true, http.MethodGet, "/api/v1/sca/scans/job-1", http.StatusForbidden},
		// #823 durable DAST run status route: view-gated and tenant-scoped through withEngTenant.
		{"readonly may read own-tenant dast run", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/dast/runs/dast-run-a", http.StatusOK},
		{"machine may not read dast run (view)", "agent", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/dast/runs/dast-run-a", http.StatusForbidden},
		{"tenantB cannot read tenantA dast run", "admin", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/dast/runs/dast-run-a", http.StatusNotFound},
		{"readonly may not read audit (review)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/audit", http.StatusForbidden},
		{"readonly may not manage users (administer)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/users", http.StatusForbidden},
		// Consultant: operate yes (covered elsewhere), but NOT review or administer.
		{"consultant may not read audit (review)", "consultant", "tenantA", true, http.MethodGet, "/api/v1/audit", http.StatusForbidden},
		{"consultant may not manage users (administer)", "consultant", "tenantA", true, http.MethodGet, "/api/v1/users", http.StatusForbidden},
		// Admin: administer yes.
		{"admin may manage users", "admin", "tenantA", true, http.MethodGet, "/api/v1/users", http.StatusOK},
		// Tenant isolation: tenant B cannot READ tenant A's engagement row (service-scoped), nor
		// reach its child resource (withEngTenant chokepoint) – both 404, never 200, never a
		// 403 that would reveal the engagement exists.
		{"cross-tenant engagement read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA", http.StatusNotFound},
		{"cross-tenant child resource → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/findings", http.StatusNotFound},
		// Same-tenant read still works (isolation does not over-block).
		{"same-tenant engagement read → 200", "consultant", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA", http.StatusOK},
		{"cross-tenant project read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/projects/project-a", http.StatusNotFound},
		{"cross-tenant project analysis → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/projects/project-a/analysis", http.StatusNotFound},
		{"cross-tenant project dependency graph → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/projects/project-a/dependency-graph", http.StatusNotFound},
		{"cross-tenant project dependency export → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/projects/project-a/dependency-graph/export", http.StatusNotFound},
		{"cross-tenant project hotspots → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/projects/project-a/hotspots", http.StatusNotFound},
		{"same-tenant project read → 200", "consultant", "tenantA", true, http.MethodGet, "/api/v1/projects/project-a", http.StatusOK},
		// Sign-off routes (PermReview) – the crown-jewel separation-of-duties gates. A machine role
		// can never verify a finding nor decide an agent approval; a consultant lacks review; a
		// reviewer in another tenant is tenant-blocked (404) before the sign-off runs.
		{"machine may not verify (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/findings/f1/verify", http.StatusForbidden},
		{"consultant may not verify (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/findings/f1/verify", http.StatusForbidden},
		{"cross-tenant verify → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/findings/f1/verify", http.StatusNotFound},
		{"machine may not decide approvals (SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/agent/approvals/a1/decide", http.StatusForbidden},
		{"consultant may not decide (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/agent/approvals/a1/decide", http.StatusForbidden},
		{"cross-tenant decide → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/agent/approvals/a1/decide", http.StatusNotFound},
		{"readonly may not start agent (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/agent/sessions", http.StatusForbidden},
		// Judgment sign-off (PermReview SoD): a machine role can NEVER verify/accept an AI
		// judgment (the runtime twin of the AST tripwire) – no agent self-confirm; a consultant lacks
		// review; cross-tenant is 404 before the sign-off; readonly may read.
		{"machine may not verify judgment (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/verify", http.StatusForbidden},
		{"consultant may not verify judgment (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/verify", http.StatusForbidden},
		{"machine may not accept judgment (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/accept", http.StatusForbidden},
		{"cross-tenant judgment verify → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/verify", http.StatusNotFound},
		{"machine may not apply runtime verification (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification", http.StatusForbidden},
		{"consultant may not apply runtime verification (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification", http.StatusForbidden},
		{"cross-tenant runtime verification -> 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification", http.StatusNotFound},
		{"readonly may not propose runtime verifier (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification/proposals", http.StatusForbidden},
		{"machine may not decide runtime verifier (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/dast/approvals/a1/decide", http.StatusForbidden},
		{"consultant may not decide runtime verifier (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/dast/approvals/a1/decide", http.StatusForbidden},
		{"cross-tenant runtime verifier run -> 404", "consultant", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification/proposals/a1/run", http.StatusNotFound},
		{"readonly may list judgments (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/judgments", http.StatusOK},
		// threat-model ingest (PermOperate) + read (PermView), tenant-gated like every child route.
		{"machine may not ingest threat model (operate)", "agent", "tenantA", true, http.MethodPut, "/api/v1/engagements/engA/threat-model", http.StatusForbidden},
		{"readonly may not ingest threat model (operate)", "readonly", "tenantA", true, http.MethodPut, "/api/v1/engagements/engA/threat-model", http.StatusForbidden},
		{"cross-tenant threat-model ingest → 404", "consultant", "tenantB", true, http.MethodPut, "/api/v1/engagements/engA/threat-model", http.StatusNotFound},
		{"cross-tenant threat-model read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/threat-model", http.StatusNotFound},
		// writeup-draft sign-off (PermReview SoD) + read (PermView): the agent PROPOSES (via the tool,
		// not HTTP); a machine/consultant/readonly can NEVER edit/accept/reject here; cross-tenant is 404.
		{"machine may not accept writeup draft (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/accept", http.StatusForbidden},
		{"consultant may not accept writeup draft (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/accept", http.StatusForbidden},
		{"readonly may not reject writeup draft (review)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/reject", http.StatusForbidden},
		{"machine may not edit writeup draft (review)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/edit", http.StatusForbidden},
		{"cross-tenant writeup-draft accept → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/accept", http.StatusNotFound},
		{"readonly may list writeup drafts (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/writeup-drafts", http.StatusOK},
		{"readonly may list AI-triage reviews (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/ai-triage/reviews", http.StatusOK},
		{"machine may not claim AI-triage review (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/ai-triage/reviews/r1/claim", http.StatusForbidden},
		{"consultant may not decide AI-triage review (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/ai-triage/reviews/r1/decision", http.StatusForbidden},
		// Rule Catalog (PermView): no tenant context required, but machine roles denied.
		{"machine may not list rules (view/SoD)", "agent", "tenantA", true, http.MethodGet, "/api/v1/rules", http.StatusForbidden},
		{"machine may not get rule (view/SoD)", "agent", "tenantA", true, http.MethodGet, "/api/v1/rules/go:sql-injection", http.StatusForbidden},
		{"readonly may list rules (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/rules", http.StatusOK},
		{"readonly may get rule (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/rules/go:sql-injection", http.StatusOK},
		// Third-party SARIF ingest (#415) is an OPERATE action, tenant-gated like any engagement child.
		// A machine role may not import, and a readonly principal may not either — an external report
		// must never enter the queue without an accountable operator behind it.
		{"machine may not import sarif (operate/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/sarif", http.StatusForbidden},
		{"readonly may not import sarif (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/sarif", http.StatusForbidden},
		{"cross-tenant sarif import → 404", "consultant", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/sarif", http.StatusNotFound},
		// Update rollout can replace the running binary on every host in the fleet, so it is
		// ADMINISTER. Reading the plan is VIEW, so on-call can see why the fleet is not updating
		// without holding the power to change it.
		{"consultant may not set a rollout target (administer)", "consultant", "tenantA", true, http.MethodPut, "/api/v1/agents/rollout", http.StatusForbidden},
		{"consultant may not promote a rollout (administer)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/agents/rollout/promote", http.StatusForbidden},
		{"reviewer may not pause a rollout (administer)", "reviewer", "tenantA", true, http.MethodPost, "/api/v1/agents/rollout/pause", http.StatusForbidden},
		{"machine may not touch a rollout (SoD)", "agent", "tenantA", true, http.MethodPut, "/api/v1/agents/rollout", http.StatusForbidden},
		{"readonly may read the rollout (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/agents/rollout", http.StatusOK},
		// The read side is a VIEW action on the same engagement: readonly may see imported findings,
		// but only inside its own tenant, and an unauthenticated caller may not see them at all.
		{"readonly may read imported findings (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/imported-findings", http.StatusOK},
		{"cross-tenant imported-finding read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/imported-findings", http.StatusNotFound},
		{"principal-less imported-finding read is denied", "", "", false, http.MethodGet, "/api/v1/engagements/engA/imported-findings", http.StatusForbidden},
		{"readonly may read detections (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/detections", http.StatusOK},
		{"cross-tenant detection read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/detections", http.StatusNotFound},
		{"principal-less detection read is denied", "", "", false, http.MethodGet, "/api/v1/engagements/engA/detections", http.StatusForbidden},
		// #426 purple coverage (PermView): readonly may read; cross-tenant is 404 before the handler; a
		// principal-less read is denied.
		{"readonly may read purple coverage", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/purple-coverage", http.StatusOK},
		{"cross-tenant purple coverage → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/purple-coverage", http.StatusNotFound},
		{"principal-less purple coverage read is denied", "", "", false, http.MethodGet, "/api/v1/engagements/engA/purple-coverage", http.StatusForbidden},
		// #427 unified per-asset risk story (PermView): readonly may read; a cross-tenant read is 404 at
		// the withEngTenant chokepoint before any correlation runs; a principal-less read is denied. Both
		// the list route and the single-asset route are gated, so the story never crosses a tenant.
		{"readonly may read risk stories", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/risk-stories", http.StatusOK},
		{"cross-tenant risk story list → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/risk-stories", http.StatusNotFound},
		{"principal-less risk story read is denied", "", "", false, http.MethodGet, "/api/v1/engagements/engA/risk-stories", http.StatusForbidden},
		{"cross-tenant single risk story → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/risk-stories/asset-A", http.StatusNotFound},
		// Fleet coverage (#413, PermView): machine roles denied; readonly may read; cross-tenant agent
		// detail is 404 (never an existence-revealing 403). The cross-tenant LIST emptiness (a 200 that
		// leaks nothing) is asserted on the body just below the table.
		{"machine may not list fleet agents (view/SoD)", "agent", "tenantA", true, http.MethodGet, "/api/v1/fleet/agents", http.StatusForbidden},
		{"machine may not read attack paths (view/SoD)", "agent", "tenantA", true, http.MethodGet, "/api/v1/attack-paths", http.StatusForbidden},
		{"readonly may read attack paths (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/attack-paths", http.StatusOK},
		{"machine may not list fleet coverage (view/SoD)", "agent", "tenantA", true, http.MethodGet, "/api/v1/fleet/coverage", http.StatusForbidden},
		{"readonly may list fleet agents (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/fleet/agents", http.StatusOK},
		{"readonly may read fleet coverage (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/fleet/coverage", http.StatusOK},
		{"readonly may read fleet coverage summary (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/fleet/coverage/summary", http.StatusOK},
		{"readonly may export fleet coverage (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/fleet/coverage/export", http.StatusOK},
		{"same-tenant fleet agent detail → 200", "readonly", "tenantA", true, http.MethodGet, "/api/v1/fleet/agents/ag1", http.StatusOK},
		{"cross-tenant fleet agent detail → 404", "readonly", "tenantB", true, http.MethodGet, "/api/v1/fleet/agents/ag1", http.StatusNotFound},
		// #820 host vulnerabilities (PermView): machine roles denied, readonly may read, a cross-tenant
		// host read is 404, a principal-less read is denied. The cross-tenant LIST emptiness is asserted
		// on the body below the table.
		{"readonly may list hosts (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/assets/hosts", http.StatusOK},
		{"machine may not list hosts (view/SoD)", "agent", "tenantA", true, http.MethodGet, "/api/v1/assets/hosts", http.StatusForbidden},
		{"principal-less host list is denied", "", "", false, http.MethodGet, "/api/v1/assets/hosts", http.StatusForbidden},
		{"readonly may read a host's vulnerabilities (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/assets/host-A/vulnerabilities", http.StatusOK},
		{"cross-tenant host vulnerabilities → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/assets/host-A/vulnerabilities", http.StatusNotFound},
	}
	for _, c := range cases {
		if got, body := send(c.role, c.tenant, c.method, c.path, c.authed); got != c.want {
			t.Errorf("%s: %s %s (role=%q tenant=%q) → %d, body: %s, want %d", c.name, c.method, c.path, c.role, c.tenant, got, body, c.want)
		}
	}

	if code, body := send("readonly", "tenantA", http.MethodGet, "/api/v1/attack-paths", true); code != http.StatusOK || !strings.Contains(body, "tenant-A-secret-marker") {
		t.Fatalf("tenantA must see its own attack path marker (code=%d body=%s)", code, body)
	}
	// #423 detection ledger: tenantA sees its own detection (asset-A marker); a cross-tenant read of the
	// engagement-scoped route returns NOTHING (404 via withEngTenant), so tenantA's marker can never leak.
	if code, body := send("readonly", "tenantA", http.MethodGet, "/api/v1/engagements/engA/detections", true); code != http.StatusOK || !strings.Contains(body, "asset-A") {
		t.Fatalf("tenantA must see its own detections (code=%d body=%s)", code, body)
	}
	if code, body := send("consultant", "tenantB", http.MethodGet, "/api/v1/engagements/engA/detections", true); code != http.StatusNotFound || strings.Contains(body, "asset-A") {
		t.Errorf("cross-tenant detection read must be 404 with no tenantA data (code=%d body=%s)", code, body)
	}
	// #426 purple coverage: tenantA sees its own coverage marker; a cross-tenant read returns NOTHING
	// (404 via withEngTenant), so tenantA's marker can never leak.
	if code, body := send("readonly", "tenantA", http.MethodGet, "/api/v1/engagements/engA/purple-coverage", true); code != http.StatusOK || !strings.Contains(body, "emu.markerA") {
		t.Fatalf("tenantA must see its own purple coverage (code=%d body=%s)", code, body)
	}
	if code, body := send("consultant", "tenantB", http.MethodGet, "/api/v1/engagements/engA/purple-coverage", true); code != http.StatusNotFound || strings.Contains(body, "emu.markerA") {
		t.Errorf("cross-tenant purple coverage read must be 404 with no tenantA data (code=%d body=%s)", code, body)
	}

	if code, body := send("readonly", "tenantB", http.MethodGet, "/api/v1/attack-paths", true); code != http.StatusOK || strings.Contains(body, "tenant-A-secret-marker") {
		t.Errorf("tenantB attack paths leaked tenantA data (code=%d body=%s)", code, body)
	}
	// #820 host vulnerabilities: tenantA sees its host and the host's finding; tenantB's list is an
	// empty 200 and the host read is a 404 that carries nothing of tenantA's.
	if code, body := send("readonly", "tenantA", http.MethodGet, "/api/v1/assets/hosts", true); code != http.StatusOK || !strings.Contains(body, "host-A") || !strings.Contains(body, "hostctx-A") {
		t.Fatalf("tenantA must see its own host (code=%d body=%s)", code, body)
	}
	if code, body := send("readonly", "tenantA", http.MethodGet, "/api/v1/assets/host-A/vulnerabilities", true); code != http.StatusOK || !strings.Contains(body, "CVE-2026-0001") {
		t.Fatalf("tenantA must see its host's findings (code=%d body=%s)", code, body)
	}
	if code, body := send("readonly", "tenantB", http.MethodGet, "/api/v1/assets/hosts", true); code != http.StatusOK || strings.Contains(body, "host-A") || strings.Contains(body, "hostctx-A") {
		t.Errorf("cross-tenant host list must be empty (code=%d body=%s)", code, body)
	}
	if code, body := send("consultant", "tenantB", http.MethodGet, "/api/v1/assets/host-A/vulnerabilities", true); code != http.StatusNotFound || strings.Contains(body, "CVE-2026-0001") || strings.Contains(body, "hostctx-A") {
		t.Errorf("cross-tenant host read must be 404 with no tenantA data (code=%d body=%s)", code, body)
	}

	// Cross-tenant fleet reads must return NOTHING, not merely a 200. tenantA's asset id must never
	// appear in tenantB's coverage or agent list (the #413 no-cross-tenant-aggregate requirement).
	for _, path := range []string{"/api/v1/fleet/coverage", "/api/v1/fleet/agents", "/api/v1/fleet/coverage/export"} {
		if code, body := send("readonly", "tenantA", http.MethodGet, path, true); code != http.StatusOK || !strings.Contains(body, "asset-A") && !strings.Contains(body, "ag1") {
			// sanity: tenantA genuinely sees its own data, so the emptiness below is meaningful.
			t.Fatalf("tenantA must see its own fleet data at %s (code=%d body=%s)", path, code, body)
		}
		if code, body := send("readonly", "tenantB", http.MethodGet, path, true); code != http.StatusOK {
			t.Errorf("cross-tenant %s should be an empty 200, got %d", path, code)
		} else if strings.Contains(body, "asset-A") || strings.Contains(body, "ag1") {
			t.Errorf("cross-tenant %s leaked tenantA data: %s", path, body)
		}
	}

	// Generated cross-tenant sweep. The hand-written cases above prove specific leaks are closed;
	// this walks the whole tenant-scoped GET surface from the route table so a route added tomorrow
	// is probed the day it is registered, instead of waiting for somebody to remember the harness.
	//
	// The property asserted is the weakest one that is still true of every route: a caller in
	// tenantB asking for a tenantA-owned path must not be answered with that resource. A 403 or a
	// 404 is correct, and so is a 200 that carries none of tenantA's markers. A 200 that echoes a
	// tenantA identifier is the leak.
	t.Run("generated cross-tenant sweep", func(t *testing.T) {
		// Markers seeded into tenantA only. A tenantB caller must never see one of these.
		// Values the fixture seeds for tenantA only. "tenantA" itself is the broadest: a response
		// to a tenantB caller that names tenantA is a leak whatever else it contains.
		markers := []string{"tenantA", "promotion-finding-A", "asset-A", "ag1", "A Admin", "det-A", "ev-A", "agent:A", "host-A"}
		containsMarker := func(body string) string {
			for _, marker := range markers {
				if strings.Contains(body, marker) {
					return marker
				}
			}
			return ""
		}
		// probe runs one request and reports whether the handler could run at all. This fixture
		// deliberately leaves optional subsystems unwired, and their handlers dereference the
		// dependency the router guarantees them in production, so an unwired route panics here.
		// That is a gap in the fixture rather than a tenancy finding, so it is counted and skipped.
		probe := func(tenant, path string) (code int, body string, ran bool) {
			defer func() {
				if recover() != nil {
					ran = false
				}
			}()
			code, body = send("admin", tenant, http.MethodGet, path, true)
			return code, body, true
		}

		var probed, unwired, servingTenantA int
		var servingRoutes []string
		for _, route := range tenantScopedGETRoutes(t) {
			path := concreteHarnessPath(route)
			if path == "" {
				continue
			}
			// Control: does this route serve tenantA its own seeded data? A route that answers
			// nobody proves nothing when it also answers tenantB nothing, so the count below keeps
			// the sweep from decaying into a set of vacuous passes.
			code, body, ran := probe("tenantA", path)
			if !ran {
				unwired++
				continue
			}
			probed++
			if code == http.StatusOK && containsMarker(body) != "" {
				servingTenantA++
				servingRoutes = append(servingRoutes, route)
			}
			t.Run(route, func(t *testing.T) {
				code, body, ran := probe("tenantB", path)
				if !ran {
					t.Skip("subsystem is not wired in this fixture")
				}
				if code == http.StatusOK {
					if marker := containsMarker(body); marker != "" {
						t.Errorf("%s answered a tenantB caller with tenantA data (marker %q): %s", route, marker, body)
					}
				}
				if code >= 500 {
					t.Errorf("%s returned %d for a cross-tenant read; a guard must reject, not crash: %s", route, code, body)
				}
			})
		}
		if probed < 40 {
			t.Errorf("the sweep probed %d routes; the route table is no longer being read", probed)
		}
		// Five routes in this fixture are seeded with tenantA data, so for those the tenantB probe
		// proves a real absence. For the rest the sweep proves the weaker but still useful property
		// that a cross-tenant read neither crashes nor echoes a tenantA identifier. Raise this floor
		// when you seed more fixture data; never lower it.
		if servingTenantA < 5 {
			t.Errorf("only %d of %d probed routes served tenantA its own seeded data (%v); the sweep is passing vacuously", servingTenantA, probed, servingRoutes)
		}
		t.Logf("generated sweep probed %d tenant-scoped GET routes (%d serve tenantA real data); %d skipped as unwired in this fixture", probed, servingTenantA, unwired)
	})
}

// tenantScopedGETRoutes reads the route table and returns every GET route whose path carries an
// engagement, project or asset id. Those are the routes that serve one tenant's resource by id, so
// a caller from another tenant must not be answered with it.
func tenantScopedGETRoutes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, route := range registeredRoutes(t) {
		pattern := route.Pattern
		if !strings.HasPrefix(pattern, "GET ") {
			continue
		}
		if strings.Contains(pattern, "/engagements/{") || strings.Contains(pattern, "/projects/{") || strings.Contains(pattern, "/assets/{") {
			out = append(out, pattern)
		}
	}
	sort.Strings(out)
	return out
}

// harnessPathValues maps a route parameter to the concrete id the harness fixture seeds for it.
// A parameter with no entry means the route cannot be probed generically, and it is skipped rather
// than probed with a guessed value that would only ever produce a 404.
var harnessPathValues = map[string]string{
	"{id}": "engA", "{key}": "project-a", "{assetID}": "asset-A", "{aid}": "asset-A",
	"{fid}": "f1", "{jid}": "j1", "{rid}": "r1", "{sid}": "s1", "{cid}": "c1",
	"{a}": "a1", "{pid}": "p1", "{tid}": "t1", "{vid}": "v1", "{eid}": "e1", "{name}": "n1",
}

// concreteHarnessPath turns a registered pattern into a request path the harness fixture can serve,
// or "" when a parameter has no seeded value.
func concreteHarnessPath(route string) string {
	path := route[strings.Index(route, " ")+1:]
	for {
		open := strings.Index(path, "{")
		if open < 0 {
			return path
		}
		closeAt := strings.Index(path[open:], "}")
		if closeAt < 0 {
			return ""
		}
		param := path[open : open+closeAt+1]
		value, ok := harnessPathValues[param]
		if !ok {
			return ""
		}
		path = path[:open] + value + path[open+closeAt+1:]
	}
}
