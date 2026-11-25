package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	snapshotdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	relationshipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentrelationship"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
)

// assessmentMarker appears in the body of an assessment route only when tenantA's own record was
// served. It is the actor that created the cycle members, the closure manifest and the relationship
// candidate, it is in the closed cycle's name, and it is part of the lineage identity the
// comparison's item carries. No path this seed declares contains it.
const assessmentMarker = "tenantA-assessment-seed-marker"

// assessmentFinalSnapshot is the snapshot the closed cycle's final retest finalized. A comparison and
// its summary name a cycle and two snapshots and nothing a person wrote, so this id is their marker.
// No path this seed declares contains it.
const assessmentFinalSnapshot = shared.ID("assessment-seed-snapshot-final")

// assessmentNow stamps every record this seed plants. The fixture's assessment cycle service stamps a
// status change with its own clock, fixed at time.Unix(1, 0), and a cycle cannot change before it was
// created, so the records carry that same instant.
var assessmentNow = time.Unix(1, 0).UTC()

const (
	// The closed cycle: a root, the retest it was closed on, and a second retest of the root, which
	// is the other branch head a relationship preview can select.
	assessmentClosedCycle  = shared.ID("assessment-seed-cycle-closed")
	assessmentRoot         = shared.ID("assessment-seed-root")
	assessmentFinal        = shared.ID("assessment-seed-final")
	assessmentBranch       = shared.ID("assessment-seed-branch")
	assessmentRootSnapshot = shared.ID("assessment-seed-snapshot-root")
	// Two singleton cycles with one finalized snapshot each, which is the pair a relationship
	// candidate links. The legacy one was completed before closure manifests existed, which is the
	// only cycle the legacy reopen route reopens; the archive route ends the open one.
	assessmentLegacyCycle    = shared.ID("assessment-seed-cycle-legacy")
	assessmentLegacyRoot     = shared.ID("assessment-seed-legacy-root")
	assessmentLegacySnapshot = shared.ID("assessment-seed-snapshot-legacy")
	assessmentOpenCycle      = shared.ID("assessment-seed-cycle-open")
	assessmentOpenRoot       = shared.ID("assessment-seed-open-root")
	assessmentOpenSnapshot   = shared.ID("assessment-seed-snapshot-open")
	// The closure commit takes the manifest id from the fixture's id generator, which names every
	// record eng-1. The comparison and the candidate take theirs from this seed's own generators.
	assessmentManifest   = shared.ID("eng-1")
	assessmentComparison = shared.ID("assessment-seed-comparison-1")
	assessmentCandidate  = shared.ID("assessment-seed-candidate-1")
	assessmentIdentity   = shared.ID(assessmentMarker + "-identity")
)

func init() {
	closed := map[string]string{"{cycleId}": assessmentClosedCycle.String()}
	manifest := map[string]string{"{cycleId}": assessmentClosedCycle.String(), "{manifestId}": assessmentManifest.String()}
	comparison := map[string]string{"{comparisonId}": assessmentComparison.String()}
	reads := map[string]map[string]string{
		"GET /api/v1/assessment-cycles/{cycleId}":                                       closed,
		"GET /api/v1/assessment-cycles/{cycleId}/members":                               closed,
		"GET /api/v1/assessment-cycles/{cycleId}/closure-manifests":                     closed,
		"GET /api/v1/assessment-cycles/{cycleId}/closure-manifests/{manifestId}":        manifest,
		"GET /api/v1/assessment-cycles/{cycleId}/closure-manifests/{manifestId}/report": manifest,
		"GET /api/v1/assessment-comparisons/{comparisonId}":                             comparison,
		"GET /api/v1/assessment-comparisons/{comparisonId}/items":                       comparison,
		"GET /api/v1/assessment-comparisons/{comparisonId}/summary":                     comparison,
		"GET /api/v1/assessment-relationship-candidates/{candidateId}":                  {"{candidateId}": assessmentCandidate.String()},
	}
	values := map[string]map[string]string{}
	routes := make([]string, 0, len(reads))
	for route, value := range reads {
		routes = append(routes, route)
		values[route] = value
	}
	// The write routes under a cycle, a comparison or a candidate take its id from the read route on
	// the parent path. Some need more. The legacy reopen and the archive both refuse a cycle closed
	// with a manifest (the reopen with a 409, the archive with a 400, because the archived cycle would
	// still name its active manifest), so they address the legacy and the open singleton cycle; and the
	// two reviews address the comparison's one item.
	values["POST /api/v1/assessment-cycles/{cycleId}/reopen"] = map[string]string{"{cycleId}": assessmentLegacyCycle.String()}
	values["POST /api/v1/assessment-cycles/{cycleId}/archive"] = map[string]string{"{cycleId}": assessmentOpenCycle.String()}
	item := map[string]string{"{itemId}": assessmentComparisonItemID(assessmentComparison, assessmentIdentity).String()}
	values["POST /api/v1/assessment-comparisons/{comparisonId}/items/{itemId}/confirm"] = item
	values["POST /api/v1/assessment-comparisons/{comparisonId}/items/{itemId}/unlink"] = item
	registerHarnessSeed(harnessSeed{
		Name:            "assessment",
		Routes:          routes,
		RoutePathValues: values,
		Run:             seedAssessment,
	})
}

// seedAssessment plants a closed assessment cycle, its snapshots and lifecycle comparison, two
// singleton cycles and a relationship candidate that links them, all under tenantA, through the real
// in-memory stores and use cases. The cycles go into the fixture's own cycle store, behind the cycle
// service the router already holds, and the closure and relationship-change dependencies are wired onto
// that service. The snapshots, the lineage and the comparison and relationship services are this
// seed's own: the snapshot routes read another seed's snapshot service, which is not reachable here,
// so the snapshots only feed the closure, the comparison and the candidate.
//
// No route here has a guard of its own beyond its permission: every handler passes the caller's tenant
// to the use case, and each store keys every record by it. That key is what stands between tenantB
// and these records. The cycle detail and member routes also resolve every member's assessment
// through the engagement service, which is scoped by the same tenant, and so do the archive and the
// legacy reopen, which answer with that detail and roll the change back when it cannot be read.
func seedAssessment(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	ctx := context.Background()
	const tenant = shared.ID("tenantA")
	api, cycles := w.assessmentCycleAPI, w.assessmentCycles
	if api == nil || cycles == nil {
		t.Fatal("the assessment seed needs the fixture's assessment cycle service and store")
	}
	snapshots := memory.NewAssessmentSnapshotRepository()

	// Every member view reads its assessment, and the closure policy needs the final retest completed.
	for _, id := range []shared.ID{assessmentRoot, assessmentFinal, assessmentBranch, assessmentLegacyRoot, assessmentOpenRoot} {
		assessment, err := engdom.New(id, tenant, "assessment "+id.String(), "client", assessmentNow)
		if err != nil {
			t.Fatalf("build assessment %s: %v", id, err)
		}
		if err := assessment.Transition(engdom.StatusActive, assessmentNow); err != nil {
			t.Fatalf("activate assessment %s: %v", id, err)
		}
		if err := assessment.Transition(engdom.StatusCompleted, assessmentNow); err != nil {
			t.Fatalf("complete assessment %s: %v", id, err)
		}
		if err := w.engagements.Create(ctx, assessment); err != nil {
			t.Fatalf("store assessment %s: %v", id, err)
		}
	}

	newCycle := func(id, root shared.ID, name string) *cycledom.AssessmentCycle {
		cycle, err := cycledom.NewAssessmentCycle(id, tenant, name, cycledom.BoundaryStandalone, "", "", root, assessmentMarker, assessmentNow)
		if err != nil {
			t.Fatalf("build assessment cycle %s: %v", id, err)
		}
		return cycle
	}
	closedCycle := newCycle(assessmentClosedCycle, assessmentRoot, "assessment cycle "+assessmentMarker)
	// The first retest becomes the selected head, because its predecessor is the head when it is
	// added; the second leaves the head where it is.
	for _, retest := range []shared.ID{assessmentFinal, assessmentBranch} {
		if _, err := closedCycle.AdvanceRetest(retest, assessmentRoot, closedCycle.Version, assessmentMarker, assessmentNow); err != nil {
			t.Fatalf("add retest %s: %v", retest, err)
		}
	}
	legacyCycle := newCycle(assessmentLegacyCycle, assessmentLegacyRoot, "legacy assessment cycle")
	if err := legacyCycle.Transition(cycledom.StatusCompleted, legacyCycle.Version, assessmentMarker, assessmentNow); err != nil {
		t.Fatalf("complete the legacy assessment cycle: %v", err)
	}
	openCycle := newCycle(assessmentOpenCycle, assessmentOpenRoot, "open assessment cycle")
	for _, cycle := range []*cycledom.AssessmentCycle{closedCycle, legacyCycle, openCycle} {
		if err := cycles.CreateCycle(ctx, cycle); err != nil {
			t.Fatalf("store assessment cycle %s: %v", cycle.ID, err)
		}
	}
	member := func(build func() (*cycledom.Member, error)) {
		value, err := build()
		if err != nil {
			t.Fatalf("build assessment cycle member: %v", err)
		}
		if err := cycles.CreateMember(ctx, value); err != nil {
			t.Fatalf("store assessment cycle member %s: %v", value.AssessmentID, err)
		}
	}
	member(func() (*cycledom.Member, error) {
		return cycledom.NewInitialMember(tenant, assessmentClosedCycle, assessmentRoot, assessmentMarker, assessmentNow)
	})
	member(func() (*cycledom.Member, error) {
		return cycledom.NewRetestMember(tenant, assessmentClosedCycle, assessmentFinal, assessmentRoot, 1, assessmentMarker, assessmentNow)
	})
	member(func() (*cycledom.Member, error) {
		return cycledom.NewRetestMember(tenant, assessmentClosedCycle, assessmentBranch, assessmentRoot, 2, assessmentMarker, assessmentNow)
	})
	member(func() (*cycledom.Member, error) {
		return cycledom.NewInitialMember(tenant, assessmentLegacyCycle, assessmentLegacyRoot, assessmentMarker, assessmentNow)
	})
	member(func() (*cycledom.Member, error) {
		return cycledom.NewInitialMember(tenant, assessmentOpenCycle, assessmentOpenRoot, assessmentMarker, assessmentNow)
	})

	for _, planted := range []struct{ cycle, assessment, snapshot shared.ID }{
		{assessmentClosedCycle, assessmentRoot, assessmentRootSnapshot},
		{assessmentClosedCycle, assessmentFinal, assessmentFinalSnapshot},
		{assessmentLegacyCycle, assessmentLegacyRoot, assessmentLegacySnapshot},
		{assessmentOpenCycle, assessmentOpenRoot, assessmentOpenSnapshot},
	} {
		snapshot := assessmentSeedSnapshot(w, tenant, planted.cycle, planted.assessment, planted.snapshot)
		if _, created, err := snapshots.CreateFinalizedCAS(ctx, snapshot, 0); err != nil || !created {
			t.Fatalf("store assessment snapshot %s: created=%v err=%v", planted.snapshot, created, err)
		}
	}

	// One finding identity, observed in the root and the final snapshot, gives the lifecycle
	// comparison its one item.
	lineage := memory.NewFindingLineageRepository()
	target := "repository:https://example.com/repository.git@0123456789abcdef0123456789abcdef01234567"
	canonical, err := findinglineage.CanonicalizeFingerprintV1(findinglineage.FingerprintCanonicalInputV1{
		CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: target,
		IdentityFields: map[string]findinglineage.CanonicalValue{"rule_id": findinglineage.Text("assessment-seed-rule")},
	})
	if err != nil {
		t.Fatalf("canonicalize the assessment finding: %v", err)
	}
	identity := findinglineage.Identity{
		TenantID: tenant, CycleID: assessmentClosedCycle, ID: assessmentIdentity, ProducerKind: "sca", FindingKind: "vulnerability",
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: canonical.Fingerprint, TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: target, CanonicalIdentityFields: canonical.IdentityFields, FirstSeenSnapshotID: assessmentRootSnapshot, CreatedAt: assessmentNow,
	}
	risk := 5000
	observation := func(id, snapshotID shared.ID) findinglineage.Observation {
		// Medium, so the item stays actionable without becoming a closure blocker.
		return findinglineage.Observation{
			TenantID: tenant, CycleID: assessmentClosedCycle, ID: id, SnapshotID: snapshotID, IdentityID: identity.ID, ProducerKind: "sca", FindingKind: "vulnerability",
			TargetCanonical: target, SourceFindingID: "source-" + id.String(), Severity: shared.SeverityMedium, RiskScoreMilli: &risk,
			ComponentVersion: "1.0.0", Location: "go.mod", Reachability: "reachable", EvidenceDigest: strings.Repeat("a", 64),
			ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sca", ToolVersion: "1", LaneKey: "sca", RuleID: "assessment-seed-rule"}, ObservedAt: assessmentNow,
		}
	}
	if err := lineage.CreateIdentityWithObservation(ctx, identity, observation("assessment-seed-observation-root", assessmentRootSnapshot)); err != nil {
		t.Fatalf("store the assessment finding identity: %v", err)
	}
	if err := lineage.AppendObservation(ctx, observation("assessment-seed-observation-final", assessmentFinalSnapshot)); err != nil {
		t.Fatalf("store the final assessment finding observation: %v", err)
	}

	clock := fixedClock{t: assessmentNow}
	transactions := memory.NewTenantTransactionRunner()
	comparisons := memory.NewAssessmentComparisonRepository()
	verification, err := comparisonuc.NewRetestVerificationReader(lineage, snapshots, memory.NewRetestRepository())
	if err != nil {
		t.Fatalf("comparison verification reader: %v", err)
	}
	comparisonService, err := comparisonuc.NewService(comparisons, snapshots, cycles, lineage, transactions, w.audit, clock,
		&assessmentSeedIDs{prefix: "assessment-seed-comparison"}, verification, nil)
	if err != nil {
		t.Fatalf("assessment comparison service: %v", err)
	}
	reviewer, err := lineageuc.NewService(lineage, transactions, w.audit, clock, &assessmentSeedIDs{prefix: "assessment-seed-review"}, nil)
	if err != nil {
		t.Fatalf("finding lineage service: %v", err)
	}
	queue := memory.NewJobQueue(&assessmentSeedIDs{prefix: "assessment-seed-job"}, clock.Now)
	comparisonService.SetAPIStores(memory.NewAssessmentCycleRequestRepository(), queue, reviewer)
	queued, created, decision, err := comparisonService.Queue(ctx, comparisonuc.QueueInput{
		TenantID: tenant, BaselineSnapshotID: assessmentRootSnapshot, CurrentSnapshotID: assessmentFinalSnapshot, Mode: cmpdom.ModeLifecycle,
		FingerprintVersion: 1, RiskModelVersion: comparisonuc.RiskModelVersionV1, Actor: assessmentMarker,
	})
	if err != nil || !created || !decision.Allowed {
		t.Fatalf("queue the assessment comparison: created=%v decision=%+v err=%v", created, decision, err)
	}
	completed, err := comparisonService.Generate(ctx, comparisonuc.WorkInput{TenantID: tenant, ComparisonID: queued.ID, Actor: assessmentMarker})
	if err != nil || completed.Status != cmpdom.StatusComplete || len(completed.Items) != 1 {
		t.Fatalf("generate the assessment comparison: status=%s items=%d err=%v", completed.Status, len(completed.Items), err)
	}
	if want := assessmentComparisonItemID(assessmentComparison, assessmentIdentity); completed.ID != assessmentComparison || completed.Items[0].ID != want {
		t.Fatalf("planted comparison %s with item %s, but the routes are addressed with %s and %s", completed.ID, completed.Items[0].ID, assessmentComparison, want)
	}

	// Closure needs the real decision reader and report renderer over the same stores; the relationship
	// previews need the comparison service to recompute what a change would replace.
	decisions, err := cycleuc.NewClosureDecisionReader(lineage, snapshots, memory.NewRetestRepository(), memory.NewSLAStore())
	if err != nil {
		t.Fatalf("closure decision reader: %v", err)
	}
	reporter, err := cycleuc.NewClosureReportService(cycles, cycles, snapshots, comparisons, decisions, w.audit)
	if err != nil {
		t.Fatalf("closure report service: %v", err)
	}
	key := []byte(strings.Repeat("assessment-seed-preview-key-", 2))
	if err := api.SetClosureDependencies(cycles, snapshots, comparisons, decisions, reporter, queue, key); err != nil {
		t.Fatalf("wire assessment closure: %v", err)
	}
	if err := api.SetRelationshipChangeDependencies(snapshots, comparisons, lineage, memory.NewScanJobStore(), comparisonService, key); err != nil {
		t.Fatalf("wire assessment relationship changes: %v", err)
	}
	reason := "closed by " + assessmentMarker
	preview, err := api.PreviewClosure(ctx, cycleuc.ClosurePreviewInput{TenantID: tenant, Actor: assessmentMarker, CycleID: assessmentClosedCycle, Reason: reason})
	if err != nil || preview.PreviewToken == "" {
		t.Fatalf("preview the assessment cycle closure: blockers=%+v err=%v", preview.Policy.Blockers, err)
	}
	commit, err := api.CommitClosure(ctx, cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: tenant, Actor: assessmentMarker, Route: "assessment seed", IdempotencyKey: "assessment-seed-closure"},
		CycleID: assessmentClosedCycle, ExpectedVersion: preview.CycleVersion, PreviewToken: preview.PreviewToken, Reason: reason,
	})
	if err != nil {
		t.Fatalf("close the assessment cycle: %v", err)
	}
	var closure cycleuc.ClosureCommitResult
	if err := json.Unmarshal(commit.Body, &closure); err != nil {
		t.Fatalf("decode the assessment cycle closure: %v", err)
	}
	if closure.Manifest.ID != assessmentManifest.String() {
		t.Fatalf("closed the assessment cycle with manifest %s, but the routes are addressed with %s", closure.Manifest.ID, assessmentManifest)
	}

	relationships, err := relationshipuc.NewService(memory.NewAssessmentRelationshipRepository(), cycles, snapshots, lineage, transactions,
		&assessmentSeedIDs{prefix: "assessment-seed-candidate"}, clock, w.audit, nil)
	if err != nil {
		t.Fatalf("assessment relationship service: %v", err)
	}
	// The exact boundary alone is not evidence enough for a candidate, so an imported reference
	// digest is the second signal.
	candidate, created, err := relationships.Generate(ctx, relationshipuc.GenerateInput{
		TenantID: tenant, PredecessorCycleID: assessmentLegacyCycle, SuccessorCycleID: assessmentOpenCycle,
		ImportedReferenceHash: strings.Repeat("c", 64), Actor: assessmentMarker,
	})
	if err != nil || !created || candidate.ID != assessmentCandidate {
		t.Fatalf("planted relationship candidate %s (created=%v err=%v), but the routes are addressed with %s", candidate.ID, created, err, assessmentCandidate)
	}

	w.rt.SetAssessmentComparisons(comparisonService)
	w.rt.SetAssessmentRelationships(relationships)
	return []string{assessmentMarker, assessmentFinalSnapshot.String()}
}

// assessmentSeedSnapshot builds a finalized snapshot of one native run whose single lane covered
// its whole scope, so the closure policy finds no coverage gap. The marker is its actor.
func assessmentSeedSnapshot(w *harnessWorld, tenant, cycleID, assessmentID, snapshotID shared.ID) *snapshotdom.Snapshot {
	t := w.t
	t.Helper()
	runID := "assessment-seed-run-" + snapshotID.String()
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repository.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatalf("canonicalize the assessment scan target: %v", err)
	}
	finished := assessmentNow.Add(-time.Minute)
	lanes := []scanrun.Lane{{
		TenantID: tenant, EngagementID: assessmentID, ScanRunID: runID, LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded,
		Target: target, AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
		StartedAt: finished.Add(-time.Minute), FinishedAt: &finished, ResultRef: "result:" + runID, EvidenceRef: "evidence:" + runID,
		ResultSHA256: strings.Repeat("a", 64), ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, SealedAt: &finished,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}},
		Stages:   []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: finished.Add(-time.Minute), FinishedAt: &finished}},
	}}
	if lanes[0].ManifestHash, err = scanrun.ComputeManifestHash(lanes[0]); err != nil {
		t.Fatalf("hash the assessment scan lane: %v", err)
	}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		t.Fatalf("hash the assessment scan run: %v", err)
	}
	snapshot, err := snapshotdom.NewFinalized(tenant, snapshotID, cycleID, assessmentID, snapshotdom.Boundary{Kind: cycledom.BoundaryStandalone},
		"request-"+snapshotID.String(), assessmentMarker, assessmentNow, []snapshotdom.SelectedRun{{
			ID: runID, ManifestHash: manifestHash, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: lanes,
		}})
	if err != nil {
		t.Fatalf("build assessment snapshot %s: %v", snapshotID, err)
	}
	return snapshot
}

// assessmentComparisonItemID is the id a comparison gives the item for one finding identity, a digest
// of the two that the domain computes when the comparison completes. Run fails if the planted item
// comes back under another id, so the review routes stay addressed at the item that exists.
func assessmentComparisonItemID(comparisonID, identityID shared.ID) shared.ID {
	digest := sha256.Sum256([]byte("synapse:assessment-comparison-item:v1\x00" + comparisonID.String() + "\x00" + identityID.String()))
	return shared.ID("comparison-item-" + hex.EncodeToString(digest[:16]))
}

// assessmentSeedIDs hands out distinct, predictable ids under one prefix, so the routes can be
// addressed with ids known before the records exist.
type assessmentSeedIDs struct {
	prefix string
	n      int
}

func (g *assessmentSeedIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("%s-%d", g.prefix, g.n))
}
