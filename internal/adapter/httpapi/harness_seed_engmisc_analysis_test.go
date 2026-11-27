package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskstory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/threatmodeluc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/writeupdraftuc"
)

// seedEngmiscImportedFindings swaps the harness's empty read side for the real in-memory store holding
// one third-party finding of tenantA. The store is partitioned by tenant, so it is tenantB's empty
// partition that the route must answer when the guard is bypassed.
func seedEngmiscImportedFindings(w *harnessWorld) {
	store := memory.NewImportedFindingStore()
	item := importedfinding.ImportedFinding{
		ID: engmiscImportedFinding, TenantID: "tenantA", EngagementID: engmiscEngagement,
		Severity: shared.SeverityHigh, Title: "title " + engmiscMarker, Message: "message " + engmiscMarker,
		Location: importedfinding.Location{Path: "src/handler.go", StartLine: 12},
		Provenance: importedfinding.Provenance{
			ToolName: "external-scanner", ToolVersion: "1.0", RuleID: "EXT-001", SourceDigest: "digest-" + engmiscMarker,
			IngestedBy: "operator", IngestedAt: engmiscNow,
		},
		Audit: shared.Audit{CreatedAt: engmiscNow, UpdatedAt: engmiscNow},
	}
	if _, _, err := store.Save(engmiscTenantCtx(), "tenantA", []importedfinding.ImportedFinding{item}); err != nil {
		w.t.Fatalf("seed imported finding: %v", err)
	}
	w.rt.SetImportedFindings(store)
}

// seedEngmiscThreatModel replaces the no-op threat-model stand-in with the real use case over the
// in-memory store. That store is keyed by engagement alone, so a missing guard would serve the model.
func seedEngmiscThreatModel(w *harnessWorld) {
	service, err := threatmodeluc.NewService(memory.NewThreatModelStore(), &harnessAudit{}, engmiscClock{})
	if err != nil {
		w.t.Fatalf("threat model service: %v", err)
	}
	model := threatmodel.Model{
		Components: []threatmodel.Component{
			{ID: "web", Name: "web " + engmiscMarker, Kind: threatmodel.KindProcess, Boundary: "dmz"},
			{ID: "db", Name: "database", Kind: threatmodel.KindDataStore, Boundary: "internal"},
		},
		Flows:      []threatmodel.DataFlow{{ID: "flow-1", From: "web", To: "db", Data: "orders"}},
		Boundaries: []threatmodel.TrustBoundary{{ID: "dmz", Name: "dmz"}, {ID: "internal", Name: "internal"}},
	}
	if _, err := service.Ingest(engmiscTenantCtx(), "operator", "tenantA", engmiscEngagement, model); err != nil {
		w.t.Fatalf("seed threat model: %v", err)
	}
	w.rt.SetThreatModel(service)
}

// seedEngmiscWriteupDrafts replaces the no-op draft stand-in with the real use case over the in-memory
// store, which is also keyed by engagement alone. The matrix still denies every sign-off (review) role
// before a draft is touched, so only the read changes.
func seedEngmiscWriteupDrafts(w *harnessWorld) {
	service, err := writeupdraftuc.NewService(memory.NewWriteupDraftStore(), &harnessAudit{}, engmiscClock{}, &engmiscIDs{})
	if err != nil {
		w.t.Fatalf("write-up draft service: %v", err)
	}
	if _, err := service.Propose(engmiscTenantCtx(), "agent:engmisc", engmiscEngagement, engmiscFinding,
		"description "+engmiscMarker, "remediation "+engmiscMarker); err != nil {
		w.t.Fatalf("seed write-up draft: %v", err)
	}
	w.rt.SetWriteupDrafts(service)
}

// engmiscProvenance is a detection-provenance reader that answers tenantA's row to every caller.
//
// The real in-memory store refuses to read without a tenant bound to the context, and the sweep's
// requests carry the tenant only on the principal, so the real store would answer a validation error
// to tenantA as well. This reader binds tenantA itself and filters nothing, which keeps the row
// reachable and leaves the route's tenant guard as the only thing standing between tenantB and it.
type engmiscProvenance struct {
	store *memory.DetectionProvenanceStore
}

func (p engmiscProvenance) ListDetectionProvenance(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error) {
	return p.store.ListCurrent(shared.WithTenant(ctx, "tenantA"), engagementID)
}

func (p engmiscProvenance) DetectionProvenanceTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error) {
	return p.store.ListTransitions(shared.WithTenant(ctx, "tenantA"), engagementID, detectionID)
}

// seedEngmiscDetectionProvenance admits one pending provenance row of tenantA into the real store.
func seedEngmiscDetectionProvenance(w *harnessWorld) {
	store := memory.NewDetectionProvenanceStore()
	detection := engmiscDetection
	current := detectionprovenance.Current{
		TenantID: "tenantA", EngagementID: engmiscEngagement, DetectionID: detection,
		Status: detectionprovenance.StatusPending, PendingInput: []byte("input"), UpdatedAt: engmiscNow,
	}
	received := detectionprovenance.Transition{
		TenantID: "tenantA", EngagementID: engmiscEngagement, DetectionID: detection, Sequence: 1,
		Kind: detectionprovenance.Received, Status: detectionprovenance.StatusPending,
		AgentID: "engmisc-agent", AssetID: engmiscAsset, OccurredAt: engmiscNow,
		TelemetryRefs: []fleetagent.TelemetryReference{{StreamID: "stream-1", Epoch: 1, Sequence: 1, EventID: "event-1", Digest: "digest-1"}},
	}
	if err := store.AdmitPending(engmiscTenantCtx(), current, received); err != nil {
		w.t.Fatalf("seed detection provenance: %v", err)
	}
	w.rt.SetDetectionProvenanceReader(engmiscProvenance{store: store})
}

// engmiscRiskStories answers the same assembled story for every caller. The real assembler derives the
// tenant from the request context, which the sweep's requests do not carry, so it would refuse tenantA
// too; this reader returns tenantA's story unconditionally.
type engmiscRiskStories struct{ story riskstory.Story }

func (r engmiscRiskStories) StoriesForEngagement(context.Context, shared.ID) ([]riskstory.Story, error) {
	return []riskstory.Story{r.story}, nil
}

func (r engmiscRiskStories) StoryForAsset(context.Context, shared.ID, shared.ID) (riskstory.Story, error) {
	return r.story, nil
}

func seedEngmiscRiskStories(w *harnessWorld) {
	story, err := riskstory.Assemble(riskstory.Inputs{
		AssetID: engmiscAsset, TenantID: "tenantA",
		Identity:    riskstory.AssetFacts{Kind: "host", Key: engmiscMarker, Name: engmiscMarker, Provenance: riskstory.Provenance{Kind: riskstory.ProvAsset, ID: engmiscAsset}},
		GeneratedAt: engmiscNow,
	})
	if err != nil {
		w.t.Fatalf("assemble risk story: %v", err)
	}
	w.rt.SetRiskStoryReader(engmiscRiskStories{story: story})
}

// engmiscDASTRuns serves tenantA's runs to every caller, from the real in-memory run store. The
// store keys a run by tenant and id, so this reader pins tenantA instead of using the caller's tenant.
type engmiscDASTRuns struct{ store *memory.DASTRunStore }

func (r engmiscDASTRuns) Submit(context.Context, shared.ID, shared.ID, string, dastrunner.Probe) (dastrun.Run, error) {
	return dastrun.Run{}, fmt.Errorf("%w: the harness never submits a DAST run", shared.ErrForbidden)
}

func (r engmiscDASTRuns) GetRun(ctx context.Context, _, runID shared.ID) (dastrun.Run, error) {
	return r.store.GetDASTRun(ctx, "tenantA", runID)
}

// seedEngmiscDASTRuns replaces the harness's one-run DAST stand-in. The matrix still reads the run
// "dast-run-a", so that row is kept next to the "r1" the generated sweep asks for.
func seedEngmiscDASTRuns(w *harnessWorld) {
	store := memory.NewDASTRunStore()
	finished := engmiscNow.Add(time.Minute)
	for _, id := range []shared.ID{engmiscRun, "dast-run-a"} {
		run := dastrun.Run{
			ID: id, TenantID: "tenantA", EngagementID: engmiscEngagement, ActionID: "act-" + id, Actor: engmiscMarker,
			Status: dastrun.RunSucceeded, Verdict: "confirmed", HTTPStatus: 200, EvidenceID: "evidence-" + id,
			StartedAt: engmiscNow, FinishedAt: &finished,
		}
		if err := store.SaveDASTRun(engmiscTenantCtx(), run); err != nil {
			w.t.Fatalf("seed dast run %s: %v", id, err)
		}
	}
	w.rt.SetDASTRunner(engmiscDASTRuns{store: store})
}
