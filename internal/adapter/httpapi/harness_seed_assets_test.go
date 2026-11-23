package httpapi

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/businessassetuc"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/endpointstate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/legalholduc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/privacyexport"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// assetsMarker is planted in the text of every tenantA record this seed creates, so a response that
// carries it can only have been built from tenantA's data. It is a superset of the sweep's broad
// "tenantA" marker on purpose: a route whose rows do not echo the tenant id still carries it.
const assetsMarker = "tenantA-assets-marker"

func init() {
	registerHarnessSeed(harnessSeed{
		Name: "assets",
		Routes: []string{
			"GET /api/v1/appsec/assets/{assetID}",
			"GET /api/v1/appsec/assets/{assetID}/coverage",
			"GET /api/v1/appsec/assets/{assetID}/engagements",
			"GET /api/v1/appsec/assets/{assetID}/findings",
			"GET /api/v1/appsec/assets/{assetID}/history",
			"GET /api/v1/appsec/assets/{assetID}/posture",
			"GET /api/v1/appsec/assets/{assetID}/projects",
			"GET /api/v1/appsec/assets/{assetID}/technical-assets",
			"GET /api/v1/assets/{assetID}/packages",
			"GET /api/v1/assets/{assetID}/vulnerabilities",
			"GET /api/v1/fleet/assets/{id}/desired-capabilities",
			"GET /api/v1/fleet/assets/{id}/processes",
			"GET /api/v1/fleet/assets/{id}/timeline",
			"GET /api/v1/fleet/engagements/{id}/privacy-export",
		},
		Run: seedAssets,
	})
}

// The seeded services write their audit entries to a private fakeAudit each, not to the harness audit
// log: tests elsewhere read that log, and a seed must not change what they see.

// assetsTaggedPosture is the real business-asset service with one change: a posture it computed
// successfully carries assetsMarker in its explanation. A posture is only a rating, an explanation and
// two count maps, none of which names the tenant, so without the tag a foreign caller that was wrongly
// answered with tenantA's posture would get a body the sweep cannot tell from an empty one. The wrapper
// never looks at the tenant: it tags what the service returned and passes every error through, so it
// cannot hide a missing guard and cannot invent a leak that the service did not make.
type assetsTaggedPosture struct{ *businessassetuc.Service }

func (s assetsTaggedPosture) Posture(ctx context.Context, tenantID, id shared.ID) (businessassetuc.Posture, error) {
	posture, err := s.Service.Posture(ctx, tenantID, id)
	if err == nil {
		posture.Explanation += " (" + assetsMarker + ")"
	}
	return posture, err
}

// assetsNoBindings and assetsNoAgents stand in for the two desired-state inputs that only the gap
// report reads. The routes this seed targets read the stored desired state, never a binding or an agent,
// and a stand-in that is always empty cannot answer for a tenant by accident.
type assetsNoBindings struct{}

func (assetsNoBindings) ListCurrentBindings(context.Context, shared.ID) ([]desireduc.CurrentBinding, error) {
	return nil, nil
}

type assetsNoAgents struct{}

func (assetsNoAgents) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	return nil, nil
}

// seedAssets wires the business-asset (appsec) service, the fleet process, timeline, desired-capability
// and privacy-export services, and plants tenantA data for them. The path values the generated sweep
// substitutes are fixed by harnessPathValues: {assetID} is "asset-A" and {id} is "engA", and the fleet
// routes read {id} as an ASSET id. So tenantA gets a business asset and a host asset both named
// "asset-A", and a host asset named "engA", so that each route can find the record its path names.
func seedAssets(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	at := time.Unix(1, 0).UTC()
	ctx := shared.WithTenant(context.Background(), "tenantA")

	// Technical host assets. "asset-A" is what the host package and vulnerability routes (/assets/{assetID}/...)
	// are asked for; "engA" is what the fleet routes (/fleet/assets/{id}/...) are asked for.
	for _, h := range []*asset.Asset{
		{ID: "asset-A", TenantID: "tenantA", Kind: asset.KindHost, Key: "machine-id/asset-A", Name: assetsMarker + " host", Attributes: map[string]string{"os": "linux"}},
		{ID: "engA", TenantID: "tenantA", Kind: asset.KindHost, Key: "machine-id/engA", Name: assetsMarker + " fleet host", Attributes: map[string]string{"os": "linux"}},
	} {
		if err := w.assets.UpsertAsset(ctx, h); err != nil {
			t.Fatalf("seed host asset %s: %v", h.ID, err)
		}
	}

	seedBusinessAsset(ctx, w, at)
	seedFleetAssets(ctx, w, at)
	return []string{assetsMarker, "bizeng-A", "bizfind-A"}
}

// seedBusinessAsset plants one tenantA business asset with a project and a technical asset linked, one
// engagement assigned to it, and one finding on that engagement, then wires the real service over the
// same in-memory store the technical assets live in.
func seedBusinessAsset(ctx context.Context, w *harnessWorld, at time.Time) {
	t := w.t
	t.Helper()
	// The store lists a business asset's engagements through the engagement repository.
	w.assets.SetEngagementRepository(w.engagements)

	findings := memory.NewFindingRepository()
	svc, err := businessassetuc.NewService(w.assets, findings, memory.NewImportedFindingStore(), memory.NewJudgmentStore(), memory.NewRetestRepository(), &fakeAudit{}, fixedClock{t: at}, engIDs{})
	if err != nil {
		t.Fatalf("business asset service: %v", err)
	}

	// The id equals the key, so the route resolves it as an id and as a key alike.
	business, err := asset.NewBusinessAsset("asset-A", "tenantA", "asset-A", assetsMarker+" payments", "owned by tenantA", asset.BusinessAssetApplication, asset.CriticalityHigh, "tenantA-owner", nil, "seed", at)
	if err != nil {
		t.Fatalf("build business asset: %v", err)
	}
	if err := w.assets.CreateBusinessAsset(ctx, business); err != nil {
		t.Fatalf("seed business asset: %v", err)
	}

	// The engagement carries the marker in its name and in a scope value, because the history and
	// coverage reads echo those and nothing else of it.
	if err := w.engagements.Create(ctx, &engagement.Engagement{
		ID: "bizeng-A", TenantID: "tenantA", Name: assetsMarker + " engagement", Client: "tenantA", Status: engagement.StatusActive,
		Scope: engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetRepo, Value: "https://git.example/" + assetsMarker}}},
	}); err != nil {
		t.Fatalf("seed business asset engagement: %v", err)
	}
	f, err := finding.NewManual("bizfind-A", "bizeng-A", finding.ManualInput{Title: assetsMarker + " finding", Severity: shared.SeverityHigh}, at)
	if err != nil {
		t.Fatalf("build business asset finding: %v", err)
	}
	if err := findings.Upsert(ctx, []finding.Finding{f}); err != nil {
		t.Fatalf("seed business asset finding: %v", err)
	}

	// Plant the links and the assignment through the service, so they take the path a request takes.
	if err := svc.ReplaceProjects(ctx, "tenantA", "asset-A", []asset.ComponentMembership{
		{ComponentID: "project-a", Role: asset.MembershipPrimary, Provenance: assetsMarker},
	}, "seed"); err != nil {
		t.Fatalf("seed business asset projects: %v", err)
	}
	if err := svc.ReplaceTechnicalAssets(ctx, "tenantA", "asset-A", []asset.ComponentMembership{
		{ComponentID: "host-A", Role: asset.MembershipSupporting, Provenance: assetsMarker},
	}, "seed"); err != nil {
		t.Fatalf("seed business asset technical assets: %v", err)
	}
	if err := svc.AssignEngagement(ctx, "tenantA", "bizeng-A", "asset-A", "seed"); err != nil {
		t.Fatalf("seed business asset engagement assignment: %v", err)
	}
	w.rt.SetBusinessAssets(assetsTaggedPosture{svc})
}

// seedFleetAssets wires the fleet read services that live behind the incident block of the route table,
// and plants tenantA data for the host "engA" and the engagement "engA". The incident reader is wired
// over an empty event store only because the block registers nothing without it; no incident is planted.
func seedFleetAssets(ctx context.Context, w *harnessWorld, at time.Time) {
	t := w.t
	t.Helper()

	incidents, err := incidentuc.NewService(memory.NewIncidentEventStore())
	if err != nil {
		t.Fatalf("incident service: %v", err)
	}
	w.rt.SetIncidents(incidents)

	processes := memory.NewEndpointProcessStore()
	if err := processes.SaveProcesses(ctx, []ports.ProcessSnapshot{{
		TenantID: "tenantA", AssetID: "engA", EntityID: "proc-assets-A", PID: 4242, Comm: assetsMarker, Path: "/usr/bin/" + assetsMarker, Running: true, LastSeenAt: at,
	}}); err != nil {
		t.Fatalf("seed process snapshot: %v", err)
	}
	w.rt.SetEndpointProcesses(processes)

	timelineStore := memory.NewEndpointTimelineStore()
	if err := timelineStore.AppendTimeline(ctx, []endpoint.TimelineEntry{{
		OccurredAt: at, TenantID: "tenantA", AssetID: "engA", EntityKind: endpoint.EntityProcess, EntityID: "proc-assets-A",
		Kind: endpoint.TimelineProcessStart, EventID: "event-assets-A", Summary: assetsMarker + " started",
	}}); err != nil {
		t.Fatalf("seed timeline entry: %v", err)
	}
	timeline, err := endpointstate.NewService(timelineStore)
	if err != nil {
		t.Fatalf("endpoint timeline service: %v", err)
	}
	w.rt.SetEndpointTimeline(timeline)

	desired, err := desireduc.NewService(memory.NewFleetDesiredStore(), w.assets, assetsNoBindings{}, assetsNoAgents{}, &fakeAudit{}, fixedClock{t: at}, engIDs{}, 24*time.Hour)
	if err != nil {
		t.Fatalf("desired capability service: %v", err)
	}
	// Set through the service: it checks the asset is a host in the tenant, which "engA" now is.
	if _, err := desired.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: "tenantA", AssetID: "engA", Capabilities: []string{"process-telemetry", "file-telemetry"}, Actor: shared.ID(assetsMarker),
	}); err != nil {
		t.Fatalf("seed desired capabilities: %v", err)
	}
	w.rt.SetDesiredCapabilities(desired)

	// Privacy export of engagement "engA": one detection and one legal hold, both tenantA's.
	detections := memory.NewDetectionRecordStore()
	rule, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("detection rule det.process_enumeration is not registered")
	}
	host := shared.ID(assetsMarker + "-host")
	detected, err := detection.NewDetection(rule, host, "agent:assets", []detection.Event{{
		Class: detection.ClassProcess, At: at, Host: host,
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"},
	}}, at)
	if err != nil {
		t.Fatalf("build detection: %v", err)
	}
	if err := detections.AppendDetection(ctx, detection.Record{
		ID: shared.ID(assetsMarker + "-detection"), TenantID: "tenantA", EngagementID: "engA", AssetID: "engA", AgentID: "agent:assets",
		Detection: detected, EvidenceID: "evidence-assets-A", BatchSeq: 1, RecordedAt: at,
	}); err != nil {
		t.Fatalf("seed detection record: %v", err)
	}
	holds, err := legalholduc.NewService(memory.NewLegalHoldStore(), &fakeAudit{}, func() time.Time { return at })
	if err != nil {
		t.Fatalf("legal hold service: %v", err)
	}
	if _, err := holds.Place(ctx, "seed", "engA", assetsMarker+" hold"); err != nil {
		t.Fatalf("seed legal hold: %v", err)
	}
	export, err := privacyexport.NewService(detections, holds, &fakeAudit{}, func() time.Time { return at })
	if err != nil {
		t.Fatalf("privacy export service: %v", err)
	}
	w.rt.SetPrivacyExport(export)
}
