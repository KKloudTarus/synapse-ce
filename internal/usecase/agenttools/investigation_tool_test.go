package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeIncidentReader struct {
	items     []incident.Incident
	get       map[shared.ID]incident.Incident
	listCalls int
}

func (f *fakeIncidentReader) Get(_ context.Context, id shared.ID) (incident.Incident, error) {
	if inc, ok := f.get[id]; ok {
		return inc, nil
	}
	return incident.Incident{}, shared.ErrNotFound
}

func (f *fakeIncidentReader) ListByDetectionIDs(_ context.Context, ids []shared.ID, limit int) ([]incident.Incident, error) {
	f.listCalls++
	wanted := make(map[shared.ID]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}
	var out []incident.Incident
	for _, inc := range f.items {
		for _, id := range inc.DetectionIDs {
			if _, ok := wanted[id]; ok {
				out = append(out, inc)
				break
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

type fakeDetectionReader struct{ items []detection.Record }

func (f *fakeDetectionReader) ListDetections(_ context.Context, _ shared.ID) ([]detection.Record, error) {
	return append([]detection.Record(nil), f.items...), nil
}

type fakeTimelineReader struct {
	items []endpoint.TimelineEntry
	got   ports.EndpointTimelineQuery
}

func (f *fakeTimelineReader) Query(_ context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	f.got = q
	return append([]endpoint.TimelineEntry(nil), f.items...), nil
}

func fakeInvestigationToolset() *InvestigationToolset {
	now := time.Unix(2_000_000, 0).UTC()
	inc := incident.Incident{
		ID: "inc-7", AssetID: "asset-1", Title: "Suspicious process", Severity: shared.SeverityHigh,
		State: incident.StateInvestigating, Disposition: incident.DispositionUnknown,
		DetectionIDs: []shared.ID{"det-1"}, Revision: 2, CreatedAt: now, UpdatedAt: now.Add(time.Minute),
		Risk: &riskassessment.RiskAssessment{Risk: 88, Confidence: 61, Coverage: 43, ReasonCodes: []string{"network_fanout"}},
	}
	incidents := &fakeIncidentReader{items: []incident.Incident{inc}, get: map[shared.ID]incident.Incident{inc.ID: inc}}
	detections := &fakeDetectionReader{items: []detection.Record{{
		ID: "det-1", TenantID: "tenant-1", EngagementID: "eng-1", AssetID: "asset-1",
		Detection: detection.Detection{Observed: now},
	}}}
	timeline := &fakeTimelineReader{items: []endpoint.TimelineEntry{{
		OccurredAt: now, TenantID: "tenant-1", AssetID: "asset-1", EntityKind: endpoint.EntityProcess,
		EntityID: "proc-1", Kind: endpoint.TimelineProcessExec, EventID: "event-1", Summary: "exec token=secret-value",
	}}}
	return &InvestigationToolset{Incidents: incidents, Detections: detections, Timeline: timeline}
}

func TestProposeInvestigation(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)
	if err := c.EnableInvestigation(*fakeInvestigationToolset()); err != nil {
		t.Fatal(err)
	}

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeInvestigation {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_investigation has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_investigation must be advertised after EnableJudgments")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeInvestigation,
		Arguments: json.RawMessage(`{"incident_id":"inc-7","tactic":"lateral_movement","confidence":72,"drivers":["new_exec_paths","network_fanout_spike"],"relevant_event_ids":["event-1"],"suggested_next_step":"retro_hunt_similar_activity"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Data == nil {
		t.Fatal("must return Data")
	}
	// PROPOSED, score 0, agent-attributed, scoped to the incident, evidence-gated capability.
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapInvestigation || fp.got.SubjectKind != judgment.SubjectIncident || fp.got.SubjectID != "inc-7" || fp.got.EngagementID != "eng-1" {
		t.Fatalf("subject/scope wiring wrong: %+v", fp.got)
	}
	ic, ok := fp.got.Claim.(judgment.InvestigationClaim)
	if !ok || ic.Tactic != judgment.TacticLateralMovement || ic.Confidence != 72 || len(ic.Drivers) != 2 ||
		len(ic.RelevantEventIDs) != 1 || ic.RelevantEventIDs[0] != "event-1" || ic.SuggestedNextStep != judgment.NextRetroHuntSimilar {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
}

func TestProposeInvestigationDisabledFailsClosed(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder()) // no EnableJudgments
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeInvestigation {
			t.Fatal("propose_investigation must not be advertised without a judgment proposer")
		}
	}
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeInvestigation, Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("dispatch must fail closed when judgments are disabled")
	}
}

func TestInvestigationReadsAreEngagementScopedRedactedAndReadOnly(t *testing.T) {
	c, audit := newCatalog(t, nil, nil, subfinder())
	tools := fakeInvestigationToolset()
	// This incident/detection belongs to a different engagement and must never cross the session boundary.
	foreign := incident.Incident{ID: "inc-foreign", AssetID: "asset-2", DetectionIDs: []shared.ID{"det-foreign"}}
	tools.Incidents.(*fakeIncidentReader).items = append(tools.Incidents.(*fakeIncidentReader).items, foreign)
	tools.Incidents.(*fakeIncidentReader).get[foreign.ID] = foreign
	tools.Detections.(*fakeDetectionReader).items = append(tools.Detections.(*fakeDetectionReader).items, detection.Record{
		ID: "det-foreign", TenantID: "tenant-1", EngagementID: "eng-other", AssetID: "asset-2",
	})
	foreignTenant := incident.Incident{ID: "inc-foreign-tenant", AssetID: "asset-1", DetectionIDs: []shared.ID{"det-foreign-tenant"}}
	tools.Incidents.(*fakeIncidentReader).items = append(tools.Incidents.(*fakeIncidentReader).items, foreignTenant)
	tools.Incidents.(*fakeIncidentReader).get[foreignTenant.ID] = foreignTenant
	tools.Detections.(*fakeDetectionReader).items = append(tools.Detections.(*fakeDetectionReader).items, detection.Record{
		ID: "det-foreign-tenant", TenantID: "tenant-other", EngagementID: "eng-1", AssetID: "asset-1",
	})
	tools.Timeline.(*fakeTimelineReader).items = append(tools.Timeline.(*fakeTimelineReader).items, endpoint.TimelineEntry{
		OccurredAt: time.Unix(2_000_000, 0).UTC(), TenantID: "tenant-other", AssetID: "asset-1",
		EntityKind: endpoint.EntityProcess, EntityID: "foreign-process", Kind: endpoint.TimelineProcessExec,
		EventID: "foreign-event", Summary: "FOREIGN_TENANT_EVENT",
	})
	if err := c.EnableInvestigation(*tools); err != nil {
		t.Fatal(err)
	}

	listed, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolListIncidents})
	if err != nil {
		t.Fatal(err)
	}
	if listed.Proposal != nil || strings.Contains(string(listed.Data), "inc-foreign") || !strings.Contains(string(listed.Data), "inc-7") {
		t.Fatalf("incident list crossed scope or became executable: %s", listed.Data)
	}

	contextResult, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name: ToolGetIncidentContext, Arguments: json.RawMessage(`{"incident_id":"inc-7","before_seconds":60,"after_seconds":120,"limit":10}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if contextResult.Proposal != nil {
		t.Fatal("incident context must be read-only")
	}
	body := string(contextResult.Data)
	if strings.Contains(body, "secret-value") || strings.Contains(body, "FOREIGN_TENANT_EVENT") || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("timeline summary was not redacted: %s", body)
	}
	timeline := tools.Timeline.(*fakeTimelineReader)
	if timeline.got.AssetID != "asset-1" || timeline.got.Limit != 11 {
		t.Fatalf("timeline query was not server-scoped/bounded: %+v", timeline.got)
	}
	if len(audit.recs) != 2 || audit.recs[0].Action != "agent.read.incidents" || audit.recs[1].Action != "agent.read.incident_context" {
		t.Fatalf("investigation reads must be audited: %+v", audit.recs)
	}

	_, err = c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name: ToolGetIncidentContext, Arguments: json.RawMessage(`{"incident_id":"inc-foreign"}`),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-engagement incident must fail as not found, got %v", err)
	}
}

func TestListIncidentsWithNoScopedDetectionsDoesNotQueryTenantIncidents(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	incidents := &fakeIncidentReader{items: []incident.Incident{{ID: "tenant-incident", DetectionIDs: []shared.ID{"tenant-detection"}}}}
	if err := c.EnableInvestigation(InvestigationToolset{
		Incidents: incidents, Detections: &fakeDetectionReader{}, Timeline: &fakeTimelineReader{},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolListIncidents})
	if err != nil {
		t.Fatal(err)
	}
	if incidents.listCalls != 0 || strings.Contains(string(result.Data), "tenant-incident") {
		t.Fatalf("an empty engagement must not query or reveal tenant incidents: calls=%d data=%s", incidents.listCalls, result.Data)
	}
}

func TestProposeInvestigationRejectsCrossEngagementIncident(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableJudgments(&fakeJudgmentProposer{})
	tools := fakeInvestigationToolset()
	foreign := incident.Incident{ID: "inc-foreign", AssetID: "asset-2", DetectionIDs: []shared.ID{"det-foreign"}}
	tools.Incidents.(*fakeIncidentReader).get[foreign.ID] = foreign
	if err := c.EnableInvestigation(*tools); err != nil {
		t.Fatal(err)
	}
	_, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeInvestigation,
		Arguments: json.RawMessage(`{"incident_id":"inc-foreign","tactic":"benign","confidence":80,"suggested_next_step":"close_as_benign"}`),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-engagement proposal must fail as not found, got %v", err)
	}
}

func TestProposeInvestigationRejectsEventOutsideBoundedContext(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableJudgments(&fakeJudgmentProposer{})
	if err := c.EnableInvestigation(*fakeInvestigationToolset()); err != nil {
		t.Fatal(err)
	}
	_, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeInvestigation,
		Arguments: json.RawMessage(`{"incident_id":"inc-7","tactic":"execution","confidence":80,"relevant_event_ids":["event-forged"],"suggested_next_step":"inspect_process_tree"}`),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an event outside the server-derived context must fail closed, got %v", err)
	}
}

func TestEnableInvestigationFailsClosedOnPartialDependencies(t *testing.T) {
	c, _ := newCatalog(t, nil, nil)
	err := c.EnableInvestigation(InvestigationToolset{Incidents: &fakeIncidentReader{}})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("partial investigation wiring must fail validation, got %v", err)
	}
	for _, tool := range c.Tools() {
		if tool.Name == ToolListIncidents || tool.Name == ToolGetIncidentContext {
			t.Fatalf("partial investigation wiring advertised %s", tool.Name)
		}
	}
}
