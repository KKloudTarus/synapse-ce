package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// engmiscMarker appears in the body of an engagement analysis route only when tenantA's own row was
// served. It is distinct from every identifier the other seeds plant, and a tenantB response must
// never contain it.
const engmiscMarker = "tenantA-engmisc-marker"

// engmiscNow is the instant every row planted by this seed carries, so the responses are stable.
var engmiscNow = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

// The sweep fills each path parameter with a fixed value (harnessPathValues): sessions, runs and
// findings are all addressed by these ids, so the planted rows must carry exactly them.
const (
	engmiscEngagement = shared.ID("engA")
	engmiscSession    = shared.ID("s1")
	engmiscRun        = shared.ID("r1")
	engmiscFinding    = shared.ID("f1")
	engmiscAsset      = shared.ID("asset-A")
	// engmiscDetection is the detection whose provenance the seed plants. Its id carries the marker,
	// so the transitions route, which echoes it on every row, answers a body only tenantA's row can fill.
	engmiscDetection = shared.ID("detection-" + engmiscMarker)
	// engmiscSnapshot is the snapshot the seed plants behind the router's snapshot service, under the
	// id the hand-written cross-tenant cases already address. Its actor is the marker.
	engmiscSnapshot = shared.ID("snapshot-A")
	// engmiscTicketLink is the id the ticket workflow's own generator gives the one manual link the
	// seed creates; seedEngmiscTickets fails if the link comes back under another id.
	engmiscTicketLink = shared.ID("engmisc-id-1")
	// engmiscImportedFinding is the imported observation seedEngmiscImportedFindings plants.
	engmiscImportedFinding = shared.ID("engmisc-imported")
	// The Jira mapping, intent and integration seedEngmiscTicketRecords plants.
	engmiscTicketMapping     = shared.ID("engmisc-ticket-mapping-A")
	engmiscTicketIntent      = shared.ID("engmisc-ticket-intent-A")
	engmiscTicketIntegration = shared.ID("engmisc-jira-integration-A")
)

func init() {
	registerHarnessSeed(harnessSeed{
		Name: "engmisc",
		Routes: []string{
			"GET /api/v1/assessment-snapshots/{snapshotId}",
			"GET /api/v1/engagements/{id}/agent/approvals",
			"GET /api/v1/engagements/{id}/agent/sessions",
			"GET /api/v1/engagements/{id}/agent/sessions/{sid}",
			"GET /api/v1/engagements/{id}/agent/sessions/{sid}/decisions",
			"GET /api/v1/engagements/{id}/agent/sessions/{sid}/plan",
			"GET /api/v1/engagements/{id}/agent/sessions/{sid}/stream",
			"GET /api/v1/engagements/{id}/cspm/runs/{rid}",
			"GET /api/v1/engagements/{id}/dast/runs/{rid}",
			"GET /api/v1/engagements/{id}/detection-provenance",
			"GET /api/v1/engagements/{id}/detections/{did}/provenance",
			"GET /api/v1/engagements/{id}/documents",
			"GET /api/v1/engagements/{id}/findings/{fid}/ticket-observations",
			"GET /api/v1/engagements/{id}/findings/{fid}/tickets",
			"GET /api/v1/engagements/{id}/imported-findings",
			"GET /api/v1/engagements/{id}/risk-stories",
			"GET /api/v1/engagements/{id}/risk-stories/{assetID}",
			"GET /api/v1/engagements/{id}/snapshots",
			"GET /api/v1/engagements/{id}/threat-model",
			"GET /api/v1/engagements/{id}/writeup-drafts",
			"GET /api/v1/projects/{key}/documents",
			"GET /api/v1/projects/{key}/source-findings/{fid}/ticket-observations",
			"GET /api/v1/projects/{key}/source-findings/{fid}/tickets",
		},
		PathValues: map[string]string{"{did}": engmiscDetection.String()},
		RoutePathValues: map[string]map[string]string{
			"GET /api/v1/assessment-snapshots/{snapshotId}":                           {"{snapshotId}": engmiscSnapshot.String()},
			"POST /api/v1/engagements/{id}/imported-findings/{observationId}/binding": {"{observationId}": engmiscImportedFinding.String()},
			"PUT /api/v1/ticket-mappings/{mappingID}":                                 {"{mappingID}": engmiscTicketMapping.String()},
			"DELETE /api/v1/ticket-mappings/{mappingID}":                              {"{mappingID}": engmiscTicketMapping.String()},
			"POST /api/v1/ticket-intents/{intentID}/reconcile":                        {"{intentID}": engmiscTicketIntent.String()},
			"POST /api/v1/ticket-intents/{intentID}/retry":                            {"{intentID}": engmiscTicketIntent.String()},
			"POST /api/v1/integrations/{integrationID}/jira-breaker/reset":            {"{integrationID}": engmiscTicketIntegration.String()},
			"GET /api/v1/integrations/{integrationID}/jira-metadata":                  {"{integrationID}": engmiscTicketIntegration.String()},
			"GET /api/v1/integrations/{integrationID}/ticket-metadata":                {"{integrationID}": engmiscTicketIntegration.String()},
			// The link is created under engagement engA. The project-scoped route resolves the project's
			// hidden context engagement instead, so it reaches no link and stays vacuous.
			"DELETE /api/v1/engagements/{id}/findings/{fid}/tickets/{linkID}":      {"{linkID}": engmiscTicketLink.String()},
			"DELETE /api/v1/projects/{key}/source-findings/{fid}/tickets/{linkID}": {"{linkID}": engmiscTicketLink.String()},
		},
		Run: seedEngmisc,
	})
}

// engmiscSeedStep is one subsystem the engagement analysis routes read. Each step wires its subsystem
// into the router and plants tenantA's row; the steps share nothing but the world.
type engmiscSeedStep struct {
	name string
	run  func(w *harnessWorld)
}

// seedEngmisc wires the engagement analysis subsystems the generated cross-tenant sweep otherwise
// cannot reach (agent sessions, imported findings, threat model, write-up drafts, detection
// provenance, risk stories, DAST runs, ticket links, document links, assessment snapshots) and
// plants one tenantA row in each, so a tenantB probe of the same path proves a real absence.
func seedEngmisc(w *harnessWorld) []string {
	w.t.Helper()
	for _, step := range []engmiscSeedStep{
		{"agent sessions", seedEngmiscAgent},
		{"imported findings", seedEngmiscImportedFindings},
		{"threat model", seedEngmiscThreatModel},
		{"write-up drafts", seedEngmiscWriteupDrafts},
		{"detection provenance", seedEngmiscDetectionProvenance},
		{"risk stories", seedEngmiscRiskStories},
		{"dast runs", seedEngmiscDASTRuns},
		{"ticket links", seedEngmiscTickets},
		{"document links", seedEngmiscDocuments},
		{"assessment snapshots", seedEngmiscSnapshots},
		{"cspm runs", seedEngmiscCSPM},
	} {
		step.run(w)
	}
	return []string{engmiscMarker}
}

// engmiscTenantCtx is the context a store write needs: the memory stores read the tenant from it.
func engmiscTenantCtx() context.Context {
	return shared.WithTenant(context.Background(), "tenantA")
}

// engmiscClock hands out the fixed seed instant.
type engmiscClock struct{}

func (engmiscClock) Now() time.Time { return engmiscNow }

// engmiscIDs hands out distinct ids, so two rows planted through one use case never collide.
type engmiscIDs struct{ n int }

func (g *engmiscIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("engmisc-id-%d", g.n))
}
