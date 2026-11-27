package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// The cross-tenant write sweep (#1702). The read sweep proves that tenantB cannot SEE
// tenantA's resources. A write that crosses the tenant boundary is worse, because it changes
// tenantA's data instead of revealing it. This sweep sends every tenant-scoped POST, PUT, PATCH and
// DELETE route (isTenantScopedPattern) as a tenantB admin, at the tenantA path the read sweep's
// values address, and fails when tenantB is answered with a success.
//
// A refusal alone proves little: a route that refuses the request for a validation reason refuses
// tenantB without ever reaching its tenant check. So after tenantB's request the sweep sends the
// very same request as tenantA. A route where tenantA's request succeeds is PROVEN: the request was
// good enough to change tenantA's data, and only the tenant made the difference. Every other route
// is VACUOUS and is logged with tenantA's status, so the gap stays visible. harnessWriteProven names
// the proven routes, and the coverage measurement counts those writes and harnessWriteForeignNoEffect.
//
// tenantA's own requests change the fixture, so the sweep runs after every other part of
// TestHostileHarness, and in a fixed order: creates and updates first, then the routes that end a
// record (a delete or an archive), a child before its parent, so that no route removes the record a
// later route addresses.

// harnessWriteRequest is what the write sweep sends to one route beyond the bare path.
type harnessWriteRequest struct {
	// body is the request body.
	body string
	// query is appended to the path, for a handler that reads a precondition from it.
	query string
	// headers are request headers the handler requires before it reads the body.
	headers map[string]string
	// tenantBound binds the caller's tenant into the request context, as the production auth
	// middleware does, for a use case that reads it from there. It is set per route, as in the
	// read sweep, so that a store partitioned by that context cannot stand in for a route guard on
	// a route that does not need it.
	tenantBound bool
}

// harnessWriteDefault is sent to a route that has no entry in harnessWriteRequests.
var harnessWriteDefault = harnessWriteRequest{body: `{}`}

// harnessWriteRequests holds, per route, the request with which tenantA's own write succeeds, so
// that tenantB's refusal of the same request is a tenant decision and not a validation one. Only a
// route that needs more than harnessWriteDefault has an entry. Where a record carries a version,
// the routes that move it name the version the previous route in the sweep's order left behind.
var harnessWriteRequests = map[string]harnessWriteRequest{
	// Engagement-row writes. No withEngTenant: the engagement service scopes them. Moving engA to
	// the status it already has succeeds without changing it, so later routes still find it active.
	"PATCH /api/v1/engagements/{id}":          {body: `{"status":"active"}`},
	"PUT /api/v1/engagements/{id}/status":     {body: `{"status":"active"}`},
	"PUT /api/v1/engagements/{id}/live-recon": {body: `{"enabled":false}`},
	// The key takes tenantB past the handler's idempotency check to the cycle lookup, which is the
	// tenant decision. tenantA is refused too, because a retest needs a completed predecessor and
	// engA stays active for the other routes.
	"POST /api/v1/engagements/{assessmentId}/retests": {headers: map[string]string{"Idempotency-Key": "write-sweep-retest"}, body: `{}`},
	// Business-asset, notification and desired-capability writes, each scoped by its service. The
	// notification service reads the tenant from the context (see the notifications seed).
	"PATCH /api/v1/appsec/assets/{assetID}":                {body: `{"key":"asset-A","name":"write sweep","description":"write sweep","type":"application","criticality":"high","owner":"write-sweep-owner","version":1}`},
	"PUT /api/v1/notifications/engagements/{nid}/settings": {body: `{"external_notifications":"signal","revision":1}`, tenantBound: true},
	"PUT /api/v1/fleet/assets/{id}/desired-capabilities":   {body: `{"capabilities":["process-telemetry"]}`},
	// Project writes, scoped by the project service. The projects seed reviewed the hotspot and the
	// issue once, so both are at version 2.
	"PUT /api/v1/projects/{key}/decoration":                     {body: `{"enabled":false}`},
	"PATCH /api/v1/projects/{key}/source-findings/{fid}":        {body: `{"status":"confirmed","version":1}`},
	"POST /api/v1/projects/{key}/hotspots/{id}/transitions":     {body: `{"to":"safe","rationale":"write sweep","expected_version":2}`},
	"POST /api/v1/projects/{key}/issues/{id}/transitions":       {body: `{"to":"wont_fix","rationale":"write sweep","expected_version":2}`},
	"POST /api/v1/projects/{key}/source-findings/{fid}/tickets": {body: `{"url":"https://tickets.example/T-2"}`},
	// The headers take tenantB past the handler's media-type check to the service. tenantA is
	// refused too: source publication is not configured in this fixture.
	"POST /api/v1/projects/{key}/analyses/{id}/source": {headers: map[string]string{"Content-Type": "application/x-tar", "X-Synapse-Tool-Version": "write-sweep"}},
	// Engagement child writes behind withEngTenant. The core seed leaves finding f1 at version 2.
	"POST /api/v1/engagements/{id}/credentials":             {body: `{"name":"n1","value":"write-sweep-secret"}`},
	"POST /api/v1/engagements/{id}/evidence":                {body: `{"content_base64":"d3JpdGUgc3dlZXA=","filename":"sweep.txt"}`},
	"POST /api/v1/engagements/{id}/findings":                {body: `{"title":"write sweep","severity":"high"}`},
	"POST /api/v1/engagements/{id}/findings/{fid}/comments": {body: `{"body":"write sweep"}`},
	"POST /api/v1/engagements/{id}/findings/{fid}/tickets":  {body: `{"url":"https://tickets.example/T-1"}`},
	"PATCH /api/v1/engagements/{id}/findings/{fid}":         {body: `{"status":"confirmed","version":2}`},
	"POST /api/v1/engagements/{id}/findings/{fid}/retests":  {body: `{"outcome":"still_vulnerable","note":"write sweep","version":3}`},
	"PUT /api/v1/engagements/{id}/findings/{fid}/assignee":  {body: `{"assignee":"p","version":4}`},
	"POST /api/v1/engagements/{id}/sbom":                    {body: `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"write-sweep","version":"1.0.0","purl":"pkg:generic/write-sweep@1.0.0"}]}`},
	// AI-triage review (aitriage seed): claimed by the caller, then decided by its owner.
	"POST /api/v1/ai-triage/reviews/{rid}/claim":    {body: `{"version":1}`},
	"POST /api/v1/ai-triage/reviews/{rid}/decision": {body: `{"decision":"accept","rationale":"write sweep","version":2}`},
	// SIEM sink planted by the siem seed. Each write moves its version by one.
	"PATCH /api/v1/siem/sinks/{id}":       {body: `{"name":"write sweep sink","version":1}`},
	"POST /api/v1/siem/sinks/{id}/origin": {body: `{"origin":"https://splunk-seed-moved.example:8088","secret":"splunk-seed-moved","replay":"cursor","version":2}`},
	"POST /api/v1/siem/sinks/{id}/pause":  {body: `{"version":3}`},
	"POST /api/v1/siem/sinks/{id}/resume": {body: `{"version":4}`},
	"POST /api/v1/siem/sinks/{id}/secret": {body: `{"secret":"splunk-seed-rotated","version":5}`},
	"POST /api/v1/siem/sinks/{id}/test":   {body: ``},
	// Notification channel planted by the notifications seed at revision 1 and paused by its one failed
	// delivery. The update and the resume each move the revision by one, and the test needs it resumed.
	"PATCH /api/v1/notifications/channels/{nid}":       {body: `{"name":"write sweep channel","type":"webhook","enabled":true,"url":"https://hooks-a.example/notify","secret":"write-sweep-signing-secret","revision":1}`, tenantBound: true},
	"POST /api/v1/notifications/channels/{nid}/resume": {body: `{"revision":2}`, tenantBound: true},
	"POST /api/v1/notifications/channels/{nid}/test":   {body: `{}`, tenantBound: true},
	"DELETE /api/v1/notifications/channels/{nid}":      {query: "?revision=3", tenantBound: true},
	// Integration planted by the integrations seed, which leaves it at version 2. Each write that names
	// a version moves it by one; the archive ends it, so it runs last.
	"POST /api/v1/integrations/{id}/bindings":   {body: `{"project_id":"integrations-seed-project","external_key":"pipelines/write-sweep","external_name":"write sweep"}`},
	"POST /api/v1/integrations/{id}/disable":    {body: `{"version":2}`},
	"POST /api/v1/integrations/{id}/enable":     {body: `{"version":3}`},
	"POST /api/v1/integrations/{id}/operations": {body: `{"type":"poll"}`},
	"PUT /api/v1/integrations/{id}":             {body: `{"name":"write sweep integration","endpoint":"https://ci-a.example","version":4}`},
	"POST /api/v1/integrations/{id}/archive":    {body: `{"version":5}`},
	// Assessment cycles planted by the assessment seed. A commit carries the signed, single-use token its
	// own preview returned, and the sweep sends one fixed body, so tenantA's commit is refused at the
	// token check exactly as tenantB's is: the three commit routes stay vacuous. The previews read the
	// closed cycle, at version 4, without changing it. The legacy reopen addresses the legacy cycle,
	// completed at version 2 without a manifest, and the archive ends the open cycle at version 1.
	"POST /api/v1/assessment-cycles/{cycleId}/archive": {headers: map[string]string{"Idempotency-Key": "write-sweep-cycle-archive", "If-Match": `"1"`}},
	"POST /api/v1/assessment-cycles/{cycleId}/closure-commits": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-closure-commit", "If-Match": `"4"`},
		body:    `{"preview_token":"write-sweep-preview","reason":"write sweep"}`,
	},
	"POST /api/v1/assessment-cycles/{cycleId}/closure-previews": {body: `{"reason":"write sweep"}`},
	"POST /api/v1/assessment-cycles/{cycleId}/relationship-commits": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-relationship-commit", "If-Match": `"4"`},
		body:    `{"command":"select_head","selected_head_assessment_id":"assessment-seed-branch","preview_token":"write-sweep-preview","reason":"write sweep"}`,
	},
	"POST /api/v1/assessment-cycles/{cycleId}/relationship-previews": {body: `{"command":"select_head","selected_head_assessment_id":"assessment-seed-branch"}`},
	"POST /api/v1/assessment-cycles/{cycleId}/reopen": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-cycle-reopen", "If-Match": `"2"`},
		body:    `{"reason":"write sweep"}`,
	},
	"POST /api/v1/assessment-cycles/{cycleId}/reopen-commits": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-reopen-commit", "If-Match": `"4"`},
		body:    `{"preview_token":"write-sweep-preview","reason":"write sweep"}`,
	},
	// The comparison planted by the assessment seed, at version 3, and its one item. A review resolves a
	// lineage match candidate for an item pending identity review, and the seed's item is not pending
	// review, so tenantA's request is refused after it has found the comparison and the item: both review
	// routes stay vacuous.
	"POST /api/v1/assessment-comparisons/{comparisonId}/items/{itemId}/confirm": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-comparison-confirm", "If-Match": `"3"`},
		body:    `{"candidate_id":"write-sweep-candidate","source_observation_id":"assessment-seed-observation-final","reason":"write sweep"}`,
	},
	"POST /api/v1/assessment-comparisons/{comparisonId}/items/{itemId}/unlink": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-comparison-unlink", "If-Match": `"3"`},
		body:    `{"candidate_id":"write-sweep-candidate","source_observation_id":"assessment-seed-observation-final","reason":"write sweep"}`,
	},
	// The relationship candidate planted by the assessment seed, at version 1. Dismissing it records the
	// decision and changes no cycle.
	"POST /api/v1/assessment-relationship-candidates/{candidateId}/decisions": {
		headers: map[string]string{"Idempotency-Key": "write-sweep-relationship-decision", "If-Match": `"1"`},
		body:    `{"action":"dismiss","reason":"write sweep"}`,
	},
}

// harnessWriteProven names the routes the sweep proves: tenantB is refused and tenantA's same
// request succeeds. The sweep fails when a listed route is not proven and when a proven route is not
// listed, so the coverage measurement (TestTenantScopedRoutesAreCoveredByTheHostileHarness), which
// counts these routes and harnessWriteForeignNoEffect alone, never counts a write the sweep did not
// prove.
var harnessWriteProven = []string{
	// Engagement rows, scoped by the engagement service.
	"PATCH /api/v1/engagements/{id}",
	"PUT /api/v1/engagements/{id}/asset",
	"PUT /api/v1/engagements/{id}/authorization-window",
	"PUT /api/v1/engagements/{id}/live-recon",
	"PUT /api/v1/engagements/{id}/offensive-roe",
	"PUT /api/v1/engagements/{id}/roe",
	"PUT /api/v1/engagements/{id}/scope",
	"PUT /api/v1/engagements/{id}/status",
	// Engagement children behind withEngTenant.
	"DELETE /api/v1/engagements/{id}/credentials/{name}",
	"PATCH /api/v1/engagements/{id}/findings/{fid}",
	"POST /api/v1/engagements/{id}/credentials",
	"POST /api/v1/engagements/{id}/dast/approvals/{aid}/decide",
	"POST /api/v1/engagements/{id}/emulation",
	"POST /api/v1/engagements/{id}/evidence",
	"POST /api/v1/engagements/{id}/exploitation/rehearsals",
	"POST /api/v1/engagements/{id}/findings",
	"POST /api/v1/engagements/{id}/findings/{fid}/comments",
	"POST /api/v1/engagements/{id}/findings/{fid}/retests",
	"POST /api/v1/engagements/{id}/findings/{fid}/tickets",
	"POST /api/v1/engagements/{id}/findings/{fid}/verify",
	"POST /api/v1/engagements/{id}/judgments/{jid}/runtime-verification",
	"POST /api/v1/engagements/{id}/judgments/{jid}/runtime-verification/proposals",
	"POST /api/v1/engagements/{id}/sarif",
	"POST /api/v1/engagements/{id}/sbom",
	"PUT /api/v1/engagements/{id}/findings/{fid}/assignee",
	"PUT /api/v1/engagements/{id}/threat-model",
	// Projects.
	"DELETE /api/v1/projects/{key}",
	"PATCH /api/v1/projects/{key}/source-findings/{fid}",
	"POST /api/v1/projects/{key}/hotspots/{id}/transitions",
	"POST /api/v1/projects/{key}/issues/{id}/transitions",
	"POST /api/v1/projects/{key}/source-findings/{fid}/tickets",
	"PUT /api/v1/projects/{key}/decoration",
	// Business assets and fleet assets.
	"PATCH /api/v1/appsec/assets/{assetID}",
	"PUT /api/v1/appsec/assets/{assetID}/projects",
	"PUT /api/v1/appsec/assets/{assetID}/technical-assets",
	"POST /api/v1/fleet/assets/{id}/processes",
	"PUT /api/v1/fleet/assets/{id}/desired-capabilities",
	// Assessment cycles and relationship candidates (assessment seed).
	"POST /api/v1/assessment-cycles/{cycleId}/archive",
	"POST /api/v1/assessment-cycles/{cycleId}/closure-previews",
	"POST /api/v1/assessment-cycles/{cycleId}/relationship-previews",
	"POST /api/v1/assessment-cycles/{cycleId}/reopen",
	"POST /api/v1/assessment-cycles/{cycleId}/reopen-previews",
	"POST /api/v1/assessment-relationship-candidates/{candidateId}/decisions",
	// AI-triage review (aitriage seed).
	"POST /api/v1/ai-triage/reviews/{rid}/claim",
	"POST /api/v1/ai-triage/reviews/{rid}/decision",
	// Integration (integrations seed).
	"POST /api/v1/integrations/{id}/archive",
	"POST /api/v1/integrations/{id}/bindings",
	"POST /api/v1/integrations/{id}/disable",
	"POST /api/v1/integrations/{id}/enable",
	"POST /api/v1/integrations/{id}/operations",
	"PUT /api/v1/integrations/{id}",
	// Notification channel and engagement setting (notifications seed).
	"DELETE /api/v1/notifications/channels/{nid}",
	"PATCH /api/v1/notifications/channels/{nid}",
	"POST /api/v1/notifications/channels/{nid}/resume",
	"POST /api/v1/notifications/channels/{nid}/test",
	"PUT /api/v1/notifications/engagements/{nid}/settings",
	// SIEM sink (siem seed).
	"PATCH /api/v1/siem/sinks/{id}",
	"POST /api/v1/siem/sinks/{id}/origin",
	"POST /api/v1/siem/sinks/{id}/pause",
	"POST /api/v1/siem/sinks/{id}/resume",
	"POST /api/v1/siem/sinks/{id}/secret",
	"POST /api/v1/siem/sinks/{id}/test",
}

// harnessWriteForeignNoEffect lists the routes that answer a tenantB write at tenantA's path with a
// success that changes nothing of tenantA's, each with the reason. For these the sweep does not
// fail on the success. It reads tenantA's record through the GET route on the same path before and
// after tenantB's request, and fails unless tenantA was served its record before and the record is
// the same after. An entry whose route stops answering tenantB with a success fails as stale, so the
// list cannot outlive the behaviour it describes.
var harnessWriteForeignNoEffect = map[string]string{
	"DELETE /api/v1/fleet/assets/{id}/desired-capabilities": "clearing is idempotent within the caller's own tenant: the service " +
		"finds no desired state for (tenantB, id) and answers 204 without touching tenantA's row",
}

// harnessKnownUnaddressableWrites lists the tenant-scoped write routes the sweep cannot address
// because a path parameter has no value, each with the reason. As with the read sweep, the sweep
// fails for a route missing here and for an entry it can address now. The routes are grouped by
// family.
var harnessKnownUnaddressableWrites = map[string]string{
	"DELETE /api/v1/engagements/{id}/findings/{fid}/tickets/{linkID}":         "the tickets seed plants a link but declares no value for {linkID}",
	"DELETE /api/v1/projects/{key}/source-findings/{fid}/tickets/{linkID}":    "the tickets seed plants a link but declares no value for {linkID}",
	"POST /api/v1/engagements/{id}/imported-findings/{observationId}/binding": "no seed declares a value for {observationId}",
	"PUT /api/v1/fleet/assets/{id}/response-observers/{agentID}":              "no seed declares a value for {agentID}",
	"PUT /api/v1/projects/{key}/profiles/{language}":                          "no seed declares a value for {language}",

	// Notification rules, templates and deliveries: the notifications seed plants an engagement
	// setting and a channel only.
	"PATCH /api/v1/notifications/rules/{nid}":             "notification rule family not seeded yet (#1702)",
	"DELETE /api/v1/notifications/rules/{nid}":            "notification rule family not seeded yet (#1702)",
	"PATCH /api/v1/notifications/templates/{nid}":         "notification template family not seeded yet (#1702)",
	"POST /api/v1/notifications/templates/{nid}/activate": "notification template family not seeded yet (#1702)",
	"POST /api/v1/notifications/templates/{nid}/archive":  "notification template family not seeded yet (#1702)",
	"POST /api/v1/notifications/templates/{nid}/rollback": "notification template family not seeded yet (#1702)",
	"POST /api/v1/notifications/deliveries/{nid}/redrive": "notification delivery family not seeded yet (#1702)",

	// Ticket mappings, intents and the Jira breaker: the ticket workflow the engagement seed wires has
	// no Jira integration, mapping or intent.
	"PUT /api/v1/ticket-mappings/{mappingID}":                      "ticket mapping family not seeded yet (#1702)",
	"DELETE /api/v1/ticket-mappings/{mappingID}":                   "ticket mapping family not seeded yet (#1702)",
	"POST /api/v1/ticket-intents/{intentID}/reconcile":             "ticket intent family not seeded yet (#1702)",
	"POST /api/v1/ticket-intents/{intentID}/retry":                 "ticket intent family not seeded yet (#1702)",
	"POST /api/v1/integrations/{integrationID}/jira-breaker/reset": "ticket metadata family not seeded yet (#1702)",

	// Child records the seeds plant or could plant but do not name.
	"DELETE /api/v1/integrations/{id}/bindings/{bindingID}": "the integrations seed plants a binding but declares no value for {bindingID}",
	"POST /api/v1/agents/{id}/keys/{keyID}/revoke":          "fleet family not seeded yet (#1702)",
	"DELETE /api/v1/users/{id}/oidc-links/{linkId}":         "user family not seeded yet (#1702)",
}

// harnessWritePathValue returns the value the write sweep substitutes for a parameter of a write
// route. A write changes the record a read serves, so it takes, in order: a value a seed declared for
// this write route; the value a seed declared for the GET route at the same path, or at the nearest
// parent path, that carries the parameter; the value the read sweep would use (harnessPathValue).
func harnessWritePathValue(route, param string) (string, bool) {
	for _, seed := range sortedHarnessSeeds() {
		if value, ok := seed.RoutePathValues[route][param]; ok {
			return value, true
		}
	}
	_, path, _ := strings.Cut(route, " ")
	best, bestLen := "", 0
	for _, seed := range sortedHarnessSeeds() {
		for read, values := range seed.RoutePathValues {
			readPath, isGET := strings.CutPrefix(read, http.MethodGet+" ")
			value, declared := values[param]
			if !isGET || !declared || len(readPath) <= bestLen {
				continue
			}
			if path == readPath || strings.HasPrefix(path, readPath+"/") {
				best, bestLen = value, len(readPath)
			}
		}
	}
	if bestLen > 0 {
		return best, true
	}
	return harnessPathValue(route, param)
}

// harnessWritePath turns a write route into the path the write sweep sends, or "" when a parameter
// has no value.
func harnessWritePath(route string) string {
	_, path, _ := strings.Cut(route, " ")
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
		value, ok := harnessWritePathValue(route, param)
		if !ok {
			return ""
		}
		path = path[:open] + value + path[open+closeAt+1:]
	}
}

// harnessCountedWriteRoutes are the write routes the coverage measurement counts: the proven ones,
// and the ones whose foreign success is shown to leave tenantA's record unchanged.
func harnessCountedWriteRoutes() []string {
	out := append([]string(nil), harnessWriteProven...)
	for route := range harnessWriteForeignNoEffect {
		out = append(out, route)
	}
	sort.Strings(out)
	return out
}

// tenantScopedWriteRoutes reads the route table and returns every tenant-scoped POST, PUT, PATCH
// and DELETE route, in the order the write sweep runs them.
func tenantScopedWriteRoutes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, route := range registeredRoutes(t) {
		method, _, _ := strings.Cut(route.Pattern, " ")
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			continue
		}
		if isTenantScopedPattern(route.Pattern) {
			out = append(out, route.Pattern)
		}
	}
	// A delete or an archive ends the record it names, so it runs after every route that may still
	// address that record.
	ends := func(route string) bool {
		return strings.HasPrefix(route, http.MethodDelete+" ") || strings.HasSuffix(route, "/archive")
	}
	sort.Slice(out, func(i, j int) bool {
		iEnds, jEnds := ends(out[i]), ends(out[j])
		if iEnds != jEnds {
			return jEnds
		}
		if iEnds {
			if iDepth, jDepth := strings.Count(out[i], "/"), strings.Count(out[j], "/"); iDepth != jDepth {
				return iDepth > jDepth
			}
		}
		return out[i] < out[j]
	})
	return out
}

// runHostileWriteSweep probes every tenant-scoped write route on mux; see the comment at the top of
// this file.
//
// tenantB must be refused. A success fails the route, and so does a 5xx or a handler that cannot
// run, as in the read sweep: a guard must refuse, not crash, and a crash hides whether the write
// happened. 400, 403 and 404 are the expected refusals. Any other 4xx (405, 409, 415, 422, ...)
// changes nothing either and is not failed, but it is listed: a 409 or a 422 can mean the handler
// read tenantA's record before refusing.
func runHostileWriteSweep(t *testing.T, mux *http.ServeMux) {
	// send runs one request as an admin of tenant and reports whether a handler could run at all.
	// A handler that panics has a dependency this fixture leaves unwired.
	send := func(tenant, method, path string, req harnessWriteRequest) (code int, body string, ran bool) {
		defer func() {
			if recover() != nil {
				ran = false
			}
		}()
		r := httptest.NewRequest(method, path+req.query, strings.NewReader(req.body))
		for name, value := range req.headers {
			r.Header.Set(name, value)
		}
		ctx := context.WithValue(r.Context(), principalKey, Principal{ID: "p", Role: "admin", TenantID: tenant})
		if req.tenantBound {
			ctx = shared.WithTenant(ctx, shared.ID(tenant))
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r.WithContext(ctx))
		return rec.Code, rec.Body.String(), true
	}
	success := func(code int) bool { return code >= 200 && code < 300 }

	var probed int
	var proven, vacuous, otherRefusals, foreignNoEffect, unregistered, unaddressable []string
	provenRoutes := map[string]bool{}
	reachedForeign := map[string]bool{}
	for _, route := range tenantScopedWriteRoutes(t) {
		method, _, _ := strings.Cut(route, " ")
		path := harnessWritePath(route)
		if path == "" {
			unaddressable = append(unaddressable, route)
			continue
		}
		// A route registered only when an optional subsystem is wired is absent from this fixture's
		// mux, and a request to it would be answered by the mux rather than by the route.
		if _, matched := mux.Handler(httptest.NewRequest(method, path, nil)); matched != route {
			unregistered = append(unregistered, route)
			continue
		}
		req, ok := harnessWriteRequests[route]
		if !ok {
			req = harnessWriteDefault
		}
		probed++
		if reason, listed := harnessWriteForeignNoEffect[route]; listed {
			reachedForeign[route] = true
			t.Run(route, func(t *testing.T) {
				if _, get := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil)); get != http.MethodGet+route[len(method):] {
					t.Fatalf("%s is listed in harnessWriteForeignNoEffect (%s) but has no GET route on the same path to show that tenantA's record is unchanged", route, reason)
				}
				read := func() (int, string) {
					code, body, _ := send("tenantA", http.MethodGet, path, harnessWriteRequest{tenantBound: req.tenantBound})
					return code, body
				}
				beforeCode, before := read()
				if beforeCode != http.StatusOK {
					t.Fatalf("%s: tenantA's own record at %s answered %d before the probe, so an unchanged record would prove nothing: %s", route, path, beforeCode, before)
				}
				code, body, ran := send("tenantB", method, path, req)
				if !ran {
					t.Fatalf("%s ran a handler for a tenantB caller that could not complete", route)
				}
				if !success(code) {
					t.Fatalf("%s is listed in harnessWriteForeignNoEffect (%s) but refused tenantB with %d; delete the entry so the sweep probes it like every other route", route, reason, code)
				}
				if afterCode, after := read(); afterCode != beforeCode || after != before {
					t.Errorf("%s accepted a tenantB write (status %d, request %s, response %s) and tenantA's record at %s changed:\nbefore %d %s\nafter  %d %s",
						route, code, req.body, body, path, beforeCode, before, afterCode, after)
				}
				foreignNoEffect = append(foreignNoEffect, fmt.Sprintf("%s  [tenantB %d, tenantA's record unchanged]", route, code))
			})
			continue
		}
		t.Run(route, func(t *testing.T) {
			code, body, ran := send("tenantB", method, path, req)
			if !ran {
				t.Fatalf("%s ran a handler for a tenantB caller that could not complete, so the refusal cannot be shown", route)
			}
			if success(code) {
				// The write went through. tenantA's own request is not sent: the route is reported
				// as it was found.
				t.Fatalf("%s accepted a write from a tenantB caller at tenantA's path %s: status %d, request %s, response %s", route, path, code, req.body, body)
			}
			if code >= 500 {
				t.Errorf("%s answered a tenantB write with %d; a guard must refuse, not fail: %s", route, code, body)
			}
			if code != http.StatusBadRequest && code != http.StatusForbidden && code != http.StatusNotFound {
				otherRefusals = append(otherRefusals, fmt.Sprintf("%s  [tenantB %d]", route, code))
			}
			ownerCode, _, ownerRan := send("tenantA", method, path, req)
			switch {
			case !ownerRan:
				vacuous = append(vacuous, fmt.Sprintf("%s  [tenantB %d; tenantA's handler cannot run in this fixture]", route, code))
			case success(ownerCode):
				provenRoutes[route] = true
				proven = append(proven, fmt.Sprintf("%s  [tenantB %d, tenantA %d]", route, code, ownerCode))
			default:
				vacuous = append(vacuous, fmt.Sprintf("%s  [tenantB %d, tenantA %d]", route, code, ownerCode))
			}
		})
	}
	if probed < 40 {
		t.Errorf("the write sweep probed %d routes; the route table is no longer being read", probed)
	}
	reached := map[string]bool{}
	for _, route := range unaddressable {
		reached[route] = true
		if _, listed := harnessKnownUnaddressableWrites[route]; !listed {
			t.Errorf("%s cannot be addressed: a path parameter has no value. Plant the record in a seed and declare its id in PathValues or RoutePathValues, or list the route in harnessKnownUnaddressableWrites with the reason", route)
		}
	}
	for route, reason := range harnessKnownUnaddressableWrites {
		if !reached[route] {
			t.Errorf("%s is listed in harnessKnownUnaddressableWrites (%s) but the sweep can address it now; delete the entry", route, reason)
		}
	}
	for route, reason := range harnessWriteForeignNoEffect {
		if !reachedForeign[route] {
			t.Errorf("%s is listed in harnessWriteForeignNoEffect (%s) but the sweep does not probe it; delete the entry", route, reason)
		}
	}
	listed := map[string]bool{}
	for _, route := range harnessWriteProven {
		listed[route] = true
		if !provenRoutes[route] {
			t.Errorf("%s is listed in harnessWriteProven but the sweep did not prove it; the coverage measurement counts it", route)
		}
	}
	for _, route := range tenantScopedWriteRoutes(t) {
		if provenRoutes[route] && !listed[route] {
			t.Errorf("%s is proven now; add it to harnessWriteProven and raise the coverage floor", route)
		}
	}
	t.Logf("write sweep probed %d tenant-scoped write routes: %d proven (tenantA's same request succeeded), %d vacuous, %d answer tenantB without changing tenantA's record; %d not registered in this fixture; %d unaddressable",
		probed, len(proven), len(vacuous), len(foreignNoEffect), len(unregistered), len(unaddressable))
	t.Logf("write routes proven (%d):\n  %s", len(proven), strings.Join(proven, "\n  "))
	t.Logf("write routes refused for tenantB but not shown to succeed for tenantA (%d):\n  %s", len(vacuous), strings.Join(vacuous, "\n  "))
	t.Logf("write routes that refused tenantB with a status other than 400, 403 or 404 (%d):\n  %s", len(otherRefusals), strings.Join(otherRefusals, "\n  "))
	t.Logf("write routes that answer tenantB with a success and leave tenantA's record unchanged (%d):\n  %s", len(foreignNoEffect), strings.Join(foreignNoEffect, "\n  "))
	t.Logf("write routes not registered in this fixture (%d):\n  %s", len(unregistered), strings.Join(unregistered, "\n  "))
	t.Logf("write routes the sweep cannot address (%d):\n  %s", len(unaddressable), strings.Join(unaddressable, "\n  "))
}
