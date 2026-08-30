package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// incidentReader is the read side of the Phase-C incident store this API surfaces (#594 C7):
// project a single incident, and list the tenant's incidents (optionally scoped to one asset).
// incidentuc.Service satisfies it. Defined here so the adapter depends on a narrow port, not the
// concrete usecase.
type incidentReader interface {
	Get(ctx context.Context, id shared.ID) (incident.Incident, error)
	ListByAsset(ctx context.Context, assetID shared.ID, limit int) ([]incident.Incident, error)
}

// incidentTriager is the analyst-triage write side (#594 C5): the human-driven mutations, each
// recorded as an attributable event on the append-only log. incidenttriage.Service satisfies it.
// The actor is the FIRST arg after ctx precisely because it must be the server-side authenticated
// principal, never a request-body field.
type incidentTriager interface {
	AssignOwner(ctx context.Context, actor string, id shared.ID, owner string) (incident.Incident, error)
	Comment(ctx context.Context, actor string, id shared.ID, text string) (incident.Incident, error)
	ChangeStatus(ctx context.Context, actor string, id shared.ID, to incident.State) (incident.Incident, error)
	SetDisposition(ctx context.Context, actor string, id shared.ID, disposition incident.Disposition) (incident.Incident, error)
}

// incidentRiskReassessor runs the tri-score assembler for one incident (#594 C3/D/X5):
// re-gather Threat + Exposure + Behavior + telemetry Coverage, run the deterministic Scorer, and
// record the RiskAssessment on the append-only incident log. riskscoreuc.Service satisfies it. The actor
// is the FIRST arg after ctx: it must be the server-side authenticated principal, never a body field.
type incidentRiskReassessor interface {
	Reassess(ctx context.Context, actor string, incidentID shared.ID) (incident.Incident, error)
}

// SetIncidents wires the incident read surface (nil ⇒ the routes are not registered).
func (rt *Router) SetIncidents(r incidentReader) { rt.incidents = r }

// SetIncidentRiskReassessor wires the tri-score reassessment surface (nil ⇒ the route is not registered).
func (rt *Router) SetIncidentRiskReassessor(r incidentRiskReassessor) { rt.incidentRiskReassessor = r }

// SetIncidentTriage wires the incident triage surface (nil ⇒ the triage routes are not registered).
func (rt *Router) SetIncidentTriage(t incidentTriager) { rt.incidentTriage = t }

const (
	defaultIncidentPageLimit = 200
	maxIncidentPageLimit     = 1000
	// incidentBodyLimit caps a triage request body (each is a single short string) — parity with the
	// finding-triage handlers, so a large body cannot be read unbounded.
	incidentBodyLimit = 8 << 10
)

// incidentListResponse carries a page of incidents plus an HONEST truncation flag: Truncated is true
// when more incidents (of ANY state) exist beyond this page, so a client filtering by state knows the
// filter ran over a capped page rather than the whole store (there is no store-level state index —
// state is a projection, not a column).
type incidentListResponse struct {
	Incidents []incident.Incident `json:"incidents"`
	Truncated bool                `json:"truncated"`
}

type assignIncidentOwnerRequest struct {
	Owner string `json:"owner"`
}

type commentIncidentRequest struct {
	Text string `json:"text"`
}

type changeIncidentStatusRequest struct {
	To string `json:"to"`
}

type setIncidentDispositionRequest struct {
	Disposition string `json:"disposition"`
}

// incidentTenantContext puts the effective fleet tenant onto the context so the tenant-scoped
// usecase + RLS see a non-empty tenant even in a single-tenant deployment (mirrors fleetTenant used
// by the asset/coverage handlers; incidentuc takes the tenant from the context, not as a param).
func incidentTenantContext(r *http.Request) context.Context {
	return shared.WithTenant(r.Context(), fleetTenant(r.Context()))
}

func parseIncidentPageLimit(raw string) (int, error) {
	if raw == "" {
		return defaultIncidentPageLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: limit must be a positive integer", shared.ErrValidation)
	}
	if n > maxIncidentPageLimit {
		n = maxIncidentPageLimit
	}
	return n, nil
}

// listIncidents returns a tenant-scoped page of incidents. Query params: `asset` (empty ⇒ all
// incidents in the tenant), `limit` (1..1000, default 200), `state` (an optional page-level filter on
// the current projected state). Truncation is detected with a limit+1 probe so Truncated is honest.
func (rt *Router) listIncidents(w http.ResponseWriter, r *http.Request) {
	limit, err := parseIncidentPageLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var stateFilter incident.State
	if raw := r.URL.Query().Get("state"); raw != "" {
		stateFilter = incident.State(raw)
		if !stateFilter.Valid() {
			writeError(w, rt.log, fmt.Errorf("%w: unknown incident state %q", shared.ErrValidation, raw))
			return
		}
	}
	ctx := incidentTenantContext(r)
	assetID := shared.ID(r.URL.Query().Get("asset"))
	// Probe one past the limit so Truncated reflects the raw page (before any state filter).
	list, err := rt.incidents.ListByAsset(ctx, assetID, limit+1)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	truncated := len(list) > limit
	if truncated {
		list = list[:limit]
	}
	if stateFilter != "" {
		filtered := make([]incident.Incident, 0, len(list))
		for _, inc := range list {
			if inc.State == stateFilter {
				filtered = append(filtered, inc)
			}
		}
		list = filtered
	}
	writeJSON(w, http.StatusOK, incidentListResponse{Incidents: list, Truncated: truncated})
}

// getIncident returns the projected incident by id (404 if absent or cross-tenant).
func (rt *Router) getIncident(w http.ResponseWriter, r *http.Request) {
	inc, err := rt.incidents.Get(incidentTenantContext(r), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (rt *Router) assignIncidentOwner(w http.ResponseWriter, r *http.Request) {
	var req assignIncidentOwnerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, incidentBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	inc, err := rt.incidentTriage.AssignOwner(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), req.Owner)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (rt *Router) commentIncident(w http.ResponseWriter, r *http.Request) {
	var req commentIncidentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, incidentBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	inc, err := rt.incidentTriage.Comment(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), req.Text)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (rt *Router) changeIncidentStatus(w http.ResponseWriter, r *http.Request) {
	var req changeIncidentStatusRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, incidentBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	inc, err := rt.incidentTriage.ChangeStatus(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), incident.State(req.To))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

// reassessIncidentRisk runs the tri-score assembler for the incident and returns the updated incident
// (whose .Risk now carries the RiskAssessment). No request body: the factors are gathered server-side.
func (rt *Router) reassessIncidentRisk(w http.ResponseWriter, r *http.Request) {
	inc, err := rt.incidentRiskReassessor.Reassess(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

func (rt *Router) setIncidentDisposition(w http.ResponseWriter, r *http.Request) {
	var req setIncidentDispositionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, incidentBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	inc, err := rt.incidentTriage.SetDisposition(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), incident.Disposition(req.Disposition))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, inc)
}
