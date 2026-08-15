package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sla"
)

func (rt *Router) listEngagementSLAs(w http.ResponseWriter, r *http.Request) {
	items, err := rt.sla.List(r.Context(), slaTenant(r), slaEngagement(r))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"slas": items})
}

func (rt *Router) getFindingSLA(w http.ResponseWriter, r *http.Request) {
	item, err := rt.sla.Get(r.Context(), slaTenant(r), slaEngagement(r), slaFinding(r))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) listSLAAssessments(w http.ResponseWriter, r *http.Request) {
	items, err := rt.sla.AssessmentHistory(r.Context(), slaTenant(r), slaEngagement(r), slaFinding(r))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assessments": items})
}

func (rt *Router) listSLAEvents(w http.ResponseWriter, r *http.Request) {
	items, err := rt.sla.LifecycleEvents(r.Context(), slaTenant(r), slaEngagement(r), slaFinding(r))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": items})
}

func (rt *Router) transitionFindingSLA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		To                  sla.RemediationStatus `json:"to"`
		Reason              string                `json:"reason"`
		CompensatingControl string                `json:"compensating_control"`
		AcceptanceExpiresAt *time.Time            `json:"acceptance_expires_at"`
		Version             int                   `json:"version"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	item, err := rt.sla.Transition(r.Context(), slaTenant(r), slaEngagement(r), slaFinding(r), sla.TransitionCommand{
		To: body.To, Reason: body.Reason, CompensatingControl: body.CompensatingControl,
		AcceptanceExpiresAt: body.AcceptanceExpiresAt, Actor: PrincipalFrom(r.Context()), ExpectedVersion: body.Version,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) listSLAPolicies(w http.ResponseWriter, r *http.Request) {
	tenantID := slaTenant(r)
	active, err := rt.sla.ActivePolicy(r.Context(), tenantID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	items, err := rt.sla.Policies(r.Context(), tenantID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "policies": items})
}

func (rt *Router) activateSLAPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config sla.Config `json:"config"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	policy, created, err := rt.sla.ActivatePolicy(r.Context(), slaTenant(r), body.Config, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"policy": policy, "created": created})
}

func slaTenant(r *http.Request) shared.ID {
	return shared.ID(strings.TrimSpace(TenantFrom(r.Context())))
}

func slaEngagement(r *http.Request) shared.ID {
	return shared.ID(strings.TrimSpace(r.PathValue("id")))
}

func slaFinding(r *http.Request) shared.ID {
	return shared.ID(strings.TrimSpace(r.PathValue("fid")))
}
