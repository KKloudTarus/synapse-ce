package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
)

type scopeTargetDTO struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type createEngagementRequest struct {
	Name           string           `json:"name"`
	Client         string           `json:"client"`
	InScope        []scopeTargetDTO `json:"in_scope"`
	OutOfScope     []scopeTargetDTO `json:"out_of_scope"`
	AuthorizedFrom string           `json:"authorized_from"` // RFC3339, optional
	AuthorizedTo   string           `json:"authorized_to"`   // RFC3339, optional
	Timezone       string           `json:"timezone"`        // IANA, optional (display)
	AssetID        string           `json:"asset_id"`
}

// parseRFC3339Ptr parses an optional RFC3339 timestamp. Empty -> (nil, nil).
func parseRFC3339Ptr(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func toTargets(dtos []scopeTargetDTO) []engdom.Target {
	out := make([]engdom.Target, 0, len(dtos))
	for _, d := range dtos {
		out = append(out, engdom.Target{Kind: engdom.TargetKind(d.Kind), Value: d.Value})
	}
	return out
}

func (rt *Router) createEngagement(w http.ResponseWriter, r *http.Request) {
	var req createEngagementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	from, err := parseRFC3339Ptr(req.AuthorizedFrom)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_from must be RFC3339"})
		return
	}
	to, err := parseRFC3339Ptr(req.AuthorizedTo)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_to must be RFC3339"})
		return
	}
	if req.Timezone != "" {
		if _, err := time.LoadLocation(req.Timezone); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "timezone must be a valid IANA name"})
			return
		}
	}
	tenantID := shared.TenantOrDefault(shared.ID(TenantFrom(r.Context())))
	if req.AssetID != "" && rt.businessAssets != nil {
		a, getErr := rt.businessAssets.Get(r.Context(), tenantID, shared.ID(req.AssetID))
		if getErr != nil {
			writeError(w, rt.log, getErr)
			return
		}
		if !a.AcceptsAssignments() {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "retired asset is read-only"})
			return
		}
	}
	e, err := rt.eng.Create(r.Context(), enguc.CreateInput{
		TenantID:        tenantID,
		BusinessAssetID: shared.ID(req.AssetID),
		CreatedBy:       PrincipalFrom(r.Context()), // engagement owner (ownership)
		Name:            req.Name,
		Client:          req.Client,
		InScope:         toTargets(req.InScope),
		OutOfScope:      toTargets(req.OutOfScope),
		AuthorizedFrom:  from,
		AuthorizedTo:    to,
		Timezone:        req.Timezone,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

func (rt *Router) listEngagements(w http.ResponseWriter, r *http.Request) {
	// Scope the listing to the principal's tenant; the repo treats '' (default tenant)
	// as unscoped, so single-tenant behavior is unchanged until users carry a real tenant.
	list, err := rt.eng.List(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (rt *Router) getEngagement(w http.ResponseWriter, r *http.Request) {
	e, err := rt.eng.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

type updateScopeRequest struct {
	InScope    []scopeTargetDTO `json:"in_scope"`
	OutOfScope []scopeTargetDTO `json:"out_of_scope"`
}

// updateScope replaces an engagement's scope. The execution gate reads scope
// live, so the change takes effect on the next tool run.
func (rt *Router) updateScope(w http.ResponseWriter, r *http.Request) {
	var req updateScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	e, err := rt.eng.UpdateScope(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), toTargets(req.InScope), toTargets(req.OutOfScope))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

type setWindowRequest struct {
	AuthorizedFrom string `json:"authorized_from"` // RFC3339, optional (empty clears)
	AuthorizedTo   string `json:"authorized_to"`   // RFC3339, optional (empty clears)
	Timezone       string `json:"timezone"`        // IANA, optional (display)
}

func (rt *Router) setAuthorizationWindow(w http.ResponseWriter, r *http.Request) {
	var req setWindowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	from, err := parseRFC3339Ptr(req.AuthorizedFrom)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_from must be RFC3339"})
		return
	}
	to, err := parseRFC3339Ptr(req.AuthorizedTo)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "authorized_to must be RFC3339"})
		return
	}
	if req.Timezone != "" {
		if _, err := time.LoadLocation(req.Timezone); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "timezone must be a valid IANA name"})
			return
		}
	}
	e, err := rt.eng.SetWindow(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), from, to, req.Timezone)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

type transitionRequest struct {
	Status string `json:"status"` // target lifecycle status: active|completed|archived
}

// transitionEngagement applies a lifecycle status change (activate/complete/archive).
func (rt *Router) transitionEngagement(w http.ResponseWriter, r *http.Request) {
	var req transitionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	e, err := rt.eng.Transition(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), engdom.Status(req.Status))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

type blackoutDTO struct {
	From string `json:"from"` // RFC3339
	To   string `json:"to"`   // RFC3339
}

type roeRequest struct {
	AllowedToolClasses []string      `json:"allowed_tool_classes"` // empty = no restriction
	Blackouts          []blackoutDTO `json:"blackouts"`
}

// setLiveRecon toggles the engagement's lab-only live-recon enablement.
func (rt *Router) setLiveRecon(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		// Required when enabling: re-confirm the AUP version and
		// record a lab-authorization attestation. Ignored when disabling.
		AUPVersion  string `json:"aup_version"`
		Attestation string `json:"attestation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	e, err := rt.eng.SetLiveRecon(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), req.Enabled, req.AUPVersion, req.Attestation)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// setRoE replaces the engagement's rules of engagement. The execution gate
// enforces tool-class + blackout rules on every tool run.
func (rt *Router) setRoE(w http.ResponseWriter, r *http.Request) {
	var req roeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	var roe engdom.RoE
	for _, c := range req.AllowedToolClasses {
		roe.AllowedToolClasses = append(roe.AllowedToolClasses, engdom.ToolClass(c))
	}
	for _, b := range req.Blackouts {
		from, err := time.Parse(time.RFC3339, b.From)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "blackout.from must be RFC3339"})
			return
		}
		to, err := time.Parse(time.RFC3339, b.To)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "blackout.to must be RFC3339"})
			return
		}
		roe.Blackouts = append(roe.Blackouts, engdom.Blackout{From: from, To: to})
	}
	e, err := rt.eng.SetRoE(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), roe)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}
