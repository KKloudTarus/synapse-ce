package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetrolloutuc"
)

// fleetRolloutService is the operator-facing slice of the rollout lifecycle.
type fleetRolloutService interface {
	Get(ctx context.Context, tenantID shared.ID, channel string) (*fleetrollout.Plan, error)
	SetTarget(ctx context.Context, in fleetrolloutuc.SetTargetInput) (*fleetrollout.Plan, error)
	Promote(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID) (*fleetrollout.Plan, error)
	Pause(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID, reason string) (*fleetrollout.Plan, error)
	Resume(ctx context.Context, tenantID shared.ID, channel string, actor shared.ID) (*fleetrollout.Plan, error)
}

// SetFleetRolloutAdmin wires the operator routes. Optional: when nil they are not registered.
func (rt *Router) SetFleetRolloutAdmin(s fleetRolloutService) { rt.fleetRolloutAdmin = s }

// rolloutView is the operator's view of a plan.
//
// `promoted_to_all` and `paused` are on the wire as their own fields rather than folded into a single
// status string: an operator deciding whether it is safe to promote needs to see the canary list and
// the pause reason, not a word that summarises them away.
type rolloutView struct {
	Channel       string   `json:"channel"`
	TargetVersion string   `json:"target_version"`
	CanaryGroups  []string `json:"canary_groups"`
	PromotedToAll bool     `json:"promoted_to_all"`
	Paused        bool     `json:"paused"`
	PauseReason   string   `json:"pause_reason,omitempty"`
	UpdatedBy     string   `json:"updated_by"`
	UpdatedAt     string   `json:"updated_at"`
}

func toRolloutView(p *fleetrollout.Plan) rolloutView {
	groups := p.CanaryGroups
	if groups == nil {
		groups = []string{}
	}
	return rolloutView{
		Channel: p.Channel, TargetVersion: p.TargetVersion, CanaryGroups: groups,
		PromotedToAll: p.PromotedToAll, Paused: p.Paused, PauseReason: p.PauseReason,
		UpdatedBy: p.UpdatedBy.String(), UpdatedAt: p.Audit.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func (rt *Router) rolloutChannel(r *http.Request) string {
	return fleetrollout.NormalizeChannel(r.URL.Query().Get("channel"))
}

// getFleetRollout returns the current plan for a channel.
func (rt *Router) getFleetRollout(w http.ResponseWriter, r *http.Request) {
	plan, err := rt.fleetRolloutAdmin.Get(r.Context(), fleetTenant(r.Context()), rt.rolloutChannel(r))
	if errors.Is(err, shared.ErrNotFound) {
		// No plan is a legitimate resting state, not an error the operator must interpret. It is
		// reported as an explicit "no rollout" rather than a 404, so a UI can render the difference
		// between "nothing configured" and "the channel does not exist".
		writeJSON(w, http.StatusOK, map[string]any{
			"channel": rt.rolloutChannel(r), "configured": false,
			"reason": string(fleetrollout.ReasonNoPlan),
		})
		return
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "rollout": toRolloutView(plan)})
}

// setFleetRolloutTarget starts or replaces a rollout. Promotion always resets — see the use case.
func (rt *Router) setFleetRolloutTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetVersion string   `json:"target_version"`
		CanaryGroups  []string `json:"canary_groups"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid rollout body"})
		return
	}
	plan, err := rt.fleetRolloutAdmin.SetTarget(r.Context(), fleetrolloutuc.SetTargetInput{
		TenantID:      fleetTenant(r.Context()),
		Channel:       rt.rolloutChannel(r),
		TargetVersion: req.TargetVersion,
		CanaryGroups:  req.CanaryGroups,
		Actor:         shared.ID(PrincipalFrom(r.Context())),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "rollout": toRolloutView(plan)})
}

// promoteFleetRollout releases the target to every group.
func (rt *Router) promoteFleetRollout(w http.ResponseWriter, r *http.Request) {
	plan, err := rt.fleetRolloutAdmin.Promote(r.Context(), fleetTenant(r.Context()),
		rt.rolloutChannel(r), shared.ID(PrincipalFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "rollout": toRolloutView(plan)})
}

// pauseFleetRollout stops every offer. The reason is required by the use case.
func (rt *Router) pauseFleetRollout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid pause body"})
		return
	}
	plan, err := rt.fleetRolloutAdmin.Pause(r.Context(), fleetTenant(r.Context()),
		rt.rolloutChannel(r), shared.ID(PrincipalFrom(r.Context())), req.Reason)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "rollout": toRolloutView(plan)})
}

// resumeFleetRollout lifts a pause without advancing the rollout.
func (rt *Router) resumeFleetRollout(w http.ResponseWriter, r *http.Request) {
	plan, err := rt.fleetRolloutAdmin.Resume(r.Context(), fleetTenant(r.Context()),
		rt.rolloutChannel(r), shared.ID(PrincipalFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "rollout": toRolloutView(plan)})
}
