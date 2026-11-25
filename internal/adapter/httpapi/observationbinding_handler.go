package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/observationbindinguc"
)

// bindingDecisionBodyCap bounds the request body. A decision carries a finding id and a sentence.
const bindingDecisionBodyCap = 8 << 10

// observationBinder is the narrow view of the binding usecase the HTTP layer needs.
type observationBinder interface {
	Decide(ctx context.Context, req observationbindinguc.DecideRequest) (observationbinding.Binding, error)
	Current(ctx context.Context, tenantID, engagementID shared.ID) (map[observationbinding.Identity]observationbinding.Binding, error)
	List(ctx context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error)
}

// SetObservationBindings wires the binding usecase and enables its routes. Optional: when nil the routes
// are not registered and the imported-finding read reports every link as a candidate, which is what it is
// without a decision record.
func (rt *Router) SetObservationBindings(s observationBinder) { rt.observationBindings = s }

type bindingPayload struct {
	ID               string `json:"id"`
	Scope            string `json:"scope"`
	ExternalIdentity string `json:"external_identity"`
	FindingID        string `json:"finding_id"`
	ObservationID    string `json:"observation_id"`
	Version          int    `json:"version"`
	DecidedBy        string `json:"decided_by"`
	Reason           string `json:"reason"`
	DecidedAt        string `json:"decided_at"`
	// SupersededAt is empty while this version is the one in force.
	SupersededAt string `json:"superseded_at,omitempty"`
	Current      bool   `json:"current"`
	// Orphaned marks a binding in force whose identity matches no observation in the engagement any
	// more. It happens when a tool changes how it fingerprints a result: the decision is still recorded
	// but has quietly stopped applying to anything, and without this an operator would never find out.
	Orphaned bool `json:"orphaned,omitempty"`
}

type bindingDecisionRequest struct {
	FindingID string `json:"finding_id"`
	Reason    string `json:"reason"`
	// ExpectedVersion is omitted for a first adoption. Supplying it changes an existing decision, and a
	// value that is not the version in force is refused rather than applied.
	ExpectedVersion int `json:"expected_version,omitempty"`
}

func toBindingPayload(b observationbinding.Binding) bindingPayload {
	out := bindingPayload{
		ID:               b.ID.String(),
		Scope:            b.Scope,
		ExternalIdentity: b.ExternalIdentity,
		FindingID:        b.FindingID.String(),
		ObservationID:    b.ObservationID.String(),
		Version:          b.Version,
		DecidedBy:        b.DecidedBy.String(),
		Reason:           b.Reason,
		DecidedAt:        b.DecidedAt.UTC().Format(time.RFC3339),
		Current:          b.Current(),
	}
	if !b.SupersededAt.IsZero() {
		out.SupersededAt = b.SupersededAt.UTC().Format(time.RFC3339)
	}
	return out
}

// decideObservationBinding records that a person approved an observation onto a canonical finding.
func (rt *Router) decideObservationBinding(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bindingDecisionBodyCap))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "binding decision could not be read or exceeds the size bound"})
		return
	}
	var req bindingDecisionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "binding decision is not valid JSON"})
		return
	}
	binding, err := rt.observationBindings.Decide(r.Context(), observationbindinguc.DecideRequest{
		// The RAW tenant is passed on. The use case resolves the engagement inside it and takes the row
		// tenant from the ENGAGEMENT, so the value that authorizes the write is the value that stamps it.
		TenantID:        shared.ID(TenantFrom(r.Context())),
		EngagementID:    shared.ID(r.PathValue("id")),
		ObservationID:   shared.ID(r.PathValue("observationId")),
		FindingID:       shared.ID(req.FindingID),
		Actor:           shared.ID(PrincipalFrom(r.Context())),
		Reason:          req.Reason,
		ExpectedVersion: req.ExpectedVersion,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toBindingPayload(binding))
}

// listObservationBindings returns every version of every binding in the engagement, newest first, and
// marks the ones in force that no longer match any observation.
func (rt *Router) listObservationBindings(w http.ResponseWriter, r *http.Request) {
	tenant := shared.ID(TenantFrom(r.Context()))
	engagement := shared.ID(r.PathValue("id"))
	bindings, err := rt.observationBindings.List(r.Context(), tenant, engagement)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	// A binding whose identity no observation carries any more has stopped applying. The decision is
	// still on record, which is correct, but a reader who cannot see that it is dangling would believe
	// the observation is still governed by it.
	live := map[observationbinding.Identity]bool{}
	if rt.importedFindings != nil {
		observations, obsErr := rt.importedFindings.ListByEngagement(r.Context(), shared.TenantOrDefault(tenant), engagement)
		if obsErr != nil {
			writeError(w, rt.log, obsErr)
			return
		}
		for _, observation := range observations {
			live[observationbinding.Identity{Scope: observation.BindingScope(), ExternalIdentity: observation.BindingExternalIdentity()}] = true
		}
	}
	out := make([]bindingPayload, 0, len(bindings))
	for _, binding := range bindings {
		payload := toBindingPayload(binding)
		payload.Orphaned = binding.Current() && len(live) > 0 && !live[binding.Key()]
		out = append(out, payload)
	}
	writeJSON(w, http.StatusOK, out)
}
