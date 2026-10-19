package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ticketObservationReader interface {
	ListTicketObservations(context.Context, shared.ID, shared.ID, shared.ID) (ports.TicketInboundView, error)
}

func (rt *Router) findingTicketObservations(w http.ResponseWriter, r *http.Request) {
	tenant, engagement, finding := shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid"))
	if _, err := rt.ticketing.GetFindingTickets(r.Context(), tenant, engagement, finding); err != nil {
		writeError(w, rt.log, err)
		return
	}
	reader, ok := rt.ticketing.(ticketObservationReader)
	if !ok {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	view, err := reader.ListTicketObservations(r.Context(), tenant, engagement, finding)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	observations, proposals, comments := make([]any, 0, len(view.Observations)), make([]any, 0, len(view.Proposals)), make([]any, 0, len(view.Comments))
	for _, o := range view.Observations {
		observations = append(observations, map[string]any{"remote_id": o.RemoteID, "status_category": o.StatusCategory, "deleted_or_unreadable": o.DeletedOrUnreadable, "checked_at": o.CheckedAt, "provider_updated_at": o.ProviderUpdatedAt})
	}
	for _, p := range view.Proposals {
		proposals = append(proposals, map[string]any{"id": p.ID, "remote_id": p.RemoteID, "state": p.State, "observed_at": p.ObservedAt, "resolution_context": p.ResolutionName})
	}
	for _, c := range view.Comments {
		comments = append(comments, map[string]any{"id": c.ID, "remote_id": c.RemoteID, "origin": "external", "body": c.Body, "created_at": c.CreatedAt})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"observations": observations, "proposals": proposals, "comments": comments})
}
