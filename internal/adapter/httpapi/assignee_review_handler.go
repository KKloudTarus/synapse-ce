package httpapi

import (
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (rt *Router) SetAssigneeReviewReader(reader ports.AssigneeReviewReader) {
	rt.assigneeReview = reader
}

func (rt *Router) listAssigneeReview(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "limit must be 1..100"})
			return
		}
		limit = n
	}
	engCursor, findCursor := r.URL.Query().Get("cursor_engagement_id"), r.URL.Query().Get("cursor_finding_id")
	if (engCursor == "") != (findCursor == "") {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "both cursor fields are required"})
		return
	}
	items, err := rt.assigneeReview.ListAssigneeReview(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(engCursor), shared.ID(findCursor), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var next any
	if len(items) == limit {
		last := items[len(items)-1]
		next = map[string]string{"engagement_id": last.EngagementID.String(), "finding_id": last.FindingID.String()}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
}
