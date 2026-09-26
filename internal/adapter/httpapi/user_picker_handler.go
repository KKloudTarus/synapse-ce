package httpapi

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"net/http"
	"strconv"
)

func (rt *Router) SetUserPickerReader(reader ports.UserPickerReader) { rt.userPicker = reader }
func (rt *Router) listUserChoices(w http.ResponseWriter, r *http.Request) {
	limit := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 50 {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "limit must be 1..50"})
			return
		}
		limit = n
	}
	items, err := rt.userPicker.ListUserChoices(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.URL.Query().Get("team_id")), r.URL.Query().Get("q"), shared.ID(r.URL.Query().Get("cursor")), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].ID.String()
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
}
