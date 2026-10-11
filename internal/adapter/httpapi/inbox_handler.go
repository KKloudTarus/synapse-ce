package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	inboxuc "github.com/KKloudTarus/synapse-ce/internal/usecase/inbox"
)

func (rt *Router) SetInbox(service *inboxuc.Service) { rt.inbox = service }

func (rt *Router) inboxScope(w http.ResponseWriter, r *http.Request) (shared.ID, shared.ID, bool) {
	if r.URL.Query().Get("user_id") != "" || r.URL.Query().Get("tenant_id") != "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "user and tenant come from the signed-in session"})
		return "", "", false
	}
	return shared.ID(TenantFrom(r.Context())), shared.ID(PrincipalFrom(r.Context())), true
}

func (rt *Router) listMyInbox(w http.ResponseWriter, r *http.Request) {
	tenant, user, ok := rt.inboxScope(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	page, err := rt.inbox.List(r.Context(), tenant, user, r.URL.Query().Get("cursor"), r.URL.Query().Get("unread") == "true", limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (rt *Router) countMyInbox(w http.ResponseWriter, r *http.Request) {
	tenant, user, ok := rt.inboxScope(w, r)
	if !ok {
		return
	}
	count, err := rt.inbox.Unread(r.Context(), tenant, user)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"unread": count})
}

func (rt *Router) readMyInbox(w http.ResponseWriter, r *http.Request) {
	tenant, user, ok := rt.inboxScope(w, r)
	if !ok {
		return
	}
	if err := rt.inbox.MarkRead(r.Context(), tenant, user, shared.ID(r.PathValue("id"))); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) readAllMyInbox(w http.ResponseWriter, r *http.Request) {
	tenant, user, ok := rt.inboxScope(w, r)
	if !ok {
		return
	}
	if err := rt.inbox.MarkAllRead(r.Context(), tenant, user); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) listMyNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	tenant, user, ok := rt.inboxScope(w, r)
	if !ok {
		return
	}
	items, err := rt.inbox.Preferences(r.Context(), tenant, user)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (rt *Router) saveMyNotificationPreference(w http.ResponseWriter, r *http.Request) {
	tenant, user, ok := rt.inboxScope(w, r)
	if !ok {
		return
	}
	var body struct {
		UserID    string                  `json:"user_id"`
		TenantID  string                  `json:"tenant_id"`
		EventType notification.EventType  `json:"event_type"`
		Channel   string                  `json:"channel"`
		State     notification.Preference `json:"state"`
		Revision  int                     `json:"revision"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid preference"})
		return
	}
	if body.UserID != "" || body.TenantID != "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "user and tenant come from the signed-in session"})
		return
	}
	item, err := rt.inbox.SavePreference(r.Context(), tenant, user, body.EventType, body.Channel, body.State, body.Revision)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
