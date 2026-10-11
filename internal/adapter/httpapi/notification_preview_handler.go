package httpapi

import (
	"net/http"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// A preview against stored events also needs view: the events describe engagement data, which view
// governs, and manage_integrations alone does not grant reading it.
func forbidEventRead(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, errorBody{Error: "insufficient permissions: previewing stored events requires the " + string(userdom.PermView) + " capability"})
}

// listNotificationPreviewEvents lists the tenant's newest events of one type a template preview can
// render against (#1372). It names each event and never returns its data or template context.
func (rt *Router) listNotificationPreviewEvents(w http.ResponseWriter, r *http.Request) {
	if !callerCan(r, userdom.PermView) {
		forbidEventRead(w)
		return
	}
	items, err := rt.notifications.ListPreviewEvents(r.Context(), domain.EventType(r.URL.Query().Get("event_type")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// previewNotificationTemplate prepares a template preview for a channel and an event type, against
// the type's fixture or a stored event (#1372). Nothing is sent or stored. Responses are never
// logged: once rendering lands (#1365) they carry message text.
func (rt *Router) previewNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	var in notificationuc.PreviewInput
	if err := decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	if !in.EventID.IsZero() && !callerCan(r, userdom.PermView) {
		forbidEventRead(w)
		return
	}
	preview, err := rt.notifications.PreviewTemplate(r.Context(), in)
	if err != nil {
		rt.writeTemplateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}
