package httpapi

import (
	"net/http"

	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// getNotificationEmailSettings returns only safe relay metadata and the tenant's
// currently approved recipient domains. Relay credentials never leave the usecase.
func (rt *Router) getNotificationEmailSettings(w http.ResponseWriter, r *http.Request) {
	item, err := rt.notifications.EmailSettings(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// putNotificationEmailSettings atomically replaces the supplied sections. The
// route is administrator-only; the service still performs DNS proof and revision checks.
func (rt *Router) putNotificationEmailSettings(w http.ResponseWriter, r *http.Request) {
	var in notificationuc.EmailSettingsInput
	if err := decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.UpdateEmailSettings(r.Context(), PrincipalFrom(r.Context()), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
