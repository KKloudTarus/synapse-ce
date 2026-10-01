package httpapi

import (
	"net/http"

	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// getNotificationEngagementSetting returns an engagement's external notification override (#1360).
func (rt *Router) getNotificationEngagementSetting(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.EngagementNotificationSetting(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// putNotificationEngagementSetting changes an engagement's override. Lowering it is open to the
// route's manage_integrations; letting more data out needs administer.
func (rt *Router) putNotificationEngagementSetting(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var in notificationuc.EngagementSettingInput
	if err = decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	in.AllowRaise = callerCan(r, userdom.PermAdminister)
	item, err := rt.notifications.SetEngagementNotificationSetting(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
