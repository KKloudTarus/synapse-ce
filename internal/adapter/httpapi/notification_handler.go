package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const notificationBodyCap = 32 << 10

func decodeNotificationBody(w http.ResponseWriter, r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, notificationBodyCap))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: invalid notification request", shared.ErrValidation)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: notification request must contain one JSON object", shared.ErrValidation)
	}
	return nil
}

// callerCan reports whether the authenticated principal holds perm. Routes are gated by rt.authz;
// this is for the few handlers whose route admits a narrower permission and that refuse one part of
// the request to callers without a broader one.
//
// It asks the same decision as the route guard, so a credential restriction that denies a route
// also denies the broader part of a request here.
func callerCan(r *http.Request, perm userdom.Permission) bool {
	return decideRequest(r, authz.Action{Permission: perm}).Allowed
}

func notificationID(r *http.Request) (shared.ID, error) {
	id := shared.ID(strings.TrimSpace(r.PathValue("nid")))
	if id.IsZero() {
		return "", fmt.Errorf("%w: notification id is required", shared.ErrValidation)
	}
	return id, nil
}

// listNotificationEventTypes serves the event catalog so the console builds rule and template forms
// from EventSpec instead of hard-coded lists. It holds no tenant data, so any member may read it.
func (rt *Router) listNotificationEventTypes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": domain.EventCatalog()})
}

func (rt *Router) listNotificationChannels(w http.ResponseWriter, r *http.Request) {
	items, err := rt.notifications.ListChannels(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []domain.Channel{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
func (rt *Router) createNotificationChannel(w http.ResponseWriter, r *http.Request) {
	var in notificationuc.ChannelInput
	if err := decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.CreateChannel(r.Context(), PrincipalFrom(r.Context()), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}
func (rt *Router) getNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.GetChannel(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
func (rt *Router) updateNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var in notificationuc.ChannelInput
	if err = decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	// The route admits manage_integrations; re-pointing the channel still needs administer (#1358).
	in.AllowDestinationChange = callerCan(r, userdom.PermAdminister)
	// So does raising its data class (#1360).
	in.AllowClassRaise = in.AllowDestinationChange
	item, err := rt.notifications.UpdateChannel(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
func (rt *Router) deleteNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	revision, err := requiredRevision(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err = rt.notifications.DeleteChannel(r.Context(), PrincipalFrom(r.Context()), id, revision); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) testNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	delivery, err := rt.notifications.TestChannel(r.Context(), PrincipalFrom(r.Context()), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"delivery_id": delivery, "state": "pending"})
}

// resumeNotificationChannel clears an automatic pause (#1464). The body carries the revision the
// administrator saw, so a resume never acts on a channel that changed underneath them.
func (rt *Router) resumeNotificationChannel(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var in notificationuc.ResumeInput
	if err = decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.ResumeChannel(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) listNotificationChannelHealthEvents(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	items, err := rt.notifications.ListChannelHealthEvents(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []domain.ChannelHealthEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (rt *Router) listNotificationRules(w http.ResponseWriter, r *http.Request) {
	items, err := rt.notifications.ListRules(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []domain.Rule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
func (rt *Router) createNotificationRule(w http.ResponseWriter, r *http.Request) {
	var in notificationuc.RuleInput
	if err := decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.CreateRule(r.Context(), PrincipalFrom(r.Context()), in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}
func (rt *Router) getNotificationRule(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.GetRule(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
func (rt *Router) updateNotificationRule(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var in notificationuc.RuleInput
	if err = decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.UpdateRule(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}
func (rt *Router) deleteNotificationRule(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	revision, err := requiredRevision(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err = rt.notifications.DeleteRule(r.Context(), PrincipalFrom(r.Context()), id, revision); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func requiredRevision(r *http.Request) (int, error) {
	value, err := strconv.Atoi(r.URL.Query().Get("revision"))
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%w: positive revision query parameter is required", shared.ErrValidation)
	}
	return value, nil
}

func (rt *Router) listNotificationDeliveries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ports.NotificationDeliveryFilter{ChannelID: shared.ID(strings.TrimSpace(q.Get("channel_id"))), EventType: domain.EventType(q.Get("event_type")), State: domain.DeliveryState(q.Get("state"))}
	for key, target := range map[string]*time.Time{"from": &f.From, "to": &f.Until} {
		if raw := q.Get(key); raw != "" {
			at, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				writeError(w, rt.log, fmt.Errorf("%w: invalid %s timestamp", shared.ErrValidation, key))
				return
			}
			*target = at
		}
	}
	if !f.From.IsZero() && !f.Until.IsZero() && f.From.After(f.Until) {
		writeError(w, rt.log, fmt.Errorf("%w: from must precede to", shared.ErrValidation))
		return
	}
	if f.EventType != "" && !f.EventType.Valid() {
		writeError(w, rt.log, fmt.Errorf("%w: invalid event type", shared.ErrValidation))
		return
	}
	if f.State != "" && !f.State.Valid() {
		writeError(w, rt.log, fmt.Errorf("%w: invalid delivery state", shared.ErrValidation))
		return
	}
	if rawLimit := q.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, rt.log, fmt.Errorf("%w: delivery limit must be between 1 and 200", shared.ErrValidation))
			return
		}
		f.Limit = limit
	}
	if cursor := q.Get("cursor"); cursor != "" {
		parts := strings.SplitN(cursor, "|", 2)
		if len(parts) != 2 || parts[1] == "" {
			writeError(w, rt.log, fmt.Errorf("%w: invalid delivery cursor", shared.ErrValidation))
			return
		}
		at, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			writeError(w, rt.log, fmt.Errorf("%w: invalid delivery cursor", shared.ErrValidation))
			return
		}
		f.Before, f.BeforeID = at, shared.ID(parts[1])
	}
	page, err := rt.notifications.ListDeliveries(r.Context(), f)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if page.Items == nil {
		page.Items = []domain.Delivery{}
	}
	writeJSON(w, http.StatusOK, page)
}
func (rt *Router) listNotificationSourceFailures(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ports.NotificationSourceFailureFilter{EventType: domain.EventType(q.Get("event_type"))}
	if f.EventType != "" && !f.EventType.Valid() {
		writeError(w, rt.log, fmt.Errorf("%w: invalid event type", shared.ErrValidation))
		return
	}
	for key, target := range map[string]*time.Time{"from": &f.From, "to": &f.Until} {
		if raw := q.Get(key); raw != "" {
			at, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				writeError(w, rt.log, fmt.Errorf("%w: invalid %s timestamp", shared.ErrValidation, key))
				return
			}
			*target = at
		}
	}
	if !f.From.IsZero() && !f.Until.IsZero() && f.From.After(f.Until) {
		writeError(w, rt.log, fmt.Errorf("%w: from must precede to", shared.ErrValidation))
		return
	}
	if raw := q.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 200 {
			writeError(w, rt.log, fmt.Errorf("%w: source limit must be between 1 and 200", shared.ErrValidation))
			return
		}
		f.Limit = limit
	}
	if raw := q.Get("offset"); raw != "" {
		offset, err := strconv.Atoi(raw)
		if err != nil || offset < 0 {
			writeError(w, rt.log, fmt.Errorf("%w: source offset must be nonnegative", shared.ErrValidation))
			return
		}
		f.Offset = offset
	}
	page, err := rt.notifications.ListSourceFailures(r.Context(), f)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if page.Items == nil {
		page.Items = []domain.SourceFailure{}
	}
	writeJSON(w, http.StatusOK, page)
}
func (rt *Router) getNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.GetDelivery(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) redriveNotificationDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var in notificationuc.RedriveInput
	if err = decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.RedriveDelivery(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (rt *Router) listNotificationAttempts(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	items, err := rt.notifications.ListAttempts(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []domain.Attempt{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
