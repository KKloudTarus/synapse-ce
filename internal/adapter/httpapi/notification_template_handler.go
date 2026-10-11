package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// templateValidationBody is the 400 body of a template the engine rejected: the usual error string
// plus the field, event type, engine code and line, so the console can point at the problem. It
// never carries the template source.
type templateValidationBody struct {
	Error     string           `json:"error"`
	Field     string           `json:"field"`
	EventType domain.EventType `json:"event_type"`
	Code      string           `json:"code"`
	Line      int              `json:"line,omitempty"`
	// Path locates the value inside a webhook custom body (#1376).
	Path string `json:"path,omitempty"`
}

func (rt *Router) writeTemplateError(w http.ResponseWriter, err error) {
	var rejection *notificationuc.TemplateValidationError
	if errors.As(err, &rejection) {
		writeJSON(w, http.StatusBadRequest, templateValidationBody{
			Error: rejection.Error(), Field: rejection.Field, EventType: rejection.EventType, Code: string(rejection.Code), Line: rejection.Line, Path: rejection.Path,
		})
		return
	}
	writeError(w, rt.log, err)
}

func queryInt(r *http.Request, name string) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%w: %s must be a non-negative integer", shared.ErrValidation, name)
	}
	return value, nil
}

func (rt *Router) listNotificationTemplates(w http.ResponseWriter, r *http.Request) {
	limit, err := queryInt(r, "limit")
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	query := r.URL.Query()
	items, err := rt.notifications.ListTemplates(r.Context(), ports.NotificationTemplateQuery{
		EventType: domain.EventType(query.Get("event_type")), Family: domain.TemplateFamily(query.Get("family")),
		Locale: tenancy.Locale(query.Get("locale")), Status: domain.TemplateStatus(query.Get("status")),
		AfterID: shared.ID(query.Get("after")), Limit: limit,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []domain.Template{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// listBuiltinNotificationTemplates exposes the build's read-only defaults so an operator can
// clone their exact source into a tenant draft. Built-ins have no tenant-specific identity.
func (rt *Router) listBuiltinNotificationTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": rt.notifications.ListBuiltinTemplates()})
}

func (rt *Router) createNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	var in notificationuc.TemplateInput
	if err := decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.CreateTemplate(r.Context(), PrincipalFrom(r.Context()), in)
	if err != nil {
		rt.writeTemplateError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (rt *Router) getNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.GetTemplate(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) updateNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var in notificationuc.TemplateUpdateInput
	if err = decodeNotificationBody(w, r, &in); err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.notifications.UpdateTemplate(r.Context(), PrincipalFrom(r.Context()), id, in)
	if err != nil {
		rt.writeTemplateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (rt *Router) listNotificationTemplateVersions(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	before, err := queryInt(r, "before")
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	limit, err := queryInt(r, "limit")
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	items, err := rt.notifications.ListTemplateVersions(r.Context(), id, before, limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if items == nil {
		items = []domain.TemplateVersion{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// changeNotificationTemplate serves activate, rollback and archive, which share a body.
func (rt *Router) changeNotificationTemplate(change func(*notificationuc.Service, *http.Request, string, shared.ID, notificationuc.TemplateChangeInput) (notificationuc.TemplateDetail, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := notificationID(r)
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		var in notificationuc.TemplateChangeInput
		if err = decodeNotificationBody(w, r, &in); err != nil {
			writeError(w, rt.log, err)
			return
		}
		if in.Revision < 1 {
			writeError(w, rt.log, fmt.Errorf("%w: positive revision is required", shared.ErrValidation))
			return
		}
		item, err := change(rt.notifications, r, PrincipalFrom(r.Context()), id, in)
		if err != nil {
			rt.writeTemplateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}
}

func (rt *Router) activateNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	rt.changeNotificationTemplate(func(s *notificationuc.Service, r *http.Request, actor string, id shared.ID, in notificationuc.TemplateChangeInput) (notificationuc.TemplateDetail, error) {
		return s.ActivateTemplate(r.Context(), actor, id, in)
	})(w, r)
}

func (rt *Router) rollbackNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	rt.changeNotificationTemplate(func(s *notificationuc.Service, r *http.Request, actor string, id shared.ID, in notificationuc.TemplateChangeInput) (notificationuc.TemplateDetail, error) {
		return s.RollbackTemplate(r.Context(), actor, id, in)
	})(w, r)
}

func (rt *Router) archiveNotificationTemplate(w http.ResponseWriter, r *http.Request) {
	rt.changeNotificationTemplate(func(s *notificationuc.Service, r *http.Request, actor string, id shared.ID, in notificationuc.TemplateChangeInput) (notificationuc.TemplateDetail, error) {
		return s.ArchiveTemplate(r.Context(), actor, id, in)
	})(w, r)
}

// previewNotificationTemplateResolution answers which template a channel renders an event type
// with (#1371), so the rule form can show it per selected channel. It resolves on the server,
// through the same code the send-time renderer (#1365) will call, instead of re-implementing the
// tiers in the console. The body names the tier, template and version, never template source.
func (rt *Router) previewNotificationTemplateResolution(w http.ResponseWriter, r *http.Request) {
	id, err := notificationID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	resolution, err := rt.notifications.PreviewTemplateResolution(r.Context(), id, domain.EventType(r.URL.Query().Get("event_type")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, resolution)
}
