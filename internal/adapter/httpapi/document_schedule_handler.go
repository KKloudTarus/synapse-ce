package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type documentScheduling interface {
	SaveSchedule(context.Context, shared.ID, ports.DocumentActor, documentuc.ScheduleInput) (docpublish.Schedule, error)
	ListSchedules(context.Context, shared.ID, docpublish.Scope, shared.ID) ([]docpublish.Schedule, error)
	DeleteSchedule(context.Context, shared.ID, ports.DocumentActor, shared.ID, int) error
	EmailDestinations(context.Context, shared.ID, ports.DocumentActor) ([]documentuc.ScheduleEmailDestination, error)
}

type documentScheduleHistory interface {
	RunHistory(context.Context, shared.ID, shared.ID) ([]ports.DocumentScheduleRunView, error)
}

func (rt *Router) SetDocumentScheduling(service documentScheduling, ids ports.IDGenerator) {
	rt.documentScheduling = service
	rt.documentScheduleIDs = ids
}

func (rt *Router) SetDocumentScheduleHistory(service documentScheduleHistory) {
	rt.documentScheduleHistory = service
}

type documentScheduleRequest struct {
	SourceKind      docpublish.SourceKind          `json:"source_kind"`
	SourceRef       string                         `json:"source_ref"`
	ScopeID         shared.ID                      `json:"scope_id"`
	Destination     docpublish.ScheduleDestination `json:"destination"`
	IntegrationID   shared.ID                      `json:"integration_id,omitempty"`
	EmailChannelID  shared.ID                      `json:"email_channel_id,omitempty"`
	Timezone        string                         `json:"timezone"`
	Frequency       docpublish.ScheduleFrequency   `json:"frequency"`
	Weekday         int                            `json:"weekday,omitempty"`
	Day             int                            `json:"day,omitempty"`
	Hour            int                            `json:"hour"`
	Minute          int                            `json:"minute"`
	Enabled         bool                           `json:"enabled"`
	ExpectedVersion int                            `json:"expected_version,omitempty"`
}

type documentScheduleDisableRequest struct {
	ExpectedVersion int `json:"expected_version"`
}

type documentScheduleView struct {
	ID             shared.ID                      `json:"id"`
	SourceKind     docpublish.SourceKind          `json:"source_kind"`
	SourceRef      string                         `json:"source_ref"`
	Scope          docpublish.Scope               `json:"scope"`
	ScopeID        shared.ID                      `json:"scope_id"`
	Destination    docpublish.ScheduleDestination `json:"destination"`
	IntegrationID  shared.ID                      `json:"integration_id,omitempty"`
	EmailChannelID shared.ID                      `json:"email_channel_id,omitempty"`
	Timezone       string                         `json:"timezone"`
	Frequency      docpublish.ScheduleFrequency   `json:"frequency"`
	Weekday        int                            `json:"weekday,omitempty"`
	Day            int                            `json:"day,omitempty"`
	Hour           int                            `json:"hour"`
	Minute         int                            `json:"minute"`
	Enabled        bool                           `json:"enabled"`
	Version        int                            `json:"version"`
	NextDueAt      time.Time                      `json:"next_due_at"`
	UpdatedAt      time.Time                      `json:"updated_at"`
}

type documentScheduleEmailDestinationView struct {
	ID             shared.ID `json:"id"`
	Name           string    `json:"name"`
	RecipientCount int       `json:"recipient_count"`
}

type documentScheduleRunView struct {
	ID             shared.ID                          `json:"id"`
	DueAt          time.Time                          `json:"due_at"`
	State          docpublish.ScheduleOccurrenceState `json:"state"`
	ContentHash    string                             `json:"content_hash,omitempty"`
	RemotePageID   string                             `json:"remote_page_id,omitempty"`
	RemoteVersion  int                                `json:"remote_version,omitempty"`
	DeliveredCount int                                `json:"delivered_count"`
	UncertainCount int                                `json:"uncertain_count"`
	FailedCount    int                                `json:"failed_count"`
	UpdatedAt      time.Time                          `json:"updated_at"`
}

func documentScheduleRunResponse(value ports.DocumentScheduleRunView) documentScheduleRunView {
	return documentScheduleRunView{ID: value.ID, DueAt: value.DueAt, State: value.State, ContentHash: value.ContentHash, RemotePageID: value.RemotePageID, RemoteVersion: value.RemoteVersion, DeliveredCount: value.DeliveredCount, UncertainCount: value.UncertainCount, FailedCount: value.FailedCount, UpdatedAt: value.UpdatedAt}
}

func documentScheduleResponse(value docpublish.Schedule) documentScheduleView {
	return documentScheduleView{ID: value.ID, SourceKind: value.Source.SourceKind, SourceRef: value.Source.SourceRef, Scope: value.Source.Scope, ScopeID: value.Source.ScopeID, Destination: value.Destination, IntegrationID: value.IntegrationID, EmailChannelID: value.EmailChannelID, Timezone: value.Timezone, Frequency: value.Frequency, Weekday: value.Weekday, Day: value.Day, Hour: value.Hour, Minute: value.Minute, Enabled: value.Enabled, Version: value.Version, NextDueAt: value.NextDueAt, UpdatedAt: value.UpdatedAt}
}

func (rt *Router) saveDocumentSchedule(w http.ResponseWriter, r *http.Request) {
	var body documentScheduleRequest
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	actor, ok := documentActor(r)
	if !ok || rt.documentScheduleIDs == nil {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	scope, valid := body.SourceKind.Scope()
	if !valid || body.ScopeID.IsZero() {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}
	item, err := rt.documentScheduling.SaveSchedule(r.Context(), shared.ID(TenantFrom(r.Context())), actor, documentuc.ScheduleInput{
		ID: rt.documentScheduleIDs.NewID(), Source: docpublish.Source{SourceKind: body.SourceKind, SourceRef: body.SourceRef, Scope: scope, ScopeID: body.ScopeID}, Destination: body.Destination,
		IntegrationID: body.IntegrationID, EmailChannelID: body.EmailChannelID, Timezone: body.Timezone, Frequency: body.Frequency, Weekday: body.Weekday, Day: body.Day, Hour: body.Hour, Minute: body.Minute, Enabled: body.Enabled, ExpectedVersion: body.ExpectedVersion,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, documentScheduleResponse(item))
}

func (rt *Router) listDocumentSchedules(w http.ResponseWriter, r *http.Request) {
	scope := docpublish.Scope(r.URL.Query().Get("scope"))
	scopeID := shared.ID(r.URL.Query().Get("scope_id"))
	if (scope != docpublish.Engagement && scope != docpublish.Project) || scopeID.IsZero() {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}
	items, err := rt.documentScheduling.ListSchedules(r.Context(), shared.ID(TenantFrom(r.Context())), scope, scopeID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]documentScheduleView, 0, len(items))
	for _, item := range items {
		out = append(out, documentScheduleResponse(item))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) disableDocumentSchedule(w http.ResponseWriter, r *http.Request) {
	var body documentScheduleDisableRequest
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	actor, ok := documentActor(r)
	if !ok {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	if err := rt.documentScheduling.DeleteSchedule(r.Context(), shared.ID(TenantFrom(r.Context())), actor, shared.ID(r.PathValue("id")), body.ExpectedVersion); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) documentScheduleEmailDestinations(w http.ResponseWriter, r *http.Request) {
	actor, ok := documentActor(r)
	if !ok {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	items, err := rt.documentScheduling.EmailDestinations(r.Context(), shared.ID(TenantFrom(r.Context())), actor)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]documentScheduleEmailDestinationView, 0, len(items))
	for _, item := range items {
		out = append(out, documentScheduleEmailDestinationView{ID: item.ID, Name: item.Name, RecipientCount: item.RecipientCount})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) documentScheduleRuns(w http.ResponseWriter, r *http.Request) {
	items, err := rt.documentScheduleHistory.RunHistory(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]documentScheduleRunView, 0, len(items))
	for _, item := range items {
		out = append(out, documentScheduleRunResponse(item))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}
