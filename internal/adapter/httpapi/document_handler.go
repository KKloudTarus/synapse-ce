package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	documentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// documentPublishing is deliberately smaller than docpublish.Service's worker surface.
// HTTP can request or view work; it cannot advance remote publishing steps.
type documentPublishing interface {
	Publish(context.Context, shared.ID, ports.DocumentActor, documentuc.PublishInput) (documentuc.ReleaseResult, error)
	Unpublish(context.Context, shared.ID, ports.DocumentActor, shared.ID, string) (documentuc.ReleaseResult, error)
	ResumePreparedPublication(context.Context, shared.ID, ports.DocumentActor, shared.ID, int) (docpublish.Intent, error)
	Links(context.Context, shared.ID, docpublish.Scope, shared.ID) ([]docpublish.Link, error)
	Intent(context.Context, shared.ID, shared.ID) (docpublish.Intent, error)
}

func (rt *Router) SetDocumentPublishing(service documentPublishing) { rt.documentPublishing = service }

type documentPublishRequest struct {
	IntegrationID shared.ID             `json:"integration_id"`
	SourceKind    docpublish.SourceKind `json:"source_kind"`
	ScopeID       shared.ID             `json:"scope_id"`
	SourceRef     string                `json:"source_ref"`
	RequestKey    string                `json:"request_key"`
}

type documentUnpublishRequest struct {
	RequestKey string `json:"request_key"`
}

type documentResumeRequest struct {
	Version int `json:"version"`
}

type documentIntentView struct {
	ID        shared.ID         `json:"id"`
	LinkID    shared.ID         `json:"link_id,omitempty"`
	Action    docpublish.Action `json:"action"`
	State     string            `json:"state"`
	Version   int               `json:"version"`
	Attempts  int               `json:"attempts"`
	ErrorCode string            `json:"error_code,omitempty"`
	RemoteURL string            `json:"remote_url,omitempty"`
	RemoteID  string            `json:"remote_id,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type documentLinkView struct {
	ID                   shared.ID             `json:"id"`
	IntegrationID        shared.ID             `json:"integration_id"`
	SourceKind           docpublish.SourceKind `json:"source_kind"`
	SourceRef            string                `json:"source_ref"`
	Scope                docpublish.Scope      `json:"scope"`
	ScopeID              shared.ID             `json:"scope_id"`
	Container            string                `json:"container"`
	RemoteURL            string                `json:"remote_url"`
	RemoteVersion        int                   `json:"remote_version"`
	RemoteRevisionKind   string                `json:"remote_revision_kind"`
	ContentHash          string                `json:"content_hash"`
	Revision             int                   `json:"revision"`
	RestrictionStatus    string                `json:"restriction_status"`
	RestrictionCheckedAt *time.Time            `json:"restriction_checked_at,omitempty"`
	RetiredAt            *time.Time            `json:"retired_at,omitempty"`
	UpdatedAt            time.Time             `json:"updated_at"`
}

func documentActor(r *http.Request) (ports.DocumentActor, bool) {
	p, ok := principalObj(r.Context())
	if !ok || p.ID == "" {
		return ports.DocumentActor{}, false
	}
	return ports.DocumentActor{UserID: shared.ID(p.ID), MembershipID: shared.ID(p.MembershipID), PersonID: shared.ID(p.PersonID)}, true
}

func documentIntentResponse(value docpublish.Intent) documentIntentView {
	return documentIntentView{ID: value.ID, LinkID: value.LinkID, Action: value.Action, State: string(value.State), Version: value.Version, Attempts: value.Attempts, ErrorCode: value.ErrorCode, RemoteURL: value.RemoteURL, RemoteID: value.RemoteID, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}

func documentLinkResponse(value docpublish.Link) documentLinkView {
	return documentLinkView{ID: value.ID, IntegrationID: value.IntegrationID, SourceKind: value.SourceKind, SourceRef: value.SourceRef, Scope: value.Scope, ScopeID: value.ScopeID, Container: value.Container, RemoteURL: value.RemoteURL, RemoteVersion: value.RemoteVersion, RemoteRevisionKind: documentRevisionKind(value.RemoteRevision), ContentHash: value.ContentHash, Revision: value.Revision, RestrictionStatus: value.RestrictionStatus, RestrictionCheckedAt: value.RestrictionCheckedAt, RetiredAt: value.RetiredAt, UpdatedAt: value.UpdatedAt}
}

func documentReleaseResponse(value documentuc.ReleaseResult) any {
	response := map[string]any{"skipped": value.Skipped}
	if value.Intent != nil {
		response["intent"] = documentIntentResponse(*value.Intent)
	}
	if value.Link != nil {
		response["link"] = documentLinkResponse(*value.Link)
	}
	return response
}

func (rt *Router) publishDocument(w http.ResponseWriter, r *http.Request) {
	var body documentPublishRequest
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	actor, ok := documentActor(r)
	if !ok {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	result, err := rt.documentPublishing.Publish(r.Context(), shared.ID(TenantFrom(r.Context())), actor, documentuc.PublishInput{IntegrationID: body.IntegrationID, SourceKind: body.SourceKind, ScopeID: body.ScopeID, SourceRef: body.SourceRef, RequestKey: body.RequestKey})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, documentReleaseResponse(result))
}

func (rt *Router) documentIntent(w http.ResponseWriter, r *http.Request) {
	item, err := rt.documentPublishing.Intent(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, documentIntentResponse(item))
}

func (rt *Router) resumePreparedDocumentPublication(w http.ResponseWriter, r *http.Request) {
	var body documentResumeRequest
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	actor, ok := documentActor(r)
	if !ok {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	item, err := rt.documentPublishing.ResumePreparedPublication(r.Context(), shared.ID(TenantFrom(r.Context())), actor, shared.ID(r.PathValue("id")), body.Version)
	if err != nil {
		var refused *ports.DocumentProviderError
		if errors.As(err, &refused) {
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusConflict, errorBody{Error: "Destination access or restricted sharing could not be verified. Correct access before resuming."})
			return
		}
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, documentIntentResponse(item))
}

func (rt *Router) engagementDocuments(w http.ResponseWriter, r *http.Request) {
	rt.documentLinks(w, r, docpublish.Engagement, shared.ID(r.PathValue("id")))
}

func (rt *Router) projectDocuments(w http.ResponseWriter, r *http.Request) {
	if rt.projects == nil {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	project, err := rt.projects.Get(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	rt.documentLinks(w, r, docpublish.Project, project.ID)
}

func (rt *Router) documentLinks(w http.ResponseWriter, r *http.Request, scope docpublish.Scope, scopeID shared.ID) {
	items, err := rt.documentPublishing.Links(r.Context(), shared.ID(TenantFrom(r.Context())), scope, scopeID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]documentLinkView, 0, len(items))
	for _, item := range items {
		out = append(out, documentLinkResponse(item))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) unpublishDocument(w http.ResponseWriter, r *http.Request) {
	var body documentUnpublishRequest
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	actor, ok := documentActor(r)
	if !ok {
		writeError(w, rt.log, shared.ErrForbidden)
		return
	}
	result, err := rt.documentPublishing.Unpublish(r.Context(), shared.ID(TenantFrom(r.Context())), actor, shared.ID(r.PathValue("id")), body.RequestKey)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, documentReleaseResponse(result))
}

func documentRevisionKind(token string) string {
	if token != "" {
		return "opaque"
	}
	return "numeric"
}
