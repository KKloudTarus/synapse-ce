package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	ticketuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type ticketWorkflow interface {
	SaveMapping(context.Context, shared.ID, shared.ID, ticketuc.MappingInput) (ticketing.Mapping, error)
	DeleteMapping(context.Context, shared.ID, shared.ID, int, string) error
	ListMappings(context.Context, shared.ID, ticketing.Scope, shared.ID) ([]ticketing.Mapping, error)
	Metadata(context.Context, shared.ID, shared.ID, string, string, string) (ports.TicketMetadata, error)
	GetFindingTickets(context.Context, shared.ID, shared.ID, shared.ID) (ticketuc.FindingTickets, error)
	LinkManual(context.Context, shared.ID, shared.ID, shared.ID, string) (ticketing.Link, bool, error)
	Unlink(context.Context, shared.ID, shared.ID, shared.ID, shared.ID) error
	Preview(context.Context, ticketuc.PreviewRequest) (ticketuc.Preview, error)
	Submit(context.Context, ticketuc.SubmitRequest) (ticketing.Intent, bool, error)
	Reconcile(context.Context, shared.ID, shared.ID, int) (ticketing.Intent, error)
	RetryUncertain(context.Context, shared.ID, shared.ID, int, bool, string, string) (ticketing.Intent, error)
	ResetBreaker(context.Context, shared.ID, shared.ID, string, string, string) error
}

func (rt *Router) SetTicketing(service ticketWorkflow) {
	rt.ticketing = service
}

type ticketLinkView struct {
	ID            shared.ID `json:"id"`
	ExternalURL   string    `json:"external_url"`
	ExternalID    string    `json:"external_id"`
	IntegrationID shared.ID `json:"integration_id"`
	CreatedAt     any       `json:"created_at"`
}

func ticketLinkResponse(l ticketing.Link) ticketLinkView {
	return ticketLinkView{l.ID, l.ExternalURL, l.ExternalID, l.IntegrationID, l.CreatedAt}
}

type ticketIntentView struct {
	ID        shared.ID `json:"id"`
	FindingID shared.ID `json:"finding_id"`
	MappingID shared.ID `json:"mapping_id"`
	State     string    `json:"state"`
	Version   int       `json:"version"`
	Attempts  int       `json:"attempts"`
	ErrorCode string    `json:"error_code"`
	RemoteID  string    `json:"remote_id,omitempty"`
	RemoteURL string    `json:"remote_url,omitempty"`
	CreatedAt any       `json:"created_at"`
}

func ticketIntentResponse(i ticketing.Intent) ticketIntentView {
	return ticketIntentView{i.ID, i.FindingID, i.MappingID, string(i.State), i.Version, i.Attempts, i.ErrorCode, i.RemoteID, i.RemoteURL, i.CreatedAt}
}

func ticketMappingResponse(m ticketing.Mapping) any {
	return map[string]any{"id": m.ID, "integration_id": m.IntegrationID, "scope": m.Scope, "scope_id": m.ScopeID, "project_key": m.ProjectKey, "issue_type": m.IssueType, "component": m.Component, "labels": m.Labels, "priority_map": m.PriorityMap, "security_level": m.SecurityLevel, "summary_template": m.SummaryTemplate, "description_template": m.DescriptionTemplate, "field_values": m.FieldValues, "transition_id": m.Transition, "version": m.Version, "data_class": m.DataClass, "locale": m.Locale, "waiver_reason": m.WaiverReason, "auto_push_enabled": m.AutoPushEnabled, "auto_push_min_severity": m.AutoPushMinSeverity, "grouping_mode": m.GroupingMode, "status_transitions": m.StatusTransitions}
}

func (rt *Router) listTicketMappings(w http.ResponseWriter, r *http.Request) {
	items, err := rt.ticketing.ListMappings(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), ticketing.Scope(r.URL.Query().Get("scope")), shared.ID(r.URL.Query().Get("scope_id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]any, 0, len(items))
	for _, m := range items {
		out = append(out, ticketMappingResponse(m))
	}
	writeJSON(w, http.StatusOK, out)
}
func (rt *Router) saveTicketMapping(w http.ResponseWriter, r *http.Request) {
	var input ticketuc.MappingInput
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	input.Actor = PrincipalFrom(r.Context())
	principal, _ := principalObj(r.Context())
	input.AllowAdmin = userdom.Role(principal.Role).Can(userdom.PermAdminister)
	id := shared.ID(r.PathValue("mappingID"))
	m, err := rt.ticketing.SaveMapping(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), id, input)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	status := http.StatusOK
	if id.IsZero() {
		status = http.StatusCreated
	}
	writeJSON(w, status, ticketMappingResponse(m))
}
func (rt *Router) deleteTicketMapping(w http.ResponseWriter, r *http.Request) {
	version, _ := strconv.Atoi(r.URL.Query().Get("version"))
	if version < 1 {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}
	err := rt.ticketing.DeleteMapping(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("mappingID")), version, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) jiraMetadata(w http.ResponseWriter, r *http.Request) {
	meta, err := rt.ticketing.Metadata(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("integrationID")), r.URL.Query().Get("project_key"), r.URL.Query().Get("issue_type"), r.URL.Query().Get("issue_key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}
func (rt *Router) resetJiraBreaker(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ProjectKey string `json:"project_key"`
		IssueType  string `json:"issue_type"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	err := rt.ticketing.ResetBreaker(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("integrationID")), input.ProjectKey, input.IssueType, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) findingTickets(w http.ResponseWriter, r *http.Request) {
	data, err := rt.ticketing.GetFindingTickets(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	links := make([]ticketLinkView, 0, len(data.Links))
	for _, l := range data.Links {
		links = append(links, ticketLinkResponse(l))
	}
	intents := make([]ticketIntentView, 0, len(data.Intents))
	for _, i := range data.Intents {
		intents = append(intents, ticketIntentResponse(i))
	}
	mappings := make([]any, 0, len(data.Mappings))
	for _, m := range data.Mappings {
		mappings = append(mappings, ticketMappingResponse(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links, "intents": intents, "mappings": mappings})
}
func (rt *Router) linkTicket(w http.ResponseWriter, r *http.Request) {
	var input struct {
		URL string `json:"url"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	link, created, err := rt.ticketing.LinkManual(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")), input.URL)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, ticketLinkResponse(link))
}
func (rt *Router) unlinkTicket(w http.ResponseWriter, r *http.Request) {
	err := rt.ticketing.Unlink(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("fid")), shared.ID(r.PathValue("linkID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) previewTicket(w http.ResponseWriter, r *http.Request) {
	var input struct {
		MappingID shared.ID `json:"mapping_id"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	p, err := rt.ticketing.Preview(r.Context(), ticketuc.PreviewRequest{TenantID: shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), MappingID: input.MappingID, FindingID: shared.ID(r.PathValue("fid")), EngagementID: shared.ID(r.PathValue("id"))})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	var payload map[string]json.RawMessage
	if err = json.Unmarshal(p.Payload, &payload); err != nil {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}
	links := make([]map[string]string, 0, len(p.Links))
	for _, link := range p.Links {
		links = append(links, map[string]string{"label": link.Label, "url": link.URL})
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": payload["fields"], "summary": p.Summary, "description": p.Description, "links": links, "security_waived": p.SecurityWaived, "data_class": p.DataClass, "digest": p.Digest, "mapping_version": p.MappingVersion, "marker_required": p.MarkerRequired, "marker_format": p.MarkerFormat})
}
func (rt *Router) submitTicket(w http.ResponseWriter, r *http.Request) {
	var input struct {
		MappingID     shared.ID `json:"mapping_id"`
		PreviewDigest string    `json:"preview_digest"`
		RequestKey    string    `json:"request_key"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	i, _, err := rt.ticketing.Submit(r.Context(), ticketuc.SubmitRequest{TenantID: shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), MappingID: input.MappingID, FindingID: shared.ID(r.PathValue("fid")), EngagementID: shared.ID(r.PathValue("id")), RequestKey: input.RequestKey, PreviewDigest: input.PreviewDigest, Actor: PrincipalFrom(r.Context())})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, ticketIntentResponse(i))
}
func (rt *Router) reconcileTicket(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version int `json:"version"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	tenant, id := shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("intentID"))
	i, err := rt.ticketing.Reconcile(r.Context(), tenant, id, input.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, ticketIntentResponse(i))
}
func (rt *Router) retryTicket(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version     int    `json:"version"`
		Acknowledge bool   `json:"acknowledge_duplicate_risk"`
		Reason      string `json:"reason"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	i, err := rt.ticketing.RetryUncertain(r.Context(), shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), shared.ID(r.PathValue("intentID")), input.Version, input.Acknowledge, input.Reason, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, ticketIntentResponse(i))
}
func (rt *Router) bulkSubmitTickets(w http.ResponseWriter, r *http.Request) {
	var input struct {
		MappingID shared.ID `json:"mapping_id"`
		Items     []struct {
			FindingID     shared.ID `json:"finding_id"`
			PreviewDigest string    `json:"preview_digest"`
			RequestKey    string    `json:"request_key"`
		} `json:"items"`
	}
	if !decodeIntegrationJSON(w, r, &input) {
		return
	}
	if len(input.Items) < 1 || len(input.Items) > 50 {
		writeError(w, rt.log, shared.ErrValidation)
		return
	}
	out := make([]any, 0, len(input.Items))
	for _, item := range input.Items {
		i, _, err := rt.ticketing.Submit(r.Context(), ticketuc.SubmitRequest{TenantID: shared.TenantOrDefault(shared.ID(TenantFrom(r.Context()))), MappingID: input.MappingID, FindingID: item.FindingID, EngagementID: shared.ID(r.PathValue("id")), RequestKey: item.RequestKey, PreviewDigest: item.PreviewDigest, Actor: PrincipalFrom(r.Context())})
		if err != nil {
			code := "unavailable"
			if errors.Is(err, shared.ErrValidation) {
				code = "validation"
			}
			if errors.Is(err, shared.ErrNotFound) {
				code = "not_found"
			}
			if errors.Is(err, shared.ErrConflict) {
				code = "conflict"
			}
			out = append(out, map[string]any{"finding_id": item.FindingID, "error_code": code})
		} else {
			out = append(out, map[string]any{"finding_id": item.FindingID, "intent": ticketIntentResponse(i)})
		}
	}
	writeJSON(w, http.StatusAccepted, out)
}
