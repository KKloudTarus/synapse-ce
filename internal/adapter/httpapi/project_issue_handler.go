package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type projectIssueResponse struct {
	ID                  string                  `json:"id"`
	RuleKey             string                  `json:"rule_key"`
	RuleName            string                  `json:"rule_name"`
	Type                string                  `json:"type"`
	Title               string                  `json:"title"`
	Description         string                  `json:"description"`
	Severity            string                  `json:"severity"`
	FindingKind         string                  `json:"finding_kind"`
	CWE                 string                  `json:"cwe"`
	Language            string                  `json:"language"`
	File                string                  `json:"file"`
	Location            string                  `json:"location"`
	SourceLocation      *finding.SourceLocation `json:"source_location,omitempty"`
	Status              string                  `json:"status"`
	Version             int                     `json:"version"`
	IsNew               bool                    `json:"is_new"`
	FirstSeenAnalysisID string                  `json:"first_seen_analysis_id"`
	LastSeenAnalysisID  string                  `json:"last_seen_analysis_id"`
	FirstSeenAt         time.Time               `json:"first_seen_at"`
	LastSeenAt          time.Time               `json:"last_seen_at"`
}

type projectIssueCursorResponse struct {
	BeforeLastSeenAt time.Time `json:"before_last_seen_at"`
	BeforeID         string    `json:"before_id"`
}

type projectIssueFacetsResponse struct {
	Types      map[string]int `json:"types"`
	Statuses   map[string]int `json:"statuses"`
	Severities map[string]int `json:"severities"`
	RuleKeys   map[string]int `json:"rule_keys"`
	Languages  map[string]int `json:"languages"`
}

type projectIssueSummaryResponse struct {
	Total    int `json:"total"`
	Open     int `json:"open"`
	Resolved int `json:"resolved"`
}

type projectIssuePageResponse struct {
	Items   []projectIssueResponse      `json:"items"`
	Next    *projectIssueCursorResponse `json:"next"`
	Facets  projectIssueFacetsResponse  `json:"facets"`
	Summary projectIssueSummaryResponse `json:"summary"`
}

type projectIssueEventResponse struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	Actor     string    `json:"actor"`
	Rationale string    `json:"rationale"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

type transitionIssueRequest struct {
	To              string `json:"to"`
	Rationale       string `json:"rationale"`
	ExpectedVersion int    `json:"expected_version"`
}

var projectIssueQueryParameters = map[string]bool{
	"lens": true, "status": true, "type": true, "severity": true, "rule": true,
	"language": true, "path": true, "new_code": true, "search": true,
	"limit": true, "before_last_seen_at": true, "before_id": true,
}

func (rt *Router) listProjectIssues(w http.ResponseWriter, r *http.Request) {
	filter, err := projectIssueListParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	page, err := rt.projects.ListIssues(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), filter)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := projectIssuePageResponse{
		Items: make([]projectIssueResponse, len(page.Items)),
		Facets: projectIssueFacetsResponse{
			Types: page.Facets.Types, Statuses: page.Facets.Statuses, Severities: page.Facets.Severities,
			RuleKeys: page.Facets.RuleKeys, Languages: page.Facets.Languages,
		},
		Summary: projectIssueSummaryResponse{Total: page.Summary.Total, Open: page.Summary.Open, Resolved: page.Summary.Resolved},
	}
	names := rt.ruleNames(r, page.Items)
	for i, item := range page.Items {
		out.Items[i] = projectIssueDTO(item, names[item.RuleKey])
	}
	if page.Next != nil {
		out.Next = &projectIssueCursorResponse{BeforeLastSeenAt: page.Next.BeforeLastSeenAt, BeforeID: page.Next.BeforeID.String()}
	}
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) getProjectIssue(w http.ResponseWriter, r *http.Request) {
	item, err := rt.projects.GetIssue(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, projectIssueDTO(item, rt.ruleName(r, item.RuleKey)))
}

func (rt *Router) transitionProjectIssue(w http.ResponseWriter, r *http.Request) {
	var req transitionIssueRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	to := issue.Status(strings.TrimSpace(req.To))
	if !to.Valid() {
		writeError(w, rt.log, fmt.Errorf("%w: invalid transition target status", shared.ErrValidation))
		return
	}
	updated, _, err := rt.projects.TransitionIssue(r.Context(), PrincipalFrom(r.Context()),
		shared.ID(TenantFrom(r.Context())), r.PathValue("key"), shared.ID(r.PathValue("id")), to, req.Rationale, req.ExpectedVersion)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, projectIssueDTO(updated, rt.ruleName(r, updated.RuleKey)))
}

func (rt *Router) projectIssueHistory(w http.ResponseWriter, r *http.Request) {
	events, err := rt.projects.IssueHistory(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]projectIssueEventResponse, len(events))
	for i, e := range events {
		out[i] = projectIssueEventResponse{From: string(e.From), To: string(e.To), Actor: e.Actor, Rationale: e.Rationale, Version: e.Version, CreatedAt: e.CreatedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

func projectIssueDTO(item issue.Issue, ruleName string) projectIssueResponse {
	return projectIssueResponse{
		ID: item.ID.String(), RuleKey: item.RuleKey, RuleName: ruleName, Type: string(item.Type),
		Title: item.Title, Description: item.Description, Severity: string(item.Severity), FindingKind: string(item.Kind),
		CWE: item.CWE, Language: item.Language, File: item.File, Location: item.Location, SourceLocation: item.SourceLocation,
		Status: string(item.Status), Version: item.Version, IsNew: item.IsNew,
		FirstSeenAnalysisID: item.FirstSeenAnalysisID, LastSeenAnalysisID: item.LastSeenAnalysisID,
		FirstSeenAt: item.FirstSeenAt, LastSeenAt: item.LastSeenAt,
	}
}

// ruleName resolves a single catalog rule name (best-effort, read-only).
func (rt *Router) ruleName(r *http.Request, ruleKey string) string {
	if rt.rules == nil || strings.TrimSpace(ruleKey) == "" {
		return ""
	}
	if cr, err := rt.rules.Get(r.Context(), rule.Key(ruleKey)); err == nil {
		return cr.Name
	}
	return ""
}

// ruleNames resolves the distinct rule names for a page in one pass.
func (rt *Router) ruleNames(r *http.Request, items []issue.Issue) map[string]string {
	names := map[string]string{}
	if rt.rules == nil {
		return names
	}
	for _, item := range items {
		if _, seen := names[item.RuleKey]; seen || strings.TrimSpace(item.RuleKey) == "" {
			continue
		}
		if cr, err := rt.rules.Get(r.Context(), rule.Key(item.RuleKey)); err == nil {
			names[item.RuleKey] = cr.Name
		} else {
			names[item.RuleKey] = ""
		}
	}
	return names
}

func projectIssueListParams(r *http.Request) (issue.ListFilter, error) {
	for key := range r.URL.Query() {
		if !projectIssueQueryParameters[key] {
			return issue.ListFilter{}, fmt.Errorf("%w: unsupported query parameter: %s", shared.ErrValidation, key)
		}
	}
	q := r.URL.Query()
	filter := issue.ListFilter{
		Lens:        issue.LensOverall,
		RuleKey:     strings.TrimSpace(q.Get("rule")),
		Language:    strings.TrimSpace(q.Get("language")),
		PathPrefix:  strings.TrimSpace(q.Get("path")),
		Search:      strings.TrimSpace(q.Get("search")),
		NewCodeOnly: strings.EqualFold(strings.TrimSpace(q.Get("new_code")), "true"),
		Limit:       25,
	}
	if raw := strings.TrimSpace(q.Get("lens")); raw != "" {
		lens := issue.Lens(raw)
		if !lens.Valid() {
			return issue.ListFilter{}, fmt.Errorf("%w: invalid lens", shared.ErrValidation)
		}
		filter.Lens = lens
	}
	for _, field := range []struct {
		name  string
		value string
	}{{"rule", filter.RuleKey}, {"language", filter.Language}, {"path", filter.PathPrefix}, {"search", filter.Search}} {
		if utf8.RuneCountInString(field.value) > 256 {
			return issue.ListFilter{}, fmt.Errorf("%w: %s exceeds maximum length", shared.ErrValidation, field.name)
		}
	}
	if raw := strings.TrimSpace(q.Get("status")); raw != "" {
		status := issue.Status(raw)
		if !status.Valid() {
			return issue.ListFilter{}, fmt.Errorf("%w: invalid issue status", shared.ErrValidation)
		}
		filter.Status = &status
	}
	if raw := strings.TrimSpace(q.Get("type")); raw != "" {
		t := rule.Type(raw)
		if !t.Valid() {
			return issue.ListFilter{}, fmt.Errorf("%w: invalid issue type", shared.ErrValidation)
		}
		filter.Type = &t
	}
	if raw := strings.TrimSpace(q.Get("severity")); raw != "" {
		sev := shared.Severity(raw)
		if !sev.Valid() {
			return issue.ListFilter{}, fmt.Errorf("%w: invalid issue severity", shared.ErrValidation)
		}
		filter.Severity = &sev
	}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return issue.ListFilter{}, fmt.Errorf("%w: limit must be between 1 and 100", shared.ErrValidation)
		}
		filter.Limit = limit
	}
	rawTime, rawID := strings.TrimSpace(q.Get("before_last_seen_at")), strings.TrimSpace(q.Get("before_id"))
	if (rawTime == "") != (rawID == "") {
		return issue.ListFilter{}, fmt.Errorf("%w: before_last_seen_at and before_id must be supplied together", shared.ErrValidation)
	}
	if rawTime != "" {
		before, err := time.Parse(time.RFC3339Nano, rawTime)
		if err != nil {
			return issue.ListFilter{}, fmt.Errorf("%w: before_last_seen_at must be RFC3339", shared.ErrValidation)
		}
		filter.BeforeLastSeenAt, filter.BeforeID = before, shared.ID(rawID)
	}
	return filter, nil
}
