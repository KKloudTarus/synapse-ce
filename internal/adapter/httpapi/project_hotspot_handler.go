package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	rulesuc "github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
)

type projectHotspotResponse struct {
	ID                  string    `json:"id"`
	RuleKey             string    `json:"rule_key"`
	RuleName            string    `json:"rule_name"`
	Title               string    `json:"title"`
	Description         string    `json:"description"`
	Severity            string    `json:"severity"`
	FindingKind         string    `json:"finding_kind"`
	CWE                 string    `json:"cwe"`
	Location            string    `json:"location"`
	Status              string    `json:"status"`
	Version             int       `json:"version"`
	FirstSeenAnalysisID string    `json:"first_seen_analysis_id"`
	LastSeenAnalysisID  string    `json:"last_seen_analysis_id"`
	FirstSeenAt         time.Time `json:"first_seen_at"`
	LastSeenAt          time.Time `json:"last_seen_at"`
}

type projectHotspotCursorResponse struct {
	BeforeLastSeenAt time.Time `json:"before_last_seen_at"`
	BeforeID         string    `json:"before_id"`
}

type projectHotspotFacetsResponse struct {
	Statuses   map[string]int `json:"statuses"`
	RuleKeys   map[string]int `json:"rule_keys"`
	Severities map[string]int `json:"severities"`
}

type projectHotspotSummaryResponse struct {
	Total       int     `json:"total"`
	Reviewed    int     `json:"reviewed"`
	ReviewedPct float64 `json:"reviewed_pct"`
	Grade       string  `json:"grade"`
}

type projectHotspotPageResponse struct {
	Items   []projectHotspotResponse      `json:"items"`
	Next    *projectHotspotCursorResponse `json:"next"`
	Facets  projectHotspotFacetsResponse  `json:"facets"`
	Summary projectHotspotSummaryResponse `json:"summary"`
}

var projectHotspotQueryParameters = map[string]bool{
	"lens": true, "status": true, "rule": true, "severity": true, "search": true,
	"limit": true, "before_last_seen_at": true, "before_id": true,
}

func (rt *Router) listProjectHotspots(w http.ResponseWriter, r *http.Request) {
	filter, err := projectHotspotListParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	page, err := rt.projects.ListHotspots(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), filter)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := projectHotspotPageResponse{
		Items:  make([]projectHotspotResponse, len(page.Items)),
		Facets: projectHotspotFacetsResponse{Statuses: page.Facets.Statuses, RuleKeys: page.Facets.RuleKeys, Severities: page.Facets.Severities},
		Summary: projectHotspotSummaryResponse{
			Total:       page.Summary.Total,
			Reviewed:    page.Summary.Reviewed,
			ReviewedPct: page.Summary.ReviewedPct,
			Grade:       string(page.Summary.Grade),
		},
	}
	ruleNames := make(map[string]string)
	if rt.rules != nil && len(page.Items) > 0 {
		catalogRules, err := rt.rules.List(
			r.Context(),
			rulesuc.Filter{
				Types: []rule.Type{rule.TypeSecurityHotspot},
			},
		)
		if err != nil {
			writeError(w, rt.log, fmt.Errorf("load security hotspot rule catalog: %w", err))
			return
		}
		for _, catalogRule := range catalogRules {
			ruleNames[string(catalogRule.Key)] = catalogRule.Name
		}
	}

	for i, item := range page.Items {
		out.Items[i] = rt.projectHotspotDTO(item, ruleNames[item.RuleKey])
	}
	if page.Next != nil {
		out.Next = &projectHotspotCursorResponse{BeforeLastSeenAt: page.Next.BeforeLastSeenAt, BeforeID: page.Next.BeforeID.String()}
	}
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) getProjectHotspot(w http.ResponseWriter, r *http.Request) {
	item, err := rt.projects.GetHotspot(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	ruleName := ""
	if rt.rules != nil {
		catalogRule, err := rt.rules.Get(r.Context(), rule.Key(item.RuleKey))
		if err != nil {
			writeError(w, rt.log, fmt.Errorf("failed to load rule catalog for %s: %w", item.RuleKey, err))
			return
		}
		ruleName = catalogRule.Name
	}
	writeJSON(w, http.StatusOK, rt.projectHotspotDTO(item, ruleName))
}

func (rt *Router) projectHotspotDTO(item hotspot.Hotspot, ruleName string) projectHotspotResponse {
	return projectHotspotResponse{
		ID: item.ID.String(), RuleKey: item.RuleKey, RuleName: ruleName, Title: item.Title, Description: item.Description,
		Severity: string(item.Severity), FindingKind: string(item.Kind), CWE: item.CWE, Location: item.Location,
		Status: string(item.Status), Version: item.Version, FirstSeenAnalysisID: item.FirstSeenAnalysisID,
		LastSeenAnalysisID: item.LastSeenAnalysisID, FirstSeenAt: item.FirstSeenAt, LastSeenAt: item.LastSeenAt,
	}
}

func projectHotspotListParams(r *http.Request) (hotspot.ListFilter, error) {
	for key := range r.URL.Query() {
		if !projectHotspotQueryParameters[key] {
			return hotspot.ListFilter{}, fmt.Errorf("%w: unsupported query parameter: %s", shared.ErrValidation, key)
		}
	}
	q := r.URL.Query()
	filter := hotspot.ListFilter{RuleKey: strings.TrimSpace(q.Get("rule")), Search: strings.TrimSpace(q.Get("search")), Limit: 25}

	if rawLens := strings.TrimSpace(q.Get("lens")); rawLens != "" {
		if rawLens != string(hotspot.LensOverall) && rawLens != string(hotspot.LensNewCode) {
			return hotspot.ListFilter{}, fmt.Errorf("%w: invalid lens", shared.ErrValidation)
		}
		filter.Lens = hotspot.Lens(rawLens)
	} else {
		filter.Lens = hotspot.LensOverall
	}

	if filter.RuleKey != "" && utf8.RuneCountInString(filter.RuleKey) > 256 {
		return hotspot.ListFilter{}, fmt.Errorf("%w: rule exceeds maximum length", shared.ErrValidation)
	}
	if utf8.RuneCountInString(filter.Search) > 256 {
		return hotspot.ListFilter{}, fmt.Errorf("%w: search exceeds maximum length", shared.ErrValidation)
	}
	if raw := strings.TrimSpace(q.Get("status")); raw != "" {
		status := hotspot.Status(raw)
		if !status.Valid() {
			return hotspot.ListFilter{}, fmt.Errorf("%w: invalid hotspot status", shared.ErrValidation)
		}
		filter.Status = &status
	}
	if raw := strings.TrimSpace(q.Get("severity")); raw != "" {
		severity := shared.Severity(raw)
		if !severity.Valid() {
			return hotspot.ListFilter{}, fmt.Errorf("%w: invalid hotspot severity", shared.ErrValidation)
		}
		filter.Severity = &severity
	}
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return hotspot.ListFilter{}, fmt.Errorf("%w: limit must be between 1 and 100", shared.ErrValidation)
		}
		filter.Limit = limit
	}
	rawTime, rawID := strings.TrimSpace(q.Get("before_last_seen_at")), strings.TrimSpace(q.Get("before_id"))
	if (rawTime == "") != (rawID == "") {
		return hotspot.ListFilter{}, fmt.Errorf("%w: before_last_seen_at and before_id must be supplied together", shared.ErrValidation)
	}
	if rawTime != "" {
		before, err := time.Parse(time.RFC3339Nano, rawTime)
		if err != nil {
			return hotspot.ListFilter{}, fmt.Errorf("%w: before_last_seen_at must be RFC3339", shared.ErrValidation)
		}
		filter.BeforeLastSeenAt, filter.BeforeID = before, shared.ID(rawID)
	}
	return filter, nil
}

type transitionHotspotRequest struct {
	To              string `json:"to"`
	Rationale       string `json:"rationale"`
	ExpectedVersion int    `json:"expected_version"`
}

type reviewEventResponse struct {
	ID              string    `json:"id"`
	From            string    `json:"from"`
	To              string    `json:"to"`
	Actor           string    `json:"actor"`
	Rationale       string    `json:"rationale"`
	PreviousVersion int       `json:"previous_version"`
	Version         int       `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
}

func (rt *Router) transitionProjectHotspot(w http.ResponseWriter, r *http.Request) {
	var req transitionHotspotRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	actor := PrincipalFrom(r.Context())
	toStatus := hotspot.Status(req.To)
	if !toStatus.Valid() {
		writeError(w, rt.log, fmt.Errorf("%w: invalid transition target status", shared.ErrValidation))
		return
	}
	updated, event, err := rt.projects.TransitionHotspot(r.Context(), actor, shared.ID(TenantFrom(r.Context())), r.PathValue("key"), shared.ID(r.PathValue("id")), toStatus, req.Rationale, req.ExpectedVersion)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	ruleName := ""
	if rt.rules != nil {
		catalogRule, err := rt.rules.Get(r.Context(), rule.Key(updated.RuleKey))
		if err != nil {
			writeError(w, rt.log, fmt.Errorf("failed to load rule catalog for %s: %w", updated.RuleKey, err))
			return
		}
		ruleName = catalogRule.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hotspot": rt.projectHotspotDTO(updated, ruleName),
		"event": reviewEventResponse{
			ID:              event.ID.String(),
			From:            string(event.From),
			To:              string(event.To),
			Actor:           event.Actor,
			Rationale:       event.Rationale,
			PreviousVersion: event.PreviousVersion,
			Version:         event.Version,
			CreatedAt:       event.CreatedAt,
		},
	})
}

func (rt *Router) projectHotspotHistory(w http.ResponseWriter, r *http.Request) {
	events, err := rt.projects.HotspotHistory(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]reviewEventResponse, len(events))
	for i, e := range events {
		out[i] = reviewEventResponse{
			ID:              e.ID.String(),
			From:            string(e.From),
			To:              string(e.To),
			Actor:           e.Actor,
			Rationale:       e.Rationale,
			PreviousVersion: e.PreviousVersion,
			Version:         e.Version,
			CreatedAt:       e.CreatedAt,
		}
	}
	writeJSON(w, http.StatusOK, out)
}
