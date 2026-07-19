package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/rules"
)

type projectHotspotServiceStub struct {
	projectService
	page      hotspot.Page
	item      hotspot.Hotspot
	listErr   error
	getErr    error
	listCalls int
	getCalls  int
	tenant    shared.ID
	key       string
}

func (s *projectHotspotServiceStub) ListHotspots(_ context.Context, tenantID shared.ID, key string, _ hotspot.ListFilter) (hotspot.Page, error) {
	s.listCalls++
	s.tenant, s.key = tenantID, key
	return s.page, s.listErr
}

func (s *projectHotspotServiceStub) GetHotspot(_ context.Context, tenantID shared.ID, key string, _ shared.ID) (hotspot.Hotspot, error) {
	s.getCalls++
	s.tenant, s.key = tenantID, key
	return s.item, s.getErr
}

type hotspotRulesStub struct {
	rulesService
	item rule.Rule
}

func (s hotspotRulesStub) Get(context.Context, rule.Key) (rule.Rule, error) { return s.item, nil }
func (s hotspotRulesStub) List(context.Context, rules.Filter) ([]rule.Rule, error) {
	return []rule.Rule{s.item}, nil
}

func hotspotFixture() hotspot.Hotspot {
	at := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	return hotspot.Hotspot{
		ID: "hotspot-1", TenantID: "tenant-a", ProjectID: "project-a", Key: "sast:rule:main.go:7", FindingIdentity: "sast:rule:main.go:7",
		RuleKey: "rule", Title: "Review this", Description: "Sensitive operation", Severity: shared.SeverityHigh,
		Kind: finding.KindSAST, CWE: "CWE-798", Location: "main.go:7", Status: hotspot.StatusToReview, Version: 1,
		FirstSeenAnalysisID: "a1", LastSeenAnalysisID: "a2", FirstSeenAt: at, LastSeenAt: at.Add(time.Hour),
	}
}

func TestListProjectHotspotsReturnsScopedProjectionAndFacets(t *testing.T) {
	stub := &projectHotspotServiceStub{page: hotspot.Page{Items: []hotspot.Hotspot{hotspotFixture()}, Next: &hotspot.Cursor{BeforeLastSeenAt: time.Unix(2, 0), BeforeID: "cursor"}, Facets: hotspot.Facets{Statuses: map[string]int{"to_review": 1}, RuleKeys: map[string]int{"rule": 1}, Severities: map[string]int{"high": 1}}}}
	rt := &Router{log: discardLog(), projects: stub, rules: hotspotRulesStub{item: rule.Rule{Name: "Sensitive rule", Key: "rule"}}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments/hotspots?status=to_review&severity=high&limit=10", nil)
	req.SetPathValue("key", "payments")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	rt.listProjectHotspots(rec, req)
	if rec.Code != http.StatusOK || stub.listCalls != 1 || stub.tenant != "tenant-a" || stub.key != "payments" {
		t.Fatalf("code=%d calls=%d tenant=%q key=%q body=%s", rec.Code, stub.listCalls, stub.tenant, stub.key, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"TenantID", "tenant_id", "ProjectID", "project_id", "EngagementID", "engagement_id", "InternalIssues"} {
		if strings.Contains(body, secret) {
			t.Fatalf("hotspot response leaked %q: %s", secret, body)
		}
	}
	var decoded struct {
		Items  []projectHotspotResponse      `json:"items"`
		Next   *projectHotspotCursorResponse `json:"next"`
		Facets projectHotspotFacetsResponse  `json:"facets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Items) != 1 || decoded.Items[0].RuleName != "Sensitive rule" || decoded.Facets.Statuses["to_review"] != 1 || decoded.Next == nil {
		t.Fatalf("decoded=%+v", decoded)
	}
}

func TestProjectHotspotRejectsMalformedQuery(t *testing.T) {
	for _, query := range []string{"?status=bad", "?severity=bogus", "?limit=0", "?before_id=only", "?unexpected=x"} {
		rt := &Router{log: discardLog(), projects: &projectHotspotServiceStub{}}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/hotspots"+query, nil)
		req.SetPathValue("key", "p")
		rec := httptest.NewRecorder()
		rt.listProjectHotspots(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("query=%s code=%d body=%s", query, rec.Code, rec.Body.String())
		}
	}
}

func TestGetProjectHotspotMapsCrossTenantToNotFound(t *testing.T) {
	stub := &projectHotspotServiceStub{getErr: fmt.Errorf("cross-tenant: %w", shared.ErrNotFound)}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/p/hotspots/id", nil)
	req.SetPathValue("key", "p")
	req.SetPathValue("id", "id")
	rec := httptest.NewRecorder()
	rt.getProjectHotspot(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant code=%d body=%s", rec.Code, rec.Body.String())
	}
}

type trackingHotspotRulesStub struct {
	rulesService
	item      rule.Rule
	listCalls int
	getCalls  int
}

func (s *trackingHotspotRulesStub) Get(context.Context, rule.Key) (rule.Rule, error) {
	s.getCalls++
	return s.item, nil
}
func (s *trackingHotspotRulesStub) List(context.Context, rules.Filter) ([]rule.Rule, error) {
	s.listCalls++
	return []rule.Rule{s.item}, nil
}

func TestListProjectHotspotsBatchesRuleLookup(t *testing.T) {
	items := make([]hotspot.Hotspot, 25)
	for i := range items {
		items[i] = hotspotFixture()
		items[i].RuleKey = fmt.Sprintf("rule-%d", i)
	}
	stub := &projectHotspotServiceStub{page: hotspot.Page{Items: items}}
	rulesStub := &trackingHotspotRulesStub{item: rule.Rule{Name: "Sensitive rule", Key: "rule-0"}}
	rt := &Router{log: discardLog(), projects: stub, rules: rulesStub}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments/hotspots", nil)
	req.SetPathValue("key", "payments")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()

	rt.listProjectHotspots(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rulesStub.listCalls != 1 {
		t.Fatalf("expected 1 list call, got %d", rulesStub.listCalls)
	}
	if rulesStub.getCalls != 0 {
		t.Fatalf("expected 0 get calls, got %d", rulesStub.getCalls)
	}
}
