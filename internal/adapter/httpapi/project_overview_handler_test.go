package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectOverviewServiceStub struct {
	projectService
	overview projectuc.Overview
	err      error
	calls    int
	tenant   shared.ID
	key      string
}

func (s *projectOverviewServiceStub) Overview(_ context.Context, tenantID shared.ID, key string) (projectuc.Overview, error) {
	s.calls++
	s.tenant, s.key = tenantID, key
	return s.overview, s.err
}

func TestProjectOverviewAnalyzedResponse(t *testing.T) {
	stub := &projectOverviewServiceStub{overview: analyzedProjectOverviewFixture()}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req.SetPathValue("key", "payments-api")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()

	rt.projectOverview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q", got)
	}
	if stub.calls != 1 || stub.tenant != "tenant-a" || stub.key != "payments-api" {
		t.Fatalf("call budget calls=%d tenant=%q key=%q", stub.calls, stub.tenant, stub.key)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["state"] != "analyzed" {
		t.Fatalf("body=%v", body)
	}
	analysis := body["latest_analysis"].(map[string]any)
	if analysis["id"] != "analysis-42" || analysis["source_ref"] != "main" || analysis["source_commit"] != "abc123" {
		t.Fatalf("analysis=%v", analysis)
	}
	gate := body["gate"].(map[string]any)
	failed := gate["failed_conditions"].([]any)
	if gate["status"] != "failed" || len(failed) != 1 || failed[0].(map[string]any)["operator"] != "<=" {
		t.Fatalf("gate=%v", gate)
	}
	lenses := body["lenses"].(map[string]any)
	overall := lenses["overall"].(map[string]any)
	if overall["coverage"].(map[string]any)["value"] != 72.349 {
		t.Fatalf("coverage=%v", overall["coverage"])
	}
	newCode := lenses["new_code"].(map[string]any)
	maintainability := newCode["maintainability"].(map[string]any)
	if maintainability["grade"] != nil || maintainability["unavailable_reason"] != "changed_line_metrics_not_available" {
		t.Fatalf("new-code maintainability=%v", maintainability)
	}
}

func TestProjectOverviewNotAnalyzedResponsePreservesNulls(t *testing.T) {
	stub := &projectOverviewServiceStub{overview: notAnalyzedProjectOverviewFixture()}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req.SetPathValue("key", "payments-api")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()

	rt.projectOverview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"state":"not_analyzed"`, `"latest_analysis":null`, `"gate":null`, `"grade":null`, `"value":null`, `"unavailable_reason":"no_analysis"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
}

func TestProjectOverviewPassedGateEmitsEmptyFailedConditions(t *testing.T) {
	overview := analyzedProjectOverviewFixture()
	overview.Gate.Status = projectuc.OverviewGatePassed
	overview.Gate.FailedConditions = []projectuc.OverviewGateCondition{}
	stub := &projectOverviewServiceStub{overview: overview}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req.SetPathValue("key", "payments-api")
	rec := httptest.NewRecorder()

	rt.projectOverview(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"failed_conditions":[]`) {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProjectOverviewFailedConditionsPreserveOrder(t *testing.T) {
	overview := analyzedProjectOverviewFixture()
	overview.Gate.FailedConditions = []projectuc.OverviewGateCondition{
		{Metric: "new_high", Operator: projectuc.OverviewGateOperatorLE, Threshold: 0, Actual: 2},
		{Metric: "new_critical", Operator: projectuc.OverviewGateOperatorLE, Threshold: 0, Actual: 1},
	}
	rt := &Router{log: discardLog(), projects: &projectOverviewServiceStub{overview: overview}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req.SetPathValue("key", "payments-api")
	rec := httptest.NewRecorder()

	rt.projectOverview(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	first := strings.Index(rec.Body.String(), `"metric":"new_high"`)
	second := strings.Index(rec.Body.String(), `"metric":"new_critical"`)
	if first < 0 || second < 0 || first > second {
		t.Fatalf("failed conditions order not preserved: %s", rec.Body.String())
	}
}

func TestProjectOverviewErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err       error
		status    int
		notLeaked string
	}{
		"not found":     {err: shared.ErrNotFound, status: http.StatusNotFound},
		"store failure": {err: errors.New("database secret dsn"), status: http.StatusInternalServerError, notLeaked: "database secret dsn"},
	} {
		t.Run(name, func(t *testing.T) {
			rt := &Router{log: discardLog(), projects: &projectOverviewServiceStub{err: tc.err}}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/missing/overview", nil)
			req.SetPathValue("key", "missing")
			rec := httptest.NewRecorder()
			rt.projectOverview(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
			}
			if tc.notLeaked != "" && strings.Contains(rec.Body.String(), tc.notLeaked) {
				t.Fatalf("leaked internal error: %s", rec.Body.String())
			}
		})
	}
}

func TestProjectOverviewRouteRequiresViewPermission(t *testing.T) {
	stub := &projectOverviewServiceStub{overview: notAnalyzedProjectOverviewFixture()}
	rt := &Router{log: discardLog(), projects: stub}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "machine", Role: "agent", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || stub.calls != 0 {
		t.Fatalf("machine code=%d calls=%d body=%s", rec.Code, stub.calls, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "reader", Role: "readonly", TenantID: "tenant-a"}))
	rec = httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || stub.calls != 1 {
		t.Fatalf("readonly code=%d calls=%d body=%s", rec.Code, stub.calls, rec.Body.String())
	}
}

func TestProjectOverviewResponseDoesNotLeakForbiddenFields(t *testing.T) {
	stub := &projectOverviewServiceStub{overview: analyzedProjectOverviewFixture()}
	rt := &Router{log: discardLog(), projects: stub}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/payments-api/overview", nil)
	req.SetPathValue("key", "payments-api")
	rec := httptest.NewRecorder()

	rt.projectOverview(rec, req)

	body := rec.Body.String()
	for _, forbidden := range []string{
		"tenant_id", "project_id", "internal_issues", "secret-sentinel", "engagement",
		"source_binding", "SourceBinding", "https://", "/repo", "findings", "result", "components", "vulnerabilities",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("overview leaked %q: %s", forbidden, body)
		}
	}
}

func analyzedProjectOverviewFixture() projectuc.Overview {
	gradeB, gradeA, gradeC := projectuc.OverviewGradeB, projectuc.OverviewGradeA, projectuc.OverviewGradeC
	coverage, duplication := 72.349, 4.25
	newIssues := 4
	reasonChanged := projectuc.ReasonChangedLineMetricsNotAvailable
	reasonHotspots := projectuc.ReasonSecurityHotspotsNotAvailable
	reasonAccepted := projectuc.ReasonIssueLifecycleNotAvailable
	gateKey, gateName := "release", "Release"
	gateSource := projectuc.OverviewGateSourceManaged
	baselineID := "analysis-41"
	return projectuc.Overview{
		State: projectuc.OverviewStateAnalyzed,
		Project: projectuc.OverviewProject{
			Key:  "payments-api",
			Name: "Payments API",
		},
		LatestAnalysis: &projectuc.OverviewAnalysis{
			ID: "analysis-42", CreatedAt: time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC),
			SourceRef: "main", SourceCommit: "abc123",
			NewCode: projectuc.OverviewNewCodePeriod{
				HasBaseline:        true,
				BaselineAnalysisID: &baselineID,
			},
		},
		Gate: &projectuc.OverviewGate{
			Status: projectuc.OverviewGateFailed, Key: &gateKey, Name: &gateName, Source: &gateSource,
			FailedConditions: []projectuc.OverviewGateCondition{{Metric: "new_high", Operator: projectuc.OverviewGateOperatorLE, Threshold: 0, Actual: 2}},
		},
		IssueSummary: projectuc.OverviewIssueSummary{
			NewCodeTotal:         projectuc.CountMetric{Availability: projectuc.MetricAvailable, Value: &newIssues},
			AcceptedOverallTotal: projectuc.CountMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reasonAccepted},
		},
		Overall: projectuc.OverviewLens{
			Security:                 projectuc.RatingMetric{Availability: projectuc.MetricAvailable, Grade: &gradeB},
			Reliability:              projectuc.RatingMetric{Availability: projectuc.MetricAvailable, Grade: &gradeA},
			Maintainability:          projectuc.RatingMetric{Availability: projectuc.MetricAvailable, Grade: &gradeC},
			SecurityHotspotsReviewed: projectuc.PercentageMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reasonHotspots},
			Coverage:                 projectuc.PercentageMetric{Availability: projectuc.MetricAvailable, Value: &coverage},
			Duplications:             projectuc.PercentageMetric{Availability: projectuc.MetricAvailable, Value: &duplication},
		},
		NewCode: projectuc.OverviewLens{
			Security:                 projectuc.RatingMetric{Availability: projectuc.MetricAvailable, Grade: &gradeA},
			Reliability:              projectuc.RatingMetric{Availability: projectuc.MetricAvailable, Grade: &gradeB},
			Maintainability:          projectuc.RatingMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reasonChanged},
			SecurityHotspotsReviewed: projectuc.PercentageMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reasonHotspots},
			Coverage:                 projectuc.PercentageMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reasonChanged},
			Duplications:             projectuc.PercentageMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reasonChanged},
		},
	}
}

func notAnalyzedProjectOverviewFixture() projectuc.Overview {
	reason := projectuc.ReasonNoAnalysis
	unavailableRating := projectuc.RatingMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reason}
	unavailablePercentage := projectuc.PercentageMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reason}
	return projectuc.Overview{
		State:   projectuc.OverviewStateNotAnalyzed,
		Project: projectuc.OverviewProject{Key: "payments-api", Name: "Payments API"},
		IssueSummary: projectuc.OverviewIssueSummary{
			NewCodeTotal:         projectuc.CountMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reason},
			AcceptedOverallTotal: projectuc.CountMetric{Availability: projectuc.MetricUnavailable, UnavailableReason: &reason},
		},
		Overall: projectuc.OverviewLens{
			Security: unavailableRating, Reliability: unavailableRating, Maintainability: unavailableRating,
			SecurityHotspotsReviewed: unavailablePercentage, Coverage: unavailablePercentage, Duplications: unavailablePercentage,
		},
		NewCode: projectuc.OverviewLens{
			Security: unavailableRating, Reliability: unavailableRating, Maintainability: unavailableRating,
			SecurityHotspotsReviewed: unavailablePercentage, Coverage: unavailablePercentage, Duplications: unavailablePercentage,
		},
	}
}
