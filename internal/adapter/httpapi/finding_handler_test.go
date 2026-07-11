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

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
)

// in-test finding/comment repos (adapter tests stay infra-free).
type findRepoFake struct{ byID map[shared.ID]finding.Finding }

func newFindRepoFake() *findRepoFake { return &findRepoFake{byID: map[shared.ID]finding.Finding{}} }
func (r *findRepoFake) Upsert(_ context.Context, fs []finding.Finding) error {
	for _, f := range fs {
		if f.Version <= 0 {
			f.Version = 1
		}
		r.byID[f.ID] = f
	}
	return nil
}
func (r *findRepoFake) ListByEngagement(_ context.Context, eng shared.ID) ([]finding.Finding, error) {
	out := []finding.Finding{}
	for _, f := range r.byID {
		if f.EngagementID == eng {
			out = append(out, f)
		}
	}
	return out, nil
}
func (r *findRepoFake) ListPublishableByEngagement(ctx context.Context, eng shared.ID) ([]finding.Finding, error) {
	all, err := r.ListByEngagement(ctx, eng)
	if err != nil {
		return nil, err
	}
	return finding.Publishable(all), nil
}
func (r *findRepoFake) UpdateStatus(_ context.Context, eng, id shared.ID, st finding.Status, ver int) (finding.Finding, error) {
	f, ok := r.byID[id]
	if !ok || f.EngagementID != eng {
		return finding.Finding{}, fmt.Errorf("finding %s: %w", id, shared.ErrNotFound)
	}
	if f.Version != ver {
		return finding.Finding{}, fmt.Errorf("finding %s moved: %w", id, shared.ErrConflict)
	}
	f.Status, f.Version = st, f.Version+1
	r.byID[id] = f
	return f, nil
}
func (r *findRepoFake) SetAssignee(_ context.Context, eng, id shared.ID, a string, ver int) (finding.Finding, error) {
	f, ok := r.byID[id]
	if !ok || f.EngagementID != eng {
		return finding.Finding{}, fmt.Errorf("finding %s: %w", id, shared.ErrNotFound)
	}
	if f.Version != ver {
		return finding.Finding{}, fmt.Errorf("finding %s moved: %w", id, shared.ErrConflict)
	}
	f.Assignee, f.Version = a, f.Version+1
	r.byID[id] = f
	return f, nil
}

type commentRepoFake struct{ added []finding.Comment }

func (c *commentRepoFake) Add(_ context.Context, cm finding.Comment) error {
	c.added = append(c.added, cm)
	return nil
}
func (c *commentRepoFake) ListByEngagementFinding(_ context.Context, _, _ shared.ID) ([]finding.Comment, error) {
	return c.added, nil
}

type retestRepoFake struct{ added []finding.Retest }

func (r *retestRepoFake) Add(_ context.Context, rt finding.Retest) error {
	r.added = append(r.added, rt)
	return nil
}
func (r *retestRepoFake) ListByEngagementFinding(_ context.Context, _, _ shared.ID) ([]finding.Retest, error) {
	return r.added, nil
}

func newFindingsRouter() (*Router, *findRepoFake) {
	repo := newFindRepoFake()
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	svc := findingsuc.NewService(repo, &commentRepoFake{}, &retestRepoFake{}, &fakeAudit{}, clock, engIDs{})
	// createFinding verifies the engagement exists – seed "e1".
	engRepo := newEngRepoFake()
	_ = engRepo.Create(context.Background(), &engdom.Engagement{ID: shared.ID("e1"), Status: engdom.StatusActive})
	engSvc := enguc.NewService(engRepo, clock, engIDs{}, &fakeAudit{})
	return &Router{log: discardLog(), findings: svc, eng: engSvc}, repo
}

func TestCVSSEndpoint(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.cvssScore(rec, httptest.NewRequest(http.MethodGet, "/api/v1/cvss?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("valid vector: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Score != 9.8 || body.Severity != "critical" {
		t.Errorf("got score=%v severity=%q, want 9.8/critical", body.Score, body.Severity)
	}

	rec = httptest.NewRecorder()
	rt.cvssScore(rec, httptest.NewRequest(http.MethodGet, "/api/v1/cvss?vector=bogus", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad vector: want 400, got %d", rec.Code)
	}
}

func TestCreateFindingAndStatusConflict(t *testing.T) {
	rt, _ := newFindingsRouter()

	// Create a manual finding; severity derives from the CVSS vector.
	body := `{"title":"SQLi in login","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e1/findings", strings.NewReader(body))
	req.SetPathValue("id", "e1")
	rec := httptest.NewRecorder()
	rt.createFinding(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID       string `json:"ID"`
		Severity string `json:"Severity"`
		Version  int    `json:"Version"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Severity != "critical" || created.Version != 1 {
		t.Fatalf("created finding: severity=%q version=%d, want critical/1", created.Severity, created.Version)
	}

	patch := func(version int) int {
		b := fmt.Sprintf(`{"status":"confirmed","version":%d}`, version)
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/engagements/e1/findings/"+created.ID, strings.NewReader(b))
		req.SetPathValue("id", "e1")
		req.SetPathValue("fid", created.ID)
		rec := httptest.NewRecorder()
		rt.updateFindingStatus(rec, req)
		return rec.Code
	}
	// Stale version -> 409 conflict (lost-update guard).
	if code := patch(0); code != http.StatusConflict {
		t.Errorf("stale version: want 409, got %d", code)
	}
	// Correct version -> 200.
	if code := patch(1); code != http.StatusOK {
		t.Errorf("correct version: want 200, got %d", code)
	}
}

func TestRecordRetestEndpoint(t *testing.T) {
	rt, repo := newFindingsRouter()
	repo.byID["manual:1"] = finding.Finding{ID: "manual:1", EngagementID: "e1", Title: "XSS", Status: finding.StatusConfirmed, Version: 1}

	// Record a "remediated" retest at the current version.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/e1/findings/manual:1/retests",
		strings.NewReader(`{"outcome":"remediated","note":"fixed in v2","version":1}`))
	req.SetPathValue("id", "e1")
	req.SetPathValue("fid", "manual:1")
	rec := httptest.NewRecorder()
	rt.recordRetest(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("record retest status %d: %s", rec.Code, rec.Body.String())
	}

	// History lists the retest.
	greq := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/e1/findings/manual:1/retests", nil)
	greq.SetPathValue("id", "e1")
	greq.SetPathValue("fid", "manual:1")
	grec := httptest.NewRecorder()
	rt.listRetests(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("list retests status %d", grec.Code)
	}
	var rs []finding.Retest
	if err := json.Unmarshal(grec.Body.Bytes(), &rs); err != nil {
		t.Fatalf("decode retests: %v", err)
	}
	if len(rs) != 1 || rs[0].Outcome != finding.RetestRemediated {
		t.Errorf("unexpected retest history: %+v", rs)
	}
}
