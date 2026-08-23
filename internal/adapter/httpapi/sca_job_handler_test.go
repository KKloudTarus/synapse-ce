package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	scauc "github.com/KKloudTarus/synapse-ce/internal/usecase/sca"
)

// scanJobsFake is an in-test scan-job store: adapter tests stay free of infrastructure imports.
type scanJobsFake struct{ jobs map[string]ports.ScanJob }

func (s scanJobsFake) CreateRunning(context.Context, ports.ScanJob) error { return nil }
func (s scanJobsFake) Save(context.Context, ports.ScanJob) error          { return nil }

func (s scanJobsFake) LatestForEngagement(context.Context, shared.ID) (ports.ScanJob, error) {
	return ports.ScanJob{}, shared.ErrNotFound
}

func (s scanJobsFake) LatestForEngagements(context.Context, []shared.ID) (map[shared.ID]ports.ScanJob, error) {
	return map[shared.ID]ports.ScanJob{}, nil
}

func (s scanJobsFake) GetJob(_ context.Context, id string) (ports.ScanJob, error) {
	job, ok := s.jobs[id]
	if !ok {
		return ports.ScanJob{}, shared.ErrNotFound
	}
	return job, nil
}

func (s scanJobsFake) ListStaleRunning(context.Context, time.Time, int) ([]ports.ScanJob, error) {
	return nil, nil
}

// newScanJobRouter wires the scan-job read route over two tenants' engagements and one scan job
// owned by tenantA.
func newScanJobRouter(t *testing.T) *Router {
	t.Helper()
	repo := newEngRepoFake()
	for _, e := range []*engdom.Engagement{
		{ID: "engA", TenantID: "tenantA", Name: "A", Client: "A", Status: engdom.StatusActive},
		{ID: "engB", TenantID: "tenantB", Name: "B", Client: "B", Status: engdom.StatusActive},
	} {
		if err := repo.Create(context.Background(), e); err != nil {
			t.Fatalf("seed engagement %s: %v", e.ID, err)
		}
	}
	jobs := scanJobsFake{jobs: map[string]ports.ScanJob{
		"job-A": {ID: "job-A", EngagementID: "engA", Target: "tenant-a-secret-target", Kind: "local", Status: ports.ScanRunning, Stage: "resolve"},
	}}
	rt := &Router{
		log: discardLog(),
		eng: enguc.NewService(repo, fixedClock{t: time.Unix(1, 0)}, engIDs{}, &fakeAudit{}),
		sca: scauc.NewService(nil, nil, nil, nil, jobs, nil, nil, nil, ports.Provenance{}, fixedClock{}, &fakeAudit{}, shared.SeverityInfo, 0, nil, nil, nil, nil, nil, nil, nil),
	}
	return rt
}

func scanJobCall(rt *Router, tenant, jobID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sca/scans/"+jobID, nil)
	req.SetPathValue("id", jobID)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: "consultant", TenantID: tenant}))
	rec := httptest.NewRecorder()
	rt.scanJob(rec, req)
	return rec
}

func TestScanJobReturnsOwnTenantJob(t *testing.T) {
	rec := scanJobCall(newScanJobRouter(t), "tenantA", "job-A")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var job ports.ScanJob
	if err := json.NewDecoder(rec.Body).Decode(&job); err != nil {
		t.Fatalf("decode scan job: %v", err)
	}
	if job.ID != "job-A" || job.Status != ports.ScanRunning {
		t.Fatalf("job = %+v", job)
	}
}

// The engagement is in the RESPONSE, not the path, so withEngTenant cannot wrap this route. The
// handler must re-check the tenant itself and leak nothing about another tenant's scan.
func TestScanJobCrossTenantIsNotFoundAndLeaksNothing(t *testing.T) {
	rec := scanJobCall(newScanJobRouter(t), "tenantB", "job-A")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	for _, leak := range []string{"job-A", "engA", "tenant-a-secret-target"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("cross-tenant response leaked %q: %s", leak, rec.Body.String())
		}
	}
}

func TestScanJobUnknownIDIsNotFound(t *testing.T) {
	rec := scanJobCall(newScanJobRouter(t), "tenantA", "job-missing")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
}

func TestScanJobRequiresID(t *testing.T) {
	rt := newScanJobRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sca/scans/", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: "consultant", TenantID: "tenantA"}))
	rec := httptest.NewRecorder()
	rt.scanJob(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}
