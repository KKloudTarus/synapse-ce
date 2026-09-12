package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/accuracy"
)

type fakeAccuracyReader struct {
	runs      []accuracy.Run
	lastLimit int
}

func (f *fakeAccuracyReader) Recent(_ context.Context, limit int) ([]accuracy.Run, error) {
	f.lastLimit = limit
	return f.runs, nil
}

func TestListAccuracyRunsUnwiredReturnsEmpty(t *testing.T) {
	rt := &Router{log: discardLog()}
	rec := httptest.NewRecorder()
	rt.listAccuracyRuns(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engine/accuracy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Runs []accuracyRunDTO `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Runs) != 0 {
		t.Errorf("unwired reader should return no runs, got %d", len(body.Runs))
	}
}

func TestListAccuracyRunsServesRuns(t *testing.T) {
	run, err := accuracy.New("run-1", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "detection-golden-v1", "synapse-accuracy-report-v1", 9,
		accuracy.Metrics{TruePositives: 10, FalsePositives: 1, Precision: 0.9091, Recall: 1, F1: 0.9524, FalseDiscoveryRate: 0.0909},
		[]accuracy.GroupMetrics{{Group: "npm", Cases: 3, Metrics: accuracy.Metrics{Precision: 1, Recall: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeAccuracyReader{runs: []accuracy.Run{*run}}
	rt := &Router{log: discardLog(), accuracyRuns: reader}
	rec := httptest.NewRecorder()
	rt.listAccuracyRuns(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engine/accuracy?limit=25", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if reader.lastLimit != 25 {
		t.Errorf("limit passed to reader = %d, want 25", reader.lastLimit)
	}
	var body struct {
		Runs []accuracyRunDTO `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(body.Runs))
	}
	got := body.Runs[0]
	if got.ID != "run-1" || got.RanAt != "2026-01-02T03:04:05Z" || got.CorpusVersion != "detection-golden-v1" {
		t.Errorf("run header wrong: %+v", got)
	}
	if got.Overall.TruePositives != 10 || got.Overall.FalsePositives != 1 || got.Overall.Precision != 0.9091 {
		t.Errorf("overall metrics wrong: %+v", got.Overall)
	}
	if len(got.Groups) != 1 || got.Groups[0].Group != "npm" {
		t.Errorf("groups wrong: %+v", got.Groups)
	}
}

// TestAccuracyRouteRegisteredWithoutIntegrations pins that the route is registered unconditionally:
// a deployment with integrations (and the accuracy job) unwired must still get 200 with an empty
// list, not a 404. Guards against the route regressing back inside an optional-subsystem block.
func TestAccuracyRouteRegisteredWithoutIntegrations(t *testing.T) {
	rt := &Router{log: discardLog()} // integrations nil, accuracyRuns nil
	principal := context.WithValue(context.Background(), principalKey, Principal{ID: "p", Role: "readonly", TenantID: "tenantA"})
	rec := httptest.NewRecorder()
	rt.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engine/accuracy", nil).WithContext(principal))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (route must be registered even with integrations off); body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Runs []accuracyRunDTO `json:"runs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Runs) != 0 {
		t.Errorf("unwired job should return no runs, got %d", len(body.Runs))
	}
}

func TestListAccuracyRunsClampsBadLimit(t *testing.T) {
	reader := &fakeAccuracyReader{}
	rt := &Router{log: discardLog(), accuracyRuns: reader}
	for _, q := range []string{"?limit=0", "?limit=-5", "?limit=99999", "?limit=abc", ""} {
		rec := httptest.NewRecorder()
		rt.listAccuracyRuns(rec, httptest.NewRequest(http.MethodGet, "/api/v1/engine/accuracy"+q, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%q: status %d", q, rec.Code)
		}
		if reader.lastLimit <= 0 || reader.lastLimit > 1000 {
			t.Errorf("%q: reader limit %d out of range", q, reader.lastLimit)
		}
	}
}
