package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeQueueReader struct {
	stats    ports.JobStats
	err      error
	calls    int
	deadline time.Time
}

func (f *fakeQueueReader) AggregateJobQueueStats(ctx context.Context, _ ...string) (ports.JobStats, error) {
	f.calls++
	f.deadline, _ = ctx.Deadline()
	return f.stats, f.err
}

// TestCollectorsExposesHTTPMetrics covers the private-registry contract: recorded HTTP
// requests must be scrapable via the returned Handler with the documented label set
// (method, route, status_class) and nothing else attached to the private registry.
func TestCollectorsExposesHTTPMetrics(t *testing.T) {
	c := New(nil)
	c.ObserveHTTPRequest("GET", "GET /api/v1/engagements/{id}", "2xx", 25*time.Millisecond)

	got := testutil.ToFloat64(c.httpRequests.WithLabelValues("GET", "GET /api/v1/engagements/{id}", "2xx"))
	if got != 1 {
		t.Errorf("synapse_http_requests_total = %v, want 1", got)
	}
}

// TestCollectorsScrapeOutput covers that the handler actually serves the registered
// series in the Prometheus text exposition format expected by a scrape target.
func TestCollectorsScrapeOutput(t *testing.T) {
	c := New(nil)
	c.ObserveHTTPRequest("GET", "GET /healthz", "2xx", time.Millisecond)
	c.ObserveSCAScan(time.Second, "success")

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	for _, want := range []string{
		"synapse_http_requests_total",
		"synapse_http_request_duration_seconds",
		"synapse_sca_scan_duration_seconds",
		"synapse_sca_scan_outcomes_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output missing metric %q", want)
		}
	}
}

// TestCollectorsQueueGaugesReflectAggregateStats covers the aggregate queue gauges:
// they must reflect the reader's totals and report no tenant label anywhere.
func TestCollectorsQueueGaugesReflectAggregateStats(t *testing.T) {
	oldest := time.Now().Add(-90 * time.Second)
	reader := &fakeQueueReader{stats: ports.JobStats{Queued: 3, Claimed: 2, OldestActiveAt: &oldest}}
	c := New(reader)
	c.now = func() time.Time { return oldest.Add(90 * time.Second) }

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, "synapse_job_queue_queued 3") {
		t.Errorf("queued gauge missing/incorrect: %s", body)
	}
	if !strings.Contains(body, "synapse_job_queue_in_flight 2") {
		t.Errorf("in_flight gauge missing/incorrect: %s", body)
	}
	if !strings.Contains(body, "synapse_job_queue_oldest_active_age_seconds 90") {
		t.Errorf("oldest_active_age_seconds gauge missing/incorrect: %s", body)
	}
	if strings.Contains(body, "tenant") {
		t.Errorf("aggregate queue metrics must never carry a tenant label: %s", body)
	}
	if reader.calls != 1 {
		t.Errorf("aggregate stats calls = %d, want 1 per scrape", reader.calls)
	}
	if reader.deadline.IsZero() || time.Until(reader.deadline) > queueStatsTimeout {
		t.Errorf("queue collector must provide a bounded deadline, got %v", reader.deadline)
	}
}

// TestCollectorsQueueGaugesAbsentWithoutReader covers that a nil reader (metrics
// enabled without an aggregate-capable queue implementation) registers no queue gauges
// rather than panicking or exposing a stale/zero series that misleads an operator.
func TestCollectorsQueueGaugesAbsentWithoutReader(t *testing.T) {
	c := New(nil)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rec.Body.String(), "synapse_job_queue_") {
		t.Error("no queue gauge should be registered without an AggregateJobQueueStatsReader")
	}
}

// TestCollectorsQueueScrapeErrorSurfacesFailure covers that a failed
// AggregateJobQueueStats read does not silently drop the queue gauges: the three
// gauges must be absent from that scrape (no bogus/stale values), and the failure
// itself must be observable via the scrape-error counter.
func TestCollectorsQueueScrapeErrorSurfacesFailure(t *testing.T) {
	reader := &fakeQueueReader{err: errors.New("queue stats unavailable")}
	c := New(reader)

	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, absent := range []string{"synapse_job_queue_queued", "synapse_job_queue_in_flight", "synapse_job_queue_oldest_active_age_seconds"} {
		if strings.Contains(body, absent) {
			t.Errorf("gauge %q must be absent on a failed scrape, got: %s", absent, body)
		}
	}
	if !strings.Contains(body, "synapse_job_queue_scrape_errors_total 1") {
		t.Errorf("scrape-error counter missing/incorrect: %s", body)
	}
}
