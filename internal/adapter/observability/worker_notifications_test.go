package observability

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type workerPendingReader struct {
	pending     map[notification.ChannelType]time.Time
	err         error
	hasDeadline bool
}

func (r *workerPendingReader) NotificationOldestPending(ctx context.Context) (map[notification.ChannelType]time.Time, error) {
	_, r.hasDeadline = ctx.Deadline()
	return r.pending, r.err
}

func TestWorkerNotificationMetricsCountOnlyBoundedChannels(t *testing.T) {
	metrics := NewWorkerNotificationMetrics(nil)
	metrics.ObserveNotificationAttempt(notification.ChannelWebhook, 20*time.Millisecond, true, false)
	metrics.ObserveNotificationAttempt(notification.ChannelSlack, 100*time.Millisecond, false, true)
	metrics.ObserveNotificationAttempt(notification.ChannelEmail, -time.Second, false, false)
	metrics.ObserveNotificationDeadLetter(notification.ChannelSlack)
	metrics.ObserveNotificationAttempt(notification.ChannelType("tenant-private-destination"), 40*time.Millisecond, true, true)

	if got := testutil.ToFloat64(metrics.sent.WithLabelValues("webhook", "generic")); got != 1 {
		t.Fatalf("webhook sent = %v", got)
	}
	if got := testutil.ToFloat64(metrics.failed.WithLabelValues("slack", "slack")); got != 1 {
		t.Fatalf("slack failures = %v", got)
	}
	if got := testutil.ToFloat64(metrics.dead.WithLabelValues("slack", "slack")); got != 1 {
		t.Fatalf("slack dead letters = %v", got)
	}
	if got := testutil.ToFloat64(metrics.fallbacks.WithLabelValues("slack", "slack")); got != 1 {
		t.Fatalf("slack fallback = %v", got)
	}
	if got := testutil.ToFloat64(metrics.sent.WithLabelValues("other", "other")); got != 1 {
		t.Fatalf("unrecognized channel was not collapsed: %v", got)
	}

	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status: %d", rec.Code)
	}
	for _, want := range []string{
		"synapse_notification_worker_sent_total",
		"synapse_notification_worker_failed_total",
		"synapse_notification_worker_dead_lettered_total",
		"synapse_notification_worker_delivery_duration_seconds",
		"synapse_notification_worker_template_fallback_total",
		"channel_type=\"other\"",
		"provider=\"smtp\"",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in scrape", want)
		}
	}
	for _, forbidden := range []string{"tenant-private-destination", "tenant_id=", "channel_id=", "recipient=", "destination="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("unbounded or sensitive metric label %q", forbidden)
		}
	}
}

func TestWorkerNotificationPendingAgeAndFailedScrape(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	reader := &workerPendingReader{pending: map[notification.ChannelType]time.Time{
		notification.ChannelSlack: now.Add(-2 * time.Minute),
		notification.ChannelEmail: now.Add(1 * time.Minute), // clock skew must not produce a negative gauge
		"unknown-provider":        now.Add(-10 * time.Minute),
	}}
	pending := newWorkerNotificationPendingCollector(reader, func() time.Time { return now })
	reg := prometheus.NewRegistry()
	reg.MustRegister(pending)
	scrape := func() string {
		t.Helper()
		rec := httptest.NewRecorder()
		promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("scrape status: %d body: %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	first := scrape()
	for _, want := range []string{
		"synapse_notification_worker_oldest_pending_age_seconds{channel_type=\"slack\",provider=\"slack\"} 120",
		"synapse_notification_worker_oldest_pending_age_seconds{channel_type=\"email\",provider=\"smtp\"} 0",
		"synapse_notification_worker_oldest_pending_age_seconds{channel_type=\"other\",provider=\"other\"} 600",
		"synapse_notification_worker_oldest_pending_age_seconds{channel_type=\"webhook\",provider=\"generic\"} 0",
		"synapse_notification_worker_pending_scrape_error 0",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("missing metric %q in %s", want, first)
		}
	}
	if !reader.hasDeadline {
		t.Fatal("database metrics read has no deadline")
	}
	reader.err = errors.New("private database connection failed")
	second := scrape()
	if !strings.Contains(second, "synapse_notification_worker_pending_scrape_error 1") {
		t.Fatal("failed scrape was not reported")
	}
	if strings.Contains(second, "synapse_notification_worker_oldest_pending_age_seconds{") {
		t.Fatal("reported a stale/partial backlog when the database failed")
	}
	if strings.Contains(second, reader.err.Error()) {
		t.Fatal("exposed raw database error in metrics")
	}
}

func TestWorkerNotificationMetricsConcurrentAttempts(t *testing.T) {
	metrics := NewWorkerNotificationMetrics(nil)
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.ObserveNotificationAttempt(notification.ChannelWebhook, time.Millisecond, true, false)
		}()
	}
	wg.Wait()
	if got := testutil.ToFloat64(metrics.sent.WithLabelValues("webhook", "generic")); got != n {
		t.Fatalf("concurrent updates lost: got %v want %d", got, n)
	}
}
