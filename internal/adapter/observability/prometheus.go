// Package observability adapts Synapse's bounded telemetry seams to Prometheus.
package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const queueStatsTimeout = time.Second

// Collectors owns a private Prometheus registry. It contains no global
// collectors, so only Synapse's documented metrics are exposed by /metrics.
type Collectors struct {
	registry     *prometheus.Registry
	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	scaDuration  *prometheus.HistogramVec
	scaOutcomes  *prometheus.CounterVec
	queueReader  ports.AggregateJobQueueStatsReader
	now          func() time.Time
}

// New constructs the bounded Prometheus collectors used by the API metrics listener.
func New(queueReader ports.AggregateJobQueueStatsReader) *Collectors {
	c := &Collectors{
		registry:    prometheus.NewRegistry(),
		queueReader: queueReader,
		now:         time.Now,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: "http", Name: "requests_total",
			Help: "Total HTTP requests handled by the API.",
		}, []string{"method", "route", "status_class"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "synapse", Subsystem: "http", Name: "request_duration_seconds",
			Help: "HTTP request handling duration in seconds.",
		}, []string{"method", "route", "status_class"}),
		scaDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "synapse", Subsystem: "sca", Name: "scan_duration_seconds",
			Help: "Completed SCA scan execution duration.",
		}, []string{"outcome"}),
		scaOutcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: "sca", Name: "scan_outcomes_total",
			Help: "Terminal SCA scan outcomes.",
		}, []string{"outcome"}),
	}
	c.registry.MustRegister(c.httpRequests, c.httpDuration, c.scaDuration, c.scaOutcomes)
	if queueReader != nil {
		queue := newQueueCollector(queueReader, c.now)
		c.registry.MustRegister(queue)
	}
	return c
}

type queueCollector struct {
	reader          ports.AggregateJobQueueStatsReader
	now             func() time.Time
	queued          *prometheus.Desc
	inFlight        *prometheus.Desc
	oldestActiveAge *prometheus.Desc
	scrapeErrors    prometheus.Counter
}

func (c *queueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.queued
	ch <- c.inFlight
	ch <- c.oldestActiveAge
	ch <- c.scrapeErrors.Desc()
}

func (c *queueCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), queueStatsTimeout)
	defer cancel()
	stats, err := c.reader.AggregateJobQueueStats(ctx)
	if err != nil {
		// Do not emit bogus/stale gauge values for queued/in_flight/oldest_active_age; the
		// scrape-error counter makes the failure itself observable instead of the gauges
		// silently vanishing from the scrape exactly when queue health matters.
		c.scrapeErrors.Inc()
		ch <- c.scrapeErrors
		return
	}
	age := 0.0
	if stats.OldestActiveAt != nil {
		age = c.now().Sub(*stats.OldestActiveAt).Seconds()
		if age < 0 {
			age = 0
		}
	}
	ch <- prometheus.MustNewConstMetric(c.queued, prometheus.GaugeValue, float64(stats.Queued))
	ch <- prometheus.MustNewConstMetric(c.inFlight, prometheus.GaugeValue, float64(stats.Claimed))
	ch <- prometheus.MustNewConstMetric(c.oldestActiveAge, prometheus.GaugeValue, age)
	ch <- c.scrapeErrors
}

func newQueueCollector(reader ports.AggregateJobQueueStatsReader, now func() time.Time) *queueCollector {
	return &queueCollector{
		reader:          reader,
		now:             now,
		queued:          prometheus.NewDesc("synapse_job_queue_queued", "Aggregate queued durable jobs.", nil, nil),
		inFlight:        prometheus.NewDesc("synapse_job_queue_in_flight", "Aggregate claimed durable jobs.", nil, nil),
		oldestActiveAge: prometheus.NewDesc("synapse_job_queue_oldest_active_age_seconds", "Age of the oldest queued or claimed durable job.", nil, nil),
		scrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: "job_queue", Name: "scrape_errors_total",
			Help: "Failed attempts to read aggregate durable job queue stats for this scrape.",
		}),
	}
}

// ObserveHTTPRequest records a bounded HTTP request outcome.
func (c *Collectors) ObserveHTTPRequest(method, route, statusClass string, duration time.Duration) {
	c.httpRequests.WithLabelValues(method, route, statusClass).Inc()
	c.httpDuration.WithLabelValues(method, route, statusClass).Observe(duration.Seconds())
}

// ObserveSCAOutcome records one terminal SCA outcome without an execution duration.
func (c *Collectors) ObserveSCAOutcome(outcome string) {
	c.scaOutcomes.WithLabelValues(outcome).Inc()
}

// ObserveSCAScan records one completed SCA execution outcome and its duration.
func (c *Collectors) ObserveSCAScan(duration time.Duration, outcome string) {
	c.scaDuration.WithLabelValues(outcome).Observe(duration.Seconds())
	c.ObserveSCAOutcome(outcome)
}

// Handler returns the private-registry Prometheus metrics endpoint.
func (c *Collectors) Handler() http.Handler {
	return promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{})
}

var _ ports.SCAObserver = (*Collectors)(nil)
