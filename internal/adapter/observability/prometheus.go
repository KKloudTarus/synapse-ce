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
// The optional pool reader supplies aggregate pool metrics without connection or tenant labels.
func New(queueReader ports.AggregateJobQueueStatsReader, pool ports.PoolStatsReader) *Collectors {
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
	if pool != nil {
		c.registry.MustRegister(newPGXPoolCollector(pool))
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

type pgxPoolCollector struct {
	pool             ports.PoolStatsReader
	connections      *prometheus.Desc
	acquires         *prometheus.Desc
	newConnections   *prometheus.Desc
	destroyed        *prometheus.Desc
	acquireDuration  *prometheus.Desc
	emptyAcquireWait *prometheus.Desc
}

func newPGXPoolCollector(pool ports.PoolStatsReader) *pgxPoolCollector {
	return &pgxPoolCollector{
		pool:             pool,
		connections:      prometheus.NewDesc("synapse_postgres_pool_connections", "PostgreSQL pool connections by fixed state.", []string{"state"}, nil),
		acquires:         prometheus.NewDesc("synapse_postgres_pool_acquires_total", "PostgreSQL pool acquire attempts by fixed outcome.", []string{"outcome"}, nil),
		newConnections:   prometheus.NewDesc("synapse_postgres_pool_new_connections_total", "PostgreSQL pool connections created.", nil, nil),
		destroyed:        prometheus.NewDesc("synapse_postgres_pool_connections_destroyed_total", "PostgreSQL pool connections destroyed by fixed reason.", []string{"reason"}, nil),
		acquireDuration:  prometheus.NewDesc("synapse_postgres_pool_acquire_duration_seconds", "Cumulative PostgreSQL pool connection acquisition duration.", nil, nil),
		emptyAcquireWait: prometheus.NewDesc("synapse_postgres_pool_empty_acquire_wait_seconds", "Cumulative wait time when PostgreSQL pool acquisition found no idle connection.", nil, nil),
	}
}

func (c *pgxPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.connections
	ch <- c.acquires
	ch <- c.newConnections
	ch <- c.destroyed
	ch <- c.acquireDuration
	ch <- c.emptyAcquireWait
}

func (c *pgxPoolCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.pool.PoolStats()
	for _, metric := range []struct {
		state string
		value int32
	}{
		{"acquired", stats.AcquiredConns},
		{"constructing", stats.ConstructingConns},
		{"idle", stats.IdleConns},
		{"max", stats.MaxConns},
		{"total", stats.TotalConns},
	} {
		ch <- prometheus.MustNewConstMetric(c.connections, prometheus.GaugeValue, float64(metric.value), metric.state)
	}
	for _, metric := range []struct {
		outcome string
		value   int64
	}{
		{"acquired", stats.AcquireCount},
		{"canceled", stats.CanceledAcquireCount},
		{"empty", stats.EmptyAcquireCount},
	} {
		ch <- prometheus.MustNewConstMetric(c.acquires, prometheus.CounterValue, float64(metric.value), metric.outcome)
	}
	ch <- prometheus.MustNewConstMetric(c.newConnections, prometheus.CounterValue, float64(stats.NewConnsCount))
	ch <- prometheus.MustNewConstMetric(c.destroyed, prometheus.CounterValue, float64(stats.MaxIdleDestroyCount), "max_idle")
	ch <- prometheus.MustNewConstMetric(c.destroyed, prometheus.CounterValue, float64(stats.MaxLifetimeDestroy), "max_lifetime")
	ch <- prometheus.MustNewConstMetric(c.acquireDuration, prometheus.CounterValue, stats.AcquireDuration.Seconds())
	ch <- prometheus.MustNewConstMetric(c.emptyAcquireWait, prometheus.CounterValue, stats.EmptyAcquireWaitTime.Seconds())
}

var _ prometheus.Collector = (*pgxPoolCollector)(nil)

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
