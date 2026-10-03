// Package observability owns private Prometheus registries for API and worker
// processes. Notification deliveries are observed only by synapse-worker.
package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// WorkerNotificationMetrics is process-local; no tenant, channel ID, user,
// recipient or destination can enter its bounded label set.
type WorkerNotificationMetrics struct {
	registry  *prometheus.Registry
	sent      *prometheus.CounterVec
	failed    *prometheus.CounterVec
	dead      *prometheus.CounterVec
	latency   *prometheus.HistogramVec
	fallbacks *prometheus.CounterVec
}

type notificationMetricFamily struct {
	channel  notification.ChannelType
	provider string
}

var notificationMetricFamilies = [...]notificationMetricFamily{
	{notification.ChannelWebhook, "generic"},
	{notification.ChannelSlack, "slack"},
	{notification.ChannelEmail, "smtp"},
	{notification.ChannelTeams, "teams"},
	{notification.ChannelTelegram, "telegram"},
	{notification.ChannelGoogleChat, "google_chat"},
	{notification.ChannelDiscord, "discord"},
	{"other", "other"},
}

func workerNotificationLabels(channel notification.ChannelType) (string, string) {
	switch channel {
	case notification.ChannelWebhook:
		return string(channel), "generic"
	case notification.ChannelSlack:
		return string(channel), "slack"
	case notification.ChannelEmail:
		return string(channel), "smtp"
	case notification.ChannelTeams, notification.ChannelTelegram, notification.ChannelGoogleChat, notification.ChannelDiscord:
		// One provider per chat channel type, so the provider label is the type itself.
		return string(channel), string(channel)
	default:
		// Never turn an untrusted/future database value into a label.
		return "other", "other"
	}
}

// NewWorkerNotificationMetrics installs an isolated, worker-owned registry.
// Pending age is a live per-scrape RLS-safe aggregate, not the age of the last
// claimed job (which could hide an older, stranded pending delivery).
func NewWorkerNotificationMetrics(reader ports.NotificationPendingMetricsReader) *WorkerNotificationMetrics {
	const subsystem = "notification_worker"
	labels := []string{"channel_type", "provider"}
	m := &WorkerNotificationMetrics{
		registry: prometheus.NewRegistry(),
		sent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: subsystem, Name: "sent_total",
			Help: "Committed successful notification delivery attempts in this worker process.",
		}, labels),
		failed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: subsystem, Name: "failed_total",
			Help: "Committed unsuccessful notification delivery attempts, including retryable attempts.",
		}, labels),
		dead: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: subsystem, Name: "dead_lettered_total",
			Help: "Committed terminal notification delivery transitions observed by this worker.",
		}, labels),
		latency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "synapse", Subsystem: subsystem, Name: "delivery_duration_seconds",
			Help:    "Duration of a committed delivery attempt, excluding time waiting in the queue.",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, labels),
		fallbacks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "synapse", Subsystem: subsystem, Name: "template_fallback_total",
			Help: "Committed delivery attempts rendered with built-in fallback content.",
		}, labels),
	}
	m.registry.MustRegister(m.sent, m.failed, m.dead, m.latency, m.fallbacks)
	for _, family := range notificationMetricFamilies {
		typeLabel, _ := workerNotificationLabels(family.channel)
		provider := family.provider
		m.sent.WithLabelValues(typeLabel, provider).Add(0)
		m.failed.WithLabelValues(typeLabel, provider).Add(0)
		m.dead.WithLabelValues(typeLabel, provider).Add(0)
		m.latency.WithLabelValues(typeLabel, provider)
		m.fallbacks.WithLabelValues(typeLabel, provider).Add(0)
	}
	if reader != nil {
		m.registry.MustRegister(newWorkerNotificationPendingCollector(reader, time.Now))
	}
	return m
}

// ObserveNotificationAttempt is called after FinishAttempt commits, not when
// a sender returns: a stale lease or failed transaction cannot inflate counts.
func (m *WorkerNotificationMetrics) ObserveNotificationAttempt(channel notification.ChannelType, elapsed time.Duration, delivered, templateFallback bool) {
	if m == nil {
		return
	}
	typeLabel, provider := workerNotificationLabels(channel)
	if delivered {
		m.sent.WithLabelValues(typeLabel, provider).Inc()
	} else {
		m.failed.WithLabelValues(typeLabel, provider).Inc()
	}
	if elapsed < 0 {
		elapsed = 0
	}
	m.latency.WithLabelValues(typeLabel, provider).Observe(elapsed.Seconds())
	if templateFallback {
		m.fallbacks.WithLabelValues(typeLabel, provider).Inc()
	}
}

// ObserveNotificationDeadLetter is emitted only after a durable transition;
// terminal retries and worker OnDeadLetter must not count the same row twice.
func (m *WorkerNotificationMetrics) ObserveNotificationDeadLetter(channel notification.ChannelType) {
	if m == nil {
		return
	}
	typeLabel, provider := workerNotificationLabels(channel)
	m.dead.WithLabelValues(typeLabel, provider).Inc()
}

func (m *WorkerNotificationMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry is the worker scrape registry. Other worker series, including SIEM,
// register here so the process exposes one /metrics listener.
func (m *WorkerNotificationMetrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.registry
}

type workerNotificationPendingCollector struct {
	reader ports.NotificationPendingMetricsReader
	now    func() time.Time
	oldest *prometheus.Desc
	errors *prometheus.Desc
}

func newWorkerNotificationPendingCollector(reader ports.NotificationPendingMetricsReader, now func() time.Time) *workerNotificationPendingCollector {
	return &workerNotificationPendingCollector{
		reader: reader, now: now,
		oldest: prometheus.NewDesc(
			"synapse_notification_worker_oldest_pending_age_seconds",
			"Age of the oldest pending or retrying notification across all RLS-scoped tenants; zero if empty.",
			[]string{"channel_type", "provider"}, nil,
		),
		errors: prometheus.NewDesc(
			"synapse_notification_worker_pending_scrape_error",
			"Whether the last scrape failed to read a complete notification backlog snapshot.",
			nil, nil,
		),
	}
}

func (c *workerNotificationPendingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.oldest
	ch <- c.errors
}

func (c *workerNotificationPendingCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	oldest, err := c.reader.NotificationOldestPending(ctx)
	if err != nil {
		// Never emit partial/stale healthy ages when any tenant read fails.
		ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, 1)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, 0)
	ages := make(map[string]float64, len(notificationMetricFamilies))
	now := c.now()
	for channel, at := range oldest {
		typeLabel, provider := workerNotificationLabels(channel)
		key := typeLabel + "/" + provider
		age := now.Sub(at).Seconds()
		if age < 0 {
			age = 0
		}
		if age > ages[key] {
			ages[key] = age
		}
	}
	for _, family := range notificationMetricFamilies {
		typeLabel, _ := workerNotificationLabels(family.channel)
		provider := family.provider
		ch <- prometheus.MustNewConstMetric(c.oldest, prometheus.GaugeValue, ages[typeLabel+"/"+provider], typeLabel, provider)
	}
}

var _ ports.NotificationDeliveryObserver = (*WorkerNotificationMetrics)(nil)
var _ prometheus.Collector = (*workerNotificationPendingCollector)(nil)
