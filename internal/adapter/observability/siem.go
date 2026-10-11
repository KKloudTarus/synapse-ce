package observability

import "github.com/prometheus/client_golang/prometheus"

// SIEMMetrics records export health with a fixed label set. Event ids and
// destination URLs are not labels.
type SIEMMetrics struct {
	batches *prometheus.CounterVec
	items   *prometheus.CounterVec
	dropped *prometheus.CounterVec
	retries *prometheus.CounterVec
	gaps    *prometheus.CounterVec
	blocked *prometheus.CounterVec
	backlog *prometheus.GaugeVec
	lag     *prometheus.GaugeVec
}

// NewSIEMMetrics registers the SIEM series on registry.
func NewSIEMMetrics(registry *prometheus.Registry) *SIEMMetrics {
	m := &SIEMMetrics{
		batches: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "synapse_siem_batches_total", Help: "SIEM batches by provider and result."}, []string{"provider", "result"}),
		items:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "synapse_siem_items_total", Help: "SIEM records by provider and disposition."}, []string{"provider", "disposition"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "synapse_siem_dropped_total", Help: "SIEM records handled without provider delivery."}, []string{"provider", "disposition"}),
		retries: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "synapse_siem_retries_total", Help: "SIEM retryable provider failures."}, []string{"provider"}),
		gaps:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "synapse_siem_gaps_total", Help: "SIEM source gaps and chain breaks."}, []string{"source"}),
		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "synapse_siem_blocked_total", Help: "SIEM partitions blocked for an operator."}, []string{"reason"}),
		backlog: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "synapse_siem_backlog_age_seconds", Help: "Age of the oldest unsent SIEM record."}, []string{"source"}),
		lag:     prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "synapse_siem_lag_records", Help: "Unsent SIEM records."}, []string{"source"}),
	}
	registry.MustRegister(m.batches, m.items, m.dropped, m.retries, m.gaps, m.blocked, m.backlog, m.lag)
	return m
}

func label(value, fallback string) string {
	if value == "" || len(value) > 80 {
		return fallback
	}
	return value
}

// Batch records one batch result.
func (m *SIEMMetrics) Batch(provider, result string) {
	m.batches.WithLabelValues(label(provider, "unknown"), label(result, "unknown")).Inc()
}

// Items records a disposition count.
func (m *SIEMMetrics) Items(provider, disposition string, n int) {
	if n > 0 {
		provider = label(provider, "unknown")
		m.items.WithLabelValues(provider, label(disposition, "unknown")).Add(float64(n))
		if disposition == "quarantined" || disposition == "suppressed" {
			m.dropped.WithLabelValues(provider, disposition).Add(float64(n))
		}
	}
}

// Retry records a retryable failure.
func (m *SIEMMetrics) Retry(provider string) {
	m.retries.WithLabelValues(label(provider, "unknown")).Inc()
}

// Gap records a source gap.
func (m *SIEMMetrics) Gap(source string) {
	m.gaps.WithLabelValues(label(source, "unknown")).Inc()
}

// Backlog sets age and lag gauges.
func (m *SIEMMetrics) Backlog(source string, ageSeconds float64, records int) {
	source = label(source, "unknown")
	m.backlog.WithLabelValues(source).Set(ageSeconds)
	m.lag.WithLabelValues(source).Set(float64(records))
}

// Blocked records an operator block. The reason is truncated and must already be secret-free.
func (m *SIEMMetrics) Blocked(reason string) {
	m.blocked.WithLabelValues(label(reason, "blocked")).Inc()
}

// Registry exposes the private registry so optional series can be added after construction.
func (c *Collectors) Registry() *prometheus.Registry { return c.registry }
