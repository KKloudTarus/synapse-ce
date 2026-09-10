package observability

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/prometheus/client_golang/prometheus"
)

func (c *Collectors) EnableNotifications() {
	if c.queueReader != nil {
		c.registry.MustRegister(newNotificationQueueCollector(c.queueReader))
	}
}

// Notification queue health uses a fixed state label and no tenant or destination labels.
type notificationQueueCollector struct {
	reader ports.AggregateJobQueueStatsReader
	jobs   *prometheus.Desc
	errors *prometheus.Desc
}

func newNotificationQueueCollector(reader ports.AggregateJobQueueStatsReader) *notificationQueueCollector {
	return &notificationQueueCollector{reader: reader, jobs: prometheus.NewDesc("synapse_notification_jobs", "Durable notification jobs by queue state.", []string{"state"}, nil), errors: prometheus.NewDesc("synapse_notification_queue_scrape_error", "Whether notification queue statistics could not be read.", nil, nil)}
}
func (c *notificationQueueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.jobs
	ch <- c.errors
}
func (c *notificationQueueCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), queueStatsTimeout)
	defer cancel()
	stats, err := c.reader.AggregateJobQueueStats(ctx, "notification.deliver")
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, 1)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.errors, prometheus.GaugeValue, 0)
	for _, v := range []struct {
		state string
		count int
	}{{"queued", stats.Queued}, {"claimed", stats.Claimed}, {"failed", stats.Failed}, {"done", stats.Done}} {
		ch <- prometheus.MustNewConstMetric(c.jobs, prometheus.GaugeValue, float64(v.count), v.state)
	}
}
