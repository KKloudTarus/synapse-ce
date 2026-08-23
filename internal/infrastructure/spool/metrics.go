package spool

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Collector exports spool health without registering globals. The agent
// composition root may register it on a private registry/listener.
type Collector struct {
	spool ports.TelemetrySpool
	now   func() time.Time

	depth       *prometheus.Desc
	bytes       *prometheus.Desc
	oldestAge   *prometheus.Desc
	nextSeq     *prometheus.Desc
	highestACK  *prometheus.Desc
	gaps        *prometheus.Desc
	gapBytes    *prometheus.Desc
	evicted     *prometheus.Desc
	corruptions *prometheus.Desc
	fsyncs      *prometheus.Desc
	fsyncTime   *prometheus.Desc
}

// NewCollector constructs an unregistered collector. A nil spool is rejected
// at collection time as an invalid metric rather than panicking a process.
func NewCollector(source ports.TelemetrySpool) *Collector {
	labels := []string{"priority"}
	return &Collector{
		spool: source, now: time.Now,
		depth:       prometheus.NewDesc("synapse_agent_spool_records", "Unacknowledged WAL records by delivery priority.", labels, nil),
		bytes:       prometheus.NewDesc("synapse_agent_spool_record_bytes", "Logical unacknowledged WAL bytes by delivery priority.", labels, nil),
		oldestAge:   prometheus.NewDesc("synapse_agent_spool_oldest_unacked_age_seconds", "Age of the oldest unacknowledged record by delivery priority.", labels, nil),
		nextSeq:     prometheus.NewDesc("synapse_agent_spool_next_sequence", "Next sequence assigned in the current incarnation by delivery priority.", labels, nil),
		highestACK:  prometheus.NewDesc("synapse_agent_spool_highest_acked_sequence", "Highest contiguous ACK in the current incarnation by delivery priority.", labels, nil),
		gaps:        prometheus.NewDesc("synapse_agent_spool_gap_records", "Durable loss-evidence records retained locally.", nil, nil),
		gapBytes:    prometheus.NewDesc("synapse_agent_spool_gap_bytes", "Bytes occupied by the durable gap journal.", nil, nil),
		evicted:     prometheus.NewDesc("synapse_agent_spool_evicted_records_total", "P3 WAL records evicted after durable gap evidence was committed.", nil, nil),
		corruptions: prometheus.NewDesc("synapse_agent_spool_corruption_events_total", "Corrupt or torn WAL intervals recovered in this process.", nil, nil),
		fsyncs:      prometheus.NewDesc("synapse_agent_spool_fsync_total", "Successful WAL and gap fsync operations in this process.", nil, nil),
		fsyncTime:   prometheus.NewDesc("synapse_agent_spool_fsync_duration_seconds_total", "Cumulative WAL and gap fsync latency in this process.", nil, nil),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{c.depth, c.bytes, c.oldestAge, c.nextSeq, c.highestACK, c.gaps, c.gapBytes, c.evicted, c.corruptions, c.fsyncs, c.fsyncTime} {
		ch <- desc
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if c.spool == nil {
		ch <- prometheus.NewInvalidMetric(c.depth, context.Canceled)
		return
	}
	stats, err := c.spool.Stats(context.Background())
	if err != nil {
		ch <- prometheus.NewInvalidMetric(c.depth, err)
		return
	}
	now := c.now()
	for _, lane := range stats.Priorities {
		priority := lane.Priority.String()
		age := float64(0)
		if !lane.OldestUnacked.IsZero() {
			age = now.Sub(lane.OldestUnacked).Seconds()
			if age < 0 {
				age = 0
			}
		}
		ch <- prometheus.MustNewConstMetric(c.depth, prometheus.GaugeValue, float64(lane.Records), priority)
		ch <- prometheus.MustNewConstMetric(c.bytes, prometheus.GaugeValue, float64(lane.Bytes), priority)
		ch <- prometheus.MustNewConstMetric(c.oldestAge, prometheus.GaugeValue, age, priority)
		ch <- prometheus.MustNewConstMetric(c.nextSeq, prometheus.GaugeValue, float64(lane.NextSequence), priority)
		ch <- prometheus.MustNewConstMetric(c.highestACK, prometheus.GaugeValue, float64(lane.HighestACKed), priority)
	}
	ch <- prometheus.MustNewConstMetric(c.gaps, prometheus.GaugeValue, float64(stats.GapRecords))
	ch <- prometheus.MustNewConstMetric(c.gapBytes, prometheus.GaugeValue, float64(stats.GapBytes))
	ch <- prometheus.MustNewConstMetric(c.evicted, prometheus.CounterValue, float64(stats.EvictedRecords))
	ch <- prometheus.MustNewConstMetric(c.corruptions, prometheus.CounterValue, float64(stats.CorruptionEvents))
	ch <- prometheus.MustNewConstMetric(c.fsyncs, prometheus.CounterValue, float64(stats.FsyncCount))
	ch <- prometheus.MustNewConstMetric(c.fsyncTime, prometheus.CounterValue, stats.FsyncTotal.Seconds())
}

var _ prometheus.Collector = (*Collector)(nil)
