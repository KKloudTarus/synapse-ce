package spool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestCollectorExportsDepthSequenceAndOldestAge(t *testing.T) {
	s := mustOpen(t, testConfig(t))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP1, "det", 32))
	mustEnqueue(t, s, testItem(fleetagent.PriorityP3, "raw", 32))
	collector := NewCollector(s)
	collector.now = func() time.Time { return testNow.Add(12 * time.Second) }
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) == 0 {
		t.Fatal("collector exported no metrics")
	}
	want := `
# HELP synapse_agent_spool_oldest_unacked_age_seconds Age of the oldest unacknowledged record by delivery priority.
# TYPE synapse_agent_spool_oldest_unacked_age_seconds gauge
synapse_agent_spool_oldest_unacked_age_seconds{priority="P0"} 0
synapse_agent_spool_oldest_unacked_age_seconds{priority="P1"} 12
synapse_agent_spool_oldest_unacked_age_seconds{priority="P2"} 0
synapse_agent_spool_oldest_unacked_age_seconds{priority="P3"} 12
# HELP synapse_agent_spool_records Unacknowledged WAL records by delivery priority.
# TYPE synapse_agent_spool_records gauge
synapse_agent_spool_records{priority="P0"} 0
synapse_agent_spool_records{priority="P1"} 1
synapse_agent_spool_records{priority="P2"} 0
synapse_agent_spool_records{priority="P3"} 1
`
	if err := testutil.GatherAndCompare(registry, strings.NewReader(want),
		"synapse_agent_spool_oldest_unacked_age_seconds", "synapse_agent_spool_records"); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorReturnsInvalidMetricWhenSourceFails(t *testing.T) {
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(NewCollector(failingStatsSpool{})); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Gather(); err == nil {
		t.Fatal("stats failure did not make scrape fail")
	}
}

type failingStatsSpool struct{}

func (failingStatsSpool) Enqueue(context.Context, ports.SpoolItem) (fleetagent.StreamPosition, error) {
	return fleetagent.StreamPosition{}, errors.New("not implemented")
}
func (failingStatsSpool) Peek(context.Context, ports.PeekSpoolRequest) ([]ports.SpoolRecord, error) {
	return nil, errors.New("not implemented")
}
func (failingStatsSpool) Ack(context.Context, ports.SpoolACK) (ports.SpoolACKResult, error) {
	return ports.SpoolACKResult{}, errors.New("not implemented")
}
func (failingStatsSpool) Flush(context.Context) error { return errors.New("not implemented") }
func (failingStatsSpool) Gaps(context.Context) ([]ports.SpoolGap, error) {
	return nil, errors.New("not implemented")
}
func (failingStatsSpool) Stats(context.Context) (ports.SpoolStats, error) {
	return ports.SpoolStats{}, errors.New("disk unavailable")
}
func (failingStatsSpool) Close() error { return nil }
