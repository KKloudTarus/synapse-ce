package observability

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSIEMMetricsSeparateQuarantineFromAck(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewSIEMMetrics(registry)
	metrics.Items("splunk_hec", "acked", 2)
	metrics.Items("splunk_hec", "acked", 0)
	metrics.Items("splunk_hec", "quarantined", 3)
	metrics.Items("elasticsearch", "suppressed", 1)

	if got := testutil.ToFloat64(metrics.items.WithLabelValues("splunk_hec", "acked")); got != 2 {
		t.Fatalf("acked items = %v, want 2", got)
	}
	if got := testutil.ToFloat64(metrics.dropped.WithLabelValues("splunk_hec", "quarantined")); got != 3 {
		t.Fatalf("quarantined dropped = %v, want 3", got)
	}
	if got := testutil.ToFloat64(metrics.dropped.WithLabelValues("elasticsearch", "suppressed")); got != 1 {
		t.Fatalf("suppressed dropped = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.items.WithLabelValues("splunk_hec", "quarantined")); got != 3 {
		t.Fatalf("quarantined items = %v, want 3", got)
	}
	gathered, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range gathered {
		if family.GetName() != "synapse_siem_dropped_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "disposition" && label.GetValue() == "acked" {
					t.Fatalf("acked records were counted as dropped: %v", metric)
				}
			}
		}
	}
}
