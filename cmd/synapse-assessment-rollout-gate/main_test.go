package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunRolloutGate(t *testing.T) {
	payload := `{"tenant_id":"tenant-a","comparable_items":1000,"producer_items":1000,"api_requests":1000,"api_window_minutes":15,"latency_window_minutes":15,"cycle_list_p95_millis":600,"cycle_detail_p95_millis":750,"comparison_page_p95_millis":750,"production_slo_continuous_minutes":30,"target_cardinality":true,"comparison_100k_duration_seconds":300,"metrics_recorded":true,"approval_recorded":true,"read_cutover_approved":true}`
	var output bytes.Buffer
	err := run([]string{"--phase", "read_cutover"}, strings.NewReader(payload), &output, &output)
	if !errors.Is(err, errRolloutGateRejected) || !strings.Contains(output.String(), `"production_latency_slo"`) {
		t.Fatalf("expected rejected cutover decision, err=%v output=%s", err, output.String())
	}
}
