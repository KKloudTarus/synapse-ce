package observability

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type notificationStatsReader struct{ t *testing.T }

func (r notificationStatsReader) AggregateJobQueueStats(_ context.Context, kinds ...string) (ports.JobStats, error) {
	if len(kinds) != 1 || kinds[0] != "notification.deliver" {
		r.t.Errorf("unfiltered metrics: %v", kinds)
	}
	return ports.JobStats{Queued: 2, Claimed: 1, Failed: 3, Done: 4}, nil
}
func TestNotificationMetricsHaveBoundedLabels(t *testing.T) {
	c := newNotificationQueueCollector(notificationStatsReader{t})
	expected := `# HELP synapse_notification_jobs Durable notification jobs by queue state.
# TYPE synapse_notification_jobs gauge
synapse_notification_jobs{state="claimed"} 1
synapse_notification_jobs{state="done"} 4
synapse_notification_jobs{state="failed"} 3
synapse_notification_jobs{state="queued"} 2
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(expected), "synapse_notification_jobs"); err != nil {
		t.Fatal(err)
	}
}
