package notification

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPagerRenderingCapsDeclaredContextAtSignal(t *testing.T) {
	svc := newRenderHarness(t).svc
	svc.SetBuiltinTemplates(notificationbuiltin.New())
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	event := domain.Event{TenantID: "tenant-a", ID: "scan-event", Type: domain.EventScanCompleted, SchemaVersion: 2, OccurredAt: time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC),
		Context: json.RawMessage(`{"vars":{"event_type":"scan.completed","severity":"critical","scan_kind":"sca","critical_count":"2","new_count":"1","fixed_count":"0","engagement_name":"private assessment","target":"private target"}}`)}
	for _, kind := range []domain.ChannelType{domain.ChannelPagerDuty, domain.ChannelJSM} {
		out, err := svc.RenderMessage(ctx, RenderInput{Channel: domain.Channel{TenantID: "tenant-a", ID: "pager", Type: kind, DataClass: domain.DataClassDetail}, Event: event})
		if err != nil {
			t.Fatal(err)
		}
		if out.Class != domain.DataClassSignal || strings.Contains(out.Message.Fields["summary"], "private") {
			t.Fatalf("pager exposed non-signal context: %+v", out)
		}
		out, err = svc.RenderMessage(ctx, RenderInput{Channel: domain.Channel{TenantID: "tenant-a", Type: kind}, Event: event, Engagement: domain.EngagementNotificationsNone})
		if err != nil || !out.Suppressed {
			t.Fatalf("pager bypassed suppression: %+v, %v", out, err)
		}
	}
}
