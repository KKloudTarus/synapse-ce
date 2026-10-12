package notification

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
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

func TestBuiltinPagerScanSummaryKeepsDeltaAndCountsWithinJSMLimit(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	for _, tc := range []struct {
		locale      tenancy.Locale
		delta       string
		counts      string
		noTimestamp string
	}{
		{locale: tenancy.LocaleEnglish, delta: "2 new, 1 fixed, 9 unchanged", counts: "critical 1, high 2, medium 3, low 4, info 2", noTimestamp: "Occurred"},
		{locale: tenancy.LocaleVietnamese, delta: "2 mới, 1 đã xử lý, 9 không đổi", counts: "nghiêm trọng 1, cao 2, TB 3, thấp 4, TT 2", noTimestamp: "Thời gian"},
	} {
		t.Run(string(tc.locale), func(t *testing.T) {
			out, _ := renderBuiltinMatrix(t, h, domain.EventScanCompleted, domain.FamilyPager, domain.DataClassSignal, tc.locale)
			summary := formatJSMSummary(t, out.Fields)
			if utf8.RuneCountInString(summary) > 130 {
				t.Fatalf("%s summary exceeds JSM limit: %d %q", tc.locale, utf8.RuneCountInString(summary), summary)
			}
			if strings.Contains(summary, tc.noTimestamp) {
				t.Fatalf("%s pager summary spends its bounded space on a timestamp: %q", tc.locale, summary)
			}
			for _, want := range []string{tc.delta, tc.counts} {
				if !strings.Contains(summary, want) {
					t.Fatalf("%s pager summary lost scan content %q: %q", tc.locale, want, summary)
				}
			}
		})
	}
}

func TestBuiltinPagerScanSummaryDoesNotInventDelta(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	spec, event, snapshot := builtinMatrixEvent(t, domain.EventScanCompleted)
	snapshot.Vars["delta_available"] = "false"
	raw, err := snapshot.Encode()
	if err != nil {
		t.Fatal(err)
	}
	event.Context = raw
	builtin, found := h.svc.builtins.Builtin(domain.EventScanCompleted, domain.FamilyPager, tenancy.LocaleEnglish)
	if !found {
		t.Fatal("missing scan pager builtin")
	}
	channel := h.channel
	channel.DataClass, channel.Locale = domain.DataClassSignal, tenancy.LocaleEnglish
	filtered, err := h.svc.renderContext(h.ctx, RenderInput{Channel: channel, Event: event}, spec, domain.DataClassSignal, domain.FamilyPager)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := renderFields(TemplateResolution{Tier: TierBuiltin, EventType: domain.EventScanCompleted, Family: domain.FamilyPager, Builtin: &builtin}, builtin.Fields, filtered.Data())
	if err != nil {
		t.Fatal(err)
	}
	summary := formatJSMSummary(t, fields)
	if !strings.Contains(summary, "comparison unavailable") || strings.Contains(summary, "2 new") || strings.Contains(summary, "1 fixed") || strings.Contains(summary, "9 unchanged") {
		t.Fatalf("delta-unavailable pager summary=%q", summary)
	}
}

func formatJSMSummary(t *testing.T, fields map[string]string) string {
	t.Helper()
	formatted, err := (messageformat.JSMFormatter{}).Format(ports.RenderedMessage{Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(formatted.Body, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Summary
}
