package notification

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestBuiltinTemplatesCompileAgainstEveryDeclaredSchema(t *testing.T) {
	for _, template := range notificationbuiltin.New().List() {
		if err := validateTemplateContent(template.TemplateKey, template.Fields); err != nil {
			t.Fatalf("%s does not compile: %v", template.Ref, err)
		}
	}
}

func TestBuiltinSignalMessageDoesNotExposeSummarySnapshotValues(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	channel := h.channel
	channel.DataClass = domain.DataClassSignal
	event := domain.Event{
		TenantID: "tenant-r", ID: "builtin-scan", Type: domain.EventScanCompleted, SchemaVersion: 2,
		OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		Context:    json.RawMessage(`{"vars":{"event_type":"scan.completed","event_label":"Scan completed","occurred_at":"2026-10-02T09:00:00Z","scan_kind":"sast","total_count":"3","title":"SUMMARY-SECRET","summary":"SUMMARY-SECRET","engagement_name":"SUMMARY-SECRET","target":"SUMMARY-SECRET"}}`),
	}
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
	if err != nil || out.Resolution.Tier != TierBuiltin {
		t.Fatalf("render = %+v, %v", out, err)
	}
	if got := out.Message.Fields["body"] + out.Message.Fields["title"]; strings.Contains(got, "SUMMARY-SECRET") || !strings.Contains(got, "sast") {
		t.Fatalf("signal output = %q", got)
	}
}

func TestBuiltinScanKeepsOlderSnapshotsUsefulWithoutBlankCounts(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	channel := h.channel
	channel.DataClass = domain.DataClassSignal
	event := domain.Event{
		TenantID: "tenant-r", ID: "builtin-scan-v1", Type: domain.EventScanCompleted, SchemaVersion: 1,
		OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		Context:    json.RawMessage(`{"vars":{"event_type":"scan.completed","event_label":"Scan completed","occurred_at":"2026-10-02T09:00:00Z","scan_kind":"sast"}}`),
	}
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
	if err != nil || !strings.Contains(out.Message.Fields["body"], "Findings: unavailable") || strings.Contains(out.Message.Fields["body"], "critical ") {
		t.Fatalf("older scan render = %+v, %v", out, err)
	}
}

func TestBuiltinScanContentFollowsTheEffectiveDataClass(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	event := domain.Event{
		TenantID: "tenant-r", ID: "class-scan", Type: domain.EventScanCompleted, SchemaVersion: 2,
		OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		Context:    json.RawMessage(`{"vars":{"event_type":"scan.completed","event_label":"Scan completed","occurred_at":"2026-10-02T09:00:00Z","scan_kind":"sast","total_count":"12","critical_count":"1","high_count":"2","medium_count":"3","low_count":"4","info_count":"2","new_count":"2","fixed_count":"1","unchanged_count":"9","delta_available":"true","engagement_name":"Assessment Delta","target":"https://target.example"},"lists":{"findings":[{"id":"f-1","severity":"high","title":"Detail finding","status":"new"}]}}`),
	}
	for _, tc := range []struct {
		class       domain.DataClass
		mustContain []string
		mustOmit    []string
	}{
		{domain.DataClassSignal, []string{"critical 1", "Changes: 2 new, 1 fixed, 9 unchanged"}, []string{"Assessment Delta", "target.example", "Detail finding"}},
		{domain.DataClassSummary, []string{"Assessment Delta", `target\.example`}, []string{"Detail finding"}},
		{domain.DataClassDetail, []string{"Assessment Delta", `target\.example`, "Detail finding"}, nil},
	} {
		t.Run(string(tc.class), func(t *testing.T) {
			channel := h.channel
			channel.DataClass = tc.class
			out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
			if err != nil || out.Resolution.Tier != TierBuiltin {
				t.Fatalf("render = %+v, %v", out, err)
			}
			body := out.Message.Fields["body"]
			for _, want := range tc.mustContain {
				if !strings.Contains(body, want) {
					t.Errorf("%s body misses %q: %s", tc.class, want, body)
				}
			}
			for _, unwanted := range tc.mustOmit {
				if strings.Contains(body, unwanted) {
					t.Errorf("%s body leaks %q: %s", tc.class, unwanted, body)
				}
			}
		})
	}
}

func TestRenderMessagePassesOnlyDetailListsToTemplates(t *testing.T) {
	h := newRenderHarness(t)
	event := domain.Event{
		TenantID: "tenant-r", ID: "list-scan", Type: domain.EventScanCompleted, SchemaVersion: 2,
		Context: json.RawMessage(`{"vars":{"event_type":"scan.completed","event_label":"Scan completed","occurred_at":"2026-10-02T09:00:00Z","scan_kind":"sast"},"lists":{"findings":[{"id":"f-1","severity":"high","title":"Do not leak below detail","status":"new"}]}}`),
	}
	draft := &domain.TemplateVersion{TemplateID: shared.ID("list-template"), Version: 1, Fields: map[string]string{"title": "{{.scan_kind}}", "body": "{{range .findings}}{{.id}} {{.title}}{{end}}"}}
	detail := h.channel
	detail.DataClass = domain.DataClassDetail
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: detail, Event: event, Draft: draft})
	if err != nil || !strings.Contains(out.Message.Fields["body"], "Do not leak below detail") {
		t.Fatalf("detail list render = %+v, %v", out, err)
	}
	signal := detail
	signal.DataClass = domain.DataClassSignal
	out, err = h.svc.RenderMessage(context.Background(), RenderInput{Channel: signal, Event: event, Draft: draft})
	if err != nil || strings.Contains(out.Message.Fields["body"], "Do not leak below detail") {
		t.Fatalf("signal list render = %+v, %v", out, err)
	}
}

func TestDefaultWebhookEnvelopeKeepsRFC3339AndFiltersContext(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	channel := h.channel
	channel.Type = domain.ChannelWebhook
	channel.DataClass = domain.DataClassSignal
	event := domain.Event{
		TenantID: "tenant-r", ID: "webhook-scan", Type: domain.EventScanCompleted, SchemaVersion: 2,
		OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		Context:    json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-10-02T09:00:00.123456789Z","scan_kind":"sast","title":"SUMMARY-SECRET"}}`),
	}
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Version string                 `json:"version"`
		Data    domain.TemplateContext `json:"data"`
	}
	if err := json.Unmarshal(out.WebhookBody, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Version != domain.WebhookEnvelopeVersion || envelope.Data.Vars["occurred_at"] != "2026-10-02T09:00:00.123456789Z" || envelope.Data.Vars["title"] != "" {
		t.Fatalf("default envelope = %s", out.WebhookBody)
	}
}

func TestDefaultWebhookEnvelopeIncludesOnlyFilteredDetailLists(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	channel := h.channel
	channel.Type = domain.ChannelWebhook
	channel.DataClass = domain.DataClassDetail
	event := domain.Event{
		TenantID: "tenant-r", ID: "webhook-detail-scan", Type: domain.EventScanCompleted, SchemaVersion: 2,
		OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		Context:    json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-10-02T09:00:00Z","unexpected":"RAW-SECRET"},"lists":{"findings":[{"id":"f-1","severity":"high","title":"Allowed at detail","status":"new","extra":"RAW-SECRET"}]}}`),
	}
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data domain.TemplateContext `json:"data"`
	}
	if err := json.Unmarshal(out.WebhookBody, &envelope); err != nil {
		t.Fatal(err)
	}
	items := envelope.Data.Lists["findings"]
	if len(items) != 1 || items[0]["title"] != "Allowed at detail" || items[0]["extra"] != "" || envelope.Data.Vars["unexpected"] != "" {
		t.Fatalf("detail envelope context = %#v", envelope.Data)
	}
}

func TestDefaultWebhookEnvelopeIncludesOnlyTrustedTypedLinks(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	builder, err := consolelink.NewBuilder("https://console.example/app")
	if err != nil {
		t.Fatal(err)
	}
	h.svc.SetConsoleLinkBuilder(builder)
	channel := h.channel
	channel.Type = domain.ChannelWebhook
	event := domain.Event{
		TenantID: "tenant-r", ID: "webhook-scan-link", Type: domain.EventScanCompleted, SchemaVersion: 2,
		EngagementID: "engagement-1", SubjectID: "scan-1", OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC),
		Context: json.RawMessage(`{"vars":{"event_type":"scan.completed","occurred_at":"2026-10-02T09:00:00Z","scan_kind":"sast","total_count":"0","critical_count":"0","high_count":"0","medium_count":"0","low_count":"0","info_count":"0","delta_available":"false"}}`),
	}
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Links []domain.WebhookLink `json:"links"`
	}
	if err := json.Unmarshal(out.WebhookBody, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Links) != 1 || envelope.Links[0] != (domain.WebhookLink{Label: "Open scan", URL: "https://console.example/app/engagements/engagement-1/scanruns#scan-scan-1"}) {
		t.Fatalf("webhook links = %#v", envelope.Links)
	}
}
