package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

const builtinGoldenPath = "testdata/builtin/en.json"

type builtinGoldenOutput struct {
	Fields    map[string]string `json:"fields,omitempty"`
	Formatted string            `json:"formatted,omitempty"`
	HTML      string            `json:"html,omitempty"`
	Webhook   json.RawMessage   `json:"webhook,omitempty"`
}

// TestBuiltinRendererGoldenMatrix fixes the English output for every shipped event, family and
// data class. Pager has no delivery channel in this build, so its rows call the same Service
// context filter and renderFields path directly; the other families call Service.RenderMessage.
func TestBuiltinRendererGoldenMatrix(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	english := make(map[string]builtinGoldenOutput)
	for _, eventType := range builtinMatrixEvents() {
		for _, family := range builtinMatrixFamilies() {
			for _, class := range builtinMatrixClasses() {
				key := builtinMatrixKey(eventType, family, class)
				output, snapshot := renderBuiltinMatrix(t, h, eventType, family, class, tenancy.LocaleEnglish)
				assertBuiltinMatrixSafety(t, key, output, eventType, class, snapshot)
				english[key] = output
			}
		}
	}
	if len(english) != 84 {
		t.Fatalf("English matrix has %d cases, want 84", len(english))
	}
	encoded, err := json.MarshalIndent(english, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(builtinGoldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(builtinGoldenPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(builtinGoldenPath)
	if err != nil {
		t.Fatalf("read English builtin golden (run UPDATE_GOLDEN=1 after a deliberate content change): %v", err)
	}
	if !bytes.Equal(want, encoded) {
		t.Fatalf("English builtin matrix differs from golden; rerun with UPDATE_GOLDEN=1 only after review\n%s", diffBuiltinGolden(want, encoded))
	}
}

// TestBuiltinRendererVietnameseMatrix verifies every Vietnamese shipped template resolves and
// renders with the same class filtering. Default webhook envelopes intentionally remain locale
// neutral, so their locale assertion is resolution rather than body copy.
func TestBuiltinRendererVietnameseMatrix(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	cases := 0
	for _, eventType := range builtinMatrixEvents() {
		for _, family := range builtinMatrixFamilies() {
			for _, class := range builtinMatrixClasses() {
				key := builtinMatrixKey(eventType, family, class)
				output, snapshot := renderBuiltinMatrix(t, h, eventType, family, class, tenancy.LocaleVietnamese)
				assertBuiltinMatrixSafety(t, key, output, eventType, class, snapshot)
				if family != domain.FamilyWebhook && !containsVietnamese(string(mustJSON(t, output))) {
					t.Fatalf("%s did not render Vietnamese copy: %#v", key, output)
				}
				cases++
			}
		}
	}
	if cases != 84 {
		t.Fatalf("Vietnamese matrix has %d cases, want 84", cases)
	}
}

// TestBuiltinCopiedFieldsRenderEquivalently proves an administrator can copy a shipped template
// into a same-locale custom draft without changing the renderer output. Pager has no transport in
// this build, so its equivalent draft path is renderFields with the filtered Service context.
func TestBuiltinCopiedFieldsRenderEquivalently(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetBuiltinTemplates(notificationbuiltin.New())
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, eventType := range builtinMatrixEvents() {
			for _, family := range builtinMatrixFamilies() {
				for _, class := range builtinMatrixClasses() {
					key := builtinMatrixKey(eventType, family, class) + "/" + string(locale)
					builtin, _ := renderBuiltinMatrix(t, h, eventType, family, class, locale)
					copied := renderBuiltinCopiedFields(t, h, eventType, family, class, locale)
					if !bytes.Equal(mustJSON(t, builtin), mustJSON(t, copied)) {
						t.Fatalf("copied builtin fields changed %s\n builtin=%s\n copied=%s", key, mustJSON(t, builtin), mustJSON(t, copied))
					}
				}
			}
		}
	}
}

func builtinMatrixEvents() []domain.EventType {
	return []domain.EventType{
		domain.EventVulnerabilityAction,
		domain.EventScanCompleted,
		domain.EventQualityGateFailed,
		domain.EventSLAApproaching,
		domain.EventFleetAgentOffline,
		domain.EventIncidentCreated,
		domain.EventOwnershipChanged,
	}
}

func builtinMatrixFamilies() []domain.TemplateFamily {
	return []domain.TemplateFamily{domain.FamilyChat, domain.FamilyEmail, domain.FamilyPager, domain.FamilyWebhook}
}

func builtinMatrixClasses() []domain.DataClass {
	return []domain.DataClass{domain.DataClassSignal, domain.DataClassSummary, domain.DataClassDetail}
}

func builtinMatrixKey(event domain.EventType, family domain.TemplateFamily, class domain.DataClass) string {
	return string(event) + "/" + string(family) + "/" + string(class)
}

func renderBuiltinMatrix(t *testing.T, h *renderHarness, eventType domain.EventType, family domain.TemplateFamily, class domain.DataClass, locale tenancy.Locale) (builtinGoldenOutput, domain.TemplateContext) {
	t.Helper()
	spec, event, snapshot := builtinMatrixEvent(t, eventType)
	if family == domain.FamilyPager {
		builtin, found := h.svc.builtins.Builtin(eventType, family, locale)
		if !found {
			t.Fatalf("missing %s builtin pager template", eventType)
		}
		channel := h.channel
		channel.DataClass, channel.Locale = class, locale
		context, err := h.svc.renderContext(h.ctx, RenderInput{Channel: channel, Event: event}, spec, class, family)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := renderFields(TemplateResolution{Tier: TierBuiltin, EventType: eventType, Family: family, Builtin: &builtin}, builtin.Fields, context.Data())
		if err != nil {
			t.Fatal(err)
		}
		return builtinGoldenOutput{Fields: fields}, snapshot
	}
	channel := h.channel
	channel.Type, channel.DataClass, channel.Locale = builtinMatrixChannel(family), class, locale
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event})
	if err != nil || out.Resolution.Tier != TierBuiltin || out.Resolution.MatchedLocale != locale {
		t.Fatalf("%s/%s/%s: render=%+v err=%v", eventType, family, locale, out, err)
	}
	result := builtinGoldenOutput{Fields: out.Message.Fields}
	if out.Formatted != nil {
		result.Formatted, result.HTML = string(out.Formatted.Body), string(out.Formatted.HTMLBody)
	}
	result.Webhook = out.WebhookBody
	return result, snapshot
}

func renderBuiltinCopiedFields(t *testing.T, h *renderHarness, eventType domain.EventType, family domain.TemplateFamily, class domain.DataClass, locale tenancy.Locale) builtinGoldenOutput {
	t.Helper()
	spec, event, _ := builtinMatrixEvent(t, eventType)
	builtin, found := h.svc.builtins.Builtin(eventType, family, locale)
	if !found {
		t.Fatalf("missing %s/%s builtin template", eventType, family)
	}
	if family == domain.FamilyPager {
		channel := h.channel
		channel.DataClass, channel.Locale = class, locale
		context, err := h.svc.renderContext(h.ctx, RenderInput{Channel: channel, Event: event}, spec, class, family)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := renderFields(TemplateResolution{EventType: eventType, Family: family}, builtin.Fields, context.Data())
		if err != nil {
			t.Fatal(err)
		}
		return builtinGoldenOutput{Fields: fields}
	}
	channel := h.channel
	channel.Type, channel.DataClass, channel.Locale = builtinMatrixChannel(family), class, locale
	draft := &domain.TemplateVersion{Fields: builtin.Fields}
	out, err := h.svc.RenderMessage(context.Background(), RenderInput{Channel: channel, Event: event, Draft: draft})
	if err != nil {
		t.Fatal(err)
	}
	result := builtinGoldenOutput{Fields: out.Message.Fields, Webhook: out.WebhookBody}
	if out.Formatted != nil {
		result.Formatted, result.HTML = string(out.Formatted.Body), string(out.Formatted.HTMLBody)
	}
	return result
}

func builtinMatrixEvent(t *testing.T, eventType domain.EventType) (domain.EventSpec, domain.Event, domain.TemplateContext) {
	t.Helper()
	spec, ok := domain.LookupEvent(eventType)
	if !ok {
		t.Fatalf("missing event spec for %s", eventType)
	}
	snapshot := builtinMatrixSnapshot(spec)
	raw, err := snapshot.Encode()
	if err != nil {
		t.Fatal(err)
	}
	event := domain.Event{
		TenantID: "tenant-r", ID: shared.ID("matrix-" + string(eventType)), Type: eventType, SchemaVersion: spec.SchemaVersion,
		OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), Context: raw,
	}
	return spec, event, snapshot
}

func builtinMatrixChannel(family domain.TemplateFamily) domain.ChannelType {
	switch family {
	case domain.FamilyChat:
		return domain.ChannelSlack
	case domain.FamilyEmail:
		return domain.ChannelEmail
	case domain.FamilyWebhook:
		return domain.ChannelWebhook
	default:
		panic("pager is rendered directly by the matrix")
	}
}

func builtinMatrixSnapshot(spec domain.EventSpec) domain.TemplateContext {
	vars := map[string]string{
		"event_type":  string(spec.Type),
		"event_label": "signal-event-label",
		"occurred_at": "2026-10-02T09:00:00Z",
		"title":       "summary-title",
		"summary":     "summary-description",
		"severity":    "critical",
		"action_type": "request-review",
		"scan_kind":   "sast",
		"total_count": "12", "critical_count": "1", "high_count": "2", "medium_count": "3", "low_count": "4", "info_count": "2",
		"new_count": "2", "fixed_count": "1", "unchanged_count": "9", "delta_available": "true",
		"engagement_name": "summary-engagement", "target": "summary-target.example",
		"failed_conditions": "3", "project_name": "summary-project",
		"tier": "critical", "deadline": "2026-10-03T09:00:00Z", "lead_time_hours": "24", "finding_title": "summary-finding",
		"last_seen_at": "2026-10-02T08:00:00Z", "agent_name": "summary-agent",
		"asset_name": "detail-asset",
		"old_team":   "summary-old-team", "new_team": "summary-new-team", "old_assignee": "summary-old-assignee", "new_assignee": "summary-new-assignee", "actor": "summary-actor", "reason": "summary-reason",
	}
	lists := map[string][]map[string]string{"findings": {{"id": "detail-finding-id", "severity": "detail-high", "title": "detail-finding", "status": "detail-new"}}}
	return spec.SnapshotWithLists(vars, lists)
}

func assertBuiltinMatrixSafety(t *testing.T, key string, output builtinGoldenOutput, eventType domain.EventType, class domain.DataClass, snapshot domain.TemplateContext) {
	t.Helper()
	actual := string(mustJSON(t, output))
	if actual == "{}" || strings.Contains(actual, "<no value>") || strings.Contains(actual, "<nil>") {
		t.Fatalf("%s rendered incomplete content: %s", key, actual)
	}
	spec, _ := domain.LookupEvent(eventType)
	for _, variable := range spec.Variables {
		if variable.Class.Rank() <= class.Rank() {
			continue
		}
		if value := snapshot.Vars[variable.Name]; value != "" && strings.Contains(actual, value) {
			t.Errorf("%s leaks %s-class variable %q", key, variable.Class, variable.Name)
		}
		for _, item := range snapshot.Lists[variable.Name] {
			for _, value := range item {
				if value != "" && strings.Contains(actual, value) {
					t.Errorf("%s leaks %s-class list %q", key, variable.Class, variable.Name)
				}
			}
		}
	}
}

func mustJSON(t *testing.T, value builtinGoldenOutput) []byte {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func containsVietnamese(value string) bool {
	return strings.ContainsAny(value, "àáảãạăắằẳẵặâấầẩẫậđèéẻẽẹêếềểễệìíỉĩịòóỏõọôốồổỗộơớờởỡợùúủũụưứừửữựỳýỷỹỵ")
}

func diffBuiltinGolden(want, got []byte) string {
	return fmt.Sprintf("want %d bytes, got %d bytes", len(want), len(got))
}
