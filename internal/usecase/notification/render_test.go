package notification

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type stepClock struct{ at time.Time }

func (c *stepClock) Now() time.Time { return c.at }

// scriptedSender answers each send with the next result and keeps what it was asked to send.
type scriptedSender struct {
	results []ports.NotificationSendResult
	sent    []ports.NotificationWork
}

func (s *scriptedSender) Send(_ context.Context, w ports.NotificationWork, _ ports.NotificationChannelConfig) ports.NotificationSendResult {
	s.sent = append(s.sent, w)
	result := ports.NotificationSendResult{StatusCode: 204}
	if len(s.results) > 0 {
		result, s.results = s.results[0], s.results[1:]
	}
	return result
}

type discardRenderAudit struct{}

func (discardRenderAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type renderHarness struct {
	ctx       context.Context
	clock     *stepClock
	jobs      *memory.JobQueue
	repo      *memory.NotificationRepository
	templates *memory.NotificationTemplateStore
	sender    *scriptedSender
	svc       *Service
	channel   domain.Channel
}

func newRenderHarness(t *testing.T) *renderHarness {
	t.Helper()
	h := &renderHarness{ctx: shared.WithTenant(context.Background(), "tenant-r"), clock: &stepClock{at: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)}, sender: &scriptedSender{}}
	h.jobs = memory.NewJobQueue(idgen.RandomID{}, h.clock.Now)
	h.repo = memory.NewNotificationRepository(h.jobs, h.clock.Now)
	h.repo.SetEventProjector(NewEventBuilders())
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if h.svc, err = NewService(h.repo, cipher, h.sender, discardRenderAudit{}, h.clock, idgen.RandomID{}); err != nil {
		t.Fatal(err)
	}
	h.templates = memory.NewNotificationTemplateStore()
	h.svc.SetTemplateStore(h.templates)
	h.svc.SetFormatters(messageformat.Formatters())
	if h.channel, err = h.svc.CreateChannel(h.ctx, "admin", ChannelInput{Name: "Room", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/x", DataClass: classOf(domain.DataClassSummary), AllowClassRaise: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.CreateRule(h.ctx, "admin", RuleInput{Name: "Scans", Enabled: true, EventType: domain.EventScanCompleted, ChannelIDs: []shared.ID{h.channel.ID}}); err != nil {
		t.Fatal(err)
	}
	return h
}

func classOf(c domain.DataClass) *domain.DataClass { return &c }

// template creates and activates a chat template for scan.completed.
func (h *renderHarness) template(t *testing.T, title string) TemplateDetail {
	t.Helper()
	created, err := h.svc.CreateTemplate(h.ctx, "admin", TemplateInput{Name: "Scans", EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en",
		Fields: map[string]string{"title": title, "body": "Scan of {{.scan_kind}} finished at {{.occurred_at}}"}})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	active, err := h.svc.ActivateTemplate(h.ctx, "admin", created.ID, TemplateChangeInput{Revision: created.Revision})
	if err != nil {
		t.Fatalf("activate template: %v", err)
	}
	return active
}

// publish records one scan.completed event and returns its delivery job.
func (h *renderHarness) publish(t *testing.T, scan string) ports.QueuedJob {
	t.Helper()
	e := domain.Event{TenantID: "tenant-r", ID: shared.ID("event-" + scan), Type: domain.EventScanCompleted, SourceKind: "scan_job", SourceID: scan, SchemaVersion: 1,
		OccurredAt: h.clock.at, Data: json.RawMessage(`{"title":"Scan completed","summary":"A scan completed successfully.","scan_id":"` + scan + `","scan_kind":"sast"}`)}
	if _, err := h.repo.Publish(h.ctx, e); err != nil {
		t.Fatal(err)
	}
	return h.claim(t)
}

func (h *renderHarness) claim(t *testing.T) ports.QueuedJob {
	t.Helper()
	job, err := h.jobs.Claim(h.ctx, time.Minute, JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim = %v, %v", job, err)
	}
	return *job
}

func (h *renderHarness) delivery(t *testing.T, job ports.QueuedJob) (domain.Delivery, []domain.Attempt) {
	t.Helper()
	var payload struct {
		DeliveryID shared.ID `json:"delivery_id"`
	}
	_ = json.Unmarshal(job.Payload, &payload)
	d, err := h.repo.GetDelivery(h.ctx, "tenant-r", payload.DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := h.repo.ListAttempts(h.ctx, "tenant-r", payload.DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	return d, attempts
}

func sentText(w ports.NotificationWork) string {
	if w.Formatted == nil {
		return ""
	}
	return string(w.Formatted.Body)
}

// TestRetryReusesThePinnedTemplate is the #1365 acceptance test: a retry renders with the version
// its first attempt pinned even after another version is activated, while a new delivery renders
// with the new one.
func TestRetryReusesThePinnedTemplate(t *testing.T) {
	h := newRenderHarness(t)
	first := h.template(t, "v1 {{.title}}")
	h.sender.results = []ports.NotificationSendResult{{StatusCode: 503, ErrorCode: "http_503", Retryable: true}}
	job := h.publish(t, "scan-1")
	if err := h.svc.HandleJob(h.ctx, job); err == nil {
		t.Fatal("a 503 must be retried")
	}
	pin := "tenant:" + first.ID.String() + "@1"
	d, attempts := h.delivery(t, job)
	if d.TemplateRef != pin || len(attempts) != 1 || attempts[0].TemplateRef != pin {
		t.Fatalf("pin = %q, attempts = %+v, want %s", d.TemplateRef, attempts, pin)
	}
	if !strings.Contains(sentText(h.sender.sent[0]), "v1 Scan completed") || !strings.Contains(sentText(h.sender.sent[0]), "2026-10-01 08:00 UTC") {
		t.Fatalf("first attempt sent %s", sentText(h.sender.sent[0]))
	}

	updated, err := h.svc.UpdateTemplate(h.ctx, "admin", first.ID, TemplateUpdateInput{Fields: map[string]string{"title": "v2 {{.title}}", "body": "new"}, Revision: first.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ActivateTemplate(h.ctx, "admin", first.ID, TemplateChangeInput{Version: 2, Revision: updated.Revision}); err != nil {
		t.Fatal(err)
	}

	if err := h.jobs.Retry(h.ctx, job.ID, job.Fence, time.Second); err != nil {
		t.Fatal(err)
	}
	h.clock.at = h.clock.at.Add(2 * time.Second)
	retry := h.claim(t)
	if err := h.svc.HandleJob(h.ctx, retry); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := sentText(h.sender.sent[1]); !strings.Contains(got, "v1 Scan completed") {
		t.Fatalf("the retry rendered %s, want the pinned version 1", got)
	}
	if _, attempts := h.delivery(t, retry); len(attempts) != 2 || attempts[1].TemplateRef != pin {
		t.Fatalf("retry attempts = %+v", attempts)
	}

	h.clock.at = h.clock.at.Add(2 * time.Second) // past the per-channel rate limit
	fresh := h.publish(t, "scan-2")
	if err := h.svc.HandleJob(h.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if got := sentText(h.sender.sent[2]); !strings.Contains(got, "v2 Scan completed") {
		t.Fatalf("a new delivery rendered %s, want version 2", got)
	}
}

// TestFailingTemplateFallsBackAndDelivers is the second #1365 acceptance test: a template that no
// longer renders falls back to the driver's built-in content, records the fallback, and the
// delivery still succeeds.
func TestFailingTemplateFallsBackAndDelivers(t *testing.T) {
	h := newRenderHarness(t)
	// Stored directly, as a template saved before a catalog change would be: it names a variable
	// the event no longer declares, so it no longer compiles.
	now := h.clock.at
	broken, _, err := h.templates.CreateNotificationTemplate(h.ctx, domain.Template{TenantID: "tenant-r", ID: "broken", Name: "Broken",
		TemplateKey: domain.TemplateKey{EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en"},
		Status:      domain.TemplateDraft, Revision: 1, CreatedAt: now, CreatedBy: "admin", UpdatedAt: now, UpdatedBy: "admin"},
		map[string]string{"title": "{{.retired_variable}}", "body": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.templates.ActivateNotificationTemplate(h.ctx, ports.NotificationTemplateChange{TenantID: "tenant-r", ID: broken.ID, ExpectedRevision: broken.Revision, Actor: "admin", At: now}); err != nil {
		t.Fatal(err)
	}
	job := h.publish(t, "scan-1")
	if err := h.svc.HandleJob(h.ctx, job); err != nil {
		t.Fatalf("handle job: %v", err)
	}
	if h.sender.sent[0].Formatted != nil {
		t.Fatal("a template that failed to render still produced a payload")
	}
	d, attempts := h.delivery(t, job)
	if d.State != domain.DeliverySucceeded || d.TemplateRef != refFallback || attempts[0].TemplateRef != refFallback {
		t.Fatalf("delivery = %+v, attempts = %+v, want delivered with the fallback recorded", d, attempts)
	}
}

// TestRenderThatLeavesNothingFallsBack is the #1566 review case: every variable the template uses is
// summary class, and the engagement caps the channel at signal. The class leaves each variable out
// as empty text, so the template renders nothing; the message must fall back to the built-in
// content and record it, rather than send an empty payload a provider refuses.
func TestRenderThatLeavesNothingFallsBack(t *testing.T) {
	h := newRenderHarness(t)
	created, err := h.svc.CreateTemplate(h.ctx, "admin", TemplateInput{Name: "Summary only", EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en",
		Fields: map[string]string{"title": "{{.title}}", "body": "  {{.target}}  "}})
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	if _, err := h.svc.ActivateTemplate(h.ctx, "admin", created.ID, TemplateChangeInput{Revision: created.Revision}); err != nil {
		t.Fatalf("activate template: %v", err)
	}
	e := domain.Event{TenantID: "tenant-r", ID: "event-blank", Type: domain.EventScanCompleted, SourceKind: "scan_job", SourceID: "blank", SchemaVersion: 1,
		OccurredAt: h.clock.at, Data: json.RawMessage(`{"title":"Scan completed","scan_kind":"sast","target":"https://app.example.test"}`)}
	projected, err := NewEventBuilders().Project(h.ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	full, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: projected})
	if err != nil || full.Fallback || full.Formatted == nil {
		t.Fatalf("at the channel's own summary class = %+v, %v, want the template rendered", full, err)
	}
	capped, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: projected, Engagement: domain.EngagementNotificationsSignal})
	if err != nil {
		t.Fatal(err)
	}
	if !capped.Fallback || capped.Formatted != nil || capped.Message.TemplateRef != refFallback {
		t.Fatalf("capped at signal = %+v, want the built-in content with the fallback recorded", capped)
	}
}

// TestRenderMessageAppliesTheDataClass checks that a variable above the channel's class renders
// empty, and that an engagement set to none suppresses the message.
func TestRenderMessageAppliesTheDataClass(t *testing.T) {
	h := newRenderHarness(t)
	h.template(t, "{{.title}} [{{.scan_kind}}]")
	e := domain.Event{TenantID: "tenant-r", ID: "event-x", Type: domain.EventScanCompleted, SourceKind: "scan_job", SourceID: "x", SchemaVersion: 1,
		OccurredAt: h.clock.at, Data: json.RawMessage(`{"title":"Scan completed","scan_kind":"sast"}`)}
	projected, err := NewEventBuilders().Project(h.ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	signal := h.channel
	signal.DataClass = domain.DataClassSignal
	out, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: signal, Event: projected})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Message.Fields["title"]; got != " [sast]" {
		t.Fatalf("signal-class title = %q, want the summary-class title left out", got)
	}
	suppressed, err := h.svc.RenderMessage(h.ctx, RenderInput{Channel: h.channel, Event: projected, Engagement: domain.EngagementNotificationsNone})
	if err != nil || !suppressed.Suppressed {
		t.Fatalf("engagement none = %+v, %v", suppressed, err)
	}
}
