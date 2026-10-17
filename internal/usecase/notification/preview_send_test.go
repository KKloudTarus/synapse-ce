package notification

import (
	"errors"
	"testing"

	eventschemas "github.com/KKloudTarus/synapse-ce/docs/guide/schemas/events"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSendTemplateTestSnapshotsThePreviewedFixtureForDelivery(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetEventFixtures(eventschemas.Fixtures)
	template := h.template(t, "Original {{.title}}")
	in := PreviewInput{ChannelID: h.channel.ID, EventType: domain.EventScanCompleted, TemplateID: template.ID}
	preview, err := h.svc.PreviewTemplate(h.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Formatted == nil || preview.Message == nil {
		t.Fatalf("preview = %+v", preview)
	}

	delivery, err := h.svc.SendTemplateTest(h.ctx, "admin", in)
	if err != nil {
		t.Fatal(err)
	}
	work, err := h.repo.LoadWork(h.ctx, "tenant-r", delivery)
	if err != nil {
		t.Fatal(err)
	}
	if work.Event.Type != domain.EventScanCompleted || work.Event.SourceKind != "template_test" || work.Event.TestTemplate == nil || work.Event.TestTemplate.Fields["title"] != "Original {{.title}}" {
		t.Fatalf("test work = %+v", work.Event)
	}

	updated, err := h.svc.UpdateTemplate(h.ctx, "admin", template.ID, TemplateUpdateInput{Fields: map[string]string{"title": "Changed", "body": "Changed"}, Revision: template.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.svc.ActivateTemplate(h.ctx, "admin", template.ID, TemplateChangeInput{Revision: updated.Revision}); err != nil {
		t.Fatal(err)
	}
	job := h.claim(t)
	if err = h.svc.HandleJob(h.ctx, job); err != nil {
		t.Fatal(err)
	}
	if len(h.sender.sent) != 1 || h.sender.sent[0].Formatted == nil || string(h.sender.sent[0].Formatted.Body) != preview.Formatted.Body {
		t.Fatalf("sent = %+v, want preview body %q", h.sender.sent, preview.Formatted.Body)
	}
}

func TestSendTemplateTestRefusesStoredEvents(t *testing.T) {
	f, _ := newPreviewFixture(t)
	channel := f.slackChannel(t)
	_, err := f.svc.SendTemplateTest(f.ctx, "ada", PreviewInput{ChannelID: channel.ID, EventType: domain.EventIncidentCreated, EventID: "ev-new"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("stored event test error = %v, want validation", err)
	}
}

func TestSendTemplateTestSharesTheChannelTestRateLimit(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetEventFixtures(eventschemas.Fixtures)
	in := PreviewInput{ChannelID: h.channel.ID, EventType: domain.EventScanCompleted}
	for n := 0; n < 5; n++ {
		if _, err := h.svc.SendTemplateTest(h.ctx, "admin", in); err != nil {
			t.Fatalf("test %d: %v", n+1, err)
		}
	}
	if _, err := h.svc.SendTemplateTest(h.ctx, "admin", in); !errors.Is(err, shared.ErrSaturated) {
		t.Fatalf("sixth template test error = %v, want saturated", err)
	}
}

func TestFallbackPreviewMatchesTheQueuedTemplateTest(t *testing.T) {
	h := newRenderHarness(t)
	h.svc.SetEventFixtures(eventschemas.Fixtures)
	c := h.channel
	c.DataClass = domain.DataClassSignal
	c.Revision++
	if _, err := h.repo.UpdateChannel(h.ctx, c, "", false); err != nil {
		t.Fatal(err)
	}
	in := PreviewInput{ChannelID: c.ID, EventType: domain.EventScanCompleted, Fields: map[string]string{"title": "{{.title}}", "body": "{{.target}}"}}
	preview, err := h.svc.PreviewTemplate(h.ctx, in)
	if err != nil || !preview.Fallback || preview.Formatted == nil {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	if _, err = h.svc.SendTemplateTest(h.ctx, "admin", in); err != nil {
		t.Fatal(err)
	}
	if err = h.svc.HandleJob(h.ctx, h.claim(t)); err != nil {
		t.Fatal(err)
	}
	if len(h.sender.sent) != 1 || h.sender.sent[0].Formatted == nil || string(h.sender.sent[0].Formatted.Body) != preview.Formatted.Body {
		t.Fatalf("fallback parity failed: %+v", h.sender.sent)
	}
}

func TestEveryCatalogFixtureTestDeliversWithoutLiveSourceEntities(t *testing.T) {
	for _, spec := range domain.EventCatalog() {
		t.Run(string(spec.Type), func(t *testing.T) {
			h := newRenderHarness(t)
			h.svc.SetEventFixtures(eventschemas.Fixtures)
			input := PreviewInput{ChannelID: h.channel.ID, EventType: spec.Type}
			preview, err := h.svc.PreviewTemplate(h.ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = h.svc.SendTemplateTest(h.ctx, "admin", input); err != nil {
				t.Fatal(err)
			}
			if err = h.svc.HandleJob(h.ctx, h.claim(t)); err != nil {
				t.Fatal(err)
			}
			if len(h.sender.sent) != 1 || h.sender.sent[0].Formatted == nil || preview.Formatted == nil || string(h.sender.sent[0].Formatted.Body) != preview.Formatted.Body {
				t.Fatalf("fixture did not deliver its preview: sent=%+v", h.sender.sent)
			}
		})
	}
}
