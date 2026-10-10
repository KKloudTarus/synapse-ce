package notification

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// A webhook template's body is checked as a custom JSON body when it is saved: structure first,
// then every expression value against each event type the key can render, with the value's path.
func TestWebhookTemplateBodyIsValidatedOnSave(t *testing.T) {
	f := newBindingFixture(t)
	save := func(event domain.EventType, body string) error {
		_, err := f.svc.CreateTemplate(f.ctx, "ada", TemplateInput{Name: "hook", EventType: event, Family: domain.FamilyWebhook, Locale: "en", Fields: map[string]string{"body": body}})
		return err
	}
	if err := save(domain.EventScanCompleted, `{"title":"{{.title}}","engagement":"{{.engagement}}","v":1}`); err != nil {
		t.Fatalf("valid body: %v", err)
	}
	for name, tc := range map[string]struct {
		event domain.EventType
		body  string
		code  msgtemplate.Code
		path  string
	}{
		"not json":           {domain.EventScanCompleted, `title: x`, msgtemplate.Code(domain.WebhookBodyInvalidJSON), "$"},
		"bare expression":    {domain.EventScanCompleted, `{"n":{{.title}}}`, msgtemplate.Code(domain.WebhookBodyExpressionOutside), ""},
		"expression key":     {domain.EventScanCompleted, `{"{{.title}}":"x"}`, msgtemplate.Code(domain.WebhookBodyExpressionInKey), `$["{{.title}}"]`},
		"duplicate key":      {domain.EventScanCompleted, `{"a":"x","a":"y"}`, msgtemplate.Code(domain.WebhookBodyDuplicateKey), "$.a"},
		"array":              {domain.EventScanCompleted, `["x"]`, msgtemplate.Code(domain.WebhookBodyNotObject), "$"},
		"unknown variable":   {domain.EventScanCompleted, `{"a":{"b":["{{.password}}"]}}`, msgtemplate.CodeUnknownVariable, "$.a.b[0]"},
		"wildcard variables": {domain.AnyEventType, `{"a":"{{.engagement}}"}`, msgtemplate.CodeUnknownVariable, "$.a"},
	} {
		t.Run(name, func(t *testing.T) {
			err := save(tc.event, tc.body)
			var rejection *TemplateValidationError
			if !errors.As(err, &rejection) || !errors.Is(err, shared.ErrValidation) || rejection.Field != "body" || rejection.Code != tc.code || rejection.Path != tc.path {
				t.Fatalf("err = %#v, want code %s path %q", err, tc.code, tc.path)
			}
			if strings.Contains(err.Error(), "password") && tc.code != msgtemplate.CodeUnknownVariable {
				t.Fatalf("error quotes source: %v", err)
			}
		})
	}
}

// custom_body is a webhook-only opt-in that needs a bound template whose body still validates,
// and is audited with the binding.
func TestCustomBodyOptIn(t *testing.T) {
	f := newBindingFixture(t)
	hook := f.template(t, domain.AnyEventType, domain.FamilyWebhook, "*", true)
	webhook, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "hook", Type: domain.ChannelWebhook, Enabled: true, URL: "https://hooks.example.com/in", Secret: "0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	slack := f.slackChannel(t)
	on := true
	update := func(c domain.Channel, in ChannelInput) (domain.Channel, error) {
		current := f.repo.channels[c.ID]
		in.Name, in.Enabled, in.Revision = current.Name, true, current.Revision
		return f.svc.UpdateChannel(f.ctx, "ada", c.ID, in)
	}
	if _, err := update(webhook, ChannelInput{CustomBody: &on}); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "bound webhook template") {
		t.Fatalf("custom body without a template: %v", err)
	}
	if _, err := update(slack, ChannelInput{CustomBody: &on}); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "only available on webhook") {
		t.Fatalf("custom body on slack: %v", err)
	}
	opted, err := update(webhook, ChannelInput{TemplateID: idPtr(hook.ID), CustomBody: &on})
	if err != nil || !opted.CustomBody || opted.TemplateID != hook.ID {
		t.Fatalf("opt in = %+v err=%v", opted.TemplateBinding, err)
	}
	if meta := f.audit.last(t, "notification.channel.updated").Metadata; meta["custom_body"] != "true" || meta["previous_custom_body"] != "false" || meta["binding_changed"] != "true" {
		t.Fatalf("audit = %+v", meta)
	}
	// Unbinding while opted in is refused; turning the opt-in off with it is accepted.
	if _, err := update(webhook, ChannelInput{TemplateID: idPtr("")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unbind while opted in: %v", err)
	}
	off := false
	if out, err := update(webhook, ChannelInput{TemplateID: idPtr(""), CustomBody: &off}); err != nil || out.CustomBody || out.TemplateID != "" {
		t.Fatalf("opt out = %+v err=%v", out.TemplateBinding, err)
	}
}

// The helper for the send-time renderer renders the resolved webhook body and leaves every other
// resolution to the envelope.
func TestRenderCustomWebhookBodyFromAResolution(t *testing.T) {
	f := newBindingFixture(t)
	hook := f.template(t, domain.EventScanCompleted, domain.FamilyWebhook, "en", false)
	updated, err := f.svc.UpdateTemplate(f.ctx, "ada", hook.ID, TemplateUpdateInput{Fields: map[string]string{"body": `{"scan":"{{.title}}","ok":true}`}, Revision: hook.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ActivateTemplate(f.ctx, "ada", hook.ID, TemplateChangeInput{Revision: updated.Revision}); err != nil {
		t.Fatal(err)
	}
	channel, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "hook", Type: domain.ChannelWebhook, Enabled: true, URL: "https://hooks.example.com/in", Secret: "0123456789abcdef",
		TemplateID: idPtr(hook.ID), CustomBody: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := f.svc.ResolveTemplate(context.Background(), "tenant", channel.ID, domain.EventScanCompleted)
	if err != nil || resolution.Tier != TierChannel {
		t.Fatalf("resolution = %+v err=%v", resolution, err)
	}
	body, ok, err := RenderCustomWebhookBody(resolution, msgtemplate.Data{Vars: map[string]string{"title": `nightly","ok":false`}})
	if err != nil || !ok {
		t.Fatalf("render ok=%v err=%v", ok, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil || decoded["ok"] != true || decoded["scan"] != `nightly","ok":false` {
		t.Fatalf("body = %s err=%v", body, err)
	}
	for name, r := range map[string]TemplateResolution{
		"fallback":   {Tier: TierFallback, Family: domain.FamilyWebhook, EventType: domain.EventScanCompleted},
		"chat":       {Tier: TierChannel, Family: domain.FamilyChat, EventType: domain.EventScanCompleted, Version: resolution.Version},
		"no version": {Tier: TierTenantEvent, Family: domain.FamilyWebhook, EventType: domain.EventScanCompleted},
	} {
		if body, ok, err := RenderCustomWebhookBody(r, msgtemplate.Data{}); ok || body != nil || err != nil {
			t.Errorf("%s: body=%s ok=%v err=%v", name, body, ok, err)
		}
	}
}

func boolPtr(v bool) *bool { return &v }
