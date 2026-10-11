package notification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// bindingRepo keeps channels and rules in memory for the binding checks.
type bindingRepo struct {
	ports.NotificationRepository
	channels map[shared.ID]domain.Channel
	rules    map[shared.ID]domain.Rule
}

func newBindingRepo() *bindingRepo {
	return &bindingRepo{channels: map[shared.ID]domain.Channel{}, rules: map[shared.ID]domain.Rule{}}
}

func (r *bindingRepo) CreateChannel(_ context.Context, c domain.Channel, _ string) (domain.Channel, error) {
	if err := c.Validate(); err != nil {
		return domain.Channel{}, err
	}
	r.channels[c.ID] = c
	return c, nil
}
func (r *bindingRepo) UpdateChannel(_ context.Context, c domain.Channel, _ string, _ bool) (domain.Channel, error) {
	if err := c.Validate(); err != nil {
		return domain.Channel{}, err
	}
	r.channels[c.ID] = c
	return c, nil
}
func (r *bindingRepo) GetChannel(_ context.Context, _, id shared.ID) (domain.Channel, error) {
	c, ok := r.channels[id]
	if !ok {
		return domain.Channel{}, shared.ErrNotFound
	}
	return c, nil
}
func (r *bindingRepo) ListChannels(context.Context, shared.ID) ([]domain.Channel, error) {
	out := make([]domain.Channel, 0, len(r.channels))
	for _, c := range r.channels {
		out = append(out, c)
	}
	return out, nil
}
func (r *bindingRepo) CreateRule(_ context.Context, rule domain.Rule) (domain.Rule, error) {
	r.rules[rule.ID] = rule
	return rule, nil
}
func (r *bindingRepo) UpdateRule(_ context.Context, rule domain.Rule) (domain.Rule, error) {
	r.rules[rule.ID] = rule
	return rule, nil
}
func (r *bindingRepo) GetRule(_ context.Context, _, id shared.ID) (domain.Rule, error) {
	rule, ok := r.rules[id]
	if !ok {
		return domain.Rule{}, shared.ErrNotFound
	}
	return rule, nil
}
func (r *bindingRepo) ListRules(context.Context, shared.ID) ([]domain.Rule, error) {
	out := make([]domain.Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule)
	}
	return out, nil
}

type bindingFixture struct {
	svc      *Service
	repo     *bindingRepo
	audit    *recordingAudit
	settings *memory.TenantSettingsStore
	ctx      context.Context
}

func newBindingFixture(t *testing.T) bindingFixture {
	t.Helper()
	withTemplateCatalog(t)
	repo, audit := newBindingRepo(), &recordingAudit{}
	svc, err := NewService(repo, fakeProtector{}, nil, audit, fakeClock{time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)}, &templateIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateStore(memory.NewNotificationTemplateStore())
	settings := memory.NewTenantSettingsStore()
	svc.SetTenantSettings(settings)
	return bindingFixture{svc: svc, repo: repo, audit: audit, settings: settings, ctx: shared.WithTenant(context.Background(), "tenant")}
}

// template creates and, when activate is set, activates a template.
func (f bindingFixture) template(t *testing.T, event domain.EventType, family domain.TemplateFamily, locale tenancy.Locale, activate bool) domain.Template {
	t.Helper()
	fields := map[string]string{"title": "T", "body": "B"}
	switch family {
	case domain.FamilyEmail:
		fields = map[string]string{"subject": "S", "body": "B"}
	case domain.FamilyWebhook:
		fields = map[string]string{"body": `{"text":"B"}`}
	}
	created, err := f.svc.CreateTemplate(f.ctx, "ada", TemplateInput{Name: "tpl", EventType: event, Family: family, Locale: locale, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	if !activate {
		return created.Template
	}
	active, err := f.svc.ActivateTemplate(f.ctx, "ada", created.ID, TemplateChangeInput{Revision: created.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return active.Template
}

func (f bindingFixture) slackChannel(t *testing.T) domain.Channel {
	t.Helper()
	c, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/X"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func idPtr(id shared.ID) *shared.ID              { return &id }
func localePtr(l tenancy.Locale) *tenancy.Locale { return &l }

func TestBindingValidation(t *testing.T) {
	f := newBindingFixture(t)
	channel := f.slackChannel(t)
	chatAny := f.template(t, domain.AnyEventType, domain.FamilyChat, "*", true)
	emailAny := f.template(t, domain.AnyEventType, domain.FamilyEmail, "*", true)
	draft := f.template(t, domain.EventScanCompleted, domain.FamilyChat, "en", false)
	vietnamese := f.template(t, domain.EventScanCompleted, domain.FamilyChat, "vi", true)

	bind := func(in ChannelInput) (domain.Channel, error) {
		current := f.repo.channels[channel.ID]
		in.Name, in.Enabled, in.Revision = current.Name, current.Enabled, current.Revision
		return f.svc.UpdateChannel(f.ctx, "ada", channel.ID, in)
	}
	for name, tc := range map[string]struct {
		in   ChannelInput
		want string
	}{
		"unknown template":  {ChannelInput{TemplateID: idPtr("nope")}, "does not exist"},
		"other family":      {ChannelInput{TemplateID: idPtr(emailAny.ID)}, "email template"},
		"not active":        {ChannelInput{TemplateID: idPtr(draft.ID)}, "only an active template"},
		"locale mismatch":   {ChannelInput{TemplateID: idPtr(vietnamese.ID)}, "renders in en"},
		"invalid locale":    {ChannelInput{Locale: localePtr("fr")}, "channel locale"},
		"wildcard locale":   {ChannelInput{Locale: localePtr("*")}, "channel locale"},
		"oversized id":      {ChannelInput{TemplateID: idPtr(shared.ID(strings.Repeat("x", 200)))}, "template id"},
		"control character": {ChannelInput{TemplateID: idPtr("a\x00b")}, "template id"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := bind(tc.in); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want validation containing %q", err, tc.want)
			}
		})
	}

	// A Vietnamese channel accepts the Vietnamese template; the audit entry records the change.
	bound, err := bind(ChannelInput{TemplateID: idPtr(vietnamese.ID), Locale: localePtr("vi")})
	if err != nil || bound.TemplateID != vietnamese.ID || bound.Locale != "vi" {
		t.Fatalf("bind = %+v err=%v", bound, err)
	}
	entry := f.audit.last(t, "notification.channel.updated")
	if entry.Metadata["binding_changed"] != "true" || entry.Metadata["template_id"] != vietnamese.ID.String() || entry.Metadata["locale"] != "vi" ||
		entry.Metadata["previous_template_id"] != "" || entry.Metadata["destination_changed"] != "false" {
		t.Fatalf("audit = %+v", entry.Metadata)
	}
	// Omitted binding fields keep the binding, as the console does on a rename.
	renamed, err := bind(ChannelInput{})
	if err != nil || renamed.TemplateID != vietnamese.ID || renamed.Locale != "vi" {
		t.Fatalf("rename = %+v err=%v", renamed, err)
	}
	if f.audit.last(t, "notification.channel.updated").Metadata["binding_changed"] != "false" {
		t.Fatal("a rename recorded a binding change")
	}
	// Rebinding to "*" and unbinding with "".
	if rebound, err := bind(ChannelInput{TemplateID: idPtr(chatAny.ID)}); err != nil || rebound.TemplateID != chatAny.ID {
		t.Fatalf("rebind = %+v err=%v", rebound, err)
	}
	if meta := f.audit.last(t, "notification.channel.updated").Metadata; meta["previous_template_id"] != vietnamese.ID.String() {
		t.Fatalf("rebind audit = %+v", meta)
	}
	if unbound, err := bind(ChannelInput{TemplateID: idPtr(""), Locale: localePtr("")}); err != nil || unbound.TemplateID != "" || unbound.Locale != "" {
		t.Fatalf("unbind = %+v err=%v", unbound, err)
	}
}

// The tenant default locale decides which template locales a channel without its own may bind.
func TestBindingUsesTheTenantLocale(t *testing.T) {
	f := newBindingFixture(t)
	channel := f.slackChannel(t)
	vietnamese := f.template(t, domain.EventScanCompleted, domain.FamilyChat, "vi", true)
	in := ChannelInput{Name: channel.Name, Enabled: true, Revision: channel.Revision, TemplateID: idPtr(vietnamese.ID)}
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", channel.ID, in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("vi template on an en tenant: err = %v", err)
	}
	if _, err := f.settings.SaveTenantSettings(f.ctx, tenancy.Settings{TenantID: "tenant", DefaultLocale: "vi", TimeZone: "UTC", UpdatedAt: time.Now(), UpdatedBy: "ada"}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", channel.ID, in); err != nil {
		t.Fatalf("vi template on a vi tenant: %v", err)
	}
	resolution, err := f.svc.PreviewTemplateResolution(f.ctx, channel.ID, domain.EventScanCompleted)
	if err != nil || resolution.Tier != TierChannel || resolution.Locale != "vi" || resolution.LocaleSource != LocaleFromTenant || resolution.Template.ID != vietnamese.ID {
		t.Fatalf("resolution = %+v err=%v", resolution, err)
	}
}

// A template for one event type binds only while every rule routing to the channel is for that
// event, and a rule routing another event to the bound channel is refused.
func TestBindingAndRulesMustAgreeOnEventTypes(t *testing.T) {
	f := newBindingFixture(t)
	channel := f.slackChannel(t)
	scanOnly := f.template(t, domain.EventScanCompleted, domain.FamilyChat, "en", true)
	chatAny := f.template(t, domain.AnyEventType, domain.FamilyChat, "*", true)

	incidents, err := f.svc.CreateRule(f.ctx, "ada", RuleInput{Name: "incidents", Enabled: true, EventType: domain.EventIncidentCreated, ChannelIDs: []shared.ID{channel.ID}})
	if err != nil {
		t.Fatal(err)
	}
	bind := func(id shared.ID) error {
		current := f.repo.channels[channel.ID]
		_, err := f.svc.UpdateChannel(f.ctx, "ada", channel.ID, ChannelInput{Name: current.Name, Enabled: true, Revision: current.Revision, TemplateID: &id})
		return err
	}
	if err := bind(scanOnly.ID); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), string(incidents.ID)) {
		t.Fatalf("bind scan-only with an incident rule: %v", err)
	}
	// Moving the rule to scan events makes the binding valid.
	if _, err := f.svc.UpdateRule(f.ctx, "ada", incidents.ID, RuleInput{Name: "scans", Enabled: true, EventType: domain.EventScanCompleted, ChannelIDs: []shared.ID{channel.ID}, Revision: incidents.Revision}); err != nil {
		t.Fatal(err)
	}
	if err := bind(scanOnly.ID); err != nil {
		t.Fatalf("bind scan-only with a scan rule: %v", err)
	}
	// Now a rule routing incidents to the channel is refused, on create and on update.
	refused := RuleInput{Name: "incidents", Enabled: true, EventType: domain.EventIncidentCreated, ChannelIDs: []shared.ID{channel.ID}}
	if _, err := f.svc.CreateRule(f.ctx, "ada", refused); !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), string(scanOnly.ID)) {
		t.Fatalf("create incident rule on a scan-bound channel: %v", err)
	}
	scans := f.repo.rules[incidents.ID]
	if _, err := f.svc.UpdateRule(f.ctx, "ada", scans.ID, RuleInput{Name: "scans", Enabled: true, EventType: domain.EventIncidentCreated, ChannelIDs: []shared.ID{channel.ID}, Revision: scans.Revision}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("move scan rule to incidents: %v", err)
	}
	// A "*" binding covers every event.
	if err := bind(chatAny.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateRule(f.ctx, "ada", refused); err != nil {
		t.Fatalf("incident rule on a *-bound channel: %v", err)
	}
}

// Archiving a bound template does not break the channel: it can still be renamed, and resolution
// skips the binding.
func TestArchivedBindingFallsThrough(t *testing.T) {
	f := newBindingFixture(t)
	channel := f.slackChannel(t)
	bound := f.template(t, domain.EventScanCompleted, domain.FamilyChat, "en", true)
	wildcard := f.template(t, domain.AnyEventType, domain.FamilyChat, "en", true)
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", channel.ID, ChannelInput{Name: "ops", Enabled: true, Revision: channel.Revision, TemplateID: idPtr(bound.ID)}); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.ResolveTemplate(context.Background(), "tenant", channel.ID, domain.EventScanCompleted)
	if err != nil || got.Tier != TierChannel || got.Template.ID != bound.ID || got.Version == nil || got.Version.Version != 1 {
		t.Fatalf("bound resolution = %+v err=%v", got, err)
	}
	if _, err := f.svc.ArchiveTemplate(f.ctx, "ada", bound.ID, TemplateChangeInput{Revision: bound.Revision}); err != nil {
		t.Fatal(err)
	}
	current := f.repo.channels[channel.ID]
	if _, err := f.svc.UpdateChannel(f.ctx, "ada", channel.ID, ChannelInput{Name: "renamed", Enabled: true, Revision: current.Revision}); err != nil {
		t.Fatalf("rename with an archived binding: %v", err)
	}
	got, err = f.svc.ResolveTemplate(context.Background(), "tenant", channel.ID, domain.EventScanCompleted)
	if err != nil || got.Tier != TierTenantWildcard || got.BindingSkipped != BindingNotActive || got.Template.ID != wildcard.ID {
		t.Fatalf("archived resolution = %+v err=%v", got, err)
	}
	if _, err := f.svc.ResolveTemplate(context.Background(), "tenant", channel.ID, "not.an_event"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown event type: %v", err)
	}
}

// Creating a channel may bind a template, which is audited; without a template store a binding is
// refused.
func TestCreateChannelWithBinding(t *testing.T) {
	f := newBindingFixture(t)
	chatAny := f.template(t, domain.AnyEventType, domain.FamilyChat, "*", true)
	created, err := f.svc.CreateChannel(f.ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/X", TemplateID: idPtr(chatAny.ID), Locale: localePtr("vi")})
	if err != nil || created.TemplateID != chatAny.ID || created.Locale != "vi" {
		t.Fatalf("create = %+v err=%v", created, err)
	}
	if meta := f.audit.last(t, "notification.channel.created").Metadata; meta["template_id"] != chatAny.ID.String() || meta["locale"] != "vi" || meta["binding_changed"] != "true" {
		t.Fatalf("create audit = %+v", meta)
	}

	bare, err := NewService(newBindingRepo(), fakeProtector{}, nil, fakeAudit{}, fakeClock{time.Now()}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.CreateChannel(f.ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/X", TemplateID: idPtr(chatAny.ID)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bind without a template store: %v", err)
	}
	// Without a store and without tenant settings, resolution still answers: the fallback, in en.
	channel, err := bare.CreateChannel(f.ctx, "ada", ChannelInput{Name: "ops", Type: domain.ChannelSlack, Enabled: true, URL: "https://hooks.slack.com/services/T/B/X"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := bare.ResolveTemplate(context.Background(), "tenant", channel.ID, domain.EventScanCompleted)
	if err != nil || got.Tier != TierFallback || got.Locale != "en" || got.LocaleSource != LocaleFromDefault || got.Family != domain.FamilyChat {
		t.Fatalf("bare resolution = %+v err=%v", got, err)
	}
}
