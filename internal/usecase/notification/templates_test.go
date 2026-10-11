package notification

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// withTemplateCatalog declares template variables the production catalog does not have yet: scan
// completion exposes title and engagement, incidents title and severity.
func withTemplateCatalog(t *testing.T) {
	t.Helper()
	previous := templateCatalog
	templateCatalog = func() []domain.EventSpec {
		return []domain.EventSpec{
			{Type: domain.EventIncidentCreated, Variables: []domain.Variable{{Name: "title", Class: domain.DataClassSummary}, {Name: "severity", Class: domain.DataClassSignal}}},
			{Type: domain.EventScanCompleted, Variables: []domain.Variable{{Name: "title", Class: domain.DataClassSummary}, {Name: "engagement", Class: domain.DataClassSummary}}},
		}
	}
	t.Cleanup(func() { templateCatalog = previous })
}

type templateIDs struct{ n int }

type builtinTemplateCatalog struct{ items []ports.BuiltinTemplate }

func (c *builtinTemplateCatalog) Builtin(eventType domain.EventType, family domain.TemplateFamily, locale tenancy.Locale) (ports.BuiltinTemplate, bool) {
	for _, item := range c.items {
		if item.EventType == eventType && item.Family == family && item.Locale == locale {
			return item, true
		}
	}
	return ports.BuiltinTemplate{}, false
}

func (c *builtinTemplateCatalog) List() []ports.BuiltinTemplate { return c.items }

func (g *templateIDs) NewID() shared.ID {
	g.n++
	return shared.ID("tpl-" + string(rune('a'+g.n-1)))
}

func templateService(t *testing.T, audit ports.AuditLogger) *Service {
	t.Helper()
	svc, err := NewService(&fakeRepo{}, fakeProtector{}, nil, audit, fakeClock{time.Date(2026, 9, 29, 8, 0, 0, 0, time.UTC)}, &templateIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTemplateStore(memory.NewNotificationTemplateStore())
	return svc
}

func TestListBuiltinTemplatesCopiesTheCurrentCatalog(t *testing.T) {
	svc := templateService(t, &recordingAudit{})
	catalog := &builtinTemplateCatalog{items: []ports.BuiltinTemplate{{
		Ref: "builtin:scan.completed:chat:en@test",
		TemplateKey: domain.TemplateKey{
			EventType: domain.EventScanCompleted,
			Family:    domain.FamilyChat,
			Locale:    tenancy.LocaleEnglish,
		},
		Fields: map[string]string{"title": "Scan complete", "body": "{{.title}}"},
	}}}
	svc.SetBuiltinTemplates(catalog)

	got := svc.ListBuiltinTemplates()
	if len(got) != 1 || got[0].EventType != domain.EventScanCompleted || got[0].Family != domain.FamilyChat || got[0].Locale != tenancy.LocaleEnglish || !reflect.DeepEqual(got[0].Fields, catalog.items[0].Fields) {
		t.Fatalf("builtins = %#v", got)
	}
	got[0].Fields["title"] = "mutated"
	if catalog.items[0].Fields["title"] != "Scan complete" {
		t.Fatal("returned built-in fields mutated the delivery catalog")
	}
}

func assertNoSource(t *testing.T, entry ports.AuditEntry, sources ...string) {
	t.Helper()
	for key, value := range entry.Metadata {
		for _, source := range sources {
			if strings.Contains(value, source) {
				t.Fatalf("%s metadata %s=%q quotes template source", entry.Action, key, value)
			}
		}
	}
}

func TestTemplateLifecycleIsValidatedAndAudited(t *testing.T) {
	withTemplateCatalog(t)
	ctx := shared.WithTenant(context.Background(), "tenant")
	audit := &recordingAudit{}
	svc := templateService(t, audit)

	created, err := svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Scan done", EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en",
		Fields: map[string]string{"title": "Scan finished", "body": "{{.title}} in {{.engagement}}"}})
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != domain.TemplateDraft || created.LatestVersion != 1 || created.Latest == nil || created.Latest.Fields["body"] != "{{.title}} in {{.engagement}}" || created.Active != nil {
		t.Fatalf("created = %+v", created)
	}
	entry := audit.last(t, "notification.template.created")
	if entry.Actor != "ada" || entry.Metadata["diff"] != "body:+1/-0,title:+1/-0" || entry.Metadata["to_version"] != "1" || entry.Metadata["checksum"] == "" {
		t.Fatalf("created audit = %+v", entry)
	}
	assertNoSource(t, entry, "{{", "Scan finished")

	updated, err := svc.UpdateTemplate(ctx, "ada", created.ID, TemplateUpdateInput{Fields: map[string]string{"title": "Scan finished", "body": "{{.title}}\nEngagement {{.engagement}}"}, Revision: created.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if updated.LatestVersion != 2 || updated.Status != domain.TemplateDraft {
		t.Fatalf("updated = %+v", updated)
	}
	if entry = audit.last(t, "notification.template.updated"); entry.Metadata["diff"] != "body:+2/-1" || entry.Metadata["from_version"] != "1" || entry.Metadata["to_version"] != "2" {
		t.Fatalf("updated audit = %+v", entry)
	}
	if _, err = svc.UpdateTemplate(ctx, "ada", created.ID, TemplateUpdateInput{Fields: map[string]string{"body": "x"}, Revision: created.Revision}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update err = %v", err)
	}

	active, err := svc.ActivateTemplate(ctx, "ada", created.ID, TemplateChangeInput{Revision: updated.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if active.Status != domain.TemplateActive || active.ActiveVersion != 2 || active.Active == nil || active.Active.Version != 2 {
		t.Fatalf("activated = %+v", active)
	}
	if entry = audit.last(t, "notification.template.activated"); entry.Metadata["to_version"] != "2" || entry.Metadata["previous_status"] != "draft" || entry.Metadata["diff"] != "body:+2/-0,title:+1/-0" {
		t.Fatalf("activated audit = %+v", entry)
	}

	// A second template for the same key replaces the first one, and the audit names it.
	other, err := svc.CreateTemplate(ctx, "bob", TemplateInput{Name: "Scan v2", EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en", Fields: map[string]string{"body": "{{.engagement}}"}})
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := svc.ActivateTemplate(ctx, "bob", other.ID, TemplateChangeInput{Version: 1, Revision: other.Revision})
	if err != nil || replaced.ArchivedTemplateID != created.ID {
		t.Fatalf("replacement = %+v err=%v", replaced, err)
	}
	if entry = audit.last(t, "notification.template.activated"); entry.Metadata["archived_template_id"] != created.ID.String() {
		t.Fatalf("replacement audit = %+v", entry)
	}

	// Rollback activates an earlier version of the first template and archives the replacement.
	first, err := svc.GetTemplate(ctx, created.ID)
	if err != nil || first.Status != domain.TemplateArchived {
		t.Fatalf("first after replacement = %+v err=%v", first, err)
	}
	rolled, err := svc.RollbackTemplate(ctx, "ada", created.ID, TemplateChangeInput{Version: 1, Revision: first.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if rolled.Status != domain.TemplateActive || rolled.ActiveVersion != 1 || rolled.Active.Version != 1 || rolled.Latest.Version != 2 || rolled.ArchivedTemplateID != other.ID {
		t.Fatalf("rolled back = %+v", rolled)
	}
	if entry = audit.last(t, "notification.template.rolled_back"); entry.Metadata["from_version"] != "2" || entry.Metadata["to_version"] != "1" || entry.Metadata["diff"] != "body:+1/-2" {
		t.Fatalf("rollback audit = %+v", entry)
	}
	if _, err = svc.RollbackTemplate(ctx, "ada", created.ID, TemplateChangeInput{Version: 1, Revision: rolled.Revision}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("rollback to the active version err = %v", err)
	}
	if _, err = svc.RollbackTemplate(ctx, "ada", created.ID, TemplateChangeInput{Revision: rolled.Revision}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rollback without a version err = %v", err)
	}
	if _, err = svc.RollbackTemplate(ctx, "ada", created.ID, TemplateChangeInput{Version: 9, Revision: rolled.Revision}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rollback to a missing version err = %v", err)
	}

	versions, err := svc.ListTemplateVersions(ctx, created.ID, 0, 0)
	if err != nil || len(versions) != 2 || versions[0].Version != 2 || versions[1].Version != 1 {
		t.Fatalf("versions = %+v err=%v", versions, err)
	}

	archived, err := svc.ArchiveTemplate(ctx, "ada", created.ID, TemplateChangeInput{Revision: rolled.Revision})
	if err != nil || archived.Status != domain.TemplateArchived {
		t.Fatalf("archived = %+v err=%v", archived, err)
	}
	if entry = audit.last(t, "notification.template.archived"); entry.Metadata["previous_status"] != "active" || entry.Metadata["active_version"] != "1" {
		t.Fatalf("archive audit = %+v", entry)
	}
	if _, err = svc.ArchiveTemplate(ctx, "ada", created.ID, TemplateChangeInput{Revision: archived.Revision}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second archive err = %v", err)
	}
	for _, e := range audit.entries {
		assertNoSource(t, e, "{{", "Engagement ", "Scan finished")
	}

	// Templates are confined to the tenant of the session.
	if _, err = svc.GetTemplate(shared.WithTenant(context.Background(), "other"), created.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read err = %v", err)
	}
	if items, err := svc.ListTemplates(shared.WithTenant(context.Background(), "other"), ports.NotificationTemplateQuery{}); err != nil || len(items) != 0 {
		t.Fatalf("cross-tenant list = %v err=%v", items, err)
	}
}

// Unknown variables are rejected with the field, the event type, the engine code and the line, and
// the error never echoes the template source.
func TestTemplateValidationNamesTheFieldWithoutEchoingSource(t *testing.T) {
	withTemplateCatalog(t)
	ctx := shared.WithTenant(context.Background(), "tenant")
	svc := templateService(t, &recordingAudit{})
	source := "Private wording LITERAL-7F3A\n{{.missing_variable}}"
	_, err := svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Bad", EventType: domain.EventIncidentCreated, Family: domain.FamilyEmail, Locale: "vi",
		Fields: map[string]string{"subject": "ok", "body": source}})
	var rejection *TemplateValidationError
	if !errors.As(err, &rejection) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if rejection.Field != "body" || rejection.EventType != domain.EventIncidentCreated || rejection.Code != msgtemplate.CodeUnknownVariable || rejection.Line != 2 {
		t.Fatalf("rejection = %+v", rejection)
	}
	if strings.Contains(err.Error(), "LITERAL-7F3A") || strings.Contains(err.Error(), "Private wording") {
		t.Fatalf("error echoes the source: %v", err)
	}
	// Engine rules apply: builtins such as printf are refused.
	_, err = svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Bad", EventType: domain.EventIncidentCreated, Family: domain.FamilyPager, Locale: "en",
		Fields: map[string]string{"summary": `{{printf "%s" .title}}`}})
	if !errors.As(err, &rejection) || rejection.Code != msgtemplate.CodeForbiddenFunction {
		t.Fatalf("printf err = %v", err)
	}
	// Family fields are enforced before compiling.
	if _, err = svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Bad", EventType: domain.EventIncidentCreated, Family: domain.FamilyPager, Locale: "en",
		Fields: map[string]string{"body": "x"}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("wrong field err = %v", err)
	}
}

// A "*" template renders for every event of its family, so it may only use variables every event
// declares; the error names the first event that lacks one.
func TestWildcardTemplateValidatesAgainstEveryEvent(t *testing.T) {
	withTemplateCatalog(t)
	ctx := shared.WithTenant(context.Background(), "tenant")
	svc := templateService(t, &recordingAudit{})
	_, err := svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Any", EventType: domain.AnyEventType, Family: domain.FamilyChat, Locale: "*",
		Fields: map[string]string{"body": "{{.title}} ({{.engagement}})"}})
	var rejection *TemplateValidationError
	if !errors.As(err, &rejection) || rejection.EventType != domain.EventIncidentCreated || rejection.Code != msgtemplate.CodeUnknownVariable {
		t.Fatalf("wildcard with a scan-only variable err = %v", err)
	}
	if _, err = svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Any", EventType: domain.AnyEventType, Family: domain.FamilyChat, Locale: "*",
		Fields: map[string]string{"body": "{{.title}}"}}); err != nil {
		t.Fatalf("wildcard with a shared variable: %v", err)
	}
}

// The production catalog declares no template variables yet, so only literal text and literal
// function arguments compile until the event builders declare them.
func TestProductionCatalogAcceptsLiteralTemplatesOnly(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant")
	svc := templateService(t, &recordingAudit{})
	if _, err := svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Literal", EventType: domain.AnyEventType, Family: domain.FamilyChat, Locale: "en",
		Fields: map[string]string{"title": "Synapse alert", "body": `{{upper "heads up"}}: open Synapse for details.`}}); err != nil {
		t.Fatalf("literal template: %v", err)
	}
	for _, spec := range domain.EventCatalog() {
		if len(spec.Variables) > 0 {
			return // the catalog now declares variables; the unknown-variable case below no longer holds for every event
		}
	}
	_, err := svc.CreateTemplate(ctx, "ada", TemplateInput{Name: "Var", EventType: domain.EventScanCompleted, Family: domain.FamilyChat, Locale: "en",
		Fields: map[string]string{"body": "{{.title}}"}})
	var rejection *TemplateValidationError
	if !errors.As(err, &rejection) || rejection.Code != msgtemplate.CodeUnknownVariable {
		t.Fatalf("variable against the production catalog err = %v", err)
	}
}

func TestTemplateDiffNeverQuotesSource(t *testing.T) {
	cases := []struct {
		before, after map[string]string
		want          string
	}{
		{nil, map[string]string{"body": "a\nb"}, "body:+2/-0"},
		{map[string]string{"body": "a\nb"}, map[string]string{"body": "a\nc"}, "body:+1/-1"},
		{map[string]string{"body": "a", "title": "t"}, map[string]string{"body": "a"}, "title:+0/-1"},
		{map[string]string{"body": "a"}, map[string]string{"body": "a"}, "none"},
	}
	for _, tc := range cases {
		if got := templateDiff(tc.before, tc.after); got != tc.want {
			t.Fatalf("templateDiff(%v, %v) = %q, want %q", tc.before, tc.after, got, tc.want)
		}
	}
}
