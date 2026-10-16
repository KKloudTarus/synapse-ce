package builtin

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
)

func TestDigestBuiltinsOmitEmptyItemSeverity(t *testing.T) {
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	context, err := (notification.TemplateContext{Vars: map[string]string{"title": "Engagement created"}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest, count, err := notification.BuildDigestContext([]notification.DigestItem{
		{Event: notification.Event{ID: "severity", Type: notification.EventFindingCreated, OccurredAt: at, Context: context, Severity: shared.SeverityHigh}},
		{Event: notification.Event{ID: "no-severity", Type: notification.EventEngagementCreated, OccurredAt: at.Add(time.Minute), Context: context}},
	}, notification.CadenceHourly, at, at.Add(time.Hour), notification.DataClassDetail)
	if err != nil || count != 2 {
		t.Fatalf("BuildDigestContext count=%d err=%v", count, err)
	}

	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		t.Run(string(locale), func(t *testing.T) {
			template, ok := New().Builtin(notification.EventDigest, notification.FamilyChat, locale)
			if !ok {
				t.Fatal("missing digest chat builtin")
			}
			rendered := renderDigestBody(t, template.Fields["body"], digest)
			if strings.Contains(rendered, "[]") {
				t.Fatalf("digest rendered empty severity brackets: %q", rendered)
			}
			if !strings.Contains(rendered, "[high]") {
				t.Fatalf("digest lost populated severity: %q", rendered)
			}
			if !strings.Contains(rendered, "engagement\\.created Engagement created") {
				t.Fatalf("digest lost no-severity row: %q", rendered)
			}
		})
	}
}

func renderDigestBody(t *testing.T, source string, context notification.TemplateContext) string {
	t.Helper()
	spec, ok := notification.LookupEvent(notification.EventDigest)
	if !ok {
		t.Fatal("missing digest event spec")
	}
	vars := make([]string, 0, len(spec.Variables))
	lists := make(map[string]msgtemplate.List)
	for _, variable := range spec.Variables {
		if variable.ListCap == 0 {
			vars = append(vars, variable.Name)
			continue
		}
		lists[variable.Name] = msgtemplate.List{Cap: variable.ListCap, Fields: variable.ItemFields}
	}
	schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: vars, Lists: lists})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := msgtemplate.Compile("digest", source, schema)
	if err != nil {
		t.Fatal(err)
	}
	out, err := compiled.Render(msgtemplate.Data{Vars: context.Vars, Lists: context.Lists}, msgtemplate.MaxOutputRunes)
	if err != nil {
		t.Fatal(err)
	}
	return out.Text
}
