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

func TestCatalogVersionsChangedScanPagerAssetsIndependently(t *testing.T) {
	catalog := New()
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		template, ok := catalog.Builtin(notification.EventScanCompleted, notification.FamilyPager, locale)
		if !ok || !strings.HasSuffix(template.Ref, "@v2") {
			t.Fatalf("scan pager %s ref=%q, want v2", locale, template.Ref)
		}
	}
	for _, tc := range []struct {
		event  notification.EventType
		family notification.TemplateFamily
		locale tenancy.Locale
	}{
		{event: notification.EventScanCompleted, family: notification.FamilyChat, locale: tenancy.LocaleEnglish},
		{event: notification.EventIncidentCreated, family: notification.FamilyPager, locale: tenancy.LocaleVietnamese},
		{event: notification.EventEvidenceChainBroken, family: notification.FamilyPager, locale: tenancy.LocaleEnglish},
	} {
		template, ok := catalog.Builtin(tc.event, tc.family, tc.locale)
		if !ok || !strings.HasSuffix(template.Ref, "@v1") {
			t.Fatalf("unchanged %s/%s/%s ref=%q, want v1", tc.event, tc.family, tc.locale, template.Ref)
		}
	}
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, family := range []notification.TemplateFamily{notification.FamilyChat, notification.FamilyEmail, notification.FamilyPager} {
			template, ok := catalog.Builtin(notification.EventReportGenerated, family, locale)
			if !ok || !strings.HasSuffix(template.Ref, "@v2") {
				t.Fatalf("report generated %s/%s ref=%q, want v2", family, locale, template.Ref)
			}
		}
	}
}

func TestReportGeneratedBuiltinsOmitAbsentFactsAndKeepKnownValues(t *testing.T) {
	testCases := []struct {
		name         string
		severity     string
		findingCount int
		wantSeverity string
		wantFindings string
	}{
		{name: "absent", findingCount: -1},
		{name: "zero", severity: "low", findingCount: 0, wantSeverity: "low", wantFindings: "0"},
		{name: "present", severity: "high", findingCount: 12, wantSeverity: "high", wantFindings: "12"},
	}
	families := []struct {
		family notification.TemplateFamily
		field  string
	}{
		{family: notification.FamilyChat, field: "body"},
		{family: notification.FamilyEmail, field: "body"},
		{family: notification.FamilyPager, field: "summary"},
	}
	for _, locale := range []tenancy.Locale{tenancy.LocaleEnglish, tenancy.LocaleVietnamese} {
		for _, family := range families {
			for _, tc := range testCases {
				t.Run(string(locale)+"/"+string(family.family)+"/"+tc.name, func(t *testing.T) {
					rendered := renderReportGeneratedField(t, locale, family.family, family.field, tc.severity, tc.findingCount)
					severityLabel, findingsLabel := "Severity:", "Findings:"
					if locale == tenancy.LocaleVietnamese {
						severityLabel, findingsLabel = "Mức độ:", "Số phát hiện:"
					}
					if tc.wantSeverity == "" {
						if strings.Contains(rendered, severityLabel) {
							t.Fatalf("rendered absent severity label: %q", rendered)
						}
					} else if !strings.Contains(rendered, severityLabel+" "+tc.wantSeverity) {
						t.Fatalf("rendered=%q, want severity %q", rendered, tc.wantSeverity)
					}
					if tc.wantFindings == "" {
						if strings.Contains(rendered, findingsLabel) {
							t.Fatalf("rendered absent findings label: %q", rendered)
						}
					} else if !strings.Contains(rendered, findingsLabel+" "+tc.wantFindings) {
						t.Fatalf("rendered=%q, want findings %q", rendered, tc.wantFindings)
					}
				})
			}
		}
	}
}

func renderReportGeneratedField(t *testing.T, locale tenancy.Locale, family notification.TemplateFamily, field, severity string, findingCount int) string {
	t.Helper()
	record, err := (notification.ReportGenerated{
		TenantID: "tenant", Kind: notification.ReportKindProjectQuality, ContentHash: "sealed-content",
		GeneratedAt: time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC), Severity: shared.Severity(severity), FindingCount: findingCount,
	}).ReportGeneratedRecord()
	if err != nil {
		t.Fatal(err)
	}
	context, err := notification.DecodeTemplateContext(record.Context)
	if err != nil {
		t.Fatal(err)
	}
	spec, ok := notification.LookupEvent(notification.EventReportGenerated)
	if !ok {
		t.Fatal("report.generated event spec missing")
	}
	template, ok := New().Builtin(notification.EventReportGenerated, family, locale)
	if !ok {
		t.Fatalf("missing report.generated template for %s/%s", family, locale)
	}
	schema, err := msgtemplate.NewSchema(msgtemplate.SchemaSpec{Vars: eventVariables(spec)})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := msgtemplate.Compile("report-generated", template.Fields[field], schema)
	if err != nil {
		t.Fatal(err)
	}
	out, err := compiled.Render(msgtemplate.Data{Vars: context.Filter(spec, notification.DataClassSignal).Vars}, msgtemplate.MaxOutputRunes)
	if err != nil {
		t.Fatal(err)
	}
	return out.Text
}

func eventVariables(spec notification.EventSpec) []string {
	vars := make([]string, 0, len(spec.Variables))
	for _, variable := range spec.Variables {
		if variable.ListCap == 0 {
			vars = append(vars, variable.Name)
		}
	}
	return vars
}
