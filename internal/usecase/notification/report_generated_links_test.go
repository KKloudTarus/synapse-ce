package notification

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

func TestReportGeneratedLinksUseTypedNavigationFacts(t *testing.T) {
	builder, err := consolelink.NewBuilder("https://console.example.test/prefix")
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{}
	service.SetConsoleLinkBuilder(builder)
	for _, tc := range []struct {
		name  string
		event domain.Event
		want  string
	}{
		{"engagement", domain.Event{Type: domain.EventReportGenerated, EngagementID: "eng-1", Data: json.RawMessage(`{"report_kind":"engagement_report"}`)}, "https://console.example.test/prefix/engagements/eng-1"},
		{"assessment cycle", domain.Event{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"assessment_closure_report","cycle_id":"cycle-1"}`)}, "https://console.example.test/prefix/assessment-cycles/cycle-1"},
		{"project", domain.Event{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"project_quality_summary","project_key":"payments-api"}`)}, "https://console.example.test/prefix/code-quality/projects/payments-api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links := service.renderLinks(tc.event)
			if len(links) != 1 || links[0].Label != "Open report" || links[0].URL != tc.want {
				t.Fatalf("links=%+v", links)
			}
		})
	}
}

func TestReportGeneratedLinksRejectMissingAndHostileNavigationFacts(t *testing.T) {
	builder, err := consolelink.NewBuilder("https://console.example.test/prefix")
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{}
	service.SetConsoleLinkBuilder(builder)
	for _, event := range []domain.Event{
		{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"engagement_report"}`)},
		{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"assessment_closure_report"}`)},
		{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"project_quality_summary"}`)},
		{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"unknown","cycle_id":"cycle"}`)},
		{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"assessment_closure_report","cycle_id":".."}`)},
		{Type: domain.EventReportGenerated, Data: json.RawMessage(`{"report_kind":"project_quality_summary","project_key":".."}`)},
	} {
		if links := service.renderLinks(event); len(links) != 0 {
			t.Fatalf("invalid navigation produced links=%+v", links)
		}
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"report_kind":"assessment_closure_report","cycle_id":"//evil.example/.."}`),
		json.RawMessage(`{"report_kind":"project_quality_summary","project_key":"../../evil"}`),
	} {
		links := service.renderLinks(domain.Event{Type: domain.EventReportGenerated, Data: raw})
		if len(links) != 1 {
			t.Fatalf("safe escaped link missing for %s: %+v", raw, links)
		}
		parsed, err := url.Parse(links[0].URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "console.example.test" || parsed.Path == "/evil" {
			t.Fatalf("navigation escaped trusted origin/path: url=%q parsed=%+v err=%v", links[0].URL, parsed, err)
		}
	}
}
