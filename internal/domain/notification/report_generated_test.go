package notification

import (
	"encoding/json"
	"testing"
	"time"
)

func TestReportGeneratedNavigationFactsDoNotChangeIdentityOrContext(t *testing.T) {
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	record, err := (ReportGenerated{
		TenantID: "tenant", Kind: ReportKindAssessmentCycle, ContentHash: "sealed-content", GeneratedAt: at,
		CycleID: "cycle-1", ProjectKey: "payments-api",
	}).ReportGeneratedRecord()
	if err != nil {
		t.Fatal(err)
	}
	if record.SourceKind != "report" || record.SourceID != "assessment_closure_report:sealed-content" || record.SubjectKind != "report" || record.SubjectID != "sealed-content" {
		t.Fatalf("identity changed: %+v", record)
	}
	var data map[string]any
	if err := json.Unmarshal(record.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["cycle_id"] != "cycle-1" || data["project_key"] != "payments-api" {
		t.Fatalf("navigation facts missing: %v", data)
	}
	context, err := DecodeTemplateContext(record.Context)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := context.Vars["cycle_id"]; ok {
		t.Fatalf("cycle_id leaked into template context: %v", context.Vars)
	}
	if _, ok := context.Vars["project_key"]; ok {
		t.Fatalf("project_key leaked into template context: %v", context.Vars)
	}
	spec, ok := LookupEvent(EventReportGenerated)
	if !ok {
		t.Fatal("report.generated event spec missing")
	}
	for _, class := range []DataClass{DataClassSignal, DataClassDetail} {
		filtered := context.Filter(spec, class)
		if _, ok := filtered.Vars["cycle_id"]; ok {
			t.Fatalf("cycle_id leaked into %s context: %v", class, filtered.Vars)
		}
		if _, ok := filtered.Vars["project_key"]; ok {
			t.Fatalf("project_key leaked into %s context: %v", class, filtered.Vars)
		}
	}
}
