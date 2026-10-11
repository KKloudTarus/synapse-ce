package notification

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
)

// identityOnly is a record as the capture trigger writes it since #1344 part 2, with the facts the
// poller read from the source row.
func identityOnly(t *testing.T, eventType domain.EventType, sourceID string, facts map[string]string) domain.Event {
	t.Helper()
	seed, err := domain.TemplateContext{Vars: facts}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return domain.Event{TenantID: "tenant-1", ID: "event", Type: eventType, SourceKind: "source", SourceID: sourceID, SchemaVersion: 1,
		OccurredAt: time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC), Data: json.RawMessage(`{}`), Context: seed}
}

func project(t *testing.T, e domain.Event) (map[string]any, map[string]string) {
	t.Helper()
	projected, err := NewEventBuilders().Project(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(projected.Data, &data); err != nil {
		t.Fatal(err)
	}
	snapshot, err := domain.DecodeTemplateContext(projected.Context)
	if err != nil {
		t.Fatal(err)
	}
	return data, snapshot.Vars
}

// TestCapturedDataMatchesTheOldTrigger pins the composed data to what migration 0163's trigger
// wrote for the same source row, so the webhook body does not change with the identity-only capture.
func TestCapturedDataMatchesTheOldTrigger(t *testing.T) {
	cases := []struct {
		event domain.Event
		want  map[string]any
	}{
		{identityOnly(t, domain.EventScanCompleted, "scan-1", map[string]string{"scan_id": "scan-1", "scan_kind": "sast", "scan_target": "https://git.example.test/repo.git", "engagement_name": "Q3 audit"}),
			map[string]any{"title": "Scan completed", "summary": "A scan completed successfully.", "scan_id": "scan-1", "scan_kind": "sast"}},
		{identityOnly(t, domain.EventQualityGateFailed, "analysis-1", map[string]string{"analysis_id": "analysis-1", "project_id": "project-1", "project_name": "Payments", "failed_conditions": "2"}),
			map[string]any{"title": "Quality gate failed", "summary": "A finalized project analysis failed its quality gate.", "analysis_id": "analysis-1", "project_id": "project-1"}},
		{identityOnly(t, domain.EventIncidentCreated, "incident-1", map[string]string{"incident_id": "incident-1", "asset_id": "", "incident_title": "Suspicious login"}),
			map[string]any{"title": "Suspicious login", "summary": "Fleet correlation created an incident.", "incident_id": "incident-1", "asset_id": ""}},
		// A source row deleted before projection yields no facts; the identity still names it.
		{identityOnly(t, domain.EventScanCompleted, "scan-gone", nil),
			map[string]any{"title": "Scan completed", "summary": "A scan completed successfully.", "scan_id": "scan-gone", "scan_kind": ""}},
	}
	for _, c := range cases {
		if got, _ := project(t, c.event); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s data = %v, want %v", c.event.Type, got, c.want)
		}
	}
}

func TestIncidentTitleFollowsTheTriggerRule(t *testing.T) {
	missing, _ := project(t, identityOnly(t, domain.EventIncidentCreated, "i", map[string]string{"incident_id": "i"}))
	if missing["title"] != "Security incident created" {
		t.Fatalf("an incident without a title = %q, want the generic one", missing["title"])
	}
	empty, _ := project(t, identityOnly(t, domain.EventIncidentCreated, "i", map[string]string{"incident_id": "i", "incident_title": ""}))
	if empty["title"] != "" {
		t.Fatalf("an empty title = %q, want it kept empty", empty["title"])
	}
	long, _ := project(t, identityOnly(t, domain.EventIncidentCreated, "i", map[string]string{"incident_id": "i", "incident_title": strings.Repeat("é", 600)}))
	if n := len([]rune(long["title"].(string))); n != maxIncidentTitleRunes {
		t.Fatalf("a long title kept %d runes, want %d", n, maxIncidentTitleRunes)
	}
}

// TestRecordedDataIsKept checks that a record captured before the identity-only trigger, which
// carries its data, is not recomposed.
func TestRecordedDataIsKept(t *testing.T) {
	e := identityOnly(t, domain.EventScanCompleted, "scan-1", map[string]string{"scan_kind": "dast"})
	e.Data = json.RawMessage(`{"title":"Scan completed","summary":"A scan completed successfully.","scan_id":"scan-1","scan_kind":"sast"}`)
	if data, _ := project(t, e); data["scan_kind"] != "sast" {
		t.Fatalf("recorded data was recomposed: %v", data)
	}
}

func TestSourceFactsBecomeVariables(t *testing.T) {
	_, vars := project(t, identityOnly(t, domain.EventScanCompleted, "scan-1", map[string]string{
		"scan_id": "scan-1", "scan_kind": "sast", "scan_target": "https://ci:s3cr3t@git.example.test/repo.git?token=abc#main", "engagement_name": "Q3 audit",
	}))
	want := map[string]string{"engagement_name": "Q3 audit", "target": "https://git.example.test/repo.git", "scan_kind": "sast"}
	for name, value := range want {
		if vars[name] != value {
			t.Errorf("%s = %q, want %q", name, vars[name], value)
		}
	}
	for _, leaked := range []string{"scan_target", "scan_id"} {
		if _, ok := vars[leaked]; ok {
			t.Errorf("fact %s reached the snapshot", leaked)
		}
	}

	_, vars = project(t, identityOnly(t, domain.EventQualityGateFailed, "a", map[string]string{"analysis_id": "a", "project_name": "Payments", "failed_conditions": "2"}))
	if vars["project_name"] != "Payments" || vars["failed_conditions"] != "2" {
		t.Fatalf("gate variables = %v", vars)
	}
}

func TestScanCompletedV2DataSuppliesCountVariables(t *testing.T) {
	e := identityOnly(t, domain.EventScanCompleted, "scan-1", nil)
	e.SchemaVersion = 2
	e.Data = json.RawMessage(`{"title":"Scan completed","summary":"A scan completed successfully.","scan_id":"scan-1","scan_kind":"sast","total_count":2,"critical_count":1,"high_count":1,"medium_count":0,"low_count":0,"info_count":0,"new_count":1,"fixed_count":0,"unchanged_count":1,"delta_available":true}`)
	_, vars := project(t, e)
	for name, want := range map[string]string{"total_count": "2", "critical_count": "1", "delta_available": "true"} {
		if vars[name] != want {
			t.Errorf("%s = %q, want %q", name, vars[name], want)
		}
	}
}

func TestDisplayTargetDropsCredentials(t *testing.T) {
	for target, want := range map[string]string{
		"https://ci:token@git.example.test/org/repo.git?ref=main#readme": "https://git.example.test/org/repo.git",
		"ssh://git@git.example.test:22/org/repo.git":                     "ssh://git.example.test:22/org/repo.git",
		"git@git.example.test:org/repo.git":                              "git.example.test:org/repo.git",
		"deploy:token@registry.example.test/app:1.2?x=y":                 "registry.example.test/app:1.2",
		"registry.example.test/app:1.2":                                  "registry.example.test/app:1.2",
		"/srv/uploads/archive.tar.gz":                                    "/srv/uploads/archive.tar.gz",
		"":                                                               "",
	} {
		if got := displayTarget(target); got != want {
			t.Errorf("displayTarget(%q) = %q, want %q", target, got, want)
		}
	}
}
