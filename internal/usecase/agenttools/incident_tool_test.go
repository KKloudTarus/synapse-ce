package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeIncidents is the narrow read slice the catalog needs. err is returned as-is so a test can
// separate a genuine failure from a not-found.
type fakeIncidents struct {
	byID map[shared.ID]incident.Incident
	err  error
}

func (f *fakeIncidents) Get(_ context.Context, id shared.ID) (incident.Incident, error) {
	if f.err != nil {
		return incident.Incident{}, f.err
	}
	inc, ok := f.byID[id]
	if !ok {
		return incident.Incident{}, shared.ErrNotFound
	}
	return inc, nil
}

func sessionIncident() incident.Incident {
	at := time.Unix(1_700_000_000, 0).UTC()
	return incident.Incident{
		ID: "inc-1", AssetID: "asset-1", EngagementID: "eng-1",
		Title: "suspicious outbound burst", Severity: shared.SeverityHigh,
		State: incident.StateOpen, DetectionIDs: []shared.ID{"det-1", "det-2"},
		Timeline: []incident.TimelineRef{
			{EventID: "ev-1", OccurredAt: at, Kind: "detection", Summary: "egress to 203.0.113.9"},
		},
		Comments: []incident.Comment{{At: at, Actor: "alice", Text: "looks like exfiltration to me"}},
	}
}

func readIncident(t *testing.T, c *Catalog, id string) map[string]any {
	t.Helper()
	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name: ToolGetIncidentDetail, Arguments: json.RawMessage(`{"incident_id":"` + id + `"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return out
}

func TestGetIncidentDetailReturnsTheSessionIncident(t *testing.T) {
	c, audit := newCatalog(t, nil, nil, subfinder())
	c.EnableIncidentReads(&fakeIncidents{byID: map[shared.ID]incident.Incident{"inc-1": sessionIncident()}})

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolGetIncidentDetail {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("get_incident_detail has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("get_incident_detail must be advertised after EnableIncidentReads")
	}

	out := readIncident(t, c, "inc-1")
	if out["id"] != "inc-1" || out["title"] != "suspicious outbound burst" || out["severity"] != "high" {
		t.Fatalf("incident detail wrong: %+v", out)
	}
	if n := len(out["detection_ids"].([]any)); n != 2 {
		t.Fatalf("detection_ids = %d, want 2", n)
	}
	if n := len(out["timeline"].([]any)); n != 1 {
		t.Fatalf("timeline entries = %d, want 1", n)
	}
	// Analyst comments are counted, never returned: handing the model a human's conclusion would let it
	// propose that conclusion back as its own hypothesis.
	if out["comment_count"] != float64(1) {
		t.Errorf("comment_count = %v, want 1", out["comment_count"])
	}
	if strings.Contains(string(mustJSON(t, out)), "looks like exfiltration") {
		t.Error("analyst comment text leaked into the agent payload")
	}
	if _, present := out["risk"]; present {
		t.Error("the risk assessment must not be returned")
	}
	if len(audit.recs) == 0 || audit.recs[len(audit.recs)-1].Action != "agent.read.incident_detail" {
		t.Errorf("read was not audited: %+v", audit.recs)
	}
}

// TestGetIncidentDetailRefusesOutOfScopeIncidents is the engagement guard. get_finding_detail gets this
// for free by listing the engagement's own findings; the incident store has no engagement listing, so the
// tool fetches by id and refuses anything it cannot prove is in scope — including an incident carrying no
// engagement id, which incident.IncidentEvent documents as possible for legacy rows.
//
// All three refusals must be INDISTINGUISHABLE from a miss, so the tool cannot be used to test whether an
// id exists in another engagement.
func TestGetIncidentDetailRefusesOutOfScopeIncidents(t *testing.T) {
	other := sessionIncident()
	other.ID, other.EngagementID = "inc-other", "eng-2"
	legacy := sessionIncident()
	legacy.ID, legacy.EngagementID = "inc-legacy", ""

	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableIncidentReads(&fakeIncidents{byID: map[shared.ID]incident.Incident{
		"inc-other": other, "inc-legacy": legacy,
	}})

	for _, id := range []string{"inc-other", "inc-legacy", "inc-does-not-exist"} {
		t.Run(id, func(t *testing.T) {
			out := readIncident(t, c, id)
			if out["found"] != false {
				t.Fatalf("%s must read as not found, got %+v", id, out)
			}
			if _, leaked := out["title"]; leaked {
				t.Fatalf("%s leaked incident content: %+v", id, out)
			}
		})
	}
}

// A real store failure must never be reported as a miss: "not found" would tell the agent the incident
// does not exist when the truth is that nobody could look.
func TestGetIncidentDetailPropagatesRealFailures(t *testing.T) {
	boom := errors.New("incident store unavailable")
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableIncidentReads(&fakeIncidents{err: boom})

	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name: ToolGetIncidentDetail, Arguments: json.RawMessage(`{"incident_id":"inc-1"}`),
	}); !errors.Is(err, boom) {
		t.Fatalf("store failure must propagate, got %v", err)
	}
}

func TestGetIncidentDetailDisabledFailsClosed(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder()) // no EnableIncidentReads
	for _, ts := range c.Tools() {
		if ts.Name == ToolGetIncidentDetail {
			t.Fatal("get_incident_detail must not be advertised without an incident reader")
		}
	}
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name: ToolGetIncidentDetail, Arguments: json.RawMessage(`{"incident_id":"inc-1"}`),
	}); err == nil {
		t.Fatal("dispatch must fail closed when incident reads are disabled")
	}
}

func TestGetIncidentDetailValidatesArguments(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableIncidentReads(&fakeIncidents{byID: map[shared.ID]incident.Incident{"inc-1": sessionIncident()}})
	for name, args := range map[string]string{
		"not an object": `"inc-1"`,
		"empty id":      `{"incident_id":"   "}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
				Name: ToolGetIncidentDetail, Arguments: json.RawMessage(args),
			}); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
