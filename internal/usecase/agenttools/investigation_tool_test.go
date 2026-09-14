package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// inc7 is the incident the happy paths bind a hypothesis to; it lives in the session's engagement.
func inc7() *fakeIncidents {
	inc := sessionIncident()
	inc.ID = "inc-7"
	return &fakeIncidents{byID: map[shared.ID]incident.Incident{"inc-7": inc}}
}

func TestProposeInvestigation(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)
	c.EnableIncidentReads(inc7())

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeInvestigation {
			advertised = true
			if !json.Valid(ts.Parameters) {
				t.Error("propose_investigation has invalid JSON-schema parameters")
			}
		}
	}
	if !advertised {
		t.Fatal("propose_investigation must be advertised after EnableJudgments")
	}

	res, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeInvestigation,
		Arguments: json.RawMessage(`{"incident_id":"inc-7","tactic":"lateral_movement","confidence":72,"drivers":["new_exec_paths","network_fanout_spike"]}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if res.Data == nil {
		t.Fatal("must return Data")
	}
	// PROPOSED, score 0, agent-attributed, scoped to the incident, ungated capability.
	if fp.got.EvidenceScore != 0 || fp.got.State != judgment.StateProposed || fp.got.ProposedBy != "agent:s1" {
		t.Fatalf("must record proposed/score-0/agent: %+v", fp.got)
	}
	if fp.got.Capability != judgment.CapInvestigation || fp.got.SubjectKind != judgment.SubjectIncident || fp.got.SubjectID != "inc-7" || fp.got.EngagementID != "eng-1" {
		t.Fatalf("subject/scope wiring wrong: %+v", fp.got)
	}
	ic, ok := fp.got.Claim.(judgment.InvestigationClaim)
	if !ok || ic.Tactic != judgment.TacticLateralMovement || ic.Confidence != 72 || len(ic.Drivers) != 2 {
		t.Fatalf("claim built wrong: %#v", fp.got.Claim)
	}
}

// TestProposeInvestigationRequiresSupportingDrivers pins the two halves together: the advertised schema
// must ask for drivers, and the domain must refuse a hypothesis without them. A schema that leaves the
// supporting signals optional invites the model to send exactly what Validate rejects.
func TestProposeInvestigationRequiresSupportingDrivers(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)
	c.EnableIncidentReads(inc7())

	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			Drivers struct {
				MinItems int `json:"minItems"`
			} `json:"drivers"`
		} `json:"properties"`
	}
	for _, ts := range c.Tools() {
		if ts.Name != ToolProposeInvestigation {
			continue
		}
		if err := json.Unmarshal(ts.Parameters, &schema); err != nil {
			t.Fatalf("decode advertised schema: %v", err)
		}
	}
	if !slices.Contains(schema.Required, "drivers") {
		t.Errorf("advertised schema must require drivers, got required=%v", schema.Required)
	}
	if schema.Properties.Drivers.MinItems != 1 {
		t.Errorf("advertised drivers minItems = %d, want 1", schema.Properties.Drivers.MinItems)
	}

	for name, args := range map[string]string{
		"omitted": `{"incident_id":"inc-7","tactic":"data_exfiltration","confidence":95}`,
		"empty":   `{"incident_id":"inc-7","tactic":"data_exfiltration","confidence":95,"drivers":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			fp.got = judgment.Judgment{}
			if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
				Name: ToolProposeInvestigation, Arguments: json.RawMessage(args),
			}); err == nil {
				t.Fatal("a hypothesis with no supporting driver was accepted")
			}
			if fp.got.Capability != "" {
				t.Fatalf("a rejected hypothesis still reached the proposer: %+v", fp.got)
			}
		})
	}
}

// TestProposeInvestigationRefusesOutOfScopeIncidents is the propose-side twin of the get_incident_detail
// scope test: a hypothesis may only bind to an incident the session can read. The judgment would be stored
// under the session's engagement either way, but a SubjectIncident pointing into another engagement would
// sit in the record until a consumer dereferenced it, so it is refused at the boundary — and absent,
// other-engagement, and no-engagement-id are refused identically so the tool cannot probe for ids.
func TestProposeInvestigationRefusesOutOfScopeIncidents(t *testing.T) {
	other := sessionIncident()
	other.ID, other.EngagementID = "inc-other", "eng-2"
	legacy := sessionIncident()
	legacy.ID, legacy.EngagementID = "inc-legacy", ""

	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)
	c.EnableIncidentReads(&fakeIncidents{byID: map[shared.ID]incident.Incident{"inc-other": other, "inc-legacy": legacy}})

	var msgs []string
	for _, id := range []string{"inc-other", "inc-legacy", "inc-does-not-exist"} {
		t.Run(id, func(t *testing.T) {
			fp.got = judgment.Judgment{}
			_, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
				Name:      ToolProposeInvestigation,
				Arguments: json.RawMessage(`{"incident_id":"` + id + `","tactic":"lateral_movement","confidence":70,"drivers":["new_exec_paths"]}`),
			})
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s: want ErrValidation, got %v", id, err)
			}
			if fp.got.Capability != "" {
				t.Fatalf("%s: a hypothesis was bound to an incident outside the session engagement: %+v", id, fp.got)
			}
			msgs = append(msgs, err.Error())
		})
	}
	for _, m := range msgs[1:] {
		if m != msgs[0] {
			t.Fatalf("refusals must be indistinguishable, got %q vs %q", msgs[0], m)
		}
	}

	// An engagement-less session must not bind to a legacy incident that carries no engagement either:
	// "" == "" is exactly the match the IsZero guard refuses.
	fp.got = judgment.Judgment{}
	if _, err := c.Dispatch(context.Background(), agent.Session{ID: "s0", InitiatedBy: "alice"}, agent.ToolCall{
		Name:      ToolProposeInvestigation,
		Arguments: json.RawMessage(`{"incident_id":"inc-legacy","tactic":"lateral_movement","confidence":70,"drivers":["new_exec_paths"]}`),
	}); !errors.Is(err, shared.ErrValidation) || fp.got.Capability != "" {
		t.Fatalf("an engagement-less session bound a hypothesis to a legacy incident: err=%v got=%+v", err, fp.got)
	}

	// A real store failure is a failure, not a scope miss.
	boom := errors.New("incident store unavailable")
	c2, _ := newCatalog(t, nil, nil, subfinder())
	c2.EnableJudgments(&fakeJudgmentProposer{})
	c2.EnableIncidentReads(&fakeIncidents{err: boom})
	if _, err := c2.Dispatch(context.Background(), session(), agent.ToolCall{
		Name:      ToolProposeInvestigation,
		Arguments: json.RawMessage(`{"incident_id":"inc-7","tactic":"lateral_movement","confidence":70,"drivers":["new_exec_paths"]}`),
	}); !errors.Is(err, boom) {
		t.Fatalf("store failure must propagate, got %v", err)
	}
}

// TestProposeInvestigationDisabledFailsClosed: the tool needs BOTH a judgment proposer and an incident
// reader. A catalog that can propose but not read must not offer to bind a hypothesis to an incident it
// could never have looked at.
func TestProposeInvestigationDisabledFailsClosed(t *testing.T) {
	for name, wire := range map[string]func(*Catalog){
		"neither":        func(*Catalog) {},
		"judgments only": func(c *Catalog) { c.EnableJudgments(&fakeJudgmentProposer{}) },
		"incidents only": func(c *Catalog) { c.EnableIncidentReads(inc7()) },
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := newCatalog(t, nil, nil, subfinder())
			wire(c)
			for _, ts := range c.Tools() {
				if ts.Name == ToolProposeInvestigation {
					t.Fatal("propose_investigation must not be advertised without both a judgment proposer and an incident reader")
				}
			}
			if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{
				Name:      ToolProposeInvestigation,
				Arguments: json.RawMessage(`{"incident_id":"inc-7","tactic":"lateral_movement","confidence":70,"drivers":["new_exec_paths"]}`),
			}); err == nil {
				t.Fatal("dispatch must fail closed")
			}
		})
	}
}
