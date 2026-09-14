package agenttools

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
)

func TestProposeInvestigation(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeJudgmentProposer{}
	c.EnableJudgments(fp)

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

func TestProposeInvestigationDisabledFailsClosed(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder()) // no EnableJudgments
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeInvestigation {
			t.Fatal("propose_investigation must not be advertised without a judgment proposer")
		}
	}
	if _, err := c.Dispatch(context.Background(), session(), agent.ToolCall{Name: ToolProposeInvestigation, Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("dispatch must fail closed when judgments are disabled")
	}
}
