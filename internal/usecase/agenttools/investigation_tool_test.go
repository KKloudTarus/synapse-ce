package agenttools

import (
	"context"
	"encoding/json"
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
