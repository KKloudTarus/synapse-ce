package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeProposer records the proposer + returns a score-0 exploitation finding (mirrors the real
// exploitation.Service.Propose contract). It deliberately has NO score/verify/confirm method.
type fakeProposer struct {
	proposer string
	in       finding.ExploitationInput
}

func (f *fakeProposer) Propose(_ context.Context, proposer string, eng shared.ID, in finding.ExploitationInput) (finding.Finding, error) {
	f.proposer, f.in = proposer, in
	return finding.NewExploitation("find-1", eng, in, proposer, time.Unix(1, 0).UTC())
}

func TestProposeFinding_DisabledByDefault(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeFinding {
			t.Fatal("propose_finding must NOT be advertised without EnableFindingProposals")
		}
	}
	_, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeFinding, Arguments: json.RawMessage(`{}`)})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("disabled propose_finding must error, got %v", err)
	}
}

// TestProposeFinding_RecordsUnprovenClaim: the agent records a score-0, agent-attributed,
// NON-promotable finding; the catalog exposes no way to raise the score or confirm it.
func TestProposeFinding_RecordsUnprovenClaim(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	fp := &fakeProposer{}
	c.EnableFindingProposals(fp)

	advertised := false
	for _, ts := range c.Tools() {
		if ts.Name == ToolProposeFinding {
			advertised = true
		}
	}
	if !advertised {
		t.Fatal("propose_finding must be advertised after EnableFindingProposals")
	}

	args := json.RawMessage(`{"title":"SSRF in metadata endpoint","description":"reachable","severity":"high","cwe":"CWE-918"}`)
	res, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeFinding, Arguments: args})
	if err != nil {
		t.Fatalf("propose_finding: %v", err)
	}
	if res.Proposal != nil || res.Plan != nil || res.Data == nil {
		t.Fatal("propose_finding must return only Data (a recorded claim)")
	}
	// Attributed to the agent session, not a human.
	if fp.proposer != "agent:s1" {
		t.Fatalf("proposer = %q, want agent:s1", fp.proposer)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatal(err)
	}
	if out["evidence_score"].(float64) != 0 || out["can_promote"].(bool) != false {
		t.Fatalf("a proposed finding must be score 0 + not promotable, got %v", out)
	}
	if out["proposed_by"].(string) != "agent:s1" {
		t.Fatalf("proposed_by = %v, want agent:s1", out["proposed_by"])
	}
}

func TestProposeFindingSchemaLeavesAssetIDConditional(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableFindingProposals(&fakeProposer{})
	for _, schema := range c.Tools() {
		if schema.Name != ToolProposeFinding {
			continue
		}
		var parameters struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(schema.Parameters, &parameters); err != nil {
			t.Fatal(err)
		}
		for _, required := range parameters.Required {
			if required == "asset_id" {
				t.Fatal("asset_id must remain conditional on attribution configuration")
			}
		}
		return
	}
	t.Fatal("propose_finding schema not advertised")
}

func TestProposeFinding_RejectsBadSeverity(t *testing.T) {
	c, _ := newCatalog(t, nil, nil, subfinder())
	c.EnableFindingProposals(&fakeProposer{})
	_, err := c.Dispatch(context.Background(), planSession(), agent.ToolCall{Name: ToolProposeFinding, Arguments: json.RawMessage(`{"title":"x","description":"y","severity":"bogus"}`)})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("invalid severity must be rejected, got %v", err)
	}
}
