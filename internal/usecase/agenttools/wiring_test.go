package agenttools

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// toolNames collects the set of advertised tool names.
func toolNames(c *Catalog) map[string]bool {
	m := make(map[string]bool)
	for _, t := range c.Tools() {
		m[t.Name] = true
	}
	return m
}

func fullToolset() AgentToolset {
	return AgentToolset{
		Findings:      &fakeProposer{},
		Hypotheses:    &fakeHypProposer{},
		Reachability:  &fakeScanResults{},
		Judgments:     &fakeJudgmentProposer{},
		WriteupDrafts: &fakeWriteupdraftProposer{},
	}
}

// toolsetControlled is the EXACT set of tools EnableAgentToolset switches on beyond the always-present
// read tools. It is the parity contract: both composition roots (synapse-api inline + synapse-worker
// durable) enable their catalog through EnableAgentToolset, so both advertise these — and only these —
// extra tools. A new Enable* added to the helper without updating this list fails the "no extras" check.
var toolsetControlled = []string{
	ToolProposePlan,
	ToolProposeFinding,
	ToolProposeAttackChain,
	ToolReachabilityContext,
	ToolProposeReachability,
	ToolProposeSASTValidation,
	ToolProposeCritique,
	ToolProposeRiskNarrative,
	ToolProposeThreat,
	ToolProposeVexJustification,
	ToolProposeWriteupDraft,
}

// TestEnableAgentToolsetEnablesFullSet locks the durable/inline parity guarantee: a FULL dependency set
// advertises exactly the always-on read tools PLUS the controlled set — no more, no less. Because both
// binaries call this one helper, this assertion pins that they advertise an identical tool set.
func TestEnableAgentToolsetEnablesFullSet(t *testing.T) {
	bare, _ := newCatalog(t, nil, nil)
	base := toolNames(bare)

	c, _ := newCatalog(t, nil, nil)
	if err := c.EnableAgentToolset(fullToolset()); err != nil {
		t.Fatalf("EnableAgentToolset(full): %v", err)
	}
	full := toolNames(c)

	controlled := make(map[string]bool, len(toolsetControlled))
	for _, name := range toolsetControlled {
		controlled[name] = true
		if base[name] {
			t.Errorf("base catalog unexpectedly already advertises %q", name)
		}
		if !full[name] {
			t.Errorf("full toolset is missing controlled tool %q", name)
		}
	}
	// No tool beyond the base read tools + the controlled set may appear — a new Enable* wired into the
	// helper must be reflected here (and thus in BOTH binaries), never silently on one side only.
	for name := range full {
		if !base[name] && !controlled[name] {
			t.Errorf("EnableAgentToolset added an unexpected tool %q (update toolsetControlled + both cmds)", name)
		}
	}
}

// TestEnableAgentToolsetOptionalOff proves the optional deps (judgments, writeup drafts) gate their tools:
// nil ⇒ off, so a binary with the feature flag off advertises the same reduced set as any other.
func TestEnableAgentToolsetOptionalOff(t *testing.T) {
	c, _ := newCatalog(t, nil, nil)
	if err := c.EnableAgentToolset(AgentToolset{
		Findings:     &fakeProposer{},
		Hypotheses:   &fakeHypProposer{},
		Reachability: &fakeScanResults{},
	}); err != nil {
		t.Fatalf("EnableAgentToolset(required-only): %v", err)
	}
	names := toolNames(c)

	for _, n := range []string{ToolProposePlan, ToolProposeFinding, ToolProposeAttackChain, ToolReachabilityContext} {
		if !names[n] {
			t.Errorf("required tool %q missing", n)
		}
	}
	for _, n := range []string{
		ToolProposeReachability, ToolProposeSASTValidation, ToolProposeCritique,
		ToolProposeRiskNarrative, ToolProposeThreat, ToolProposeVexJustification, ToolProposeWriteupDraft,
	} {
		if names[n] {
			t.Errorf("optional tool %q must be OFF when its dependency is nil", n)
		}
	}
}

// TestEnableAgentToolsetFailsClosed proves a missing REQUIRED dependency returns ErrValidation and enables
// NOTHING — the durable worker fails closed rather than advertising a partial toolset (the #161 defect).
func TestEnableAgentToolsetFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		ts   AgentToolset
	}{
		{"no findings", AgentToolset{Hypotheses: &fakeHypProposer{}, Reachability: &fakeScanResults{}}},
		{"no hypotheses", AgentToolset{Findings: &fakeProposer{}, Reachability: &fakeScanResults{}}},
		{"no reachability", AgentToolset{Findings: &fakeProposer{}, Hypotheses: &fakeHypProposer{}}},
		{"empty", AgentToolset{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newCatalog(t, nil, nil)
			before := len(toolNames(c))
			err := c.EnableAgentToolset(tc.ts)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
			if after := len(toolNames(c)); after != before {
				t.Errorf("fail-closed violated: advertised tool count changed %d → %d after a rejected wiring", before, after)
			}
		})
	}
}
