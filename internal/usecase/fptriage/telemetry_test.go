package fptriage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type observedLLM struct {
	mu      sync.Mutex
	calls   int
	content string
	err     error
	usage   agent.Usage
}

func (l *observedLLM) Chat(context.Context, ports.ChatRequest) (ports.ChatResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return ports.ChatResponse{Content: l.content, Usage: l.usage}, l.err
}

func (l *observedLLM) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func TestObservedTriageEnforcesTokenBudgetBeforeProviderCall(t *testing.T) {
	llm := &observedLLM{content: `{"verdict":"sound","driver":"attacker_controlled","confidence":90}`}
	coord := New(llm, "model").WithOperationalPolicy(ports.FPTriageOperationalPolicy{MaxTokens: 1})
	critiques, telemetry := coord.assessPreparedObserved(context.Background(), prepareCandidatesForTest(2))
	if llm.count() != 0 || telemetry.RequestCount != 0 || telemetry.BudgetSkippedFindings != 2 {
		t.Fatalf("calls=%d telemetry=%+v", llm.count(), telemetry)
	}
	for _, critique := range critiques {
		if !errors.Is(critique.Err, errTriageBudgetExhausted) {
			t.Fatalf("critique error = %v, want budget exhaustion", critique.Err)
		}
	}
	if telemetry.ReservedTokens > telemetry.MaxTokens {
		t.Fatalf("reserved tokens %d exceeded max %d", telemetry.ReservedTokens, telemetry.MaxTokens)
	}
}

func TestObservedTriageFailsClosedWhenCostBudgetHasNoPricing(t *testing.T) {
	llm := &observedLLM{content: `{"verdict":"sound","driver":"attacker_controlled","confidence":90}`}
	coord := New(llm, "model").WithOperationalPolicy(ports.FPTriageOperationalPolicy{MaxTokens: 100_000, MaxCostMicroUSD: 100})
	_, telemetry := coord.assessPreparedObserved(context.Background(), prepareCandidatesForTest(1))
	if llm.count() != 0 || telemetry.BudgetSkippedFindings != 1 || telemetry.ReservedCostMicroUSD != 0 {
		t.Fatalf("unpriced cost budget was not fail-closed: calls=%d telemetry=%+v", llm.count(), telemetry)
	}
}

func TestObservedTriageRecordsUsageAndCostWithoutPromptContent(t *testing.T) {
	llm := &observedLLM{
		content: `{"verdict":"sound","driver":"attacker_controlled","confidence":90}`,
		usage:   agent.Usage{PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120},
	}
	coord := New(llm, "model").WithOperationalPolicy(ports.FPTriageOperationalPolicy{
		MaxTokens: 100_000, ProposerInputMicroUSDPerMillion: 1_000_000, ProposerOutputMicroUSDPerMillion: 2_000_000,
	})
	_, telemetry := coord.assessPreparedObserved(context.Background(), prepareCandidatesForTest(1))
	if telemetry.RequestCount != 1 || telemetry.SuccessCount != 1 || telemetry.UsedTokens != 120 || telemetry.EstimatedCostMicroUSD != 140 {
		t.Fatalf("telemetry = %+v", telemetry)
	}
	if len(telemetry.Calls) != 1 || telemetry.Calls[0].PromptTokens != 100 || telemetry.Calls[0].Outcome != "success" {
		t.Fatalf("call metric = %+v", telemetry.Calls)
	}
}

func TestProviderFailureOpensCircuitAndRemainingFindingStaysAdvisory(t *testing.T) {
	llm := &observedLLM{err: errors.New("provider unavailable")}
	coord := New(llm, "model").WithConcurrency(1).WithOperationalPolicy(ports.FPTriageOperationalPolicy{
		MaxTokens: 100_000, CircuitFailureThreshold: 1, CircuitCooldown: time.Hour,
	})
	critiques, telemetry := coord.assessPreparedObserved(context.Background(), prepareCandidatesForTest(2))
	if llm.count() != 1 || telemetry.ProviderFailureCount != 1 || telemetry.CircuitOpenCount != 1 {
		t.Fatalf("circuit telemetry = %+v, calls=%d", telemetry, llm.count())
	}
	for _, critique := range critiques {
		if critique.Err == nil || critique.VerifiedConsensus(1) {
			t.Fatalf("outage critique gained authority: %+v", critique)
		}
	}
}

func prepareCandidatesForTest(count int) []preparedFinding {
	out := make([]preparedFinding, count)
	for i := range out {
		out[i] = preparedFinding{finding: mkFinding(string(rune('a'+i)), "finding"), ready: true}
	}
	return out
}
