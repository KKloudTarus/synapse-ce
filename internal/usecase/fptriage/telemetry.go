package fptriage

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultMaxTriageTokens     int64 = 1_000_000
	defaultCircuitFailures           = 5
	defaultCircuitCooldown           = time.Minute
	requestFramingTokenCeiling int64 = 4096
)

var (
	errTriageBudgetExhausted = errors.New("AI triage request budget exhausted")
	errTriageCircuitOpen     = errors.New("AI triage provider circuit open")
)

func normalizeOperationalPolicy(p ports.FPTriageOperationalPolicy) ports.FPTriageOperationalPolicy {
	if p.MaxTokens <= 0 {
		p.MaxTokens = defaultMaxTriageTokens
	}
	if p.MaxCostMicroUSD < 0 {
		p.MaxCostMicroUSD = 0
	}
	if p.CircuitFailureThreshold < 1 {
		p.CircuitFailureThreshold = defaultCircuitFailures
	}
	if p.CircuitCooldown <= 0 {
		p.CircuitCooldown = defaultCircuitCooldown
	}
	return p
}

type requestPrice struct {
	inputMicroUSDPerMillion  int64
	outputMicroUSDPerMillion int64
}

type requestReservation struct {
	tokens int64
	cost   int64
}

type runBudget struct {
	policy       ports.FPTriageOperationalPolicy
	reserved     int64
	reservedCost int64
}

func newRunBudget(policy ports.FPTriageOperationalPolicy) *runBudget {
	return &runBudget{policy: normalizeOperationalPolicy(policy)}
}

// reservePair is called in deterministic candidate order before workers start. A verifier is never
// contacted unless the same reservation also admits the proposer, avoiding partial consensus work.
func (b *runBudget) reservePair(reqs ...pricedRequest) bool {
	var reservation requestReservation
	for _, req := range reqs {
		r := reserveRequest(req.request, req.price)
		reservation.tokens += r.tokens
		reservation.cost += r.cost
	}
	if b.reserved+reservation.tokens > b.policy.MaxTokens {
		return false
	}
	if b.policy.MaxCostMicroUSD > 0 {
		for _, req := range reqs {
			if req.price.inputMicroUSDPerMillion <= 0 || req.price.outputMicroUSDPerMillion <= 0 {
				return false
			}
		}
		if b.reservedCost+reservation.cost > b.policy.MaxCostMicroUSD {
			return false
		}
	}
	b.reserved += reservation.tokens
	b.reservedCost += reservation.cost
	return true
}

type pricedRequest struct {
	request ports.ChatRequest
	price   requestPrice
}

func reserveRequest(req ports.ChatRequest, price requestPrice) requestReservation {
	input := requestFramingTokenCeiling + int64(len(req.ResponseSchema))
	for _, message := range req.Messages {
		input += int64(len(message.Role) + len(message.Content))
	}
	for _, tool := range req.Tools {
		input += int64(len(tool.Name) + len(tool.Description) + len(tool.Parameters))
	}
	output := int64(req.MaxTokens)
	if output < 0 {
		output = 0
	}
	return requestReservation{
		tokens: input + output,
		cost:   microUSDCeiling(input, price.inputMicroUSDPerMillion) + microUSDCeiling(output, price.outputMicroUSDPerMillion),
	}
}

func microUSDCeiling(tokens, rate int64) int64 {
	if tokens <= 0 || rate <= 0 {
		return 0
	}
	return (tokens*rate + 999_999) / 1_000_000
}

type runObserver struct {
	mu        sync.Mutex
	telemetry ports.FPTriageTelemetry
}

func newRunObserver(b *runBudget) *runObserver {
	return &runObserver{telemetry: ports.FPTriageTelemetry{
		MaxTokens:            b.policy.MaxTokens,
		MaxCostMicroUSD:      b.policy.MaxCostMicroUSD,
		ReservedTokens:       b.reserved,
		ReservedCostMicroUSD: b.reservedCost,
	}}
}

func (o *runObserver) record(metric ports.FPTriageCallMetric) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.telemetry.Calls = append(o.telemetry.Calls, metric)
	switch metric.Outcome {
	case "success":
		o.telemetry.RequestCount++
		o.telemetry.SuccessCount++
	case "timeout":
		o.telemetry.RequestCount++
		o.telemetry.TimeoutCount++
	case "parse_failure":
		o.telemetry.RequestCount++
		o.telemetry.ParseFailureCount++
	case "provider_error":
		o.telemetry.RequestCount++
		o.telemetry.ProviderFailureCount++
	case "circuit_open":
		o.telemetry.CircuitOpenCount++
	}
	o.telemetry.UsedTokens += int64(metric.TotalTokens)
	o.telemetry.EstimatedCostMicroUSD += metric.EstimatedCostMicroUSD
}

func (o *runObserver) snapshot() ports.FPTriageTelemetry {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := o.telemetry
	result.Calls = append([]ports.FPTriageCallMetric(nil), result.Calls...)
	sort.SliceStable(result.Calls, func(i, j int) bool {
		if result.Calls[i].DedupKey != result.Calls[j].DedupKey {
			return result.Calls[i].DedupKey < result.Calls[j].DedupKey
		}
		return result.Calls[i].Role < result.Calls[j].Role
	})
	return result
}

type circuitBreaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openedAt  time.Time
	probe     bool
	now       func() time.Time
}

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	if threshold < 1 {
		threshold = defaultCircuitFailures
	}
	if cooldown <= 0 {
		cooldown = defaultCircuitCooldown
	}
	return &circuitBreaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

func (b *circuitBreaker) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openedAt.IsZero() {
		return true
	}
	if b.now().Sub(b.openedAt) < b.cooldown || b.probe {
		return false
	}
	b.probe = true
	return true
}

func (b *circuitBreaker) success() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures = 0
	b.openedAt = time.Time{}
	b.probe = false
	b.mu.Unlock()
}

func (b *circuitBreaker) failure() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures++
	b.probe = false
	if b.failures >= b.threshold {
		b.openedAt = b.now()
	}
	b.mu.Unlock()
}

func classifyCallError(ctx context.Context, err error) string {
	if errors.Is(err, errTriageCircuitOpen) {
		return "circuit_open"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	return "provider_error"
}

func callMetric(role, provider, model, findingID, dedupKey string, started time.Time, resp ports.ChatResponse, outcome string, price requestPrice) ports.FPTriageCallMetric {
	return ports.FPTriageCallMetric{
		FindingID:             findingID,
		DedupKey:              dedupKey,
		Role:                  role,
		Provider:              provider,
		Model:                 model,
		PromptVersion:         promptVersion,
		Outcome:               outcome,
		LatencyMillis:         time.Since(started).Milliseconds(),
		PromptTokens:          resp.Usage.PromptTokens,
		CompletionTokens:      resp.Usage.CompletionTokens,
		TotalTokens:           resp.Usage.TotalTokens,
		EstimatedCostMicroUSD: microUSDCeiling(int64(resp.Usage.PromptTokens), price.inputMicroUSDPerMillion) + microUSDCeiling(int64(resp.Usage.CompletionTokens), price.outputMicroUSDPerMillion),
	}
}

func callMetricForPrompt(role, provider, model, findingID, dedupKey, version string, started time.Time, resp ports.ChatResponse, outcome string, price requestPrice) ports.FPTriageCallMetric {
	m := callMetric(role, provider, model, findingID, dedupKey, started, resp, outcome, price)
	m.PromptVersion = version
	return m
}

func (c *Coordinator) observeEvidenceCall(ctx context.Context, llm ports.LLM, breaker *circuitBreaker, req ports.ChatRequest, role, provider, findingID, dedupKey string, price requestPrice, observer *runObserver, evidence []ports.AITriageEvidenceToken) (judgment.CritiqueClaim, []string, error) {
	started := time.Now()
	if !breaker.allow() {
		observer.record(callMetricForPrompt(role, provider, req.Model, findingID, dedupKey, evidencePromptVersion, started, ports.ChatResponse{}, "circuit_open", price))
		return judgment.CritiqueClaim{}, nil, errTriageCircuitOpen
	}
	resp, err := llm.Chat(ctx, req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			breaker.failure()
		}
		observer.record(callMetricForPrompt(role, provider, req.Model, findingID, dedupKey, evidencePromptVersion, started, resp, classifyCallError(ctx, err), price))
		return judgment.CritiqueClaim{}, nil, err
	}
	claim, citations, err := parseCritiqueWithEvidence(resp.Content, evidence)
	if err != nil {
		breaker.failure()
		observer.record(callMetricForPrompt(role, provider, req.Model, findingID, dedupKey, evidencePromptVersion, started, resp, "parse_failure", price))
		return judgment.CritiqueClaim{}, nil, err
	}
	breaker.success()
	observer.record(callMetricForPrompt(role, provider, req.Model, findingID, dedupKey, evidencePromptVersion, started, resp, "success", price))
	return claim, citations, nil
}

func (c *Coordinator) proposerPrice() requestPrice {
	return requestPrice{c.operations.ProposerInputMicroUSDPerMillion, c.operations.ProposerOutputMicroUSDPerMillion}
}

func (c *Coordinator) verifierPrice() requestPrice {
	return requestPrice{c.operations.VerifierInputMicroUSDPerMillion, c.operations.VerifierOutputMicroUSDPerMillion}
}

func (c *Coordinator) observeCall(ctx context.Context, llm ports.LLM, breaker *circuitBreaker, req ports.ChatRequest, role, provider, findingID, dedupKey string, price requestPrice, observer *runObserver) (judgment.CritiqueClaim, error) {
	started := time.Now()
	if !breaker.allow() {
		observer.record(callMetric(role, provider, req.Model, findingID, dedupKey, started, ports.ChatResponse{}, "circuit_open", price))
		return judgment.CritiqueClaim{}, errTriageCircuitOpen
	}
	resp, err := llm.Chat(ctx, req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			breaker.failure()
		}
		observer.record(callMetric(role, provider, req.Model, findingID, dedupKey, started, resp, classifyCallError(ctx, err), price))
		return judgment.CritiqueClaim{}, err
	}
	claim, err := parseCritique(resp.Content)
	if err != nil {
		breaker.failure()
		observer.record(callMetric(role, provider, req.Model, findingID, dedupKey, started, resp, "parse_failure", price))
		return judgment.CritiqueClaim{}, err
	}
	breaker.success()
	observer.record(callMetric(role, provider, req.Model, findingID, dedupKey, started, resp, "success", price))
	return claim, nil
}

func disagreement(c Critique) bool {
	return c.Verifier != nil && (c.Claim.Verdict != c.Verifier.Verdict || c.Claim.Confidence != c.Verifier.Confidence || !strings.EqualFold(c.Claim.Driver, c.Verifier.Driver))
}
