// Package fptriage runs an LLM-assisted false-positive critique over safe-to-transmit first-party
// source-analysis findings (SAST and misconfig). Secret findings are excluded before this layer so raw
// credential-bearing source context never enters an LLM transcript. The model is a PROPOSER
// only — it returns a typed judgment.CritiqueClaim (verdict ∈ refuted|sound|uncertain, a closed driver
// token, a 0..100 confidence), NEVER free prose and NEVER a suppression. The caller applies a "refuted"
// verdict as retain-and-mark: the finding stays reported and sealed, it is only held back from the CI
// gate. A wrong critique can therefore never publish a falsehood or silently delete a real weakness.
//
// This is the deterministic-second layer: the scope classifier already removes obvious test/fixture
// noise; the model handles the subtler production-scope calls (attacker-controlled? sanitized? a
// literal/constant sink? intended behavior?). It is best-effort — a model timeout/error becomes an
// "uncertain" critique and never fails the scan.
package fptriage

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SourceReader is the source-excerpt reader the coordinator uses for context (an alias for the shared
// port, so the concrete fs reader lives in infrastructure, not here). An error is non-fatal: the
// coordinator critiques on finding metadata alone.
type SourceReader = ports.SourceSnippetReader

// Critique is the model's per-finding verdict. Err is set when the (proposer) model could not be
// consulted (timeout, transport, or an unparseable/invalid reply); such a critique is treated as
// inconclusive and never marks a finding.
//
// When a DISTINCT verifier model is configured, it assesses every candidate without seeing the proposer
// output. A proposer "refuted" is only actionable if the verifier independently agrees — the stateless-
// CLI analogue of the judgment gate's "a distinct verifier's sealed verdict, self-confirm forbidden".
// VerifyAttempted records that a blind verifier was tried; Verifier is nil if that call failed.
type Critique struct {
	FindingID              string
	DedupKey               string
	Claim                  judgment.CritiqueClaim
	Verifier               *judgment.CritiqueClaim
	VerifyAttempted        bool
	ContextEvidence        []ports.AITriageEvidenceToken
	EvidenceTokens         []string
	VerifierEvidenceTokens []string
	PromptVersion          string
	Err                    error
}

// SuspectedFP reports the AI's advisory false-positive opinion. When a distinct verifier was attempted,
// BOTH models must refute at/above the bar. In single-model mode it can still return true for visibility,
// but the scan's deterministic policy never grants a gate exemption unless VerifiedConsensus is true.
func (c Critique) SuspectedFP(minConfidence int) bool {
	if c.Err != nil {
		return false
	}
	proposerFP := c.Claim.Verdict == judgment.CritiqueRefuted && c.Claim.Confidence >= minConfidence
	if !proposerFP {
		return false
	}
	if !c.VerifyAttempted {
		return true // single-model mode: no distinct verifier configured
	}
	return c.Verifier != nil && c.Verifier.Verdict == judgment.CritiqueRefuted && c.Verifier.Confidence >= minConfidence
}

// VerifiedConsensus reports whether two distinct configured model IDs independently refuted the finding
// at/above the confidence bar. This is necessary, but not sufficient, for a gate exemption: the scan policy
// also applies severity/kind/CWE floors that force dangerous classes to human review.
func (c Critique) VerifiedConsensus(minConfidence int) bool {
	return c.Err == nil && c.VerifyAttempted && c.Verifier != nil &&
		c.Claim.Verdict == judgment.CritiqueRefuted && c.Claim.Confidence >= minConfidence &&
		c.Verifier.Verdict == judgment.CritiqueRefuted && c.Verifier.Confidence >= minConfidence
}

// Coordinator critiques findings through an LLM proposer, and (when configured) a DISTINCT verifier.
type Coordinator struct {
	llm                ports.LLM
	model              string
	proposerProvider   string
	verifier           ports.LLM // optional distinct blind verifier; a proposer "refuted" is confirmed only if it agrees
	verifierModel      string
	verifierProvider   string
	independencePolicy ports.AIIndependencePolicy
	minConf            int // minimum confidence for a "refuted" to be actionable (default verdict.EvidenceThreshold)
	radius             int // source context lines each side of the finding line
	concurrency        int
	operations         ports.FPTriageOperationalPolicy
	proposerCircuit    *circuitBreaker
	verifierCircuit    *circuitBreaker
}

// preparedFinding is one immutable model input. sourceSHA256 covers the complete file when the reader
// implements ports.SourceSnippetContextReader; cacheable is false when that stronger snapshot could not
// be obtained, so a partial snippet hash can never masquerade as full source identity.
type preparedFinding struct {
	finding          finding.Finding
	snippet          string
	sourceSHA256     string
	cacheable        bool
	reader           SourceReader
	ready            bool
	evidence         []ports.AITriageEvidenceToken
	evidenceRequired bool
	evidenceErr      error
}

const (
	defaultConcurrency = 6
	maxConcurrency     = 32
)

const defaultProviderID = "openai-compatible"

// New builds a Coordinator using the backwards-compatible generic OpenAI-compatible provider
// identity. Composition roots with explicit provider metadata should use NewWithIdentity.
func New(llm ports.LLM, model string) *Coordinator {
	return NewWithIdentity(llm, defaultProviderID, model)
}

// NewWithIdentity builds a Coordinator with explicit proposer provider/model audit identity.
func NewWithIdentity(llm ports.LLM, provider, model string) *Coordinator {
	c := &Coordinator{
		llm:                llm,
		model:              strings.TrimSpace(model),
		proposerProvider:   agent.CanonicalProviderID(provider),
		independencePolicy: ports.AIIndependenceModelFamily,
		minConf:            verdict.EvidenceThreshold, // 75 — align with the gated-judgment bar
		radius:             8,
		concurrency:        defaultConcurrency,
	}
	c.WithOperationalPolicy(ports.FPTriageOperationalPolicy{})
	return c
}

// WithOperationalPolicy configures per-run resource ceilings and provider circuit breaking. Invalid
// values are replaced with finite fail-safe defaults; a zero cost ceiling leaves cost enforcement off.
func (c *Coordinator) WithOperationalPolicy(policy ports.FPTriageOperationalPolicy) *Coordinator {
	if c == nil {
		return c
	}
	policy = normalizeOperationalPolicy(policy)
	c.operations = policy
	c.proposerCircuit = newCircuitBreaker(policy.CircuitFailureThreshold, policy.CircuitCooldown)
	c.verifierCircuit = newCircuitBreaker(policy.CircuitFailureThreshold, policy.CircuitCooldown)
	return c
}

// WithMinConfidence overrides the confidence bar a "refuted" verdict must clear (clamped to 1..100).
func (c *Coordinator) WithMinConfidence(n int) *Coordinator {
	if n >= 1 && n <= 100 {
		c.minConf = n
	}
	return c
}

// WithConcurrency bounds simultaneous proposer/verifier pairs. Invalid values keep the finite default.
func (c *Coordinator) WithConcurrency(n int) *Coordinator {
	if c != nil && n > 0 && n <= maxConcurrency {
		c.concurrency = n
	}
	return c
}

// Concurrency returns the active per-coordinator call-pair limit.
func (c *Coordinator) Concurrency() int {
	if c == nil || c.concurrency < 1 {
		return defaultConcurrency
	}
	return c.concurrency
}

// WithVerifier attaches a DISTINCT verifier model. Agreement creates VerifiedConsensus, which the
// scan policy may authorize only after applying severity/kind/CWE human-review floors. A no-op if the
// client or either model identity is missing, or the verifier aliases the proposer.
func (c *Coordinator) WithVerifier(llm ports.LLM, model string) *Coordinator {
	return c.WithIndependentVerifier(llm, c.proposerProvider, model, ports.AIIndependenceModelFamily)
}

// WithIndependentVerifier attaches a verifier only when the complete provider/model identity satisfies
// the requested separation-of-duties policy. Provider policy is stronger: it requires both a different
// provider and a different canonical model family. Missing/unknown metadata is a no-op (advisory-only).
func (c *Coordinator) WithIndependentVerifier(llm ports.LLM, provider, model string, policy ports.AIIndependencePolicy) *Coordinator {
	model = strings.TrimSpace(model)
	provider = agent.CanonicalProviderID(provider)
	if llm != nil && agent.IndependentLLMs(c.proposerProvider, c.model, provider, model, string(policy)) {
		c.verifier = llm
		c.verifierModel = model
		c.verifierProvider = provider
		c.independencePolicy = policy
	}
	return c
}

// VerifierModel returns the distinct verifier model in effect, or "" when single-model.
func (c *Coordinator) VerifierModel() string { return c.verifierModel }

// ProposerProvider and VerifierProvider return canonical provider audit identities.
func (c *Coordinator) ProposerProvider() string { return c.proposerProvider }
func (c *Coordinator) VerifierProvider() string { return c.verifierProvider }

// IndependencePolicy returns the rule that admitted the configured verifier.
func (c *Coordinator) IndependencePolicy() ports.AIIndependencePolicy { return c.independencePolicy }

// ProposerModel returns the configured proposer model ID for audit metadata.
func (c *Coordinator) ProposerModel() string { return c.model }

// MinConfidence is the confidence bar in effect.
func (c *Coordinator) MinConfidence() int { return c.minConf }

// Assess critiques every candidate finding concurrently (bounded). The caller passes only the findings
// worth spending a model call on (production-scope first-party SAST/misconfig; never secrets). Order
// of the returned slice matches candidates. Best-effort: a per-finding failure is captured as
// Critique.Err, never returned as a batch error.
func (c *Coordinator) Assess(ctx context.Context, candidates []finding.Finding, src SourceReader) []Critique {
	if c == nil || c.llm == nil || len(candidates) == 0 {
		return make([]Critique, len(candidates))
	}
	prepared := make([]preparedFinding, len(candidates))
	for i := range candidates {
		// Source reads stay inside the bounded assessment goroutines on the uncached path. Cache-enabled
		// triage prepares a stable snapshot before lookup and marks it ready.
		prepared[i] = preparedFinding{finding: candidates[i], reader: src}
	}
	return c.assessPrepared(ctx, prepared)
}

// AssessWithEvidence uses the same operational budget/circuit path as Assess, but requires a valid
// deterministic dictionary for every candidate before reserving tokens or contacting either model.
func (c *Coordinator) AssessWithEvidence(ctx context.Context, candidates []finding.Finding, src SourceReader, evidence map[string][]ports.AITriageEvidenceToken) []Critique {
	if c == nil || c.llm == nil || len(candidates) == 0 {
		return make([]Critique, len(candidates))
	}
	prepared := make([]preparedFinding, len(candidates))
	for i := range candidates {
		prepared[i] = preparedFinding{finding: candidates[i], reader: src, evidence: evidence[candidates[i].DedupKey], evidenceRequired: true}
	}
	return c.assessPrepared(ctx, prepared)
}

func (c *Coordinator) prepare(ctx context.Context, f finding.Finding, src SourceReader) preparedFinding {
	return c.prepareWithEvidence(ctx, f, src, nil, false)
}

func (c *Coordinator) prepareWithEvidence(ctx context.Context, f finding.Finding, src SourceReader, evidence []ports.AITriageEvidenceToken, required bool) preparedFinding {
	normalized, evidenceErr := normalizeEvidence(evidence, required)
	p := preparedFinding{finding: f, ready: true, evidence: normalized, evidenceRequired: required, evidenceErr: evidenceErr}
	file, line, located := locationOf(f)
	if !located {
		// No source was supplied to the model, so a stable empty-source sentinel fully describes this
		// dimension of its input. Finding metadata is independently covered by the context hash.
		p.sourceSHA256 = sha256Hex(nil)
		p.cacheable = true
		return p
	}
	if src == nil {
		return p
	}
	if snapshot, ok := src.(ports.SourceSnippetContextReader); ok {
		snippet, sourceHash, err := snapshot.SnippetContext(ctx, file, line, c.radius)
		if err == nil && validSHA256(sourceHash) {
			p.snippet, p.sourceSHA256, p.cacheable = snippet, sourceHash, true
			return p
		}
		// A full-file snapshot may be unavailable (for example, an intentionally capped giant file).
		// Preserve best-effort live triage by using the ordinary snippet, uncached.
		if snippet, snippetErr := src.Snippet(ctx, file, line, c.radius); snippetErr == nil {
			p.snippet = snippet
		}
		return p
	}
	// Legacy/custom readers remain supported for uncached triage. Their snippet cannot safely key a
	// cache because it does not prove that the rest of the source file is unchanged.
	if snippet, err := src.Snippet(ctx, file, line, c.radius); err == nil {
		p.snippet = snippet
	}
	return p
}

func (c *Coordinator) assessPrepared(ctx context.Context, candidates []preparedFinding) []Critique {
	out, _ := c.assessPreparedObserved(ctx, candidates)
	return out
}

func (c *Coordinator) assessPreparedObserved(ctx context.Context, candidates []preparedFinding) ([]Critique, ports.FPTriageTelemetry) {
	out := make([]Critique, len(candidates))
	if c == nil || c.llm == nil || len(candidates) == 0 {
		return out, ports.FPTriageTelemetry{}
	}
	budget := newRunBudget(c.operations)
	type assessment struct {
		candidate preparedFinding
		proposer  ports.ChatRequest
		verifier  ports.ChatRequest
		admitted  bool
	}
	work := make([]assessment, len(candidates))
	skipped := 0
	for i, candidate := range candidates {
		if !candidate.ready {
			candidate = c.prepareWithEvidence(ctx, candidate.finding, candidate.reader, candidate.evidence, candidate.evidenceRequired)
		}
		work[i].candidate = candidate
		if candidate.evidenceErr != nil {
			version := promptVersion
			if candidate.evidenceRequired {
				version = evidencePromptVersion
			}
			out[i] = Critique{FindingID: candidate.finding.ID.String(), DedupKey: candidate.finding.DedupKey, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), candidate.evidence...), PromptVersion: version, Err: candidate.evidenceErr}
			continue
		}
		proposer := c.proposerRequest(candidate)
		requests := []pricedRequest{{request: proposer, price: c.proposerPrice()}}
		var verifier ports.ChatRequest
		if c.verifier != nil {
			verifier = c.verifierRequest(candidate)
			requests = append(requests, pricedRequest{request: verifier, price: c.verifierPrice()})
		}
		admitted := budget.reservePair(requests...)
		work[i] = assessment{candidate: candidate, proposer: proposer, verifier: verifier, admitted: admitted}
		if !admitted {
			out[i] = Critique{FindingID: candidate.finding.ID.String(), DedupKey: candidate.finding.DedupKey, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), candidate.evidence...), PromptVersion: promptVersionFor(candidate), Err: errTriageBudgetExhausted}
			skipped++
		}
	}
	observer := newRunObserver(budget)
	observer.telemetry.BudgetSkippedFindings = skipped
	sem := make(chan struct{}, c.Concurrency())
	var wg sync.WaitGroup
	for i := range work {
		if !work[i].admitted {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			for j := i; j < len(work); j++ {
				if work[j].admitted {
					out[j] = Critique{FindingID: work[j].candidate.finding.ID.String(), DedupKey: work[j].candidate.finding.DedupKey, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), work[j].candidate.evidence...), PromptVersion: promptVersionFor(work[j].candidate), Err: ctx.Err()}
				}
			}
			wg.Wait()
			return out, observer.snapshot()
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// Make the best-effort guarantee unconditional: a panic in one critique becomes that
			// finding's Err (it then gates normally), never taking down the scan pipeline.
			defer func() {
				if r := recover(); r != nil {
					out[i] = Critique{FindingID: work[i].candidate.finding.ID.String(), DedupKey: work[i].candidate.finding.DedupKey, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), work[i].candidate.evidence...), PromptVersion: promptVersionFor(work[i].candidate), Err: fmt.Errorf("critique panicked: %v", r)}
				}
			}()
			out[i] = c.assessOneObserved(ctx, work[i].candidate, work[i].proposer, work[i].verifier, observer)
		}(i)
	}
	wg.Wait()
	telemetry := observer.snapshot()
	for _, critique := range out {
		if critique.Verifier != nil {
			telemetry.Comparisons++
			if disagreement(critique) {
				telemetry.Disagreements++
			}
		}
	}
	return out, telemetry
}

func (c *Coordinator) assessOne(ctx context.Context, f finding.Finding, snippet string) Critique {
	out, _ := c.assessPreparedObserved(ctx, []preparedFinding{{finding: f, snippet: snippet, ready: true}})
	if len(out) == 0 {
		return Critique{FindingID: f.ID.String(), DedupKey: f.DedupKey, Err: context.Canceled}
	}
	return out[0]
}

func promptVersionFor(p preparedFinding) string {
	if p.evidenceRequired {
		return evidencePromptVersion
	}
	return promptVersion
}

func (c *Coordinator) proposerRequest(p preparedFinding) ports.ChatRequest {
	if p.evidenceRequired {
		return ports.ChatRequest{Model: c.model, Temperature: ports.Temp(0), MaxTokens: 512, ResponseSchema: evidenceCritiqueSchema,
			Messages: []agent.Message{{Role: "system", Content: evidenceSystemPrompt}, {Role: "user", Content: userPromptWithEvidence(p.finding, p.snippet, p.evidence)}}}
	}
	return ports.ChatRequest{Model: c.model, Temperature: ports.Temp(0), MaxTokens: 512, ResponseSchema: critiqueSchema,
		Messages: []agent.Message{{Role: "system", Content: systemPrompt}, {Role: "user", Content: userPrompt(p.finding, p.snippet)}}}
}

func (c *Coordinator) verifierRequest(p preparedFinding) ports.ChatRequest {
	if p.evidenceRequired {
		return ports.ChatRequest{Model: c.verifierModel, Temperature: ports.Temp(0), MaxTokens: 512, ResponseSchema: evidenceCritiqueSchema,
			Messages: []agent.Message{{Role: "system", Content: evidenceVerifierSystemPrompt}, {Role: "user", Content: verifierUserPromptWithEvidence(p.finding, p.snippet, p.evidence)}}}
	}
	return ports.ChatRequest{Model: c.verifierModel, Temperature: ports.Temp(0), MaxTokens: 512, ResponseSchema: critiqueSchema,
		Messages: []agent.Message{{Role: "system", Content: verifierSystemPrompt}, {Role: "user", Content: verifierUserPrompt(p.finding, p.snippet)}}}
}

func (c *Coordinator) assessOneObserved(ctx context.Context, p preparedFinding, proposerReq, verifierReq ports.ChatRequest, observer *runObserver) Critique {
	res := Critique{FindingID: p.finding.ID.String(), DedupKey: p.finding.DedupKey, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), p.evidence...), PromptVersion: promptVersionFor(p)}
	if ctx.Err() != nil {
		res.Err = ctx.Err()
		return res
	}
	// Run the verifier before the proposer result exists. Its request contains only the finding and source
	// context, so neither invocation order nor prompt content can anchor it to the proposer's conclusion.
	if c.verifier != nil {
		res.VerifyAttempted = true
		if p.evidenceRequired {
			if v, cites, verr := c.observeEvidenceCall(ctx, c.verifier, c.verifierCircuit, verifierReq, "verifier", c.verifierProvider, p.finding.ID.String(), p.finding.DedupKey, c.verifierPrice(), observer, p.evidence); verr == nil {
				res.Verifier, res.VerifierEvidenceTokens = &v, cites
			}
		} else if v, verr := c.observeCall(ctx, c.verifier, c.verifierCircuit, verifierReq, "verifier", c.verifierProvider, p.finding.ID.String(), p.finding.DedupKey, c.verifierPrice(), observer); verr == nil {
			res.Verifier = &v
		}
	}
	if p.evidenceRequired {
		claim, cites, err := c.observeEvidenceCall(ctx, c.llm, c.proposerCircuit, proposerReq, "proposer", c.proposerProvider, p.finding.ID.String(), p.finding.DedupKey, c.proposerPrice(), observer, p.evidence)
		if err != nil {
			res.Err = fmt.Errorf("critique llm: %w", err)
			return res
		}
		res.Claim, res.EvidenceTokens = claim, cites
		return res
	}
	claim, err := c.observeCall(ctx, c.llm, c.proposerCircuit, proposerReq, "proposer", c.proposerProvider, p.finding.ID.String(), p.finding.DedupKey, c.proposerPrice(), observer)
	if err != nil {
		res.Err = fmt.Errorf("critique llm: %w", err)
		return res
	}
	res.Claim = claim
	return res
}

// verify runs the distinct verifier over only the finding and source context. Returns its independent
// CritiqueClaim, or an error if the verifier is unreachable or its reply fails validation.
func (c *Coordinator) verify(ctx context.Context, f finding.Finding, snippet string) (judgment.CritiqueClaim, error) {
	if ctx.Err() != nil {
		return judgment.CritiqueClaim{}, ctx.Err()
	}
	resp, err := c.verifier.Chat(ctx, ports.ChatRequest{
		Model:          c.verifierModel,
		Temperature:    ports.Temp(0), // greedy: consensus is only meaningful if the verifier is reproducible
		MaxTokens:      512,
		ResponseSchema: critiqueSchema,
		Messages: []agent.Message{
			{Role: "system", Content: verifierSystemPrompt},
			{Role: "user", Content: verifierUserPrompt(f, snippet)},
		},
	})
	if err != nil {
		return judgment.CritiqueClaim{}, fmt.Errorf("verify llm: %w", err)
	}
	return parseCritique(resp.Content)
}

// parseCritique decodes the model's reply into a CritiqueClaim and validates it against the domain's
// closed vocabulary. The gateway does not reliably honor response_format=json_schema, so a reply may
// arrive wrapped in a markdown fence or with prose around the object — extractJSONObject recovers the
// object. Fail-closed on the fields that matter: an unknown verdict, a free-text driver (the driverRE
// grammar is what stops prose reaching a report), or an out-of-range confidence is rejected. Extra JSON
// keys the model may add (e.g. a "reasoning" field) are ignored — they decode to nothing and never reach
// the stored claim or the report, so tolerating them costs no safety and greatly improves coverage.
func parseCritique(content string) (judgment.CritiqueClaim, error) {
	obj := extractJSONObject(content)
	if obj == "" {
		return judgment.CritiqueClaim{}, fmt.Errorf("critique: no JSON object in model reply")
	}
	var raw struct {
		Verdict    string `json:"verdict"`
		Driver     string `json:"driver"`
		Confidence *int   `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(obj), &raw); err != nil {
		return judgment.CritiqueClaim{}, fmt.Errorf("critique: decode reply: %w", err)
	}
	if raw.Confidence == nil {
		return judgment.CritiqueClaim{}, fmt.Errorf("critique: confidence is required")
	}
	claim := judgment.CritiqueClaim{
		Verdict:    judgment.CritiqueVerdict(strings.ToLower(strings.TrimSpace(raw.Verdict))),
		Driver:     normalizeDriver(raw.Driver, raw.Verdict),
		Confidence: *raw.Confidence,
	}
	// The verdict and confidence stay strict because both participate in the gate decision. In
	// particular, never clamp an out-of-range model value to 100: that would turn malformed output into
	// maximum confidence. The driver is only a bounded audit label, so it remains safe to normalize and
	// default without granting authority.
	if err := claim.Validate(); err != nil {
		return judgment.CritiqueClaim{}, fmt.Errorf("critique: %w", err)
	}
	return claim, nil
}

// driverTokenRE mirrors the domain's driver grammar (a lowercase snake_case token) for local
// normalization; the domain's Validate is still the authoritative gate.
var driverTokenRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// normalizeDriver coerces a model-provided driver into the closed token grammar: lowercase, spaces and
// hyphens to underscores, other punctuation stripped, capped at 64 chars. When the model omits or
// mangles it, a verdict-derived default keeps the (still meaningful) verdict rather than dropping it —
// the substitute is a controlled token, never model prose.
func normalizeDriver(d, verdict string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r == ' ' || r == '-' || r == '_':
			return '_'
		default:
			return -1 // drop
		}
	}, d)
	d = strings.Trim(d, "_")
	// Keep a genuine short driver token (e.g. "argv_only_no_shell"); a normalized SENTENCE (too long or
	// too many words) is treated as prose and replaced with a clean verdict-derived token, so the driver
	// field can never carry a model narrative even though it now tolerates spaced input.
	if driverTokenRE.MatchString(d) && len(d) <= 48 && strings.Count(d, "_") <= 5 {
		return d
	}
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "refuted":
		return "unspecified_refutation"
	case "sound":
		return "confirmed_by_review"
	default:
		return "insufficient_context"
	}
}

// extractJSONObject recovers the first {...} object from a model reply, tolerating a leading ```json /
// ``` code fence and prose around the object. Returns "" when there is no brace-delimited object.
func extractJSONObject(content string) string {
	s := strings.TrimSpace(content)
	if strings.HasPrefix(s, "```") {
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			s = s[nl+1:] // drop the ```json fence line
		}
		if end := strings.LastIndex(s, "```"); end >= 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j <= i {
		return ""
	}
	return s[i : j+1]
}
