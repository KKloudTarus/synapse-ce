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
	FindingID       string
	DedupKey        string
	Claim           judgment.CritiqueClaim  // the proposer's verdict
	Verifier        *judgment.CritiqueClaim // the distinct verifier's verdict, when one was run
	VerifyAttempted bool                    // a distinct blind verifier was configured and tried
	Err             error
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
	llm           ports.LLM
	model         string
	verifier      ports.LLM // optional distinct blind verifier; a proposer "refuted" is confirmed only if it agrees
	verifierModel string
	minConf       int // minimum confidence for a "refuted" to be actionable (default verdict.EvidenceThreshold)
	radius        int // source context lines each side of the finding line
	concurrency   int
}

// preparedFinding is one immutable model input. sourceSHA256 covers the complete file when the reader
// implements ports.SourceSnippetContextReader; cacheable is false when that stronger snapshot could not
// be obtained, so a partial snippet hash can never masquerade as full source identity.
type preparedFinding struct {
	finding      finding.Finding
	snippet      string
	sourceSHA256 string
	cacheable    bool
	reader       SourceReader
	ready        bool
}

const (
	defaultConcurrency = 6
	maxConcurrency     = 32
)

// New builds a Coordinator. model is the proposer model id; llm must be non-nil.
func New(llm ports.LLM, model string) *Coordinator {
	return &Coordinator{
		llm:         llm,
		model:       strings.TrimSpace(model),
		minConf:     verdict.EvidenceThreshold, // 75 — align with the gated-judgment bar
		radius:      8,
		concurrency: defaultConcurrency,
	}
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
	model = strings.TrimSpace(model)
	if llm != nil && model != "" && c.model != "" && !agent.SameModel(model, c.model) {
		c.verifier = llm
		c.verifierModel = model
	}
	return c
}

// VerifierModel returns the distinct verifier model in effect, or "" when single-model.
func (c *Coordinator) VerifierModel() string { return c.verifierModel }

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

func (c *Coordinator) prepare(ctx context.Context, f finding.Finding, src SourceReader) preparedFinding {
	p := preparedFinding{finding: f, ready: true}
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
			p.snippet = snippet
			p.sourceSHA256 = sourceHash
			p.cacheable = true
			return p
		}
		// A full-file snapshot may be unavailable (for example, an intentionally capped giant file).
		// Preserve the previous best-effort triage behavior by using the ordinary snippet, uncached.
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
	out := make([]Critique, len(candidates))
	if c == nil || c.llm == nil || len(candidates) == 0 {
		return out
	}
	sem := make(chan struct{}, c.Concurrency())
	var wg sync.WaitGroup
	for i := range candidates {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			for j := i; j < len(candidates); j++ {
				out[j] = Critique{FindingID: string(candidates[j].finding.ID), DedupKey: candidates[j].finding.DedupKey, Err: ctx.Err()}
			}
			wg.Wait()
			return out
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// Make the best-effort guarantee unconditional: a panic in one critique becomes that
			// finding's Err (it then gates normally), never taking down the scan pipeline.
			defer func() {
				if r := recover(); r != nil {
					out[i] = Critique{
						FindingID: string(candidates[i].finding.ID),
						DedupKey:  candidates[i].finding.DedupKey,
						Err:       fmt.Errorf("critique panicked: %v", r),
					}
				}
			}()
			candidate := candidates[i]
			if !candidate.ready {
				candidate = c.prepare(ctx, candidate.finding, candidate.reader)
			}
			out[i] = c.assessOne(ctx, candidate.finding, candidate.snippet)
		}(i)
	}
	wg.Wait()
	return out
}

func (c *Coordinator) assessOne(ctx context.Context, f finding.Finding, snippet string) Critique {
	res := Critique{FindingID: string(f.ID), DedupKey: f.DedupKey}
	if ctx.Err() != nil {
		res.Err = ctx.Err()
		return res
	}
	req := ports.ChatRequest{
		Model:          c.model,
		Temperature:    ports.Temp(0), // greedy: the same finding must critique the same way twice
		MaxTokens:      512,           // headroom if the model emits a short rationale field before the JSON object
		ResponseSchema: critiqueSchema,
		Messages: []agent.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt(f, snippet)},
		},
	}
	// Run the verifier before the proposer result exists. Its request contains only the finding and source
	// context, so neither invocation order nor prompt content can anchor it to the proposer's conclusion.
	if c.verifier != nil {
		res.VerifyAttempted = true
		if v, verr := c.verify(ctx, f, snippet); verr == nil {
			res.Verifier = &v
		}
	}

	resp, err := c.llm.Chat(ctx, req)
	if err != nil {
		res.Err = fmt.Errorf("critique llm: %w", err)
		return res
	}
	claim, err := parseCritique(resp.Content)
	if err != nil {
		res.Err = err
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
