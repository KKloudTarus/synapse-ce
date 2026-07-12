// Package fptriage runs an LLM-assisted false-positive critique over first-party source-analysis
// findings (SAST, secret, misconfig). It fits the judgment model exactly: the model is a PROPOSER
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
// When a DISTINCT verifier model is configured, a proposer "refuted" is only actionable if the verifier
// independently agrees — the stateless-CLI analogue of the judgment gate's "a distinct verifier's sealed
// verdict, self-confirm forbidden". VerifyAttempted records that a verifier was required for this
// critique (proposer refuted at/above the bar); Verifier holds its reply (nil if the verify call failed).
type Critique struct {
	FindingID       string
	DedupKey        string
	Claim           judgment.CritiqueClaim  // the proposer's verdict
	Verifier        *judgment.CritiqueClaim // the distinct verifier's verdict, when one was run
	VerifyAttempted bool                    // a distinct verifier was required (and tried) for this critique
	Err             error
}

// SuspectedFP reports whether this critique refutes the finding with at least minConfidence — the only
// condition under which the caller exempts it from the gate. When a distinct verifier was required
// (VerifyAttempted), BOTH the proposer and the verifier must refute at/above the bar; a verifier that
// disagreed, was inconclusive, or failed to respond keeps the finding gating (conservative, fail-safe).
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

// Coordinator critiques findings through an LLM proposer, and (when configured) a DISTINCT verifier.
type Coordinator struct {
	llm           ports.LLM
	model         string
	verifier      ports.LLM // optional distinct verifier; a proposer "refuted" is confirmed only if it agrees
	verifierModel string
	minConf       int // minimum confidence for a "refuted" to be actionable (default verdict.EvidenceThreshold)
	radius        int // source context lines each side of the finding line
	concurrency   int
}

// New builds a Coordinator. model is the proposer model id; llm must be non-nil.
func New(llm ports.LLM, model string) *Coordinator {
	return &Coordinator{
		llm:         llm,
		model:       strings.TrimSpace(model),
		minConf:     verdict.EvidenceThreshold, // 75 — align with the gated-judgment bar
		radius:      8,
		concurrency: 6,
	}
}

// WithMinConfidence overrides the confidence bar a "refuted" verdict must clear (clamped to 1..100).
func (c *Coordinator) WithMinConfidence(n int) *Coordinator {
	if n >= 1 && n <= 100 {
		c.minConf = n
	}
	return c
}

// WithVerifier attaches a DISTINCT verifier model: after the proposer refutes a finding at/above the
// bar, the verifier independently re-assesses and the refutation only stands (exempts the gate) if the
// verifier agrees — mirroring the judgment gate's distinct-verifier rule in the stateless CLI. A no-op
// if llm is nil or the verifier model equals the proposer model (not a distinct verifier).
func (c *Coordinator) WithVerifier(llm ports.LLM, model string) *Coordinator {
	model = strings.TrimSpace(model)
	if llm != nil && model != "" && model != c.model {
		c.verifier = llm
		c.verifierModel = model
	}
	return c
}

// VerifierModel returns the distinct verifier model in effect, or "" when single-model.
func (c *Coordinator) VerifierModel() string { return c.verifierModel }

// MinConfidence is the confidence bar in effect.
func (c *Coordinator) MinConfidence() int { return c.minConf }

// Assess critiques every candidate finding concurrently (bounded). The caller passes only the findings
// worth spending a model call on (typically production-scope first-party SAST/secret/misconfig). Order
// of the returned slice matches candidates. Best-effort: a per-finding failure is captured as
// Critique.Err, never returned as a batch error.
func (c *Coordinator) Assess(ctx context.Context, candidates []finding.Finding, src SourceReader) []Critique {
	out := make([]Critique, len(candidates))
	if c == nil || c.llm == nil || len(candidates) == 0 {
		return out
	}
	sem := make(chan struct{}, c.concurrency)
	var wg sync.WaitGroup
	for i := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			// Make the best-effort guarantee unconditional: a panic in one critique becomes that
			// finding's Err (it then gates normally), never taking down the scan pipeline.
			defer func() {
				if r := recover(); r != nil {
					out[i] = Critique{
						FindingID: string(candidates[i].ID),
						DedupKey:  candidates[i].DedupKey,
						Err:       fmt.Errorf("critique panicked: %v", r),
					}
				}
			}()
			out[i] = c.assessOne(ctx, candidates[i], src)
		}(i)
	}
	wg.Wait()
	return out
}

func (c *Coordinator) assessOne(ctx context.Context, f finding.Finding, src SourceReader) Critique {
	res := Critique{FindingID: string(f.ID), DedupKey: f.DedupKey}
	if ctx.Err() != nil {
		res.Err = ctx.Err()
		return res
	}
	snippet := ""
	if src != nil {
		if file, line, ok := locationOf(f); ok {
			if s, err := src.Snippet(ctx, file, line, c.radius); err == nil {
				snippet = s
			}
		}
	}
	req := ports.ChatRequest{
		Model:          c.model,
		Temperature:    0,
		MaxTokens:      512, // headroom if the model emits a short rationale field before the JSON object
		ResponseSchema: critiqueSchema,
		Messages: []agent.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt(f, snippet)},
		},
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
	// Distinct-verifier consensus: only a proposer "refuted" at/above the bar is worth a second call.
	// The verifier must independently agree for the refutation to stand (SuspectedFP); a disagreement,
	// inconclusive reply, or failed call leaves Verifier nil → the finding keeps gating (fail-safe).
	if c.verifier != nil && claim.Verdict == judgment.CritiqueRefuted && claim.Confidence >= c.minConf {
		res.VerifyAttempted = true
		if v, verr := c.verify(ctx, f, snippet, claim); verr == nil {
			res.Verifier = &v
		}
	}
	return res
}

// verify runs the distinct verifier model over a proposer's refutation, adversarially framed to keep a
// real weakness from being dismissed. Returns the verifier's CritiqueClaim, or an error if unreachable.
func (c *Coordinator) verify(ctx context.Context, f finding.Finding, snippet string, proposer judgment.CritiqueClaim) (judgment.CritiqueClaim, error) {
	if ctx.Err() != nil {
		return judgment.CritiqueClaim{}, ctx.Err()
	}
	resp, err := c.verifier.Chat(ctx, ports.ChatRequest{
		Model:          c.verifierModel,
		Temperature:    0,
		MaxTokens:      512,
		ResponseSchema: critiqueSchema,
		Messages: []agent.Message{
			{Role: "system", Content: verifierSystemPrompt},
			{Role: "user", Content: verifierUserPrompt(f, snippet, proposer)},
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
		Confidence int    `json:"confidence"`
	}
	if err := json.Unmarshal([]byte(obj), &raw); err != nil {
		return judgment.CritiqueClaim{}, fmt.Errorf("critique: decode reply: %w", err)
	}
	claim := judgment.CritiqueClaim{
		Verdict:    judgment.CritiqueVerdict(strings.ToLower(strings.TrimSpace(raw.Verdict))),
		Driver:     normalizeDriver(raw.Driver, raw.Verdict),
		Confidence: clampConfidence(raw.Confidence),
	}
	// The VERDICT stays strict (it is the actual decision, and only "refuted" ever suppresses); the driver
	// is a normalized/defaulted label and the confidence is clamped, so a model that returns a valid
	// verdict is never discarded over a cosmetic field.
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

// clampConfidence bounds a model confidence into the 0..100 the domain requires.
func clampConfidence(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
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
