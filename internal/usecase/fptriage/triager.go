package fptriage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Triager adapts a Coordinator to the ports.FPTriager the scan pipeline injects, so the SAME triage runs
// for both the CLI (synchronous) and the durable API scan job. It owns the mapping from a Coordinator
// Critique to the advisory ports.AICritique DTO (dropping best-effort failures, which then gate normally)
// and builds a per-workspace source reader through the injected factory (the fs read stays in
// infrastructure, never here).
type Triager struct {
	coord     *Coordinator
	readerFor func(root string) ports.SourceSnippetReader
	minConf   int
	cache     ports.FPTriageCache
	policy    string
}

var _ ports.FPTriager = (*Triager)(nil)
var _ ports.ObservableFPTriager = (*Triager)(nil)

// NewTriager wraps a Coordinator. readerFor returns the source reader rooted at a scan's workspace dir
// (nil-safe: a nil factory means the coordinator critiques on metadata only).
func NewTriager(coord *Coordinator, readerFor func(root string) ports.SourceSnippetReader) *Triager {
	mc := 0
	if coord != nil {
		mc = coord.MinConfidence()
	}
	return &Triager{coord: coord, readerFor: readerFor, minConf: mc}
}

// WithCache enables safe reuse of typed model claims. policyVersion is part of every key, so a policy
// upgrade automatically invalidates old entries even though authorization itself is always recomputed.
// An incomplete configuration is a no-op and leaves triage uncached.
func (t *Triager) WithCache(cache ports.FPTriageCache, policyVersion string) *Triager {
	if t != nil && cache != nil && strings.TrimSpace(policyVersion) != "" {
		t.cache = cache
		t.policy = strings.TrimSpace(policyVersion)
	}
	return t
}

// Triage critiques each candidate and returns the advisory verdicts. A best-effort failure (Err set) is
// dropped so that finding gates normally. Never mutates a finding.
func (t *Triager) Triage(ctx context.Context, candidates []finding.Finding, workspaceDir string) []ports.AICritique {
	return t.TriageObserved(ctx, candidates, workspaceDir).Critiques
}

// TriageObserved performs the same fail-safe triage while returning source-free operational metrics.
func (t *Triager) TriageObserved(ctx context.Context, candidates []finding.Finding, workspaceDir string) ports.FPTriageObservedResult {
	if t == nil || t.coord == nil || len(candidates) == 0 {
		return ports.FPTriageObservedResult{}
	}
	var reader ports.SourceSnippetReader
	if t.readerFor != nil {
		reader = t.readerFor(workspaceDir)
	}
	if t.cache == nil {
		critiques, telemetry := t.coord.assessPreparedObserved(ctx, prepareCandidates(candidates, reader))
		return ports.FPTriageObservedResult{Critiques: t.mapCritiques(critiques), Telemetry: telemetry}
	}
	prepared := make([]preparedFinding, len(candidates))
	for i := range candidates {
		prepared[i] = t.coord.prepare(ctx, candidates[i], reader)
	}

	crits := make([]Critique, len(candidates))
	misses := make([]preparedFinding, 0, len(candidates))
	missIndexes := make([]int, 0, len(candidates))
	keys := make([]ports.FPTriageCacheKey, len(candidates))
	cacheable := make([]bool, len(candidates))
	cacheHits := 0
	for i := range prepared {
		key, ok := t.cacheKey(ctx, prepared[i])
		keys[i], cacheable[i] = key, ok
		if ok {
			if cached, hit, err := t.cache.Load(ctx, key); err == nil && hit {
				if critique, valid := critiqueFromCache(prepared[i].finding, key, cached); valid {
					crits[i] = critique
					cacheHits++
					continue
				}
			}
		}
		misses = append(misses, prepared[i])
		missIndexes = append(missIndexes, i)
	}
	assessed, telemetry := t.coord.assessPreparedObserved(ctx, misses)
	if len(misses) == 0 {
		telemetry = newRunObserver(newRunBudget(t.coord.operations)).snapshot()
	}
	for i, critique := range assessed {
		idx := missIndexes[i]
		crits[idx] = critique
		// A transient verifier failure is deliberately not cached: the next scan must retry the
		// independent opinion instead of making an outage look like a stable advisory result.
		if cacheable[idx] && critique.Err == nil && (keys[idx].VerifierModel == "" || critique.Verifier != nil) {
			_ = t.cache.Store(ctx, keys[idx], decisionForCache(critique))
		}
	}

	telemetry.CacheHits = cacheHits
	telemetry.Comparisons = 0
	telemetry.Disagreements = 0
	for _, critique := range crits {
		if critique.Verifier != nil {
			telemetry.Comparisons++
			if disagreement(critique) {
				telemetry.Disagreements++
			}
		}
	}
	return ports.FPTriageObservedResult{Critiques: t.mapCritiques(crits), Telemetry: telemetry}
}

func prepareCandidates(candidates []finding.Finding, reader ports.SourceSnippetReader) []preparedFinding {
	prepared := make([]preparedFinding, len(candidates))
	for i := range candidates {
		prepared[i] = preparedFinding{finding: candidates[i], reader: reader}
	}
	return prepared
}

func (t *Triager) mapCritiques(crits []Critique) []ports.AICritique {
	out := make([]ports.AICritique, 0, len(crits))
	for _, c := range crits {
		if c.Err != nil {
			continue
		}
		critique := ports.AICritique{
			FindingID:           c.FindingID,
			DedupKey:            c.DedupKey,
			Verdict:             string(c.Claim.Verdict),
			Driver:              c.Claim.Driver,
			Confidence:          c.Claim.Confidence,
			SuspectedFP:         c.SuspectedFP(t.minConf),
			Verified:            c.VerifiedConsensus(t.minConf),
			ProposerModel:       t.coord.ProposerModel(),
			ProposerProvider:    t.coord.ProposerProvider(),
			ProposerModelFamily: agent.CanonicalModelID(t.coord.ProposerModel()),
			VerifierModel:       t.coord.VerifierModel(),
			VerifierProvider:    t.coord.VerifierProvider(),
			VerifierModelFamily: agent.CanonicalModelID(t.coord.VerifierModel()),
			IndependencePolicy:  t.coord.IndependencePolicy(),
			PromptVersion:       promptVersion,
		}
		if c.Verifier != nil {
			critique.VerifierVerdict = string(c.Verifier.Verdict)
			critique.VerifierDriver = c.Verifier.Driver
			critique.VerifierConfidence = c.Verifier.Confidence
		}
		out = append(out, critique)
	}
	return out
}

func (t *Triager) cacheKey(ctx context.Context, prepared preparedFinding) (ports.FPTriageCacheKey, bool) {
	if t == nil || t.cache == nil || !prepared.cacheable || strings.TrimSpace(t.policy) == "" {
		return ports.FPTriageCacheKey{}, false
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		// Tenant identity is part of the safety boundary, not an optional optimization. A caller that
		// did not bind it still receives live triage, but cannot read or populate the cache.
		return ports.FPTriageCacheKey{}, false
	}
	key := ports.FPTriageCacheKey{
		TenantID:           tenantID,
		ScopeID:            prepared.finding.EngagementID,
		FindingFingerprint: finding.Identity(prepared.finding),
		SourceSHA256:       prepared.sourceSHA256,
		ContextSHA256:      sha256Hex([]byte(userPrompt(prepared.finding, prepared.snippet))),
		ProposerProvider:   strings.TrimSpace(t.coord.ProposerProvider()),
		ProposerModel:      strings.TrimSpace(t.coord.ProposerModel()),
		VerifierProvider:   strings.TrimSpace(t.coord.VerifierProvider()),
		VerifierModel:      strings.TrimSpace(t.coord.VerifierModel()),
		PromptVersion:      promptVersion,
		PolicyVersion:      t.policy,
	}
	if key.TenantID.IsZero() || key.ScopeID.IsZero() || strings.TrimSpace(key.FindingFingerprint) == "" ||
		!validSHA256(key.SourceSHA256) || !validSHA256(key.ContextSHA256) || key.ProposerProvider == "" ||
		key.ProposerModel == "" || (key.VerifierModel == "") != (key.VerifierProvider == "") {
		return ports.FPTriageCacheKey{}, false
	}
	return key, true
}

func decisionForCache(c Critique) ports.FPTriageCachedDecision {
	decision := ports.FPTriageCachedDecision{
		Verdict: string(c.Claim.Verdict), Driver: c.Claim.Driver, Confidence: c.Claim.Confidence,
	}
	if c.Verifier != nil {
		decision.VerifierPresent = true
		decision.VerifierVerdict = string(c.Verifier.Verdict)
		decision.VerifierDriver = c.Verifier.Driver
		decision.VerifierConfidence = c.Verifier.Confidence
	}
	return decision
}

func critiqueFromCache(f finding.Finding, key ports.FPTriageCacheKey, d ports.FPTriageCachedDecision) (Critique, bool) {
	claim := judgment.CritiqueClaim{Verdict: judgment.CritiqueVerdict(d.Verdict), Driver: d.Driver, Confidence: d.Confidence}
	if claim.Validate() != nil || (key.VerifierModel == "") != !d.VerifierPresent {
		return Critique{}, false
	}
	critique := Critique{FindingID: f.ID.String(), DedupKey: f.DedupKey, Claim: claim, VerifyAttempted: key.VerifierModel != ""}
	if d.VerifierPresent {
		verifier := judgment.CritiqueClaim{Verdict: judgment.CritiqueVerdict(d.VerifierVerdict), Driver: d.VerifierDriver, Confidence: d.VerifierConfidence}
		if verifier.Validate() != nil {
			return Critique{}, false
		}
		critique.Verifier = &verifier
	}
	return critique, true
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
