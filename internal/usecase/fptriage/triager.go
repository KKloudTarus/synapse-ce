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
var _ ports.EvidenceAwareFPTriager = (*Triager)(nil)
var _ ports.EvidenceAwareObservableFPTriager = (*Triager)(nil)

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

func (t *Triager) TriageWithEvidence(ctx context.Context, candidates []finding.Finding, workspaceDir string, evidence map[string][]ports.AITriageEvidenceToken) []ports.AICritique {
	return t.TriageObservedWithEvidence(ctx, candidates, workspaceDir, evidence).Critiques
}

// TriageObserved performs the same fail-safe triage while returning source-free operational metrics.
func (t *Triager) TriageObserved(ctx context.Context, candidates []finding.Finding, workspaceDir string) ports.FPTriageObservedResult {
	return t.triageObserved(ctx, candidates, workspaceDir, nil, false)
}

func (t *Triager) TriageObservedWithEvidence(ctx context.Context, candidates []finding.Finding, workspaceDir string, evidence map[string][]ports.AITriageEvidenceToken) ports.FPTriageObservedResult {
	return t.triageObserved(ctx, candidates, workspaceDir, evidence, true)
}

func (t *Triager) triageObserved(ctx context.Context, candidates []finding.Finding, workspaceDir string, evidence map[string][]ports.AITriageEvidenceToken, evidenceRequired bool) ports.FPTriageObservedResult {
	if t == nil || t.coord == nil || len(candidates) == 0 {
		return ports.FPTriageObservedResult{}
	}
	var reader ports.SourceSnippetReader
	if t.readerFor != nil {
		reader = t.readerFor(workspaceDir)
	}
	prepared := make([]preparedFinding, len(candidates))
	for i := range candidates {
		if evidenceRequired {
			prepared[i] = t.coord.prepareWithEvidence(ctx, candidates[i], reader, evidence[candidates[i].DedupKey], true)
		} else {
			prepared[i] = t.coord.prepare(ctx, candidates[i], reader)
		}
	}
	if t.cache == nil {
		critiques, telemetry := t.coord.assessPreparedObserved(ctx, prepared)
		return ports.FPTriageObservedResult{Critiques: t.mapCritiques(critiques), Telemetry: telemetry}
	}
	crits := make([]Critique, len(candidates))
	misses := make([]preparedFinding, 0, len(candidates))
	missIndexes := make([]int, 0, len(candidates))
	keys := make([]ports.FPTriageCacheKey, len(candidates))
	cacheable := make([]bool, len(candidates))
	cacheHits := 0
	for i := range prepared {
		if prepared[i].evidenceErr != nil {
			crits[i] = Critique{FindingID: candidates[i].ID.String(), DedupKey: candidates[i].DedupKey, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), prepared[i].evidence...), PromptVersion: promptVersionFor(prepared[i]), Err: prepared[i].evidenceErr}
			continue
		}
		key, ok := t.cacheKey(ctx, prepared[i])
		keys[i], cacheable[i] = key, ok
		if ok {
			if cached, hit, err := t.cache.Load(ctx, key); err == nil && hit {
				if critique, valid := critiqueFromCache(prepared[i], key, cached); valid {
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
		version := c.PromptVersion
		if version == "" {
			version = promptVersion
		}
		critique := ports.AICritique{
			FindingID: c.FindingID, DedupKey: c.DedupKey, Verdict: string(c.Claim.Verdict), Driver: c.Claim.Driver,
			Confidence: c.Claim.Confidence, SuspectedFP: c.SuspectedFP(t.minConf), Verified: c.VerifiedConsensus(t.minConf),
			ProposerModel: t.coord.ProposerModel(), ProposerProvider: t.coord.ProposerProvider(), ProposerModelFamily: agent.CanonicalModelID(t.coord.ProposerModel()),
			VerifierModel: t.coord.VerifierModel(), VerifierProvider: t.coord.VerifierProvider(), VerifierModelFamily: agent.CanonicalModelID(t.coord.VerifierModel()), IndependencePolicy: t.coord.IndependencePolicy(),
			PromptVersion: version, ContextEvidence: append([]ports.AITriageEvidenceToken(nil), c.ContextEvidence...), EvidenceTokens: append([]string(nil), c.EvidenceTokens...), VerifierEvidenceTokens: append([]string(nil), c.VerifierEvidenceTokens...),
		}
		if c.Verifier != nil {
			critique.VerifierVerdict, critique.VerifierDriver, critique.VerifierConfidence = string(c.Verifier.Verdict), c.Verifier.Driver, c.Verifier.Confidence
		}
		out = append(out, critique)
	}
	return out
}

func preparedPrompt(p preparedFinding) (string, string) {
	if p.evidenceRequired {
		return userPromptWithEvidence(p.finding, p.snippet, p.evidence), evidencePromptVersion
	}
	return userPrompt(p.finding, p.snippet), promptVersion
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
	prompt, version := preparedPrompt(prepared)
	key := ports.FPTriageCacheKey{
		TenantID:           tenantID,
		ScopeID:            prepared.finding.EngagementID,
		FindingFingerprint: finding.Identity(prepared.finding),
		SourceSHA256:       prepared.sourceSHA256,
		ContextSHA256:      sha256Hex([]byte(prompt)),
		ProposerProvider:   strings.TrimSpace(t.coord.ProposerProvider()),
		ProposerModel:      strings.TrimSpace(t.coord.ProposerModel()),
		VerifierProvider:   strings.TrimSpace(t.coord.VerifierProvider()),
		VerifierModel:      strings.TrimSpace(t.coord.VerifierModel()),
		PromptVersion:      version,
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
	d := ports.FPTriageCachedDecision{Verdict: string(c.Claim.Verdict), Driver: c.Claim.Driver, Confidence: c.Claim.Confidence, EvidenceTokens: append([]string(nil), c.EvidenceTokens...)}
	if c.Verifier != nil {
		d.VerifierPresent, d.VerifierVerdict, d.VerifierDriver, d.VerifierConfidence = true, string(c.Verifier.Verdict), c.Verifier.Driver, c.Verifier.Confidence
		d.VerifierEvidenceTokens = append([]string(nil), c.VerifierEvidenceTokens...)
	}
	return d
}

func critiqueFromCache(prepared preparedFinding, key ports.FPTriageCacheKey, d ports.FPTriageCachedDecision) (Critique, bool) {
	claim := judgment.CritiqueClaim{Verdict: judgment.CritiqueVerdict(d.Verdict), Driver: d.Driver, Confidence: d.Confidence}
	if claim.Validate() != nil || (key.VerifierModel == "") != !d.VerifierPresent {
		return Critique{}, false
	}
	c := Critique{FindingID: prepared.finding.ID.String(), DedupKey: prepared.finding.DedupKey, Claim: claim, VerifyAttempted: key.VerifierModel != "", ContextEvidence: append([]ports.AITriageEvidenceToken(nil), prepared.evidence...), PromptVersion: key.PromptVersion}
	if prepared.evidenceRequired {
		if key.PromptVersion != evidencePromptVersion {
			return Critique{}, false
		}
		citations, err := validateEvidenceCitations(d.EvidenceTokens, prepared.evidence)
		if err != nil || citationSupportsClaim(claim, citations, prepared.evidence) != nil {
			return Critique{}, false
		}
		c.EvidenceTokens = citations
	}
	if d.VerifierPresent {
		verifier := judgment.CritiqueClaim{Verdict: judgment.CritiqueVerdict(d.VerifierVerdict), Driver: d.VerifierDriver, Confidence: d.VerifierConfidence}
		if verifier.Validate() != nil {
			return Critique{}, false
		}
		if prepared.evidenceRequired {
			citations, err := validateEvidenceCitations(d.VerifierEvidenceTokens, prepared.evidence)
			if err != nil || citationSupportsClaim(verifier, citations, prepared.evidence) != nil {
				return Critique{}, false
			}
			c.VerifierEvidenceTokens = citations
		}
		c.Verifier = &verifier
	}
	return c, true
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
