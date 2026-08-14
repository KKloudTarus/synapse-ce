// Package riskstory is the pure, deterministic domain for the unified per-asset risk story (issue
// #427): one narrative per asset assembled from records already produced by the other pillars — the
// asset inventory (#431), the findings of every engine + their reachability verdicts, the attack-path
// graph (#419), runtime detections (#423), and the continuous vulnerability occurrences/assessments
// (#514). It CREATES no data and owns no table; it only correlates and orders existing records.
//
// Two honesty invariants are enforced here, not left to the caller:
//   - Every element references the backing record that produced it (Provenance). An element with no
//     provenance fails Validate — the story is never allowed to show something it cannot trace to
//     evidence.
//   - Uncertainty is carried, never flattened. Unknown reachability, an inferred edge, a sampled
//     telemetry window, and staleness travel as Qualifiers on the relevant element.
//
// Assembly is deterministic: the same records produce the same story in the same order, so a story can
// be diffed over time. There is NO LLM in this package (an arch test asserts it); prose narration stays
// in the human-gated writeupdraft path, outside the report.
package riskstory

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Provenance is the backing record an element is derived from. Every element carries one; the story is
// navigable to its evidence through it.
type Provenance struct {
	Kind string    `json:"kind"` // one of the ProvKind* constants
	ID   shared.ID `json:"id"`
}

// Backing-record kinds. A Provenance with any other kind, or an empty ID, fails validation.
const (
	ProvAsset        = "asset"
	ProvAssetEdge    = "asset_edge"
	ProvFinding      = "finding"
	ProvReachability = "reachability"
	ProvAttackPath   = "attack_path"
	ProvDetection    = "detection"
	ProvOccurrence   = "occurrence"
	ProvAssessment   = "assessment"
)

// Qualifier constants — the closed set of uncertainty markers carried from inputs. They are surfaced so
// an uncertain input is never presented as certain.
const (
	QualReachabilityUnknown = "reachability_unknown" // a reachability verdict of "unknown"
	QualInferredEdge        = "inferred_edge"        // an exposure/attack-path edge with inferred (not observed) confidence
	QualSampledWindow       = "sampled_telemetry_window"
	QualStale               = "stale" // last-observed older than the freshness target (see Fresh)
)

func validProvKind(k string) bool {
	switch k {
	case ProvAsset, ProvAssetEdge, ProvFinding, ProvReachability, ProvAttackPath, ProvDetection, ProvOccurrence, ProvAssessment:
		return true
	default:
		return false
	}
}

func (p Provenance) valid() bool { return validProvKind(p.Kind) && p.ID != "" }

// AssetFacts is the identity header of the story: what the asset IS.
type AssetFacts struct {
	Kind       string     `json:"kind"`
	Key        string     `json:"key"`
	Name       string     `json:"name"`
	Provenance Provenance `json:"provenance"` // the asset record itself (ProvAsset)
}

// ExposureElement is one way the asset is exposed (an exposure edge/asset). Confidence carries the
// observed-vs-inferred distinction; an inferred edge is qualified.
type ExposureElement struct {
	Description string     `json:"description"`
	Confidence  string     `json:"confidence"` // "observed" | "inferred"
	Provenance  Provenance `json:"provenance"` // ProvAssetEdge (or ProvAsset for an exposure asset)
	Qualifiers  []string   `json:"qualifiers,omitempty"`
}

// FindingElement is one finding attributed to the asset, enriched with its reachability verdict and its
// corroboration signals (on an attack path, seen under attack at runtime). Evidence carries the extra
// backing records (the reachability judgment, the attack-path binding, the vulnerability occurrence and
// its immutable assessment) so the element is fully traceable.
type FindingElement struct {
	FindingID    shared.ID `json:"finding_id"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	Priority     int       `json:"priority"` // the existing 1..5 RiskPriority (1 = act now); 0 = unset
	RiskScore    float64   `json:"risk_score"`
	KEV          bool      `json:"kev"`
	Reachability string    `json:"reachability"` // "reachable"|"not_reachable"|"unknown"|""

	// Corroboration signals. Corroboration lists the ones that are true, and RankReason explains why the
	// element ranks where it does. These RAISE the ordering over an equal-priority finding without them;
	// they do NOT mutate Priority (the promotion gate #428 owns priority mutation).
	Reachable       bool     `json:"reachable"`
	OnAttackPath    bool     `json:"on_attack_path"`
	SeenUnderAttack bool     `json:"seen_under_attack"`
	Corroboration   []string `json:"corroboration,omitempty"`
	RankReason      string   `json:"rank_reason,omitempty"`

	LastObserved time.Time    `json:"last_observed"`
	Stale        bool         `json:"stale"`
	Provenance   Provenance   `json:"provenance"` // ProvFinding
	Evidence     []Provenance `json:"evidence,omitempty"`
	Qualifiers   []string     `json:"qualifiers,omitempty"`
}

// corroborationCount is the number of corroborating signals; more signals raise the ordering.
func (f FindingElement) corroborationCount() int {
	n := 0
	for _, b := range []bool{f.Reachable, f.OnAttackPath, f.SeenUnderAttack} {
		if b {
			n++
		}
	}
	return n
}

// PathElement is an attack path the asset sits on. An inferred path is qualified.
type PathElement struct {
	Summary    string     `json:"summary"`
	Confidence string     `json:"confidence"` // "observed" | "inferred"
	Provenance Provenance `json:"provenance"` // ProvAttackPath
	Qualifiers []string   `json:"qualifiers,omitempty"`
}

// DetectionElement is a runtime detection observed on the asset.
type DetectionElement struct {
	RuleID     string     `json:"rule_id"`
	Severity   string     `json:"severity"`
	Observed   time.Time  `json:"observed"`
	Stale      bool       `json:"stale"`
	Provenance Provenance `json:"provenance"` // ProvDetection
	Qualifiers []string   `json:"qualifiers,omitempty"`
}

// Story is the assembled per-asset narrative. Score is the asset's worst (numerically lowest) finding
// priority — the existing model, surfaced; corroboration raises the ORDER of findings within the story,
// shown per element, rather than replacing the score.
type Story struct {
	AssetID     shared.ID          `json:"asset_id"`
	TenantID    shared.ID          `json:"tenant_id"`
	Identity    AssetFacts         `json:"identity"`
	Exposure    []ExposureElement  `json:"exposure"`
	Findings    []FindingElement   `json:"findings"`
	Paths       []PathElement      `json:"paths"`
	Detections  []DetectionElement `json:"detections"`
	Score       int                `json:"score"`
	Qualifiers  []string           `json:"qualifiers,omitempty"`
	GeneratedAt time.Time          `json:"generated_at"`
}

// Inputs is the correlated, per-asset raw material the use case hands to Assemble. Assemble owns the
// deterministic ordering, corroboration ranking, story-level rollup, and validation.
type Inputs struct {
	AssetID     shared.ID
	TenantID    shared.ID
	Identity    AssetFacts
	Exposure    []ExposureElement
	Findings    []FindingElement
	Paths       []PathElement
	Detections  []DetectionElement
	GeneratedAt time.Time
}

// Assemble deterministically orders and validates the correlated inputs into a Story. It computes the
// per-finding corroboration ordering + RankReason, the asset-level Score, and the story-level Qualifier
// rollup. It returns shared.ErrValidation if any element lacks a backing record.
func Assemble(in Inputs) (Story, error) {
	s := Story{
		AssetID: in.AssetID, TenantID: in.TenantID, Identity: in.Identity,
		Exposure:    append([]ExposureElement(nil), in.Exposure...),
		Findings:    append([]FindingElement(nil), in.Findings...),
		Paths:       append([]PathElement(nil), in.Paths...),
		Detections:  append([]DetectionElement(nil), in.Detections...),
		GeneratedAt: in.GeneratedAt.UTC(),
	}

	// Corroboration reason per finding (deterministic order of reasons). A fresh slice is assigned rather
	// than reusing any caller-provided backing array, keeping Assemble free of input aliasing.
	for i := range s.Findings {
		f := &s.Findings[i]
		var reasons []string
		if f.Reachable {
			reasons = append(reasons, "reachable")
		}
		if f.OnAttackPath {
			reasons = append(reasons, "on_attack_path")
		}
		if f.SeenUnderAttack {
			reasons = append(reasons, "seen_under_attack")
		}
		f.Corroboration = reasons
		if len(reasons) == 0 {
			f.RankReason = "base priority; no corroborating signals"
		} else {
			f.RankReason = "raised by corroboration: " + strings.Join(reasons, " + ")
		}
	}

	// Deterministic ordering. Findings: by effective priority (existing model), then more corroboration
	// first, then higher RiskScore, then id — so an equal-priority finding WITH corroboration outranks
	// one without, and the order is stable/diffable.
	sort.SliceStable(s.Findings, func(a, b int) bool {
		fa, fb := s.Findings[a], s.Findings[b]
		pa, pb := effectivePriority(fa.Priority), effectivePriority(fb.Priority)
		if pa != pb {
			return pa < pb
		}
		if ca, cb := fa.corroborationCount(), fb.corroborationCount(); ca != cb {
			return ca > cb
		}
		if fa.RiskScore != fb.RiskScore {
			return fa.RiskScore > fb.RiskScore
		}
		return fa.FindingID < fb.FindingID
	})
	sort.SliceStable(s.Exposure, func(a, b int) bool {
		return s.Exposure[a].Provenance.ID < s.Exposure[b].Provenance.ID
	})
	sort.SliceStable(s.Paths, func(a, b int) bool {
		return s.Paths[a].Provenance.ID < s.Paths[b].Provenance.ID
	})
	sort.SliceStable(s.Detections, func(a, b int) bool {
		da, db := s.Detections[a], s.Detections[b]
		if da.RuleID != db.RuleID {
			return da.RuleID < db.RuleID
		}
		if !da.Observed.Equal(db.Observed) {
			return da.Observed.Before(db.Observed)
		}
		return da.Provenance.ID < db.Provenance.ID
	})

	s.Score = assetScore(s.Findings)
	s.Qualifiers = rollupQualifiers(s)

	if err := s.Validate(); err != nil {
		return Story{}, err
	}
	return s, nil
}

// effectivePriority maps an unset priority (0) to the lowest bucket so it sorts last, keeping the
// existing 1..5 model intact.
func effectivePriority(p int) int {
	if p < 1 {
		return 6
	}
	return p
}

// assetScore is the asset's worst (numerically lowest) finding priority, or 0 when the asset has no
// findings. This is the existing model surfaced at the asset level; corroboration is shown per finding.
func assetScore(fs []FindingElement) int {
	best := 0
	for _, f := range fs {
		p := effectivePriority(f.Priority)
		if p > 5 {
			continue
		}
		if best == 0 || p < best {
			best = p
		}
	}
	return best
}

// rollupQualifiers gathers the distinct element-level qualifiers to the story level, in deterministic
// order, so a reader sees at a glance that the story carries uncertainty.
func rollupQualifiers(s Story) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(qs []string) {
		for _, q := range qs {
			if _, dup := seen[q]; dup {
				continue
			}
			seen[q] = struct{}{}
			out = append(out, q)
		}
	}
	for _, e := range s.Exposure {
		add(e.Qualifiers)
	}
	for _, f := range s.Findings {
		add(f.Qualifiers)
	}
	for _, p := range s.Paths {
		add(p.Qualifiers)
	}
	for _, d := range s.Detections {
		add(d.Qualifiers)
	}
	sort.Strings(out)
	return out
}

// Validate enforces the honesty invariants: the story has an asset, its identity references the asset
// record, and every element references a valid backing record (kind + non-empty id). Findings' extra
// evidence refs must also be valid.
func (s Story) Validate() error {
	if s.AssetID == "" || s.TenantID == "" {
		return fmt.Errorf("%w: risk story is missing asset/tenant scope", shared.ErrValidation)
	}
	if s.Identity.Provenance.Kind != ProvAsset || s.Identity.Provenance.ID == "" {
		return fmt.Errorf("%w: risk story identity must reference the asset record", shared.ErrValidation)
	}
	for i, e := range s.Exposure {
		if !e.Provenance.valid() {
			return fmt.Errorf("%w: exposure element %d has no backing record", shared.ErrValidation, i)
		}
	}
	for i, f := range s.Findings {
		if f.FindingID == "" || f.Provenance.Kind != ProvFinding || f.Provenance.ID == "" {
			return fmt.Errorf("%w: finding element %d has no backing finding record", shared.ErrValidation, i)
		}
		for j, ev := range f.Evidence {
			if !ev.valid() {
				return fmt.Errorf("%w: finding element %d evidence %d has no backing record", shared.ErrValidation, i, j)
			}
		}
	}
	for i, p := range s.Paths {
		if !p.Provenance.valid() {
			return fmt.Errorf("%w: path element %d has no backing record", shared.ErrValidation, i)
		}
	}
	for i, d := range s.Detections {
		if !d.Provenance.valid() {
			return fmt.Errorf("%w: detection element %d has no backing record", shared.ErrValidation, i)
		}
	}
	return nil
}

// EvidenceRefs returns every backing record the story references — identity, exposures, findings and
// their evidence, paths and detections — deduplicated and deterministically ordered. This is the
// auditor/report export: a risk narrative a customer cannot trace back to evidence is not usable in
// this project's report path, so the export always carries the full provenance set.
func (s Story) EvidenceRefs() []Provenance {
	seen := map[Provenance]struct{}{}
	var out []Provenance
	add := func(p Provenance) {
		if p.ID == "" {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	add(s.Identity.Provenance)
	for _, e := range s.Exposure {
		add(e.Provenance)
	}
	for _, f := range s.Findings {
		add(f.Provenance)
		for _, ev := range f.Evidence {
			add(ev)
		}
	}
	for _, p := range s.Paths {
		add(p.Provenance)
	}
	for _, d := range s.Detections {
		add(d.Provenance)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Kind != out[b].Kind {
			return out[a].Kind < out[b].Kind
		}
		return out[a].ID < out[b].ID
	})
	return out
}

// Fresh mirrors the fleet-coverage freshness rule (#413): a zero last-observed time is never fresh; a
// non-positive target means "no freshness requirement" (fresh once observed); otherwise fresh iff the
// gap is within the target. Callers mark an element Stale when it is not fresh.
func Fresh(lastObserved, now time.Time, target time.Duration) bool {
	if lastObserved.IsZero() {
		return false
	}
	if target <= 0 {
		return true
	}
	gap := now.Sub(lastObserved)
	if gap < 0 {
		gap = -gap
	}
	return gap <= target
}
