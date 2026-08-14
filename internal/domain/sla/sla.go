// Package sla is the pure, deterministic domain for the risk-based remediation SLA (issue #80,
// Phase 0). Given a finding's real risk context it assigns a remediation tier, a bounded 0..100
// urgency score with an explainable breakdown, and concrete mitigate-by / remediate-by due dates.
//
// It stays inside the golden rules: pure Go (no I/O, no framework, no DB), the clock is injected, and
// the output is fully determined by the inputs plus a VERSIONED Config — so a decision is reproducible
// and every result records the config version that produced it. There is NO LLM in this path; ordering
// by risk is not governance, and this package supplies the governance (due dates + tiering) on top of
// the existing KEV -> EPSS -> CVSS ordering without changing it.
package sla

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Tier is the remediation SLA tier. Emergency..Low form a severity ladder (Emergency most urgent);
// Exception is off-ladder — it is only ever reached by an override rule (e.g. no patch is available),
// never by the score, and it carries the longest due dates plus a required governance follow-up.
type Tier string

const (
	TierEmergency Tier = "emergency"
	TierCritical  Tier = "critical"
	TierHigh      Tier = "high"
	TierMedium    Tier = "medium"
	TierLow       Tier = "low"
	TierException Tier = "exception"
)

// ladder is the on-score ordering, most urgent first. rank(t) is the index; a lower rank is more
// urgent. Exception is deliberately absent — it is not comparable on the score ladder.
var ladder = []Tier{TierEmergency, TierCritical, TierHigh, TierMedium, TierLow}

func rank(t Tier) int {
	for i, l := range ladder {
		if l == t {
			return i
		}
	}
	return len(ladder) // Exception / unknown sort last (least urgent on the ladder)
}

// moreUrgent reports whether a is strictly more urgent than b on the ladder.
func moreUrgent(a, b Tier) bool { return rank(a) < rank(b) }

// escalate returns the next-more-urgent ladder tier, saturating at Emergency. Exception is returned
// unchanged (it is off-ladder).
func escalate(t Tier) Tier {
	if t == TierException {
		return t
	}
	r := rank(t)
	if r <= 0 {
		return TierEmergency
	}
	if r >= len(ladder) {
		return TierLow
	}
	return ladder[r-1]
}

// Exposure is how reachable the asset is from an untrusted network. Unknown is the neutral default so
// the feature works before any asset model exists.
type Exposure string

const (
	ExposureUnknown  Exposure = ""
	ExposureInternal Exposure = "internal"
	ExposureExternal Exposure = "external"
)

// Criticality is the business importance of the asset. Unknown is the neutral default.
type Criticality string

const (
	CriticalityUnknown Criticality = ""
	CriticalityLow     Criticality = "low"
	CriticalityMedium  Criticality = "medium"
	CriticalityHigh    Criticality = "high"
)

// Feasibility is how readily the finding can actually be remediated. PatchAvailable is neutral; the
// others reduce urgency and NoPatch routes to the Exception tier (there is nothing to remediate to, so
// the honest outcome is a governed acceptance, not an impossible due date).
type Feasibility string

const (
	FeasibilityUnknown             Feasibility = ""
	FeasibilityPatchAvailable      Feasibility = "patch_available"
	FeasibilityChangeWindow        Feasibility = "change_window"
	FeasibilityCompensatingControl Feasibility = "compensating_control"
	FeasibilityNoPatch             Feasibility = "no_patch"
)

// EPSS bands. EPSS is a 0..1 probability; the score model uses coarse bands so a decision does not swing
// on noise in the third decimal place.
const (
	epssHighBand   = 0.5
	epssMediumBand = 0.1
	epssLowBand    = 0.01
)

// Inputs is the risk context of one finding. Every field defaults to a neutral value, so a partial
// context (common before an asset model is wired) yields a defensible, reproducible result rather than
// an error.
type Inputs struct {
	Severity           shared.Severity
	CVSSScore          float64 // 0..10 base score; when 0 the Severity label is used instead
	KEV                bool    // CISA Known-Exploited
	EPSS               float64 // 0..1 exploit-prediction probability
	PublicPoC          bool
	ActiveExploitation bool
	Criticality        Criticality
	Exposure           Exposure
	Feasibility        Feasibility
}

// Breakdown is the explainable decomposition of the score: each factor's contribution, plus the names
// of every override rule that fired. It exists so a tier can be justified to an auditor.
type Breakdown struct {
	Severity       float64  `json:"severity"`
	Exploitability float64  `json:"exploitability"`
	ThreatIntel    float64  `json:"threat_intel"`
	Exposure       float64  `json:"exposure"`
	Criticality    float64  `json:"criticality"`
	Feasibility    float64  `json:"feasibility"` // an adjustment; may be negative
	Overrides      []string `json:"overrides,omitempty"`
}

// Result is the computed SLA decision for one finding. Score is bounded 0..100; MitigateBy/RemediateBy
// are absolute due dates (now + the tier's range); ConfigVersion records exactly which Config produced
// it so the decision is reproducible and explainable later.
type Result struct {
	Tier          Tier      `json:"tier"`
	Score         float64   `json:"score"`
	Breakdown     Breakdown `json:"breakdown"`
	MitigateBy    time.Time `json:"mitigate_by"`
	RemediateBy   time.Time `json:"remediate_by"`
	Reason        string    `json:"reason"`
	ComputedAt    time.Time `json:"computed_at"`
	ConfigVersion string    `json:"config_version"`
}

// Compute deterministically scores the inputs against the config and returns the tier, breakdown, and
// due dates. It performs no I/O; the same inputs, config, and clock always produce the same Result.
func Compute(in Inputs, cfg Config, now time.Time) Result {
	now = now.UTC()
	b := Breakdown{
		Severity:       severityFactor(in, cfg),
		Exploitability: exploitabilityFactor(in, cfg),
		ThreatIntel:    threatIntelFactor(in, cfg),
		Exposure:       exposureFactor(in, cfg),
		Criticality:    criticalityFactor(in, cfg),
		Feasibility:    feasibilityFactor(in, cfg),
	}
	score := clamp(b.Severity+b.Exploitability+b.ThreatIntel+b.Exposure+b.Criticality+b.Feasibility, 0, 100)

	tier := tierForScore(score, cfg)
	tier, b.Overrides = applyOverrides(tier, in, cfg)

	due := cfg.dueRange(tier)
	return Result{
		Tier:          tier,
		Score:         score,
		Breakdown:     b,
		MitigateBy:    now.Add(due.MitigateWithin),
		RemediateBy:   now.Add(due.RemediateWithin),
		Reason:        reasonFor(tier, b),
		ComputedAt:    now,
		ConfigVersion: cfg.Version,
	}
}

func severityFactor(in Inputs, cfg Config) float64 {
	band := in.severityBand()
	return cfg.Weights.Severity * cfg.severityWeight(band)
}

// severityBand prefers the numeric CVSS base score (more precise) and falls back to the Severity label
// when no score is present.
func (in Inputs) severityBand() shared.Severity {
	if in.CVSSScore > 0 {
		return shared.SeverityFromScore(in.CVSSScore)
	}
	if in.Severity != "" {
		return in.Severity
	}
	return shared.SeverityInfo
}

func exploitabilityFactor(in Inputs, cfg Config) float64 {
	// KEV dominates: a known-exploited vulnerability is maximally exploitable regardless of EPSS.
	if in.KEV {
		return cfg.Weights.Exploitability
	}
	switch {
	case in.EPSS >= epssHighBand:
		return cfg.Weights.Exploitability
	case in.EPSS >= epssMediumBand:
		return cfg.Weights.Exploitability * 0.6
	case in.EPSS >= epssLowBand:
		return cfg.Weights.Exploitability * 0.3
	default:
		return 0
	}
}

func threatIntelFactor(in Inputs, cfg Config) float64 {
	f := 0.0
	if in.ActiveExploitation {
		f += cfg.Weights.ThreatIntel
	} else if in.PublicPoC {
		f += cfg.Weights.ThreatIntel * 0.5
	}
	return f
}

func exposureFactor(in Inputs, cfg Config) float64 {
	switch in.Exposure {
	case ExposureExternal:
		return cfg.Weights.Exposure
	case ExposureInternal:
		return cfg.Weights.Exposure * 0.4
	default: // Unknown -> neutral middle
		return cfg.Weights.Exposure * 0.5
	}
}

func criticalityFactor(in Inputs, cfg Config) float64 {
	switch in.Criticality {
	case CriticalityHigh:
		return cfg.Weights.Criticality
	case CriticalityMedium:
		return cfg.Weights.Criticality * 0.6
	case CriticalityLow:
		return cfg.Weights.Criticality * 0.2
	default: // Unknown -> neutral middle
		return cfg.Weights.Criticality * 0.5
	}
}

// feasibilityFactor is an ADJUSTMENT (<= 0): a finding you cannot readily fix is less urgent to chase
// on the clock (NoPatch is instead routed to the Exception tier by an override). PatchAvailable and
// Unknown are neutral.
func feasibilityFactor(in Inputs, cfg Config) float64 {
	switch in.Feasibility {
	case FeasibilityCompensatingControl:
		return -cfg.Weights.FeasibilityRelief
	case FeasibilityChangeWindow:
		return -cfg.Weights.FeasibilityRelief * 0.5
	default:
		return 0
	}
}

func tierForScore(score float64, cfg Config) Tier {
	// Descending thresholds; the first the score meets wins. Below the lowest threshold is Low.
	switch {
	case score >= cfg.Thresholds.Emergency:
		return TierEmergency
	case score >= cfg.Thresholds.Critical:
		return TierCritical
	case score >= cfg.Thresholds.High:
		return TierHigh
	case score >= cfg.Thresholds.Medium:
		return TierMedium
	default:
		return TierLow
	}
}

// applyOverrides applies the deterministic override rules to the score-derived tier. The escalate-or-
// Exception invariant is ENFORCED here, not merely trusted to each rule: a rule's proposed tier is
// accepted only if it is at least as urgent as the current tier, or is the governed Exception routing.
// A rule that would DE-ESCALATE below the score-derived urgency is ignored (a security tool must never
// silently relax a finding's urgency), even if a future or stored Config supplies such a rule. Only a
// rule that actually changes the tier is recorded, so the breakdown/Reason never claims a rule drove
// the tier when it was a no-op. Rules run in a fixed order for determinism.
func applyOverrides(tier Tier, in Inputs, cfg Config) (Tier, []string) {
	var fired []string
	for _, rule := range cfg.overrideRules() {
		if !rule.when(in) {
			continue
		}
		next := rule.apply(tier)
		// Accept only an escalation (equal-or-more-urgent) or the Exception routing; drop a de-escalation.
		if next != TierException && moreUrgent(tier, next) {
			continue
		}
		if next != tier {
			tier = next
			fired = append(fired, rule.name)
		}
	}
	return tier, fired
}

func reasonFor(tier Tier, b Breakdown) string {
	if len(b.Overrides) > 0 {
		return fmt.Sprintf("tier %s (overrides: %s)", tier, strings.Join(b.Overrides, ", "))
	}
	return fmt.Sprintf("tier %s from score", tier)
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
