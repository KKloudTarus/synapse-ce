package sla

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Config is the versioned, fully-declarative scoring policy. Everything that determines a tier lives
// here: the factor weights (each is the MAX points that factor can contribute), the score thresholds
// that map a 0..100 score to a tier, the per-tier due-date ranges, and the override rules. Version is
// recorded on every Result, so a stored decision can always be re-derived and explained. A persistence
// layer (Phase 2) may supply a newer version; the built-in DefaultConfig is the floor.
type Config struct {
	Weights    Weights    `json:"weights"`
	Thresholds Thresholds `json:"thresholds"`
	DueRanges  DueRanges  `json:"due_ranges"`
	Version    string     `json:"version"`
}

// Weights are the maximum point contributions of each factor. Severity + Exploitability + ThreatIntel +
// Exposure + Criticality should sum to 100 so a maxed-out finding scores 100 before the (negative)
// feasibility relief. FeasibilityRelief is the maximum urgency reduction for a hard-to-fix finding.
type Weights struct {
	Severity          float64 `json:"severity"`
	Exploitability    float64 `json:"exploitability"`
	ThreatIntel       float64 `json:"threat_intel"`
	Exposure          float64 `json:"exposure"`
	Criticality       float64 `json:"criticality"`
	FeasibilityRelief float64 `json:"feasibility_relief"`
}

// Thresholds are the inclusive lower score bounds for each ladder tier, strictly descending
// (Emergency highest). A score below Medium is Low.
type Thresholds struct {
	Emergency float64 `json:"emergency"`
	Critical  float64 `json:"critical"`
	High      float64 `json:"high"`
	Medium    float64 `json:"medium"`
}

// DueRange is how long a tier has to mitigate (a compensating step) and to fully remediate.
// MitigateWithin <= RemediateWithin.
type DueRange struct {
	MitigateWithin  time.Duration `json:"mitigate_within"`
	RemediateWithin time.Duration `json:"remediate_within"`
}

// DueRanges is the per-tier due-date policy.
type DueRanges struct {
	Emergency DueRange `json:"emergency"`
	Critical  DueRange `json:"critical"`
	High      DueRange `json:"high"`
	Medium    DueRange `json:"medium"`
	Low       DueRange `json:"low"`
	Exception DueRange `json:"exception"`
}

const day = 24 * time.Hour

// DefaultConfig is the built-in policy. Weights sum to 100 (35 + 25 + 10 + 15 + 15); thresholds and due
// ranges follow common risk-based-patching guidance (KEV/critical measured in days, low in months).
// This is the reproducible floor when no stored config is active.
func DefaultConfig() Config {
	return Config{
		Version: "sla-v1",
		Weights: Weights{
			Severity:          35,
			Exploitability:    25,
			ThreatIntel:       10,
			Exposure:          15,
			Criticality:       15,
			FeasibilityRelief: 15,
		},
		Thresholds: Thresholds{
			Emergency: 85,
			Critical:  70,
			High:      50,
			Medium:    30,
		},
		DueRanges: DueRanges{
			Emergency: DueRange{MitigateWithin: 1 * day, RemediateWithin: 7 * day},
			Critical:  DueRange{MitigateWithin: 3 * day, RemediateWithin: 15 * day},
			High:      DueRange{MitigateWithin: 7 * day, RemediateWithin: 30 * day},
			Medium:    DueRange{MitigateWithin: 30 * day, RemediateWithin: 90 * day},
			Low:       DueRange{MitigateWithin: 90 * day, RemediateWithin: 180 * day},
			Exception: DueRange{MitigateWithin: 30 * day, RemediateWithin: 180 * day},
		},
	}
}

// Validate checks a Config is well-formed: a version is set, the positive factor weights are
// non-negative, the score thresholds are strictly descending and positive, and every tier's due range
// has mitigate <= remediate. Compute is robust to a malformed Config (the score is clamped), so Phase 0
// does not call this on the built-in DefaultConfig; it exists so a Phase-2 persistence layer can reject
// a stored/operator-supplied Config at the edge (returning shared.ErrValidation) rather than silently
// scoring against a degenerate policy.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("%w: sla config needs a version", shared.ErrValidation)
	}
	w := c.Weights
	for name, v := range map[string]float64{
		"severity": w.Severity, "exploitability": w.Exploitability, "threat_intel": w.ThreatIntel,
		"exposure": w.Exposure, "criticality": w.Criticality, "feasibility_relief": w.FeasibilityRelief,
	} {
		if v < 0 {
			return fmt.Errorf("%w: sla weight %q is negative", shared.ErrValidation, name)
		}
	}
	th := c.Thresholds
	if !(th.Emergency > th.Critical && th.Critical > th.High && th.High > th.Medium && th.Medium > 0) {
		return fmt.Errorf("%w: sla thresholds must be strictly descending and positive", shared.ErrValidation)
	}
	for name, r := range map[string]DueRange{
		"emergency": c.DueRanges.Emergency, "critical": c.DueRanges.Critical, "high": c.DueRanges.High,
		"medium": c.DueRanges.Medium, "low": c.DueRanges.Low, "exception": c.DueRanges.Exception,
	} {
		if r.MitigateWithin < 0 || r.RemediateWithin < 0 || r.MitigateWithin > r.RemediateWithin {
			return fmt.Errorf("%w: sla due range %q must have 0 <= mitigate <= remediate", shared.ErrValidation, name)
		}
	}
	return nil
}

// severityWeight maps a severity band to a 0..1 multiplier of the Severity weight.
func (Config) severityWeight(band shared.Severity) float64 {
	switch band {
	case shared.SeverityCritical:
		return 1.0
	case shared.SeverityHigh:
		return 0.75
	case shared.SeverityMedium:
		return 0.5
	case shared.SeverityLow:
		return 0.25
	default: // Info / unknown
		return 0.0
	}
}

func (c Config) dueRange(t Tier) DueRange {
	switch t {
	case TierEmergency:
		return c.DueRanges.Emergency
	case TierCritical:
		return c.DueRanges.Critical
	case TierHigh:
		return c.DueRanges.High
	case TierMedium:
		return c.DueRanges.Medium
	case TierLow:
		return c.DueRanges.Low
	case TierException:
		return c.DueRanges.Exception
	default:
		return c.DueRanges.Low
	}
}

// overrideRule is a deterministic escalation/routing rule. when decides if it fires for the inputs;
// apply maps the current tier to the (equal-or-more-urgent, or Exception) tier. Rules never
// de-escalate below the score-derived tier.
type overrideRule struct {
	name  string
	when  func(Inputs) bool
	apply func(Tier) Tier
}

// overrideRules is the fixed-order rule set for the built-in policy. Order is deterministic so the fired
// list and final tier are reproducible.
func (Config) overrideRules() []overrideRule {
	return []overrideRule{
		{
			// Actively exploited in the wild is always an emergency, whatever the score said.
			name:  "active_exploitation_is_emergency",
			when:  func(in Inputs) bool { return in.ActiveExploitation },
			apply: func(Tier) Tier { return TierEmergency },
		},
		{
			// A known-exploited vulnerability on an internet-facing asset escalates one tier.
			name:  "kev_external_escalates",
			when:  func(in Inputs) bool { return in.KEV && in.Exposure == ExposureExternal },
			apply: escalate,
		},
		{
			// Nothing to patch to: route to a governed Exception (accept-risk with an expiry). This is
			// deliberately NOT applied to a KEV (known-exploited) finding: Exception's due dates are
			// longer than a Critical/High window, and relaxing the clock on a vulnerability being
			// exploited in the wild is the wrong direction — a KEV no-patch keeps its score-derived
			// urgency and is mitigated by a compensating control instead. The Emergency guard covers the
			// active-exploitation and score-derived-emergency paths for the same reason.
			name: "no_patch_routes_to_exception",
			when: func(in Inputs) bool { return in.Feasibility == FeasibilityNoPatch && !in.KEV },
			apply: func(t Tier) Tier {
				if t == TierEmergency {
					return t
				}
				return TierException
			},
		},
	}
}
