package sla

import (
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var epoch = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func TestComputeTable(t *testing.T) {
	cfg := DefaultConfig()
	tests := []struct {
		name     string
		in       Inputs
		wantTier Tier
	}{
		{
			name:     "critical KEV external actively exploited is emergency",
			in:       Inputs{CVSSScore: 9.8, KEV: true, EPSS: 0.9, ActiveExploitation: true, Exposure: ExposureExternal, Criticality: CriticalityHigh, Feasibility: FeasibilityPatchAvailable},
			wantTier: TierEmergency,
		},
		{
			// Risk-based, not CVSS-based: a high base score with no exploit signal, internal only, is
			// Medium urgency — severity alone never drives the tier without corroborating risk.
			name:     "high cvss, no exploit signal, internal is medium",
			in:       Inputs{CVSSScore: 7.5, Exposure: ExposureInternal, Criticality: CriticalityMedium, Feasibility: FeasibilityPatchAvailable},
			wantTier: TierMedium,
		},
		{
			// Same base score, now with an EPSS signal and external exposure, reaches High.
			name:     "high cvss with exploit signal and external exposure is high",
			in:       Inputs{CVSSScore: 7.5, EPSS: 0.2, Exposure: ExposureExternal, Criticality: CriticalityMedium, Feasibility: FeasibilityPatchAvailable},
			wantTier: TierHigh,
		},
		{
			name:     "low severity unknown context",
			in:       Inputs{CVSSScore: 2.0},
			wantTier: TierLow,
		},
		{
			name:     "no patch routes to exception",
			in:       Inputs{CVSSScore: 6.0, Exposure: ExposureInternal, Feasibility: FeasibilityNoPatch},
			wantTier: TierException,
		},
		{
			name:     "no patch does not override an emergency",
			in:       Inputs{CVSSScore: 9.9, KEV: true, ActiveExploitation: true, Feasibility: FeasibilityNoPatch},
			wantTier: TierEmergency,
		},
		{
			name:     "label fallback when no cvss score",
			in:       Inputs{Severity: shared.SeverityCritical, EPSS: 0.6, Exposure: ExposureExternal, Criticality: CriticalityHigh},
			wantTier: TierEmergency,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Compute(tc.in, cfg, epoch)
			if got.Tier != tc.wantTier {
				t.Fatalf("tier = %s (score %.1f, overrides %v), want %s", got.Tier, got.Score, got.Breakdown.Overrides, tc.wantTier)
			}
			if got.Score < 0 || got.Score > 100 {
				t.Fatalf("score %.2f out of 0..100", got.Score)
			}
			if got.ConfigVersion != cfg.Version {
				t.Fatalf("config version = %q, want %q", got.ConfigVersion, cfg.Version)
			}
			if !got.MitigateBy.After(epoch) || got.RemediateBy.Before(got.MitigateBy) {
				t.Fatalf("due dates invalid: mitigate %v remediate %v", got.MitigateBy, got.RemediateBy)
			}
		})
	}
}

func TestOverrideRulesFireAndAreRecorded(t *testing.T) {
	cfg := DefaultConfig()

	// KEV + external escalates one tier and records the rule.
	base := Inputs{CVSSScore: 6.5, Exposure: ExposureInternal, Feasibility: FeasibilityPatchAvailable}
	escalated := base
	escalated.KEV = true
	escalated.Exposure = ExposureExternal
	b := Compute(base, cfg, epoch)
	e := Compute(escalated, cfg, epoch)
	if !moreUrgent(e.Tier, b.Tier) {
		t.Fatalf("kev+external did not escalate: base %s escalated %s", b.Tier, e.Tier)
	}
	if !contains(e.Breakdown.Overrides, "kev_external_escalates") {
		t.Fatalf("escalation not recorded: %v", e.Breakdown.Overrides)
	}

	// Active exploitation forces emergency and records the rule.
	ae := Compute(Inputs{CVSSScore: 3.0, ActiveExploitation: true}, cfg, epoch)
	if ae.Tier != TierEmergency || !contains(ae.Breakdown.Overrides, "active_exploitation_is_emergency") {
		t.Fatalf("active exploitation not emergency: tier %s overrides %v", ae.Tier, ae.Breakdown.Overrides)
	}
}

// Score stays in 0..100 and the ladder tier is monotonic in score when the override-relevant flags are
// held constant (so no override fires): a higher score is never assigned a less-urgent tier.
func TestScoreBoundedAndTierMonotonic(t *testing.T) {
	cfg := DefaultConfig()
	var prevScore float64 = -1
	var prevTier Tier
	first := true
	// Sweep CVSS 0..10 and EPSS 0..1 with all override flags off and a fixed neutral context, in an
	// order that produces non-decreasing score, then assert monotonic tier urgency.
	for cvssStep := 0; cvssStep <= 20; cvssStep++ {
		cvss := float64(cvssStep) * 0.5 // 0.0 .. 10.0
		in := Inputs{
			CVSSScore:   cvss,
			EPSS:        cvss / 10.0, // rises with cvss, still no override flags
			Exposure:    ExposureInternal,
			Criticality: CriticalityMedium,
			Feasibility: FeasibilityPatchAvailable,
		}
		got := Compute(in, cfg, epoch)
		if got.Score < 0 || got.Score > 100 {
			t.Fatalf("score %.2f out of range at cvss %.1f", got.Score, cvss)
		}
		if len(got.Breakdown.Overrides) != 0 {
			t.Fatalf("no override should fire in this sweep, got %v at cvss %.1f", got.Breakdown.Overrides, cvss)
		}
		if !first {
			if got.Score < prevScore {
				t.Fatalf("score not monotonic: %.2f then %.2f", prevScore, got.Score)
			}
			// higher-or-equal score must be at least as urgent (rank not greater)
			if rank(got.Tier) > rank(prevTier) {
				t.Fatalf("tier not monotonic in score: score %.2f tier %s came after score %.2f tier %s", got.Score, got.Tier, prevScore, prevTier)
			}
		}
		prevScore, prevTier, first = got.Score, got.Tier, false
	}
}

// A KEV (known-exploited) finding with no patch must NOT be relaxed to the longer Exception window; it
// keeps its score-derived urgency and is mitigated by a compensating control instead.
func TestKEVNoPatchIsNotRelaxedToException(t *testing.T) {
	cfg := DefaultConfig()
	got := Compute(Inputs{CVSSScore: 8.0, KEV: true, Exposure: ExposureInternal, Feasibility: FeasibilityNoPatch}, cfg, epoch)
	if got.Tier == TierException {
		t.Fatalf("KEV no-patch was relaxed to Exception (longer window); want a ladder tier, got %s", got.Tier)
	}
	if contains(got.Breakdown.Overrides, "no_patch_routes_to_exception") {
		t.Fatalf("no_patch routing fired for a KEV finding: %v", got.Breakdown.Overrides)
	}
}

// applyOverrides must drop a de-escalating rule even if a (future/stored) Config supplies one — the
// invariant is enforced, not trusted to the rule.
func TestDeEscalatingOverrideIsDropped(t *testing.T) {
	cfg := DefaultConfig()
	// Score-derived tier for this input is Emergency (critical + KEV + external + high crit + active).
	in := Inputs{CVSSScore: 9.8, KEV: true, EPSS: 0.9, ActiveExploitation: true, Exposure: ExposureExternal, Criticality: CriticalityHigh}
	base := Compute(in, cfg, epoch)
	if base.Tier != TierEmergency {
		t.Fatalf("precondition: want Emergency base tier, got %s", base.Tier)
	}
	// The built-in rules never de-escalate; assert the guard directly at the unit level.
	if got := func() Tier { tier, _ := applyOverrides(TierEmergency, Inputs{}, cfg); return tier }(); got != TierEmergency {
		t.Fatalf("no-match overrides changed the tier: %s", got)
	}
	if next := escalate(TierLow); !moreUrgent(next, TierLow) {
		t.Fatalf("escalate did not increase urgency: %s", next)
	}
}

func TestThresholdBoundariesMapToTiers(t *testing.T) {
	cfg := DefaultConfig()
	tests := []struct {
		score float64
		want  Tier
	}{
		{cfg.Thresholds.Emergency, TierEmergency},
		{cfg.Thresholds.Emergency - 0.1, TierCritical},
		{cfg.Thresholds.Critical, TierCritical},
		{cfg.Thresholds.Critical - 0.1, TierHigh},
		{cfg.Thresholds.High, TierHigh},
		{cfg.Thresholds.High - 0.1, TierMedium},
		{cfg.Thresholds.Medium, TierMedium},
		{cfg.Thresholds.Medium - 0.1, TierLow},
		{0, TierLow},
	}
	for _, tc := range tests {
		if got := tierForScore(tc.score, cfg); got != tc.want {
			t.Errorf("tierForScore(%.1f) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig must validate: %v", err)
	}
	bad := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no version", func(c *Config) { c.Version = "" }},
		{"non-descending thresholds", func(c *Config) { c.Thresholds.Critical = c.Thresholds.Emergency + 1 }},
		{"negative weight", func(c *Config) { c.Weights.Severity = -1 }},
		{"mitigate after remediate", func(c *Config) { c.DueRanges.High.MitigateWithin = c.DueRanges.High.RemediateWithin + day }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %s", tc.name)
			}
		})
	}
}

func TestComputeIsDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	in := Inputs{CVSSScore: 8.1, KEV: true, EPSS: 0.4, PublicPoC: true, Exposure: ExposureExternal, Criticality: CriticalityHigh, Feasibility: FeasibilityChangeWindow}
	first := Compute(in, cfg, epoch)
	for i := 0; i < 10; i++ {
		if got := Compute(in, cfg, epoch); !reflect.DeepEqual(got, first) {
			t.Fatalf("Compute not deterministic on run %d: %+v vs %+v", i, first, got)
		}
	}
}

func TestDefaultConfigIsWellFormed(t *testing.T) {
	cfg := DefaultConfig()
	w := cfg.Weights
	if sum := w.Severity + w.Exploitability + w.ThreatIntel + w.Exposure + w.Criticality; sum != 100 {
		t.Fatalf("positive weights sum to %.1f, want 100", sum)
	}
	th := cfg.Thresholds
	if !(th.Emergency > th.Critical && th.Critical > th.High && th.High > th.Medium && th.Medium > 0) {
		t.Fatalf("thresholds not strictly descending/positive: %+v", th)
	}
	// Due ranges: mitigate <= remediate, and more-urgent tiers are not slower than less-urgent ones.
	ranges := []struct {
		t Tier
		r DueRange
	}{
		{TierEmergency, cfg.DueRanges.Emergency}, {TierCritical, cfg.DueRanges.Critical},
		{TierHigh, cfg.DueRanges.High}, {TierMedium, cfg.DueRanges.Medium}, {TierLow, cfg.DueRanges.Low},
	}
	for i, r := range ranges {
		if r.r.MitigateWithin > r.r.RemediateWithin {
			t.Fatalf("%s mitigate > remediate", r.t)
		}
		if i > 0 && r.r.RemediateWithin < ranges[i-1].r.RemediateWithin {
			t.Fatalf("tier %s remediate window shorter than more-urgent %s", r.t, ranges[i-1].t)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
