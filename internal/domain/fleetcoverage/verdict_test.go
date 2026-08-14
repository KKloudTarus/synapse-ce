package fleetcoverage

import (
	"testing"
	"time"
)

// base is a fully-covered signal set; each test flips exactly the fields under test.
func base() Signals {
	return Signals{Authorized: true, AgentAvailable: true, Refused: false, Assessed: true, Fresh: true, Complete: true}
}

func TestResolveEachVerdict(t *testing.T) {
	cases := []struct {
		name string
		mut  func(Signals) Signals
		want Verdict
	}{
		{"covered", func(s Signals) Signals { return s }, VerdictCovered},
		{"unauthorized", func(s Signals) Signals { s.Authorized = false; return s }, VerdictUnauthorized},
		{"agent_missing", func(s Signals) Signals { s.AgentAvailable = false; return s }, VerdictAgentMissing},
		{"refused", func(s Signals) Signals { s.Refused = true; s.RefusedReason = "scope"; return s }, VerdictRefused},
		{"never", func(s Signals) Signals { s.Assessed = false; return s }, VerdictNever},
		{"stale", func(s Signals) Signals { s.Fresh = false; return s }, VerdictStale},
		{"partial", func(s Signals) Signals { s.Complete = false; return s }, VerdictPartial},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := Resolve(c.mut(base()))
			if got != c.want {
				t.Fatalf("Resolve = %q, want %q", got, c.want)
			}
			if c.want == VerdictRefused && detail != "scope" {
				t.Fatalf("refused must carry its reason, got %q", detail)
			}
		})
	}
}

// TestResolveAmbiguousPairs asserts the precedence for every pair where two conditions are true at
// once: the higher-priority verdict must win. This is the "an unauthorized asset is never merely
// stale" guarantee, exhaustively.
func TestResolveAmbiguousPairs(t *testing.T) {
	// For each ordered pair (hi, lo) with hi earlier in the resolution order, construct a signal set
	// where BOTH the hi and lo conditions hold, and assert hi wins.
	set := map[Verdict]func(Signals) Signals{
		VerdictUnauthorized: func(s Signals) Signals { s.Authorized = false; return s },
		VerdictAgentMissing: func(s Signals) Signals { s.AgentAvailable = false; return s },
		VerdictRefused:      func(s Signals) Signals { s.Refused = true; return s },
		VerdictNever:        func(s Signals) Signals { s.Assessed = false; return s },
		VerdictStale:        func(s Signals) Signals { s.Fresh = false; return s },
		VerdictPartial:      func(s Signals) Signals { s.Complete = false; return s },
	}
	order := ResolutionOrder()
	for i := 0; i < len(order); i++ {
		for j := i + 1; j < len(order); j++ {
			hi, lo := order[i], order[j]
			hiMut, okHi := set[hi]
			loMut, okLo := set[lo]
			if !okHi || !okLo { // covered has no mutator (it's the default)
				continue
			}
			s := loMut(hiMut(base())) // both conditions true
			got, _ := Resolve(s)
			if got != hi {
				t.Fatalf("pair (%s > %s): both conditions set, expected %s to win, got %s", hi, lo, hi, got)
			}
		}
	}
}

func TestPassingOnlyCovered(t *testing.T) {
	for _, v := range ResolutionOrder() {
		if v.Passing() != (v == VerdictCovered) {
			t.Fatalf("%q.Passing() must be true only for covered", v)
		}
	}
}

func TestIsFresh(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	if IsFresh(time.Time{}, now, time.Hour) {
		t.Error("never-assessed (zero) must not be fresh")
	}
	if !IsFresh(now.Add(-30*time.Minute), now, time.Hour) {
		t.Error("within target must be fresh")
	}
	if IsFresh(now.Add(-2*time.Hour), now, time.Hour) {
		t.Error("older than target must be stale")
	}
	if !IsFresh(now.Add(-100*time.Hour), now, 0) {
		t.Error("non-positive target means no freshness requirement (fresh once assessed)")
	}
}

func TestAgentStateFrom(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	if got := AgentStateFrom(now, now, time.Hour, true, false); got != AgentRevoked {
		t.Errorf("revoked must dominate, got %q", got)
	}
	if got := AgentStateFrom(now, now, time.Hour, false, true); got != AgentDecommissioned {
		t.Errorf("decommissioned must be surfaced distinctly, got %q", got)
	}
	if got := AgentStateFrom(now, now, time.Hour, true, true); got != AgentRevoked {
		t.Errorf("revoked must take precedence over decommissioned, got %q", got)
	}
	if AgentDecommissioned.Live() || !AgentDecommissioned.Valid() {
		t.Errorf("decommissioned must be valid and non-live")
	}
	if got := AgentStateFrom(time.Time{}, now, time.Hour, false, false); got != AgentStale {
		t.Errorf("never-seen must be stale, got %q", got)
	}
	if got := AgentStateFrom(now.Add(-30*time.Minute), now, time.Hour, false, false); got != AgentHealthy {
		t.Errorf("recent must be healthy, got %q", got)
	}
	if got := AgentStateFrom(now.Add(-2*time.Hour), now, time.Hour, false, false); got != AgentStale {
		t.Errorf("beyond threshold must be stale, got %q", got)
	}
	if got := AgentStateFrom(now.Add(-1000*time.Hour), now, 0, false, false); got != AgentHealthy {
		t.Errorf("disabled threshold must not force stale, got %q", got)
	}
	if AgentHealthy.Live() != true || AgentStale.Live() || AgentRevoked.Live() {
		t.Error("only healthy agents are Live")
	}
}
