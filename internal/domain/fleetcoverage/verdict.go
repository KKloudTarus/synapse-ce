// Package fleetcoverage is the pure-domain truth model for fleet coverage (#413, epic #405): given
// the facts about one (asset, capability) pair, it resolves a single coverage verdict. The whole point
// is that ABSENCE OF DATA is never rendered as clean — "unknown", "stale", "refused", "unauthorized"
// and "agent missing" are distinct verdicts, resolved in a fixed order, so a green dashboard can never
// hide an unassessed estate. It imports only stdlib + shared.
package fleetcoverage

import "time"

// Verdict is the coverage state of one (asset, capability) pair.
type Verdict string

const (
	// VerdictUnauthorized: the asset is outside the tenant's active authorization scope. It must never
	// be described as merely stale, and no findings for it may leak into any aggregate.
	VerdictUnauthorized Verdict = "unauthorized"
	// VerdictAgentMissing: no live agent advertises this capability for the asset — coverage is absent
	// because nothing can assess it, not because it is clean.
	VerdictAgentMissing Verdict = "agent_missing"
	// VerdictRefused: the most recent relevant work order was refused (with a reason).
	VerdictRefused Verdict = "refused"
	// VerdictNever: an agent exists but the pair has never been assessed.
	VerdictNever Verdict = "never"
	// VerdictStale: the last assessment is older than the capability's freshness target.
	VerdictStale Verdict = "stale"
	// VerdictPartial: the last assessment was fresh but incomplete (coverage gaps / degraded).
	VerdictPartial Verdict = "partial"
	// VerdictCovered: assessed, fresh, and complete.
	VerdictCovered Verdict = "covered"
)

// resolutionOrder is the fixed top-down order; Resolve stops at the first matching condition. Exposed
// (as a copy) via ResolutionOrder for tests that assert the ordering exhaustively.
var resolutionOrder = []Verdict{
	VerdictUnauthorized, VerdictAgentMissing, VerdictRefused,
	VerdictNever, VerdictStale, VerdictPartial, VerdictCovered,
}

// ResolutionOrder returns a copy of the fixed verdict resolution order.
func ResolutionOrder() []Verdict { return append([]Verdict(nil), resolutionOrder...) }

// Valid reports whether v is a known verdict.
func (v Verdict) Valid() bool {
	for _, k := range resolutionOrder {
		if v == k {
			return true
		}
	}
	return false
}

// Passing reports whether the verdict represents actual, trustworthy coverage. Only "covered" passes —
// every other verdict (including partial and stale) is a non-passing state a dashboard must surface.
func (v Verdict) Passing() bool { return v == VerdictCovered }

// Signals are the facts the projection reduces an (asset, capability) pair to. Resolve is a pure
// function of these — all the messy store lookups happen in the use case, the policy lives here.
type Signals struct {
	Authorized     bool      // asset is within an active authorization scope for the tenant
	AgentAvailable bool      // at least one live (non-stale) agent advertises this capability
	Refused        bool      // the most recent relevant work order was refused
	RefusedReason  string    // why (surfaced with the refused verdict)
	Assessed       bool      // a completed assessment (successful run) exists for this pair
	LastAssessed   time.Time // when the last assessment ran (zero if never)
	Fresh          bool      // the last assessment is within the capability's freshness target
	Complete       bool      // the last assessment was complete (not partial/degraded)
}

// Resolve applies the fixed top-down order and returns the first matching verdict, plus a detail
// string (the refusal reason for refused; empty otherwise). It NEVER returns covered unless the pair
// is authorized, has a live agent, was not refused, and was assessed freshly and completely.
func Resolve(s Signals) (Verdict, string) {
	switch {
	case !s.Authorized:
		return VerdictUnauthorized, ""
	case !s.AgentAvailable:
		return VerdictAgentMissing, ""
	case s.Refused:
		return VerdictRefused, s.RefusedReason
	case !s.Assessed:
		return VerdictNever, ""
	case !s.Fresh:
		return VerdictStale, ""
	case !s.Complete:
		return VerdictPartial, ""
	default:
		return VerdictCovered, ""
	}
}

// IsFresh reports whether an assessment at lastAssessed is within target of now. A zero lastAssessed
// (never assessed) is never fresh. A non-positive target means "no freshness requirement" (always
// fresh once assessed) so a policy that has not set a target does not spuriously mark everything stale.
func IsFresh(lastAssessed, now time.Time, target time.Duration) bool {
	if lastAssessed.IsZero() {
		return false
	}
	if target <= 0 {
		return true
	}
	return now.Sub(lastAssessed) <= target
}
