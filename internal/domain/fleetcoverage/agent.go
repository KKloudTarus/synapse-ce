package fleetcoverage

import "time"

// AgentHealth is the derived liveness state of a fleet agent. Stale is first-class: an agent that has
// not been seen within the threshold is neither healthy nor silently dropped.
type AgentHealth string

const (
	// AgentHealthy: seen within the staleness threshold.
	AgentHealthy AgentHealth = "healthy"
	// AgentStale: alive at last enrolment but not seen within the threshold (or never seen).
	AgentStale AgentHealth = "stale"
	// AgentRevoked: an operator revoked the credential; it must never count as covering anything.
	AgentRevoked AgentHealth = "revoked"
	// AgentDecommissioned: the agent cleanly uninstalled and self-reported removal (#412). Like revoked
	// it never covers, but it is surfaced DISTINCTLY so an orderly removal is not shown as a revocation.
	AgentDecommissioned AgentHealth = "decommissioned"
)

// Valid reports whether h is a known agent-health state.
func (h AgentHealth) Valid() bool {
	switch h {
	case AgentHealthy, AgentStale, AgentRevoked, AgentDecommissioned:
		return true
	default:
		return false
	}
}

// Live reports whether an agent in this state can currently cover work (only healthy agents do; a
// stale, revoked, or decommissioned agent contributes nothing to coverage).
func (h AgentHealth) Live() bool { return h == AgentHealthy }

// AgentStateFrom derives the health state from the last-seen time. A revoked agent is always revoked and
// a decommissioned agent is always decommissioned (revocation takes precedence when both are set, as it
// is the stronger, operator-attributed terminal state). Otherwise, an agent not seen within staleAfter
// (or never seen) is stale; a non-positive staleAfter disables the staleness check (an unset threshold
// must not mark every agent stale). now is injected for determinism.
func AgentStateFrom(lastSeen, now time.Time, staleAfter time.Duration, revoked, decommissioned bool) AgentHealth {
	if revoked {
		return AgentRevoked
	}
	if decommissioned {
		return AgentDecommissioned
	}
	if lastSeen.IsZero() {
		return AgentStale
	}
	if staleAfter <= 0 {
		return AgentHealthy
	}
	if now.Sub(lastSeen) > staleAfter {
		return AgentStale
	}
	return AgentHealthy
}
