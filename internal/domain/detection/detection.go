package detection

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// MaxEvidence bounds the context window that travels with a detection. Milestone one ships the detection
// plus a bounded window of surrounding events, never the raw stream — this cap is what keeps a detection
// small enough for Postgres to remain the system of record (the columnar tier for full telemetry is
// #424). Evidence beyond the cap is dropped from the shipped detection, not from the on-host ring buffer.
const MaxEvidence = 64

// Detection is what a matched rule emits. It carries full attribution — the host, the agent identity,
// the rule id and version, the matched evidence and the time — because the next issue (#423) turns these
// into hash-chained, attributable evidence, and evidence with a hole in its provenance is not evidence.
type Detection struct {
	RuleID      string
	RuleVersion int
	Class       Class
	Severity    shared.Severity
	HostID      shared.ID
	AgentID     shared.ID
	Evidence    []Event // bounded (MaxEvidence); the triggering event plus surrounding context
	// Truncated records that the evidence window was capped: the shipped Evidence is not the complete
	// sequence. It is a field, not just a constructor return, so the incompleteness travels with the
	// stored/hash-chained record (#423) and a reconstructed detection cannot present a bounded window as
	// the whole story. Observed count is the number of events seen before truncation (>= len(Evidence)).
	Truncated     bool
	ObservedCount int
	Observed      time.Time
}

// NewDetection builds a detection from a rule and the observed evidence, deep-copying and bounding the
// evidence defensively so a caller mutating its slice OR the payloads it points at afterwards cannot
// alter the sealed record. The rule must validate and there must be at least one evidence event — a
// detection with no evidence is a claim, not a detection.
//
// If more than MaxEvidence events are supplied, the MOST RECENT MaxEvidence are kept (the tail), because
// the triggering event and its immediate lead-up are the useful context; the drop is recorded in the
// detection's Truncated/ObservedCount fields so a caller never presents a bounded window as complete.
func NewDetection(r Rule, host, agent shared.ID, evidence []Event, at time.Time) (Detection, error) {
	return newDetection(r, host, agent, evidence, len(evidence), at)
}

// NewBurstDetection is NewDetection for a windowed rule whose burst was longer than the evidence the
// evaluator kept: observed is the number of matching events in the burst, evidence the most recent of
// them. When observed exceeds the evidence, the detection is marked truncated with that count, so a
// 120-packet burst that ships 64 packets never presents as a 64-packet one.
func NewBurstDetection(r Rule, host, agent shared.ID, evidence []Event, observed int, at time.Time) (Detection, error) {
	if observed < len(evidence) {
		observed = len(evidence)
	}
	return newDetection(r, host, agent, evidence, observed, at)
}

func newDetection(r Rule, host, agent shared.ID, evidence []Event, observed int, at time.Time) (Detection, error) {
	if err := r.Validate(); err != nil {
		return Detection{}, fmt.Errorf("detection needs a valid rule: %w", err)
	}
	if host == "" || agent == "" {
		return Detection{}, fmt.Errorf("%w: a detection must attribute a host and an agent", shared.ErrValidation)
	}
	if at.IsZero() {
		return Detection{}, fmt.Errorf("%w: a detection must carry an observation time", shared.ErrValidation)
	}
	if len(evidence) == 0 {
		return Detection{}, fmt.Errorf("%w: a detection must carry at least one evidence event", shared.ErrValidation)
	}
	for i, e := range evidence {
		if err := e.Validate(); err != nil {
			return Detection{}, fmt.Errorf("%w: detection evidence[%d] is malformed", shared.ErrValidation, i)
		}
	}

	observedCount := observed
	truncated := observed > len(evidence)
	kept := evidence
	if len(kept) > MaxEvidence {
		kept = kept[len(kept)-MaxEvidence:]
		truncated = true
	}
	cp := make([]Event, len(kept))
	for i := range kept {
		cp[i] = kept[i].clone()
	}

	return Detection{
		RuleID:        r.ID,
		RuleVersion:   r.Version,
		Class:         r.Class,
		Severity:      r.Severity,
		HostID:        host,
		AgentID:       agent,
		Evidence:      cp,
		Truncated:     truncated,
		ObservedCount: observedCount,
		Observed:      at.UTC(),
	}, nil
}

// Validate re-checks a detection's attribution, so a detection reconstructed from storage (rather than
// built through NewDetection) cannot present without a full provenance.
func (d Detection) Validate() error {
	if d.RuleID == "" || d.RuleVersion < 1 {
		return fmt.Errorf("%w: detection is missing its rule identity", shared.ErrValidation)
	}
	if !d.Class.Valid() {
		return fmt.Errorf("%w: detection %s has an unknown class", shared.ErrValidation, d.RuleID)
	}
	if !d.Severity.Valid() || d.Severity == shared.SeverityUnknown {
		return fmt.Errorf("%w: detection %s has an invalid severity", shared.ErrValidation, d.RuleID)
	}
	if d.HostID == "" || d.AgentID == "" {
		return fmt.Errorf("%w: detection %s is missing host/agent attribution", shared.ErrValidation, d.RuleID)
	}
	if len(d.Evidence) == 0 {
		return fmt.Errorf("%w: detection %s carries no evidence", shared.ErrValidation, d.RuleID)
	}
	// A detection reconstructed from storage must hold the same evidence invariants the constructor
	// enforces, so a tampered or corrupt record cannot pass with malformed or oversized evidence.
	if len(d.Evidence) > MaxEvidence {
		return fmt.Errorf("%w: detection %s carries %d evidence events, over the cap of %d",
			shared.ErrValidation, d.RuleID, len(d.Evidence), MaxEvidence)
	}
	for i, e := range d.Evidence {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("%w: detection %s evidence[%d] is malformed", shared.ErrValidation, d.RuleID, i)
		}
	}
	if d.Observed.IsZero() {
		return fmt.Errorf("%w: detection %s has no observation time", shared.ErrValidation, d.RuleID)
	}
	return nil
}
