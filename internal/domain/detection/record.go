package detection

import (
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Record is a detection as it lives in the control-plane ledger (#423): the detection itself, bound to
// the evidence-chain link that sealed it, the asset it was observed on, the agent that produced it, and
// the agent batch sequence it arrived in. The evidence-chain link is the tamper-evident ledger; this
// Record is the queryable projection over it (and the one subject to retention — the chain link is
// permanent, this row is not).
type Record struct {
	ID           shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	AssetID      shared.ID // the asset the detection was observed on, so it joins the asset risk story
	AgentID      shared.ID
	Detection    Detection
	EvidenceID   shared.ID // the evidence-chain link that sealed this detection
	BatchSeq     uint64    // the agent batch sequence it arrived in
	RecordedAt   time.Time
	ExpiresAt    time.Time // zero = never expires; a set value is enforced by audited retention
}

// Validate enforces the binding invariants: a record with no evidence link, asset, tenant, or a
// malformed detection is not a chained, attributable record and must not be stored.
func (r Record) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("%w: detection record has no id", shared.ErrValidation)
	}
	if r.TenantID == "" || r.EngagementID == "" {
		return fmt.Errorf("%w: detection record %s is missing tenant/engagement scope", shared.ErrValidation, r.ID)
	}
	if r.AssetID == "" {
		return fmt.Errorf("%w: detection record %s must reference the asset it was observed on", shared.ErrValidation, r.ID)
	}
	if r.EvidenceID == "" {
		return fmt.Errorf("%w: detection record %s must reference its evidence-chain link", shared.ErrValidation, r.ID)
	}
	if r.AgentID == "" {
		return fmt.Errorf("%w: detection record %s has no agent attribution", shared.ErrValidation, r.ID)
	}
	if err := r.Detection.Validate(); err != nil {
		return fmt.Errorf("detection record %s: %w", r.ID, err)
	}
	return nil
}

// Expired reports whether the record's retention window has elapsed at now. A zero ExpiresAt never
// expires. Expiry removes the projection row (an audited action); the sealed chain link remains.
func (r Record) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt)
}

// Incident is an incident-level rollup of repeated detections of the same rule on the same asset. It is
// a VIEW: it never replaces the underlying records, which remain the ledger. DetectionIDs lists every
// record folded in, so an auditor can always descend from the incident to the individual, attributable,
// hash-chained detections beneath it.
type Incident struct {
	Key          string // stable dedup key: rule + asset
	RuleID       string
	AssetID      shared.ID
	Severity     shared.Severity // the most severe among the folded detections
	Count        int
	First        time.Time
	Last         time.Time
	DetectionIDs []shared.ID // the underlying records, preserved
}

// Rollup folds records into incidents by (rule, asset), preserving every underlying record id. The
// result is deterministically ordered (by key) so an incident view and its trend compare across runs.
// It is a pure projection — it neither drops nor mutates the records it summarises.
func Rollup(records []Record) []Incident {
	byKey := map[string]*Incident{}
	var order []string
	for _, r := range records {
		key := r.Detection.RuleID + "\x00" + r.AssetID.String()
		inc, ok := byKey[key]
		if !ok {
			inc = &Incident{Key: key, RuleID: r.Detection.RuleID, AssetID: r.AssetID,
				Severity: r.Detection.Severity, First: r.Detection.Observed, Last: r.Detection.Observed}
			byKey[key] = inc
			order = append(order, key)
		}
		inc.Count++
		inc.DetectionIDs = append(inc.DetectionIDs, r.ID)
		if shared.SeverityRank(r.Detection.Severity) > shared.SeverityRank(inc.Severity) {
			inc.Severity = r.Detection.Severity
		}
		if r.Detection.Observed.Before(inc.First) {
			inc.First = r.Detection.Observed
		}
		if r.Detection.Observed.After(inc.Last) {
			inc.Last = r.Detection.Observed
		}
	}
	sort.Strings(order)
	out := make([]Incident, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}
