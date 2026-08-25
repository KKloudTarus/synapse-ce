package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/baseline"
)

// BaselineRecord is the persisted form of one behavioral baseline (Phase D, D5 #738): its key, lifecycle
// state, per-feature accumulators (exactly baseline.NumFeatures entries, in feature order), and the
// drift-tracker's per-baseline progress. It is a MUTABLE projection — unlike the append-only evidence and
// incident logs, a re-observation upserts it in place — but the usecase audits every state transition.
// The drift-tracker CONFIG (score/threshold) is service policy, not stored here; only its run/latch state
// travels with the baseline so drift progress survives a restart.
type BaselineRecord struct {
	Key       baseline.Key
	State     baseline.State
	Summaries []baseline.FeatureSummary
	DriftRun  int
	Drifted   bool
	UpdatedAt time.Time
}

// BaselineStore persists behavioral baselines, tenant-scoped from the context. A baseline is a mutable
// projection keyed by (tenant, group): Save upserts the record for its key; Load returns the current
// record or shared.ErrNotFound. Save is idempotent — re-saving an equal record leaves the same state.
type BaselineStore interface {
	Save(ctx context.Context, rec BaselineRecord) error
	Load(ctx context.Context, key baseline.Key) (BaselineRecord, error)
}
