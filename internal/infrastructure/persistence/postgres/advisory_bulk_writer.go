package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaterializingAdvisoryWriter adapts the bulk advisory ingester (ports.AdvisoryWriter, one advisory at a
// time) onto the observation materializer. Each ingested advisory is recorded as one observation of a named
// bulk source and re-materialized through advisory.Merge, so a CVE present in this feed AND in another
// source (the online NVD provider, a different feed dump) yields the UNION of their affected ranges instead
// of a flat last-writer-wins overwrite of advisories.data. This closes EPIC #860 D1.2: the CLI
// sync-advisories path is now a single provenance-tracked writer over the observation/canonical model,
// which the online sync already uses, rather than a second clobbering writer against the same table.
//
// A re-ingest of the same feed supersedes that source's prior observation for the same record (the
// materializer keys on (source_id, record_id, content_hash) and marks the old content not-current), so a
// feed that narrows an advisory still takes effect for its own source while other sources' ranges remain.
//
// Source identity is PER AUTHORITY (one osv, one csaf, one oval bulk source), which makes the union work
// across DIFFERENT authorities (an OSV dump and the NVD provider are separate sources, so their ranges are
// unioned) while a re-sync of the SAME authority supersedes rather than accumulating stale ranges. Two
// bounds follow and are intentional: two separate dumps of the SAME authority that disagree on one advisory
// resolve last-writer-wins (the newer snapshot is authoritative, not a union of stale + fresh); and this CLI
// osv bulk source is distinct from the ONLINE osv provider, so a deployment should feed OSV through one path
// (an offline dump OR the online provider), and a stale, un-re-synced offline dump can keep a range the
// online path later retracted until the dump is re-synced (the corpus-freshness warning surfaces staleness).
type MaterializingAdvisoryWriter struct {
	materializer *AdvisoryMaterializer
	sourceType   string                     // adapter_type: osv | csaf | oval
	sourceID     string                     // stable id of the bulk source row (== source_key)
	onSkip       func(id string, err error) // called when a single record is skipped instead of aborting the ingest; may be nil
}

var _ ports.AdvisoryWriter = (*MaterializingAdvisoryWriter)(nil)

// bulkAdvisoryAdapters is the closed set of feed kinds the CLI bulk ingest can register as a source. It
// mirrors the vulnerability_sources.adapter_type CHECK constraint for the offline-feed subset.
var bulkAdvisoryAdapters = map[string]bool{"osv": true, "csaf": true, "oval": true}

// NewMaterializingAdvisoryWriter ensures a vulnerability_sources row for the given bulk feed exists (a
// disabled, full-sync source, since an offline dump is not scheduled) and returns a writer that
// materializes each advisory as one of that source's observations. sourceKey is the stable, unique feed
// identity (used as both the primary id and the source_key); adapterType is one of osv/csaf/oval. onSkip, if
// non-nil, is called for each advisory dropped on a per-record data error instead of aborting the run.
func NewMaterializingAdvisoryWriter(ctx context.Context, pool *pgxpool.Pool, sourceKey, displayName, adapterType string, onSkip func(id string, err error)) (*MaterializingAdvisoryWriter, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: advisory pool is nil", shared.ErrValidation)
	}
	if sourceKey == "" || displayName == "" {
		return nil, fmt.Errorf("%w: bulk advisory source key and display name are required", shared.ErrValidation)
	}
	if !bulkAdvisoryAdapters[adapterType] {
		return nil, fmt.Errorf("%w: unsupported bulk advisory adapter %q", shared.ErrValidation, adapterType)
	}
	// Idempotent source bootstrap. The bulk feed is a named, disabled source (no scheduled cadence run); the
	// cadence/stale values satisfy the schema's positive-integer CHECKs but are never used because enabled is
	// false. The endpoint is a synthetic per-source value so the (adapter_type, endpoint) active-uniqueness
	// index never collides across bulk sources of the same adapter type. ON CONFLICT keeps a re-run from
	// failing and never rewrites operator edits to the row.
	endpoint := "synapse-cli-bulk:" + sourceKey
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerability_sources
		(id, source_key, display_name, adapter_type, endpoint, enabled, cadence_seconds, stale_after_seconds, sync_mode)
		VALUES ($1,$1,$2,$3,$4,FALSE,86400,172800,'full')
		ON CONFLICT (id) DO NOTHING`, sourceKey, displayName, adapterType, endpoint); err != nil {
		return nil, fmt.Errorf("bootstrap bulk advisory source %s: %w", sourceKey, err)
	}
	return &MaterializingAdvisoryWriter{materializer: NewAdvisoryMaterializer(pool), sourceType: adapterType, sourceID: sourceKey, onSkip: onSkip}, nil
}

// isSkippableRecord reports whether a Materialize error is a per-record DATA problem (a malformed record, an
// alias that collides with a different canonical, a duplicate payload) rather than an infrastructure failure.
// A bulk feed drops such a record and continues, matching the feed's own parse-skip; an infrastructure error
// (a dead connection) must still abort. Real OSV/CSAF/OVAL feeds do not hit these because the online sync
// runs the same materializer over the same data shapes, so a skip means genuinely inconsistent input.
func isSkippableRecord(err error) bool {
	return errors.Is(err, advisory.ErrAliasConflict) || errors.Is(err, shared.ErrValidation) || errors.Is(err, shared.ErrConflict)
}

// Upsert records the advisory as one current observation of this source and re-materializes the canonical
// advisory, merging with every other source's current observation for the same identity. A withdrawn feed
// advisory is recorded with StatusWithdrawn so the canonical projection keeps it out of the matcher. No
// SyncRunID is set: an offline bulk ingest is not a scheduled, tenant-scoped provenance run, so the
// materializer's sync-run/tenant provenance checks are skipped.
func (w *MaterializingAdvisoryWriter) Upsert(ctx context.Context, a advisory.Advisory) error {
	if a.ID == "" {
		return fmt.Errorf("%w: advisory id is empty", shared.ErrValidation)
	}
	status := advisory.StatusActive
	if a.Withdrawn {
		status = advisory.StatusWithdrawn
	}
	record := advisory.ObservationRecord{
		Observation: advisory.Observation{
			SourceType: w.sourceType,
			SourceID:   w.sourceID,
			RecordID:   a.ID,
			Advisory:   a,
			Status:     status,
		},
	}
	if _, err := w.materializer.Materialize(ctx, []advisory.ObservationRecord{record}); err != nil {
		// A per-record data conflict must not abort the whole bulk ingest (one bad advisory would leave every
		// later advisory unwritten); skip it and continue. An infrastructure error still aborts.
		if isSkippableRecord(err) {
			if w.onSkip != nil {
				w.onSkip(a.ID, err)
			}
			return nil
		}
		return fmt.Errorf("materialize advisory %s: %w", a.ID, err)
	}
	return nil
}
