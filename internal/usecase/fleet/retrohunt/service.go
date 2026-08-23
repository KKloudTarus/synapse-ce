// Package retrohunt pivots a runtime detection to the persisted endpoint State Timeline around the
// detection's event time (Phase C / C4, #678). It returns projected transitions, not raw telemetry, but
// queries the telemetry tier's honesty metadata for the same window so sampling and loss are never
// presented as complete endpoint history.
package retrohunt

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	DefaultBefore     = 5 * time.Minute
	DefaultAfter      = 5 * time.Minute
	DefaultMaxEntries = 1000
	maxEntries        = 9999 // leaves one look-ahead row under the timeline stores' 10k hard cap
	maxLineageDepth   = 64
)

// Config bounds every retro-hunt. Zero values select the documented defaults. Negative durations and
// entry limits outside the safe store window fail closed.
type Config struct {
	Before     time.Duration
	After      time.Duration
	MaxEntries int
}

func (c Config) withDefaults() (Config, error) {
	if c.Before < 0 || c.After < 0 || c.MaxEntries < 0 {
		return Config{}, fmt.Errorf("%w: retro-hunt bounds cannot be negative", shared.ErrValidation)
	}
	if c.Before == 0 {
		c.Before = DefaultBefore
	}
	if c.After == 0 {
		c.After = DefaultAfter
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = DefaultMaxEntries
	}
	if c.MaxEntries > maxEntries {
		return Config{}, fmt.Errorf("%w: retro-hunt max entries exceeds %d", shared.ErrValidation, maxEntries)
	}
	return c, nil
}

// DetectionPivot identifies the detection and optional stable endpoint entity whose context should be
// reconstructed. AncestorEntityIDs are the already-resolved process lineage, nearest-first or in any
// other order; the service canonicalizes them with EntityID before querying. With no EntityID, the pivot
// returns the asset-wide timeline window.
//
// Lineage resolution itself belongs to endpoint projection/persistence. C4 consumes stable entity ids;
// it never derives lineage from a bare PID, which would be unsafe under PID reuse.
type DetectionPivot struct {
	Detection         detection.Record
	EntityID          shared.ID
	AncestorEntityIDs []shared.ID
}

// CoverageReason is a stable, machine-readable explanation for an incomplete retro-hunt window.
type CoverageReason string

const (
	CoverageSampled                    CoverageReason = "telemetry_sampled"
	CoverageSequenceGap                CoverageReason = "telemetry_sequence_gap"
	CoverageLoss                       CoverageReason = "telemetry_loss"
	CoverageTelemetryUnavailable       CoverageReason = "telemetry_unavailable"
	CoverageTimelineTruncated          CoverageReason = "timeline_limit"
	CoverageDetectionEvidenceTruncated CoverageReason = "detection_evidence_truncated"
	CoverageTelemetryIncomplete        CoverageReason = "telemetry_incomplete"
)

// Coverage carries the completeness proof for the exact retro-hunt window. Complete is derived from all
// fields and can never stay true when the timeline was capped, the detection evidence was truncated, or
// telemetry reports sampling, a sequence gap, or a persisted loss.
type Coverage struct {
	Complete                   bool
	Sampled                    bool
	MaxSampleRate              int
	TimelineTruncated          bool
	DetectionEvidenceTruncated bool
	TelemetryObserved          bool
	SequenceGaps               []ports.TelemetrySequenceGap
	Losses                     []ports.TelemetryLoss
	Reasons                    []CoverageReason
}

// Result is a deterministic surrounding State Timeline ordered by (OccurredAt, EventID), accompanied by
// the exact asset/entity/window pivot and its coverage proof.
type Result struct {
	DetectionID shared.ID
	AssetID     shared.ID
	HostID      shared.ID
	EntityIDs   []shared.ID
	WindowStart time.Time
	WindowEnd   time.Time
	Entries     []endpoint.TimelineEntry
	Coverage    Coverage
}

// Service reads the durable State Timeline and the raw telemetry tier's completeness metadata.
type Service struct {
	timeline  ports.EndpointTimelineReader
	telemetry ports.TelemetryHuntReader
	config    Config
}

// NewService validates the two read dependencies and applies bounded defaults.
func NewService(timeline ports.EndpointTimelineReader, telemetry ports.TelemetryHuntReader, config Config) (*Service, error) {
	if timeline == nil || telemetry == nil {
		return nil, fmt.Errorf("%w: retro-hunt requires timeline and telemetry stores", shared.ErrValidation)
	}
	resolved, err := config.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Service{timeline: timeline, telemetry: telemetry, config: resolved}, nil
}

// AroundDetection returns the persisted State Timeline surrounding a detection's observation time. The
// authenticated tenant in ctx must match the record; tenant and asset mismatches returned by an adapter
// fail closed. Entity/lineage reads are merged and deduplicated deterministically.
func (s *Service) AroundDetection(ctx context.Context, pivot DetectionPivot) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: retro-hunt requires a context", shared.ErrValidation)
	}
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return Result{}, fmt.Errorf("%w: retro-hunt requires a tenant in context", shared.ErrValidation)
	}
	if err := pivot.Detection.Validate(); err != nil {
		return Result{}, fmt.Errorf("retro-hunt detection: %w", err)
	}
	if pivot.Detection.TenantID != tenant {
		return Result{}, fmt.Errorf("%w: detection tenant does not match authenticated tenant", shared.ErrForbidden)
	}
	entityIDs, err := canonicalEntityIDs(pivot.EntityID, pivot.AncestorEntityIDs)
	if err != nil {
		return Result{}, err
	}

	start := pivot.Detection.Detection.Observed.UTC().Add(-s.config.Before)
	end := pivot.Detection.Detection.Observed.UTC().Add(s.config.After)
	entries, truncated, err := s.queryTimeline(ctx, tenant, pivot.Detection.AssetID, entityIDs, start, end)
	if err != nil {
		return Result{}, err
	}

	honesty, err := s.telemetry.Query(ctx, ports.HuntQuery{
		Kind: ports.HuntContext, HostID: pivot.Detection.Detection.HostID, AssetID: pivot.Detection.AssetID,
		Since: start, Until: end, Limit: 1,
	})
	if err != nil {
		return Result{}, fmt.Errorf("query retro-hunt coverage: %w", err)
	}
	coverage := coverageFor(honesty, truncated, pivot.Detection.Detection.Truncated)
	return Result{
		DetectionID: pivot.Detection.ID,
		AssetID:     pivot.Detection.AssetID,
		HostID:      pivot.Detection.Detection.HostID,
		EntityIDs:   append([]shared.ID(nil), entityIDs...),
		WindowStart: start,
		WindowEnd:   end,
		Entries:     entries,
		Coverage:    coverage,
	}, nil
}

func canonicalEntityIDs(entityID shared.ID, ancestors []shared.ID) ([]shared.ID, error) {
	if entityID.IsZero() && len(ancestors) > 0 {
		return nil, fmt.Errorf("%w: retro-hunt lineage requires a focal entity id", shared.ErrValidation)
	}
	if len(ancestors) > maxLineageDepth {
		return nil, fmt.Errorf("%w: retro-hunt lineage exceeds %d ancestors", shared.ErrValidation, maxLineageDepth)
	}
	if entityID.IsZero() {
		return nil, nil
	}
	unique := map[shared.ID]struct{}{entityID: {}}
	for _, id := range ancestors {
		if id.IsZero() {
			return nil, fmt.Errorf("%w: retro-hunt lineage contains an empty entity id", shared.ErrValidation)
		}
		unique[id] = struct{}{}
	}
	out := make([]shared.ID, 0, len(unique))
	for id := range unique {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (s *Service) queryTimeline(ctx context.Context, tenant, asset shared.ID, entityIDs []shared.ID,
	start, end time.Time,
) ([]endpoint.TimelineEntry, bool, error) {
	byEvent := make(map[shared.ID]endpoint.TimelineEntry)
	queries := entityIDs
	if len(queries) == 0 {
		queries = []shared.ID{""}
	}
	for _, entityID := range queries {
		found, err := s.timeline.QueryTimeline(ctx, ports.EndpointTimelineQuery{
			AssetID: asset, From: start, To: end, EntityID: entityID, Limit: s.config.MaxEntries + 1,
		})
		if err != nil {
			return nil, false, fmt.Errorf("query endpoint timeline: %w", err)
		}
		for _, raw := range found {
			entry := raw
			entry.OccurredAt = entry.OccurredAt.UTC()
			if err := validateTimelineEntry(entry, tenant, asset, entityIDs, start, end); err != nil {
				return nil, false, err
			}
			if previous, exists := byEvent[entry.EventID]; exists && previous != entry {
				return nil, false, fmt.Errorf("%w: timeline event %s has conflicting material", shared.ErrConflict, entry.EventID)
			}
			byEvent[entry.EventID] = entry
		}
	}

	entries := make([]endpoint.TimelineEntry, 0, len(byEvent))
	for _, entry := range byEvent {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].OccurredAt.Equal(entries[j].OccurredAt) {
			return entries[i].OccurredAt.Before(entries[j].OccurredAt)
		}
		return entries[i].EventID < entries[j].EventID
	})
	truncated := len(entries) > s.config.MaxEntries
	if truncated {
		entries = entries[:s.config.MaxEntries]
	}
	return entries, truncated, nil
}

func validateTimelineEntry(entry endpoint.TimelineEntry, tenant, asset shared.ID, entityIDs []shared.ID,
	start, end time.Time,
) error {
	if entry.EventID.IsZero() || entry.EntityID.IsZero() || entry.EntityKind == "" || entry.Kind == "" || entry.OccurredAt.IsZero() {
		return fmt.Errorf("%w: timeline store returned a malformed entry", shared.ErrValidation)
	}
	if entry.TenantID != tenant || entry.AssetID != asset {
		return fmt.Errorf("%w: timeline store returned an entry outside the authenticated pivot", shared.ErrForbidden)
	}
	if entry.OccurredAt.Before(start) || entry.OccurredAt.After(end) {
		return fmt.Errorf("%w: timeline store returned an entry outside the requested window", shared.ErrValidation)
	}
	if len(entityIDs) > 0 && !containsID(entityIDs, entry.EntityID) {
		return fmt.Errorf("%w: timeline store returned an entry outside the requested lineage", shared.ErrValidation)
	}
	return nil
}

func containsID(ids []shared.ID, id shared.ID) bool {
	index := sort.Search(len(ids), func(index int) bool { return ids[index] >= id })
	return index < len(ids) && ids[index] == id
}

func coverageFor(honesty ports.HuntResult, timelineTruncated, detectionTruncated bool) Coverage {
	maxSampleRate := honesty.MaxSampleRate
	if maxSampleRate < 1 {
		maxSampleRate = 1
	}
	sampled := honesty.Sampled || maxSampleRate > 1
	telemetryObserved := honesty.RowsScanned > 0
	coverage := Coverage{
		Sampled:                    sampled,
		MaxSampleRate:              maxSampleRate,
		TimelineTruncated:          timelineTruncated,
		DetectionEvidenceTruncated: detectionTruncated,
		TelemetryObserved:          telemetryObserved,
		SequenceGaps:               append([]ports.TelemetrySequenceGap(nil), honesty.SequenceGaps...),
		Losses:                     append([]ports.TelemetryLoss(nil), honesty.Losses...),
	}
	if sampled {
		coverage.Reasons = append(coverage.Reasons, CoverageSampled)
	}
	if len(coverage.SequenceGaps) > 0 {
		coverage.Reasons = append(coverage.Reasons, CoverageSequenceGap)
	}
	if len(coverage.Losses) > 0 {
		coverage.Reasons = append(coverage.Reasons, CoverageLoss)
	}
	// The timeline intentionally outlives raw telemetry. An empty telemetry read cannot prove the
	// window complete: it may mean the raw rows expired, so surface that uncertainty explicitly.
	if !telemetryObserved {
		coverage.Reasons = append(coverage.Reasons, CoverageTelemetryUnavailable)
	}
	if timelineTruncated {
		coverage.Reasons = append(coverage.Reasons, CoverageTimelineTruncated)
	}
	if detectionTruncated {
		coverage.Reasons = append(coverage.Reasons, CoverageDetectionEvidenceTruncated)
	}
	knownIncomplete := sampled || len(coverage.SequenceGaps) > 0 || len(coverage.Losses) > 0 || !telemetryObserved
	if !honesty.Complete && !knownIncomplete {
		coverage.Reasons = append(coverage.Reasons, CoverageTelemetryIncomplete)
	}
	coverage.Complete = honesty.Complete && len(coverage.Reasons) == 0
	return coverage
}
