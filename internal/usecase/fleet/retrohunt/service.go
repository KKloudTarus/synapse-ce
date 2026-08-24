// Package retrohunt is the Phase C retro-hunt seam (#594, C4 #678): given a trigger (a detection or
// incident on an asset at a time), it pivots to the SURROUNDING endpoint State Timeline — the transitions
// just before and after the trigger — so an analyst can see what led up to and followed a detection after
// the raw telemetry that produced it has expired. It reads the durable State Timeline (B7) and is
// stateless + tenant-scoped from the context.
package retrohunt

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Request selects the window to hunt around a trigger. AssetID and Around are required; Before/After set
// how far to look back/forward (at least one must be positive). EntityID optionally focuses the hunt on
// one entity's transitions (e.g. the process a detection fired on). Limit caps the entries returned.
type Request struct {
	AssetID  shared.ID
	Around   time.Time
	Before   time.Duration
	After    time.Duration
	EntityID shared.ID
	Limit    int
}

// Result is the surrounding-timeline window. Entries are event-time ordered. Coverage combines timeline
// truncation with raw-telemetry sampling, sequence-gap, and loss metadata for the exact window.
type Result struct {
	AssetID   shared.ID
	From      time.Time
	To        time.Time
	Entries   []endpoint.TimelineEntry
	Truncated bool
	Coverage  Coverage
}

// CoverageReason is a stable, machine-readable explanation for an incomplete window.
type CoverageReason string

const (
	CoverageSampled              CoverageReason = "telemetry_sampled"
	CoverageSequenceGap          CoverageReason = "telemetry_sequence_gap"
	CoverageLoss                 CoverageReason = "telemetry_loss"
	CoverageTelemetryUnavailable CoverageReason = "telemetry_unavailable"
	CoverageTimelineTruncated    CoverageReason = "timeline_limit"
	CoverageTelemetryIncomplete  CoverageReason = "telemetry_incomplete"
)

// Coverage proves whether the returned timeline can be treated as complete for the requested window.
// Complete is false whenever raw telemetry was sampled, lost, sequence-gapped, unavailable, or the
// projected timeline was capped.
type Coverage struct {
	Complete          bool
	Sampled           bool
	MaxSampleRate     int
	TimelineTruncated bool
	TelemetryObserved bool
	SequenceGaps      []ports.TelemetrySequenceGap
	Losses            []ports.TelemetryLoss
	Reasons           []CoverageReason
}

// TelemetryHuntReader is the read-only telemetry surface used to establish coverage honesty.
type TelemetryHuntReader interface {
	Query(context.Context, ports.HuntQuery) (ports.HuntResult, error)
}

// Service answers retro-hunt queries over the endpoint State Timeline.
type Service struct {
	timeline  ports.EndpointTimelineStore
	telemetry TelemetryHuntReader
}

// SetTelemetryReader enables sampling/gap/loss coverage checks over the exact hunt window. Until a
// reader is configured, hunts remain usable but explicitly report telemetry_unavailable and incomplete.
func (s *Service) SetTelemetryReader(telemetry TelemetryHuntReader) { s.telemetry = telemetry }

// NewService constructs the retro-hunt service over an endpoint-timeline store.
func NewService(timeline ports.EndpointTimelineStore) (*Service, error) {
	if timeline == nil {
		return nil, fmt.Errorf("%w: retro-hunt service requires an endpoint timeline store", shared.ErrValidation)
	}
	return &Service{timeline: timeline}, nil
}

// Hunt returns the endpoint transitions in [Around-Before, Around+After] on the asset (optionally filtered
// to one entity). It is fail-closed: a missing asset, a zero trigger time, negative look-back/forward, or a
// zero-width window is rejected.
func (s *Service) Hunt(ctx context.Context, req Request) (Result, error) {
	if req.AssetID.IsZero() {
		return Result{}, fmt.Errorf("%w: retro-hunt requires an asset id", shared.ErrValidation)
	}
	if req.Around.IsZero() {
		return Result{}, fmt.Errorf("%w: retro-hunt requires a trigger time", shared.ErrValidation)
	}
	if req.Before < 0 || req.After < 0 {
		return Result{}, fmt.Errorf("%w: retro-hunt look-back/forward must be non-negative", shared.ErrValidation)
	}
	if req.Before == 0 && req.After == 0 {
		return Result{}, fmt.Errorf("%w: retro-hunt window is zero-width", shared.ErrValidation)
	}
	from := req.Around.Add(-req.Before)
	to := req.Around.Add(req.After)

	// Always apply a bounded effective limit (defaultHuntLimit when the caller gives none or a
	// non-positive one) and query ONE past it, so truncation is ALWAYS observable — the window is never
	// silently capped by the store's internal default without Truncated being set (coverage honesty).
	effLimit := req.Limit
	if effLimit <= 0 {
		effLimit = defaultHuntLimit
	}
	if effLimit > maxHuntLimit {
		return Result{}, fmt.Errorf("%w: retro-hunt limit exceeds %d", shared.ErrValidation, maxHuntLimit)
	}
	entries, err := s.timeline.QueryTimeline(ctx, ports.EndpointTimelineQuery{
		AssetID: req.AssetID, From: from, To: to, EntityID: req.EntityID, Limit: effLimit + 1,
	})
	if err != nil {
		return Result{}, fmt.Errorf("retro-hunt query: %w", err)
	}
	truncated := false
	if len(entries) > effLimit {
		entries = entries[:effLimit]
		truncated = true
	}
	coverage, err := s.coverage(ctx, req.AssetID, from, to, truncated)
	if err != nil {
		return Result{}, err
	}
	return Result{
		AssetID: req.AssetID, From: from, To: to, Entries: entries,
		Truncated: truncated, Coverage: coverage,
	}, nil
}

func (s *Service) coverage(ctx context.Context, assetID shared.ID, from, to time.Time, timelineTruncated bool) (Coverage, error) {
	if s.telemetry == nil {
		coverage := Coverage{MaxSampleRate: 1, TimelineTruncated: timelineTruncated}
		coverage.Reasons = append(coverage.Reasons, CoverageTelemetryUnavailable)
		if timelineTruncated {
			coverage.Reasons = append(coverage.Reasons, CoverageTimelineTruncated)
		}
		return coverage, nil
	}
	hunt, err := s.telemetry.Query(ctx, ports.HuntQuery{
		Kind: ports.HuntContext, AssetID: assetID, Since: from, Until: to, Limit: 1,
	})
	if err != nil {
		return Coverage{}, fmt.Errorf("retro-hunt coverage query: %w", err)
	}
	return coverageFor(hunt, timelineTruncated), nil
}

func coverageFor(hunt ports.HuntResult, timelineTruncated bool) Coverage {
	maxSampleRate := hunt.MaxSampleRate
	if maxSampleRate < 1 {
		maxSampleRate = 1
	}
	sampled := hunt.Sampled || maxSampleRate > 1
	coverage := Coverage{
		Sampled: sampled, MaxSampleRate: maxSampleRate, TimelineTruncated: timelineTruncated,
		TelemetryObserved: hunt.RowsScanned > 0,
		SequenceGaps:      append([]ports.TelemetrySequenceGap{}, hunt.SequenceGaps...),
		Losses:            append([]ports.TelemetryLoss{}, hunt.Losses...),
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
	if !coverage.TelemetryObserved {
		coverage.Reasons = append(coverage.Reasons, CoverageTelemetryUnavailable)
	}
	if timelineTruncated {
		coverage.Reasons = append(coverage.Reasons, CoverageTimelineTruncated)
	}
	knownIncomplete := sampled || len(coverage.SequenceGaps) > 0 || len(coverage.Losses) > 0 || !coverage.TelemetryObserved
	if !hunt.Complete && !knownIncomplete {
		coverage.Reasons = append(coverage.Reasons, CoverageTelemetryIncomplete)
	}
	coverage.Complete = hunt.Complete && len(coverage.Reasons) == 0
	return coverage
}

// defaultHuntLimit bounds a retro-hunt window when the caller specifies no (or a non-positive) limit; it
// is below the timeline store's own cap so a full page is always reportable as Truncated.
const defaultHuntLimit = 1000

// maxHuntLimit leaves room for the look-ahead row under timeline stores' 10k hard cap.
const maxHuntLimit = 9999
