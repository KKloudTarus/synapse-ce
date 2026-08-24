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

// Result is the surrounding-timeline window. Entries are event-time ordered. Truncated reports that the
// store's limit capped the window, so the caller knows the view may be partial (coverage honesty); a
// deeper gap/sample overlay from the telemetry coverage store is a documented follow-up.
type Result struct {
	AssetID   shared.ID
	From      time.Time
	To        time.Time
	Entries   []endpoint.TimelineEntry
	Truncated bool
}

// Service answers retro-hunt queries over the endpoint State Timeline.
type Service struct {
	timeline ports.EndpointTimelineStore
}

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
	return Result{AssetID: req.AssetID, From: from, To: to, Entries: entries, Truncated: truncated}, nil
}

// defaultHuntLimit bounds a retro-hunt window when the caller specifies no (or a non-positive) limit; it
// is below the timeline store's own cap so a full page is always reportable as Truncated.
const defaultHuntLimit = 1000
