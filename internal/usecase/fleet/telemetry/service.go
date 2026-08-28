// Package telemetry is the agent-side raw-telemetry tier's control plane (#424, ADR 0001). It wraps the
// dedicated ports.TelemetryStore with the honesty contract the columnar tier must uphold: ingest is
// BOUNDED and BACKPRESSURED; retention is tiered with AUDITED expiry; and retro-hunts carry sampling,
// loss, columnar-sequence-gap, and A3 delivery-gap completeness metadata.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service is the telemetry tier control plane. deliveryGaps is optional for legacy/test
// composition; production A3 wiring supplies it so hunt completeness includes transport loss.
type Service struct {
	store        ports.TelemetryStore
	deliveryGaps ports.TelemetryDeliveryGapReader
	audit        ports.AuditLogger
	clock        ports.Clock
	budget       int
}

// NewService preserves the original constructor for stores that do not compose A3 transport state.
func NewService(store ports.TelemetryStore, audit ports.AuditLogger, clock ports.Clock, budget int) (*Service, error) {
	return NewServiceWithDeliveryGaps(store, nil, audit, clock, budget)
}

// NewServiceWithDeliveryGaps wires the A3 delivery-gap ledger into retro-hunt completeness.
// The reader is intentionally a narrow port rather than the whole transport store.
func NewServiceWithDeliveryGaps(store ports.TelemetryStore, gaps ports.TelemetryDeliveryGapReader, audit ports.AuditLogger, clock ports.Clock, budget int) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: telemetry service is missing a dependency", shared.ErrValidation)
	}
	if budget <= 0 {
		return nil, fmt.Errorf("%w: telemetry ingest budget must be positive", shared.ErrValidation)
	}
	return &Service{store: store, deliveryGaps: gaps, audit: audit, clock: clock, budget: budget}, nil
}

type IngestReport struct {
	Accepted    int
	Dropped     int
	Disposition telemetry.LossDisposition
	Gap         *ports.TelemetrySequenceGap
}

func (s *Service) Ingest(ctx context.Context, batch ports.TelemetryBatch) (IngestReport, error) {
	if batch.TenantID == "" || batch.HostID == "" || batch.AgentID == "" || batch.AssetID == "" {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch needs tenant, host, agent and asset", shared.ErrValidation)
	}
	if !batch.Class.Valid() {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch has an unknown class %q", shared.ErrValidation, batch.Class)
	}
	if batch.Sequence == 0 {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch sequence must be >= 1", shared.ErrValidation)
	}
	if batch.SampleRate < 1 {
		return IngestReport{}, fmt.Errorf("%w: telemetry sample rate must be >= 1 (1 = full fidelity)", shared.ErrValidation)
	}
	if telemetry.MustNotShed(batch.Class) && batch.SampleRate > 1 {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch for protected class %q cannot be sampled", shared.ErrValidation, batch.Class)
	}
	if err := telemetryschema.Validate(batch.SchemaVersion); err != nil {
		return IngestReport{}, err
	}
	ctxTenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return IngestReport{}, fmt.Errorf("%w: telemetry ingest requires a tenant in context", shared.ErrValidation)
	}
	if batch.TenantID != ctxTenant {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch tenant %q does not match the authenticated tenant", shared.ErrForbidden, batch.TenantID)
	}

	report := IngestReport{}
	last, err := s.store.LastSequence(ctx, batch.HostID, batch.Class)
	if err != nil {
		return report, fmt.Errorf("telemetry last sequence: %w", err)
	}
	if batch.Sequence > last+1 {
		gap := ports.TelemetrySequenceGap{HostID: batch.HostID, Class: batch.Class, Missing: batch.Sequence - last - 1, LastSeen: last, Incoming: batch.Sequence}
		report.Gap = &gap
		if err := s.recordGap(ctx, "telemetry.sequence_gap", batch, map[string]string{
			"last_sequence": fmt.Sprint(last), "incoming_sequence": fmt.Sprint(batch.Sequence), "missing": fmt.Sprint(gap.Missing),
		}); err != nil {
			return report, err
		}
	}

	accepted := batch
	events := batch.Events
	report.Disposition = telemetry.Complete
	if batch.SampleRate > 1 {
		report.Disposition = telemetry.Sampled
	}
	if len(events) > s.budget {
		observed, kept := len(events), s.budget
		dropped := observed - kept

		if telemetry.MustNotShed(batch.Class) {
			return report, fmt.Errorf("%w: telemetry batch for protected class %q exceeds the ingest budget (%d > %d); caller must retain and retry the complete batch",
				shared.ErrSaturated, batch.Class, observed, s.budget)
		}

		droppedTail := batch.Events[kept:]
		events = events[:kept]
		report.Dropped = dropped
		report.Disposition = telemetry.Truncated
		dropFrom, dropTo := s.lossSpan(droppedTail)
		if err := s.store.RecordLoss(ctx, ports.TelemetryLoss{
			HostID: batch.HostID, AssetID: batch.AssetID, Class: batch.Class, Sequence: batch.Sequence, Disposition: telemetry.Truncated,
			ObservedCount: observed, KeptCount: kept, DroppedCount: dropped, Reason: "ingest budget exceeded",
			FromAt: dropFrom, ToAt: dropTo,
		}); err != nil {
			return report, fmt.Errorf("record telemetry truncation: %w", err)
		}
		if err := s.recordGap(ctx, "telemetry.overflow", batch, map[string]string{
			"budget": fmt.Sprint(s.budget), "received": fmt.Sprint(observed), "dropped": fmt.Sprint(dropped),
			"disposition": string(telemetry.Truncated),
		}); err != nil {
			return report, err
		}
	}
	report.Accepted = len(events)
	accepted.Events = events
	if err := s.store.Ingest(ctx, accepted); err != nil {
		return report, fmt.Errorf("telemetry ingest: %w", err)
	}
	return report, nil
}

// Hunt combines the columnar store's own honesty metadata with the A3 transport
// ledger. Failing to read configured delivery gaps fails closed rather than returning
// a potentially false Complete=true result.
func (s *Service) Hunt(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	res, err := s.store.Query(ctx, q)
	if err != nil {
		return ports.HuntResult{}, fmt.Errorf("telemetry hunt: %w", err)
	}
	if err := s.attachDeliveryGaps(ctx, q, &res); err != nil {
		return ports.HuntResult{}, fmt.Errorf("telemetry hunt delivery gaps: %w", err)
	}
	return res, nil
}

func (s *Service) attachDeliveryGaps(ctx context.Context, q ports.HuntQuery, res *ports.HuntResult) error {
	if s.deliveryGaps == nil {
		return nil
	}
	gapQuery := ports.TelemetryGapQuery{
		// A0.1 defines the enrolled agent as the canonical host security principal.
		AgentID: q.HostID, AssetID: q.AssetID, Since: q.Since, Until: q.Until,
	}
	if q.Class != "" {
		priority, err := fleetagent.TelemetryPriority(q.Class)
		if err != nil {
			return err
		}
		gapQuery.Priority = &priority
	}
	gaps, err := s.deliveryGaps.QueryDeliveryGaps(ctx, gapQuery)
	if err != nil {
		return err
	}
	res.DeliveryGaps = gaps
	if len(gaps) != 0 {
		res.Complete = false
	}
	return nil
}

func (s *Service) RetroRunRule(ctx context.Context, q ports.HuntQuery) ([]detection.Detection, ports.HuntResult, error) {
	q.Kind = ports.HuntRetroRule
	res, err := s.Hunt(ctx, q)
	if err != nil {
		return nil, ports.HuntResult{}, err
	}
	rules, err := detection.CatalogueByClass(q.Class)
	if err != nil {
		return nil, res, err
	}
	var fired []detection.Detection
	for _, ev := range res.Events {
		for _, r := range rules {
			if !r.Match(ev) {
				continue
			}
			d, derr := detection.NewDetection(r, ev.Host, q.HostID, []detection.Event{ev}, s.clock.Now().UTC())
			if derr != nil {
				continue
			}
			fired = append(fired, d)
		}
	}
	return fired, res, nil
}

func (s *Service) Sweep(ctx context.Context) (ports.SweepReport, error) {
	rep, err := s.store.RetentionSweep(ctx, s.clock.Now().UTC())
	if err != nil {
		return ports.SweepReport{}, fmt.Errorf("telemetry retention sweep: %w", err)
	}
	if aerr := s.audit.Record(ctx, ports.AuditEntry{
		Actor: "system:telemetry-retention", Action: "telemetry.retention_sweep", At: s.clock.Now().UTC(),
		Metadata: map[string]string{
			"warm_downsampled": fmt.Sprint(rep.WarmDownsampled), "expired": fmt.Sprint(rep.Expired),
		},
	}); aerr != nil {
		return rep, fmt.Errorf("%w: retention sweep ran but could not be audited (expired=%d)", shared.ErrSaturated, rep.Expired)
	}
	return rep, nil
}

func (s *Service) Footprint(ctx context.Context) (ports.TelemetryFootprint, error) {
	fp, err := s.store.Footprint(ctx)
	if err != nil {
		return ports.TelemetryFootprint{}, fmt.Errorf("telemetry footprint: %w", err)
	}
	return fp, nil
}

func (s *Service) lossSpan(events []detection.Event) (from, to time.Time) {
	for _, e := range events {
		if e.At.IsZero() {
			continue
		}
		at := e.At.UTC()
		if from.IsZero() || at.Before(from) {
			from = at
		}
		if to.IsZero() || at.After(to) {
			to = at
		}
	}
	if from.IsZero() {
		now := s.clock.Now().UTC()
		return now, now
	}
	return from, to
}

func (s *Service) recordGap(ctx context.Context, action string, batch ports.TelemetryBatch, meta map[string]string) error {
	meta["host"] = batch.HostID.String()
	meta["class"] = string(batch.Class)
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor: batch.AgentID.String(), Action: action, Target: batch.HostID.String(), At: s.clock.Now().UTC(), Metadata: meta,
	}); err != nil {
		return fmt.Errorf("%w: telemetry %s coverage event could not be audited", shared.ErrSaturated, action)
	}
	return nil
}
