// Package telemetry is the agent-side raw-telemetry tier's control plane (#424, ADR 0001). It wraps the
// dedicated ports.TelemetryStore with the honesty contract the columnar tier must uphold: ingest is
// BOUNDED and BACKPRESSURED (overflow at the store-rate stage, or a lost upstream batch seen as a
// sequence gap, is reported as a telemetry gap on the affected host — never a silent drop); retention is
// tiered with AUDITED expiry; a sampled window is never presented as complete; and the three retro-hunt
// patterns are served, including retro-running a detection rule over the hot window.
//
// The columnar store is reached ONLY through the port and appears in no domain type.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetryschema"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service is the telemetry tier control plane.
type Service struct {
	store  ports.TelemetryStore
	audit  ports.AuditLogger
	clock  ports.Clock
	budget int // max events accepted per Ingest call (the store-rate stage of the coherent ingest budget)
}

// NewService validates dependencies. budget > 0 bounds a single ingest; <= 0 is refused (an unbounded
// telemetry ingest is the failure mode this tier exists to avoid).
func NewService(store ports.TelemetryStore, audit ports.AuditLogger, clock ports.Clock, budget int) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: telemetry service is missing a dependency", shared.ErrValidation)
	}
	if budget <= 0 {
		return nil, fmt.Errorf("%w: telemetry ingest budget must be positive", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock, budget: budget}, nil
}

// IngestReport is the honest outcome of one ingest: how many events were accepted, how many were shed at
// the store-rate stage, the loss disposition of the batch, and any sequence gap (an upstream —
// agent/transport — loss made visible). Disposition names the store-stage outcome honestly (A0.6): a
// truncation is Truncated, a refused never-shed overflow is Dropped, an agent-sampled batch is Sampled —
// never a truncation relabelled as a sample (D2).
type IngestReport struct {
	Accepted    int
	Dropped     int // shed because the batch exceeded the ingest budget; reported, never silent
	Disposition telemetry.LossDisposition
	Gap         *ports.TelemetrySequenceGap
}

// Ingest admits one batch under the coherent ingest budget. Two stages can report a telemetry gap:
//   - a sequence gap vs. the last batch stored for this (host, class) — an upstream loss made visible;
//   - the batch exceeding the store-rate budget — the overflow is shed and reported, never dropped silently.
//
// Either gap is audited on the affected host. The accepted prefix is persisted with its sampling rate.
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
	// The wire schema version is declared per batch and validated against the range THIS reader supports
	// (telemetryschema), independent of the agent version. An unset or out-of-range version is rejected
	// fail-closed rather than parsed under a guessed shape.
	if err := telemetryschema.Validate(batch.SchemaVersion); err != nil {
		return IngestReport{}, err
	}
	// The write tenant is the AUTHENTICATED tenant on the context, never a self-declared field on the
	// wire batch: an agent must not be able to write into another tenant's partition by claiming a
	// different TenantID. Fail closed if the ctx has no tenant or the batch claims a different one.
	ctxTenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return IngestReport{}, fmt.Errorf("%w: telemetry ingest requires a tenant in context", shared.ErrValidation)
	}
	if batch.TenantID != ctxTenant {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch tenant %q does not match the authenticated tenant", shared.ErrForbidden, batch.TenantID)
	}

	report := IngestReport{}

	// Stage 1: sequence gap (an upstream agent/transport loss). Reported as a telemetry gap, not refused —
	// telemetry is lossy-tolerant, but the loss must be VISIBLE so a hunt knows the window is incomplete.
	last, err := s.store.LastSequence(ctx, batch.HostID, batch.Class)
	if err != nil {
		return report, fmt.Errorf("telemetry last sequence: %w", err)
	}
	if batch.Sequence > last+1 {
		gap := ports.TelemetrySequenceGap{HostID: batch.HostID, Class: batch.Class, Missing: batch.Sequence - last - 1, LastSeen: last, Incoming: batch.Sequence}
		report.Gap = &gap
		// HARD: a gap coverage event that cannot be audited fails the ingest rather than admitting an
		// unrecorded gap (recordGap no longer swallows the audit-write error — the D2 companion bug).
		if err := s.recordGap(ctx, "telemetry.sequence_gap", batch, map[string]string{
			"last_sequence": fmt.Sprint(last), "incoming_sequence": fmt.Sprint(batch.Sequence), "missing": fmt.Sprint(gap.Missing),
		}); err != nil {
			return report, err
		}
	}

	// Stage 2: store-rate budget — HONEST loss accounting (A0.6, fixes D2). An over-budget batch is NEVER
	// relabelled as an elevated sample rate. A never-shed class (privilege / sensitive-file) is not
	// truncated at all: it is refused (back-pressured) and recorded as Dropped, so a security-critical
	// signal is never silently cut. A sheddable class keeps its prefix but the drop is recorded as a
	// first-class Truncated loss with a reason — so a hunt sees the window as incomplete from stored data,
	// not from a lie in the sample rate.
	accepted := batch
	events := batch.Events
	report.Disposition = telemetry.Complete
	if batch.SampleRate > 1 {
		report.Disposition = telemetry.Sampled // the agent already sampled; this rides SampleRate on the rows
	}
	// If a sampled batch also overflows, the branches below overwrite Disposition with Truncated/Dropped
	// (the more actionable outcome). The single-valued report cannot express both; agent-side sampling
	// stays independently visible via SampleRate on the stored rows (HuntResult.Sampled).
	if len(events) > s.budget {
		observed, kept := len(events), s.budget
		dropped := observed - kept

		if telemetry.MustNotShed(batch.Class) {
			// Never-shed: refuse the WHOLE batch (nothing stored) and record the loss as Dropped, so the
			// agent re-sends within budget rather than a security-critical class being silently truncated.
			// The whole batch is refused, so the honest drop count is `observed`, not just the tail.
			report.Disposition = telemetry.Dropped
			report.Accepted = 0
			report.Dropped = observed
			dropFrom, dropTo := s.lossSpan(batch.Events)
			if err := s.store.RecordLoss(ctx, ports.TelemetryLoss{
				HostID: batch.HostID, AssetID: batch.AssetID, Class: batch.Class, Sequence: batch.Sequence, Disposition: telemetry.Dropped,
				ObservedCount: observed, KeptCount: 0, DroppedCount: observed, Reason: "over budget on a never-shed class",
				FromAt: dropFrom, ToAt: dropTo,
			}); err != nil {
				return report, fmt.Errorf("record telemetry drop: %w", err)
			}
			// Audit the drop (the domain's most-severe disposition) — hard, like the overflow audit: a
			// security-critical class being refused must leave an actor-attributed trail or the ingest fails.
			if err := s.recordGap(ctx, "telemetry.drop", batch, map[string]string{
				"budget": fmt.Sprint(s.budget), "received": fmt.Sprint(observed), "dropped": fmt.Sprint(observed),
				"disposition": string(telemetry.Dropped),
			}); err != nil {
				return report, err
			}
			return report, fmt.Errorf("%w: telemetry batch for never-shed class %q exceeds the ingest budget (%d > %d); refused whole rather than truncating a security-critical class",
				shared.ErrSaturated, batch.Class, observed, s.budget)
		}

		// Sheddable: keep the prefix, record the truncation as a first-class loss BEFORE storing — a
		// truncated window whose loss could not be recorded must not be stored (fail closed). The loss is
		// anchored to the DROPPED tail's earliest event time so a time-bounded hunt over it surfaces it.
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

// Hunt runs a retro-hunt query and returns its result WITH the completeness metadata (sampled / gaps),
// so a sampled or lossy window is never presented as complete.
func (s *Service) Hunt(ctx context.Context, q ports.HuntQuery) (ports.HuntResult, error) {
	res, err := s.store.Query(ctx, q)
	if err != nil {
		return ports.HuntResult{}, fmt.Errorf("telemetry hunt: %w", err)
	}
	return res, nil
}

// RetroRunRule re-runs the shipped detection rules for a class over the hot window and returns the
// detections that WOULD have fired, alongside the hunt result (so the caller sees whether the window it
// hunted was complete). This is the first of the three acceptance patterns.
func (s *Service) RetroRunRule(ctx context.Context, q ports.HuntQuery) ([]detection.Detection, ports.HuntResult, error) {
	q.Kind = ports.HuntRetroRule
	res, err := s.store.Query(ctx, q)
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

// Sweep enforces the retention tiers and AUDITS the expiry (never a silent deletion): the warm window is
// down-sampled and past-warm data is expired, with the counts recorded.
func (s *Service) Sweep(ctx context.Context) (ports.SweepReport, error) {
	rep, err := s.store.RetentionSweep(ctx, s.clock.Now().UTC())
	if err != nil {
		return ports.SweepReport{}, fmt.Errorf("telemetry retention sweep: %w", err)
	}
	// Expiry is destructive, so it MUST be auditable: if the audit write fails, surface it loudly (the
	// rows are already gone; the operator must know the deletion happened without a durable record)
	// rather than swallowing it and letting evidence expire silently.
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

// Footprint reports the store size so spend is observable.
func (s *Service) Footprint(ctx context.Context) (ports.TelemetryFootprint, error) {
	fp, err := s.store.Footprint(ctx)
	if err != nil {
		return ports.TelemetryFootprint{}, fmt.Errorf("telemetry footprint: %w", err)
	}
	return fp, nil
}

// lossSpan computes the observed-time SPAN [from, to] of the dropped events, so the loss is windowed by
// OVERLAP (a hunt overlapping any part of the span surfaces it, not just one whose window starts at the
// earliest dropped event). Events with no time are ignored; if none carry a time, both bounds fall back to
// the clock so the loss still anchors somewhere real rather than the zero time.
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

// recordGap audits a telemetry coverage event. It NO LONGER swallows the audit-write error (the D2
// companion bug): a coverage/loss event that cannot be durably recorded fails the ingest, so a gap is
// never admitted without a trail. The first-class loss record (RecordLoss) is the queryable object; this
// audit line is the human-facing trail alongside it.
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
