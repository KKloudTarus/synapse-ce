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

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
// the store-rate stage, and any sequence gap (an upstream — agent/transport — loss made visible).
type IngestReport struct {
	Accepted int
	Dropped  int // shed because the batch exceeded the ingest budget; reported, never silent
	Gap      *ports.TelemetrySequenceGap
}

// Ingest admits one batch under the coherent ingest budget. Two stages can report a telemetry gap:
//   - a sequence gap vs. the last batch stored for this (host, class) — an upstream loss made visible;
//   - the batch exceeding the store-rate budget — the overflow is shed and reported, never dropped silently.
//
// Either gap is audited on the affected host. The accepted prefix is persisted with its sampling rate.
func (s *Service) Ingest(ctx context.Context, batch ports.TelemetryBatch) (IngestReport, error) {
	if batch.TenantID == "" || batch.HostID == "" || batch.AgentID == "" {
		return IngestReport{}, fmt.Errorf("%w: telemetry batch needs tenant, host and agent", shared.ErrValidation)
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
		s.recordGap(ctx, "telemetry.sequence_gap", batch, map[string]string{
			"last_sequence": fmt.Sprint(last), "incoming_sequence": fmt.Sprint(batch.Sequence), "missing": fmt.Sprint(gap.Missing),
		})
	}

	// Stage 2: store-rate budget. Overflow is shed from the tail and reported as a telemetry gap. The
	// accepted prefix is stored with an ELEVATED sample rate so the truncation is durably visible: a
	// retro-hunt over this window will see it as sampled and therefore NOT complete — the loss cannot
	// masquerade as a full window.
	accepted := batch
	events := batch.Events
	if len(events) > s.budget {
		report.Dropped = len(events) - s.budget
		accepted.SampleRate = maxInt(batch.SampleRate, ceilDiv(len(events), s.budget))
		events = events[:s.budget]
		s.recordGap(ctx, "telemetry.overflow", batch, map[string]string{
			"budget": fmt.Sprint(s.budget), "received": fmt.Sprint(len(batch.Events)), "dropped": fmt.Sprint(report.Dropped),
			"effective_sample_rate": fmt.Sprint(accepted.SampleRate),
		})
	}
	report.Accepted = len(events)

	accepted.Events = events
	if err := s.store.Ingest(ctx, accepted); err != nil {
		return report, fmt.Errorf("telemetry ingest: %w", err)
	}
	return report, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ceilDiv(a, b int) int {
	if b <= 0 {
		return a
	}
	return (a + b - 1) / b
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

func (s *Service) recordGap(ctx context.Context, action string, batch ports.TelemetryBatch, meta map[string]string) {
	meta["host"] = batch.HostID.String()
	meta["class"] = string(batch.Class)
	_ = s.audit.Record(ctx, ports.AuditEntry{
		Actor: batch.AgentID.String(), Action: action, Target: batch.HostID.String(), At: s.clock.Now().UTC(), Metadata: meta,
	})
}
