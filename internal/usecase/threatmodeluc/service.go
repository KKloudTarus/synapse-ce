// Package threatmodeluc is the architecture-input threat-model ingest use case:
// it accepts an UNTRUSTED architecture model (from the API), bounds its size, runs the domain's fail-closed
// Validate (referential integrity), persists it per engagement, and audits the action – the server-side
// enforcement the domain seam (internal/domain/threatmodel) is reasoned over by. The agent then proposes
// STRIDE threats over the stored model. Pure orchestration over ports (no infra import).
package threatmodeluc

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Size caps on an ingested model – an untrusted payload is bounded BEFORE the (linear) Validate runs, so a
// hostile model can't exhaust memory/CPU. Generous vs any real architecture; the HTTP edge also caps bytes.
const (
	maxComponents = 2000
	maxFlows      = 10000
	maxBoundaries = 256
	maxAssets     = 2000
)

// Service ingests + serves the per-engagement threat model.
type Service struct {
	store ports.ThreatModelStore
	audit ports.AuditLogger
	clock ports.Clock
}

// NewService validates its dependencies and returns the ingest service.
func NewService(store ports.ThreatModelStore, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if store == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: threatmodel service needs store + audit + clock", shared.ErrValidation)
	}
	return &Service{store: store, audit: audit, clock: clock}, nil
}

// Ingest bounds, validates, and persists an engagement's architecture model, then audits it. Size limits are
// checked BEFORE Validate (cheap rejection of a hostile payload); Validate then fail-closes on any dangling
// reference (a typo'd boundary would otherwise hide a real crossing). The whole action is attributable.
func (s *Service) Ingest(ctx context.Context, principal string, tenantID, engagementID shared.ID, m threatmodel.Model) (threatmodel.ModelDelta, error) {
	if engagementID == "" {
		return threatmodel.ModelDelta{}, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	if len(m.Components) > maxComponents || len(m.Flows) > maxFlows || len(m.Boundaries) > maxBoundaries || len(m.Assets) > maxAssets {
		return threatmodel.ModelDelta{}, fmt.Errorf("%w: threat model exceeds size limits (components<=%d, flows<=%d, boundaries<=%d, assets<=%d)",
			shared.ErrValidation, maxComponents, maxFlows, maxBoundaries, maxAssets)
	}
	if err := m.Validate(); err != nil {
		return threatmodel.ModelDelta{}, err // fail-closed referential integrity (shared.ErrValidation-wrapped)
	}
	// Shift-left "re-run on architecture change, surface deltas": diff the new model against the PRIOR
	// one – read BEFORE Save overwrites it – so the architecture change, especially any NEW boundary crossing
	// (new attack surface), is computed, returned to the caller, and audited. Deterministic, no LLM.
	// Best-effort: a read error yields an empty delta (never fabricate an all-added delta from a failed read);
	// a first ingest (no prior → zero Model) reports everything as added.
	var delta threatmodel.ModelDelta
	if prior, _, gerr := s.store.Get(ctx, engagementID); gerr == nil {
		delta = threatmodel.Diff(prior, m)
	}
	if err := s.store.Save(ctx, engagementID, tenantID, m); err != nil {
		return threatmodel.ModelDelta{}, fmt.Errorf("save threat model: %w", err)
	}
	// Append-only, attributable audit; the AuditLogger impl hash-chains it. The delta counts make an
	// architecture change – and its security impact (new crossings) – visible + attributable in the trail.
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  principal,
		Action: "threat_model.ingest",
		Target: engagementID.String(),
		Metadata: map[string]string{
			"components":         fmt.Sprintf("%d", len(m.Components)),
			"flows":              fmt.Sprintf("%d", len(m.Flows)),
			"crossings":          fmt.Sprintf("%d", len(m.BoundaryCrossings())),
			"added_components":   fmt.Sprintf("%d", len(delta.AddedComponents)),
			"removed_components": fmt.Sprintf("%d", len(delta.RemovedComponents)),
			"added_flows":        fmt.Sprintf("%d", len(delta.AddedFlows)),
			"removed_flows":      fmt.Sprintf("%d", len(delta.RemovedFlows)),
			"new_crossings":      fmt.Sprintf("%d", len(delta.NewCrossings)),
			"closed_crossings":   fmt.Sprintf("%d", len(delta.ClosedCrossings)),
		},
		At: s.clock.Now(),
	}); err != nil {
		return threatmodel.ModelDelta{}, fmt.Errorf("audit threat-model ingest: %w", err)
	}
	return delta, nil
}

// Get returns the engagement's current model (ok=false when none has been ingested).
func (s *Service) Get(ctx context.Context, engagementID shared.ID) (threatmodel.Model, bool, error) {
	return s.store.Get(ctx, engagementID)
}
