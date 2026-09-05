// Package processreport ingests an enrolled agent's running-process report and feeds the two consumers
// that gave the behavior baseline no input before it existed: the per-host running-process projection
// (#594 B5) and the behavior baseline learner (#594 D). The shipped agent reported host package
// inventory but never its processes, so the statistical baseline in internal/domain/baseline never saw
// a single observation. This closes that gap on the agent transport plane.
//
// The asset a report is attributed to is NEVER taken from the agent's request. It is resolved
// server-side from the authenticated agent's canonical telemetry binding, exactly as telemetry and
// detection ingest resolve it, so an agent cannot report processes for a host it does not own.
package processreport

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// MaxProcesses bounds one report. A host with more live processes than this ships the first MaxProcesses;
// the baseline features (process count as a spawn-rate proxy, distinct exec paths) saturate well below
// it, so the cap costs no fidelity while keeping a misbehaving or compromised agent from flooding the
// projection.
const MaxProcesses = 4096

// AssetResolver maps an authenticated agent to the canonical host asset the control plane bound to it.
// *postgres.TelemetryTransportRepository and the in-memory twin satisfy it via ResolveTelemetryAsset.
type AssetResolver interface {
	ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error)
}

// ProcessStore persists the running-process projection. ports.EndpointProcessStore satisfies it.
type ProcessStore interface {
	SaveProcesses(ctx context.Context, snapshots []ports.ProcessSnapshot) error
}

// Learner folds the just-reported profile into the asset's behavior baseline. *behaviorbaseline.Service
// satisfies it. Optional: nil means the projection is stored but no baseline observation is taken.
type Learner interface {
	Learn(ctx context.Context, actor string, assetID shared.ID) error
}

// Process is one running process as the agent observed it, free of any domain or transport type.
type Process struct {
	PID     int
	Comm    string
	Path    string
	Running bool
}

// Service ingests a report: resolve the asset, persist the snapshots, then learn.
type Service struct {
	resolver AssetResolver
	store    ProcessStore
	learner  Learner
	clock    ports.Clock
}

// NewService validates its required dependencies. learner is optional.
func NewService(resolver AssetResolver, store ProcessStore, learner Learner, clock ports.Clock) (*Service, error) {
	if resolver == nil || store == nil || clock == nil {
		return nil, fmt.Errorf("%w: process report service is missing a dependency", shared.ErrValidation)
	}
	return &Service{resolver: resolver, store: store, learner: learner, clock: clock}, nil
}

// Result reports what a report produced, for the agent-plane response and the audit trail.
type Result struct {
	AssetID shared.ID
	Saved   int
	Learned bool
}

// Report resolves the agent's canonical asset, persists the running processes as snapshots under the
// agent's tenant, then folds the profile into the behavior baseline. The tenant is taken from the
// authenticated agent; the ctx it saves under is bound to that tenant so the store's RLS holds. An agent
// with no established binding yet (it has not reported inventory) is a validation error, not a 500: the
// binding is a prerequisite the agent satisfies by shipping inventory first.
func (s *Service) Report(ctx context.Context, tenantID, agentID shared.ID, procs []Process) (Result, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if agentID.IsZero() {
		return Result{}, fmt.Errorf("%w: process report requires an agent id", shared.ErrValidation)
	}
	// Every store call is tenant-scoped from ctx (the agent's tenant), so bind it once up front — the
	// binding resolver and the projection store both read the tenant from here.
	tctx := shared.WithTenant(ctx, tenantID)
	assetID, err := s.resolver.ResolveTelemetryAsset(tctx, agentID)
	if err != nil {
		return Result{}, fmt.Errorf("resolve host asset for agent %s: %w", agentID, err)
	}
	if assetID.IsZero() {
		return Result{}, fmt.Errorf("%w: agent %s has no bound host asset; report inventory first", shared.ErrValidation, agentID)
	}
	if len(procs) > MaxProcesses {
		procs = procs[:MaxProcesses]
	}
	now := s.clock.Now().UTC()
	snapshots := make([]ports.ProcessSnapshot, 0, len(procs))
	for _, p := range procs {
		if p.PID < 0 {
			continue
		}
		snapshots = append(snapshots, ports.ProcessSnapshot{
			TenantID: tenantID, AssetID: assetID,
			// A pid is the stable-enough identity for a point-in-time host snapshot: a re-observation of
			// the same live pid upserts in place. Prefixed so it never collides with another entity id space.
			EntityID: shared.ID(fmt.Sprintf("proc:%d", p.PID)),
			PID:      p.PID, Comm: p.Comm, Path: p.Path, Running: p.Running, LastSeenAt: now,
		})
	}
	if err := s.store.SaveProcesses(tctx, snapshots); err != nil {
		return Result{}, fmt.Errorf("save process snapshots: %w", err)
	}
	res := Result{AssetID: assetID, Saved: len(snapshots)}
	if s.learner != nil {
		// The snapshots are durably saved; a learn failure must not fail the report. The caller logs it.
		if err := s.learner.Learn(tctx, agentID.String(), assetID); err != nil {
			return res, fmt.Errorf("learn behavior baseline: %w", err)
		}
		res.Learned = true
	}
	return res, nil
}
