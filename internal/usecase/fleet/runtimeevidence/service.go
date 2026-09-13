// Package runtimeevidence is the fleet ingest use case for host runtime-reachability evidence (EPIC #1042
// #1060/#1061). A host agent ships the shared libraries it observed loaded plus the OS packages that own
// them; this use case resolves the agent's canonical host asset and its hidden vulnerability engagement,
// then joins the evidence to that engagement's findings by PACKAGE OWNERSHIP, raising (never suppressing)
// the finding for a vulnerable library that actually loaded.
//
// It holds no judgment-minting authority of its own: the join and the raise-only judgment come from the
// injected runtime attributor (internal/usecase/runtimereach), so this package stays a thin, tenant-bound
// ingest boundary. It is composition-root-only and must never be reached from the agent tool catalog.
package runtimeevidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/runtimereach"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// assetResolver maps an authenticated agent to the canonical host asset the control plane bound to it. The
// telemetry transport repository (and its in-memory twin) satisfies it via ResolveTelemetryAsset.
type assetResolver interface {
	ResolveTelemetryAsset(ctx context.Context, agentID shared.ID) (shared.ID, error)
}

// engagementResolver loads the hidden host-vulnerability engagement for a Kind=host asset.
// ports.EngagementRepository satisfies it.
type engagementResolver interface {
	GetByHostAssetID(ctx context.Context, tenantID, assetID shared.ID) (*engagement.Engagement, error)
}

// runtimeAttributor joins observed loads to an engagement's findings by package ownership and mints the
// raise-only runtime-reachability judgments. *runtimereach.Service satisfies it.
type runtimeAttributor interface {
	Attribute(ctx context.Context, engagementID shared.ID, ownership *runtimereach.Ownership, loads []runtimereach.LoadEvent) (int, error)
}

// Service ingests one agent's runtime-evidence report.
type Service struct {
	resolver    assetResolver
	engagements engagementResolver
	attributor  runtimeAttributor
}

// NewService validates its dependencies and returns the ingest service.
func NewService(resolver assetResolver, engagements engagementResolver, attributor runtimeAttributor) (*Service, error) {
	if resolver == nil || engagements == nil || attributor == nil {
		return nil, fmt.Errorf("%w: runtime-evidence ingest is missing a dependency", shared.ErrValidation)
	}
	return &Service{resolver: resolver, engagements: engagements, attributor: attributor}, nil
}

// Result reports what an ingest produced, for the agent-plane response and the audit trail.
type Result struct {
	AssetID      shared.ID
	EngagementID shared.ID
	Minted       int
	// Coverage echoes the host's declared runtime-evidence gaps (no eBPF privilege, an unreadable package
	// database, an unsupported platform, a truncated sweep). It is carried back so the caller can record that
	// this host reports partial or no runtime evidence. Coverage never suppresses a finding (runtime
	// reachability is raise-only); it is observability, so the host's absence of evidence is honest, not silent.
	Coverage []runtimereach.CoverageReason
	// Pending is true when the host has no vulnerability engagement yet (its first SCA scan has not produced
	// findings). The evidence is dropped for this sync; because attribution is idempotent and supersede-only,
	// the agent's next report re-attributes against the populated findings. It is not an error.
	Pending bool
}

// Ingest resolves the agent's host asset and its hidden engagement, then attributes the runtime evidence to
// that engagement's findings. The tenant and agent identity come from the authenticated agent, never the
// body. A report with no evidence, or a host with no engagement yet, mints nothing and is not an error
// (runtime reachability is raise-only; its absence changes no verdict).
func (s *Service) Ingest(ctx context.Context, tenantID, agentID shared.ID, report runtimereach.Report) (Result, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	if agentID.IsZero() {
		return Result{}, fmt.Errorf("%w: runtime-evidence ingest requires an agent id", shared.ErrValidation)
	}
	if err := report.Validate(); err != nil {
		return Result{}, err
	}
	tctx := shared.WithTenant(ctx, tenantID)
	assetID, err := s.resolver.ResolveTelemetryAsset(tctx, agentID)
	if err != nil {
		return Result{}, fmt.Errorf("resolve host asset for agent %s: %w", agentID, err)
	}
	if assetID.IsZero() {
		return Result{}, fmt.Errorf("%w: agent %s has no bound host asset; report inventory first", shared.ErrValidation, agentID)
	}
	eng, err := s.engagements.GetByHostAssetID(tctx, tenantID, assetID)
	if errors.Is(err, shared.ErrNotFound) {
		// The host has no vulnerability engagement yet (no scan has produced findings). Nothing to attribute
		// this sync; the next report converges once findings exist. The coverage gap is still carried back.
		return Result{AssetID: assetID, Coverage: report.Coverage, Pending: true}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("resolve host vulnerability engagement: %w", err)
	}
	if report.Empty() {
		// A coverage-only report (sensor unavailable, unreadable/unsupported package DB) has no loads to
		// attribute; carry its coverage back so the host's runtime-evidence gap is recorded, not dropped.
		return Result{AssetID: assetID, EngagementID: eng.ID, Coverage: report.Coverage}, nil
	}
	ownership, loads := report.Build()
	minted, err := s.attributor.Attribute(tctx, eng.ID, ownership, loads)
	if err != nil {
		return Result{}, fmt.Errorf("attribute runtime evidence: %w", err)
	}
	return Result{AssetID: assetID, EngagementID: eng.ID, Minted: minted, Coverage: report.Coverage}, nil
}
