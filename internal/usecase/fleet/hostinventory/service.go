// Package hostinventory is the use-case layer for the VM host agent (#410/#446, epic #405). It takes
// a host inventory an agent collected (facts + installed OS packages + coverage) and persists the
// host as a Kind=host asset in the fleet asset model (#431), reusing the asset use case's idempotent
// upsert-by-natural-key + audit path.
//
// Coverage honesty is preserved: the inventory's coverage issues are recorded (count + degraded flag
// on the asset, each issue audited), so a partial host inventory is never presented as complete. The
// package LIST feeds the SCA vulnerability pipeline separately; the asset model records the host
// identity, its facts, and a package count — it is not a package table.
package hostinventory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssetWriter is the subset of the asset use case this service needs. The read is part of the
// authorization boundary: an authenticated agent may update the host it already reports, but must
// never silently take over a host natural key already owned by a different enrolled agent.
type AssetWriter interface {
	GetAssetByKey(ctx context.Context, tenantID shared.ID, kind asset.Kind, key string) (*asset.Asset, error)
	UpsertAsset(ctx context.Context, actor string, in assetuc.UpsertAssetInput) (*asset.Asset, error)
}

// The concrete asset use case satisfies the consumer-side interface.
var _ AssetWriter = (*assetuc.Service)(nil)

// Service maps and persists a host inventory.
type Service struct {
	assets   AssetWriter
	audit    ports.AuditLogger
	clock    ports.Clock
	bindings ports.TelemetryAssetBindingStore // optional; nil ⇒ no telemetry asset binding is established
}

// SetTelemetryBinder wires the server-authoritative agent→host telemetry binding store. When set, a
// successful host-inventory sync establishes (or refreshes) the reporting agent's canonical telemetry
// asset binding — the A3 mapping that telemetry ingest requires (see the Sync doc comment). Kept an
// optional setter (nil ⇒ no binding) so telemetry-less compositions are unchanged.
func (s *Service) SetTelemetryBinder(b ports.TelemetryAssetBindingStore) { s.bindings = b }

// NewService validates its dependencies and constructs the service.
func NewService(assets AssetWriter, audit ports.AuditLogger, clock ports.Clock) (*Service, error) {
	if assets == nil {
		return nil, fmt.Errorf("%w: host inventory requires an asset writer", shared.ErrValidation)
	}
	if audit == nil {
		return nil, fmt.Errorf("%w: host inventory requires an audit logger", shared.ErrValidation)
	}
	if clock == nil {
		return nil, fmt.Errorf("%w: host inventory requires a clock", shared.ErrValidation)
	}
	return &Service{assets: assets, audit: audit, clock: clock}, nil
}

// SyncInput describes one observation of a host.
type SyncInput struct {
	TenantID  shared.ID
	Inventory dhi.HostInventory
}

// SyncResult reports what a sync produced.
type SyncResult struct {
	AssetID  shared.ID
	Complete bool
	Degraded bool
	Coverage int
}

// Sync persists the host as a Kind=host asset. It is idempotent: two syncs of an unchanged host reuse
// the asset id (keyed by the host's stable identity) and produce no churn. reporting_agent_id is stamped
// from actor, which the HTTP adapter obtains from the authenticated fleet credential; it is never read
// from Inventory. A3 uses this server-authored attribute to establish the canonical telemetry binding.
func (s *Service) Sync(ctx context.Context, actor string, in SyncInput) (*SyncResult, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return nil, fmt.Errorf("%w: host inventory actor is required", shared.ErrValidation)
	}
	if in.TenantID.IsZero() {
		return nil, fmt.Errorf("%w: host inventory tenant id is required", shared.ErrValidation)
	}
	inv := in.Inventory.Normalize()

	key := hostKey(inv.Facts)
	if key == "" {
		return nil, fmt.Errorf("%w: host has no stable identity (machine id or hostname required)", shared.ErrValidation)
	}
	if err := s.guardAssetBinding(ctx, actor, in.TenantID, key); err != nil {
		return nil, err
	}
	degraded := inv.Degraded()

	a, err := s.assets.UpsertAsset(ctx, actor, assetuc.UpsertAssetInput{
		TenantID:   in.TenantID,
		Kind:       asset.KindHost,
		Key:        key,
		Name:       displayName(inv.Facts, key),
		Attributes: attributes(inv, degraded, actor),
	})
	if err != nil {
		return nil, fmt.Errorf("host inventory: upsert host asset: %w", err)
	}

	// Audit each coverage gap so a partial host inventory is durably attributable, not just implied.
	now := s.clock.Now()
	for _, c := range inv.Coverage {
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  actor,
			Action: "host_inventory.coverage_gap",
			Target: key,
			Metadata: map[string]string{
				"tenant_id": in.TenantID.String(),
				"gap_kind":  string(c.Kind),
				"detail":    c.Detail,
			},
			At: now,
		}); err != nil {
			return nil, fmt.Errorf("host inventory: audit coverage gap: %w", err)
		}
	}

	// Establish the canonical telemetry binding this host inventory authorizes: the authenticated
	// reporting agent (actor) owns the host asset it just reconciled. Without this, telemetry ingest
	// cannot resolve the agent's asset and refuses every batch. guardAssetBinding above already proved
	// the reporting agent is not stealing another agent's host, so a cross-agent conflict here is a real
	// race and is surfaced, never swallowed.
	if s.bindings != nil {
		if err := s.bindings.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
			TenantID: in.TenantID, AgentID: shared.ID(actor), AssetID: a.ID, UpdatedAt: now,
		}); err != nil {
			return nil, fmt.Errorf("host inventory: establish telemetry asset binding: %w", err)
		}
		// Audit the establishment/refresh of this server-authoritative binding, mirroring how blocked
		// takeovers and coverage gaps are audited — the binding is a first-class trust action, so its
		// creation must be as attributable as its rejection.
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  actor,
			Action: "host_inventory.telemetry_binding_established",
			Target: a.ID.String(),
			Metadata: map[string]string{
				"tenant_id": in.TenantID.String(),
				"asset_id":  a.ID.String(),
				"agent_id":  actor,
			},
			At: now,
		}); err != nil {
			return nil, fmt.Errorf("host inventory: audit telemetry binding: %w", err)
		}
	}

	return &SyncResult{AssetID: a.ID, Complete: inv.Complete, Degraded: degraded, Coverage: len(inv.Coverage)}, nil
}

// guardAssetBinding prevents an authenticated agent from claiming the stable natural key of a host that
// is already attributed to a different enrolled agent. The audit record and security alert are emitted
// before returning the conflict, so a rejected takeover remains attributable even though no asset write
// occurs. PostgreSQL independently enforces the same invariant to close the lookup/write race.
func (s *Service) guardAssetBinding(ctx context.Context, actor string, tenantID shared.ID, key string) error {
	existing, err := s.assets.GetAssetByKey(ctx, tenantID, asset.KindHost, key)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return nil
	case err != nil:
		return fmt.Errorf("host inventory: lookup host asset: %w", err)
	}
	if existing == nil {
		return fmt.Errorf("host inventory: lookup host asset returned nil without error")
	}
	oldAgent := strings.TrimSpace(existing.Attributes["reporting_agent_id"])
	if oldAgent == "" || oldAgent == actor {
		return nil
	}

	now := s.clock.Now()
	metadata := func() map[string]string {
		return map[string]string{
			"tenant_id":    tenantID.String(),
			"asset_id":     existing.ID.String(),
			"asset_key":    key,
			"old_agent_id": oldAgent,
			"new_agent_id": actor,
		}
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   "host_inventory.asset_binding_takeover_blocked",
		Target:   existing.ID.String(),
		Metadata: metadata(),
		At:       now,
	}); err != nil {
		return fmt.Errorf("host inventory: audit blocked asset-binding takeover: %w", err)
	}
	alert := metadata()
	alert["alert_type"] = "telemetry_asset_binding_takeover"
	alert["severity"] = "high"
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:    actor,
		Action:   "security.alert",
		Target:   existing.ID.String(),
		Metadata: alert,
		At:       now,
	}); err != nil {
		return fmt.Errorf("host inventory: emit asset-binding security alert: %w", err)
	}
	return fmt.Errorf("%w: host asset %s is already bound to agent %s", shared.ErrConflict, existing.ID, oldAgent)
}

// hostKey is the host's stable natural key: the machine id when known (survives hostname changes),
// else a hostname-derived key, else empty (unidentifiable).
func hostKey(f dhi.HostFacts) string {
	if f.MachineID != "" {
		return "machine-id/" + f.MachineID
	}
	if f.Hostname != "" {
		return "hostname/" + f.Hostname
	}
	return ""
}

func displayName(f dhi.HostFacts, key string) string {
	if f.Hostname != "" {
		return f.Hostname
	}
	return key
}

func attributes(inv dhi.HostInventory, degraded bool, reportingAgent string) map[string]string {
	f := inv.Facts
	attrs := map[string]string{
		"os":                 f.OS,
		"os_version":         f.OSVersion,
		"kernel":             f.Kernel,
		"arch":               f.Arch,
		"machine_id":         f.MachineID,
		"cloud_instance":     f.CloudInstance,
		"packages":           strconv.Itoa(len(inv.Packages)),
		"complete":           strconv.FormatBool(inv.Complete),
		"degraded":           strconv.FormatBool(degraded),
		"coverage_gaps":      strconv.Itoa(len(inv.Coverage)),
		"reporting_agent_id": strings.TrimSpace(reportingAgent),
	}
	// Drop empty fact values so the asset attributes stay clean.
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	return attrs
}
