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
	"fmt"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AssetWriter is the subset of the asset use case this service needs (idempotent host upsert).
// assetuc.Service satisfies it; tests use a fake.
type AssetWriter interface {
	UpsertAsset(ctx context.Context, actor string, in assetuc.UpsertAssetInput) (*asset.Asset, error)
}

// The concrete asset use case satisfies the consumer-side interface.
var _ AssetWriter = (*assetuc.Service)(nil)

// Service maps and persists a host inventory.
type Service struct {
	assets AssetWriter
	audit  ports.AuditLogger
	clock  ports.Clock
}

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
// the asset id (keyed by the host's stable identity) and produce no churn.
func (s *Service) Sync(ctx context.Context, actor string, in SyncInput) (*SyncResult, error) {
	if strings.TrimSpace(actor) == "" {
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
	degraded := inv.Degraded()

	a, err := s.assets.UpsertAsset(ctx, actor, assetuc.UpsertAssetInput{
		TenantID:   in.TenantID,
		Kind:       asset.KindHost,
		Key:        key,
		Name:       displayName(inv.Facts, key),
		Attributes: attributes(inv, degraded),
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

	return &SyncResult{AssetID: a.ID, Complete: inv.Complete, Degraded: degraded, Coverage: len(inv.Coverage)}, nil
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

func attributes(inv dhi.HostInventory, degraded bool) map[string]string {
	f := inv.Facts
	attrs := map[string]string{
		"os":             f.OS,
		"os_version":     f.OSVersion,
		"kernel":         f.Kernel,
		"arch":           f.Arch,
		"machine_id":     f.MachineID,
		"cloud_instance": f.CloudInstance,
		"packages":       strconv.Itoa(len(inv.Packages)),
		"complete":       strconv.FormatBool(inv.Complete),
		"degraded":       strconv.FormatBool(degraded),
		"coverage_gaps":  strconv.Itoa(len(inv.Coverage)),
	}
	// Drop empty fact values so the asset attributes stay clean.
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	return attrs
}
