package memory

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanRepository keeps the current process's component snapshots available to
// background vulnerability correlation. It is not durable across restarts.
type ScanRepository struct{ inventory *ComponentInventoryStore }

func NewScanRepository(inventory ...*ComponentInventoryStore) *ScanRepository {
	store := NewComponentInventoryStore()
	if len(inventory) > 0 && inventory[0] != nil {
		store = inventory[0]
	}
	return &ScanRepository{inventory: store}
}

var _ ports.ScanRepository = (*ScanRepository)(nil)

func (r *ScanRepository) SaveScan(ctx context.Context, engagementID shared.ID, doc *sbom.SBOM, vulns []vulnerability.Vulnerability, _ ports.ScanSnapshot) (int, error) {
	if doc == nil {
		return 0, nil
	}
	if engagementID.IsZero() {
		return 0, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return 0, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	sbomID := doc.ID
	if sbomID.IsZero() {
		sbomID = shared.ID(rand.Text())
	}
	createdAt := doc.Audit.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	records := make([]sbom.ComponentRecord, 0, len(doc.Components))
	components := make(map[string]struct{}, len(doc.Components))
	for _, component := range doc.Components {
		identity := sbom.IdentityFromComponent(component)
		cpeIdentity := sbom.IdentityFromCPE(component.CPE, component.Version)
		scope, reachability, unreferenced := inventoryRiskContext(component)
		records = append(records, sbom.ComponentRecord{
			TenantID: tenantID, EngagementID: engagementID, SBOMID: sbomID, ComponentID: shared.ID(rand.Text()),
			Name: component.Name, Version: component.Version, PURL: component.PURL, CPE: cpeIdentity.Canonical,
			CPEPart: cpeIdentity.CPE.Part, CPEVendor: cpeIdentity.CPE.Vendor, CPEProduct: cpeIdentity.CPE.Product,
			CPEStatus: cpeIdentity.Status, CPEReason: cpeIdentity.Reason, CPEHash: cpeIdentity.Fingerprint,
			Ecosystem: identity.Ecosystem, Package: identity.Package, IdentityHash: identity.Fingerprint,
			IdentityStatus: identity.Status, IdentityReason: identity.Reason, Scope: scope,
			Reachability: reachability, Unreferenced: unreferenced, SBOMCreatedAt: createdAt,
		})
		components[component.Name+"\x00"+component.Version] = struct{}{}
	}
	if err := r.inventory.saveSnapshot(records); err != nil {
		return 0, err
	}
	skipped := 0
	for _, item := range vulns {
		if _, ok := components[item.Component+"\x00"+item.Version]; !ok {
			skipped++
		}
	}
	return skipped, nil
}

func inventoryRiskContext(component sbom.Component) (string, string, bool) {
	scope := component.Scope
	if scope == "" {
		scope = sbom.ScopeUnknown
	}
	switch component.Reachability {
	case sbom.ReachabilityReachable:
		return scope, vulnerability.ReachHigh, false
	case sbom.ReachabilityUnreferenced:
		return scope, vulnerability.ReachLow, true
	default:
		return scope, vulnerability.ReachUnknown, false
	}
}
