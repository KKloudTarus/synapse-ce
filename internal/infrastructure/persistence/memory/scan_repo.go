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

func (r *ScanRepository) AdmitInventory(ctx context.Context, engagementID shared.ID, scope string, admittedAt time.Time) (sbom.InventoryAdmission, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return sbom.InventoryAdmission{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	return r.inventory.admit(sbom.InventoryAdmission{TenantID: tenantID, EngagementID: engagementID, Scope: scope, AdmittedAt: admittedAt.UTC()})
}

func (r *ScanRepository) SaveScan(ctx context.Context, engagementID shared.ID, doc *sbom.SBOM, vulns []vulnerability.Vulnerability, snap ports.ScanSnapshot) (ports.ScanSaveResult, error) {
	if doc == nil {
		return ports.ScanSaveResult{}, nil
	}
	if engagementID.IsZero() {
		return ports.ScanSaveResult{}, fmt.Errorf("%w: engagement id is required", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return ports.ScanSaveResult{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	admission := snap.InventoryAdmission
	legacyAdmission := admission.Generation <= 0
	if legacyAdmission {
		var err error
		admission, err = r.AdmitInventory(ctx, engagementID, sbom.InventoryScope(doc.TargetRef), time.Now().UTC())
		if err != nil {
			return ports.ScanSaveResult{}, err
		}
	}
	if err := admission.Validate(); err != nil || admission.TenantID != tenantID || admission.EngagementID != engagementID {
		return ports.ScanSaveResult{}, fmt.Errorf("%w: inventory admission does not match scan", shared.ErrValidation)
	}
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
	coverage := sbom.IdentityCoverage{Total: len(doc.Components)}
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
			InventoryScope: admission.Scope, InventoryGeneration: admission.Generation,
		})
		if identity.Status == sbom.IdentityResolved || cpeIdentity.Status == sbom.IdentityResolved {
			coverage.Resolved++
		} else {
			coverage.Unsupported++
		}
		components[component.Name+"\x00"+component.Version] = struct{}{}
	}
	skipped := 0
	for _, item := range vulns {
		if _, ok := components[item.Component+"\x00"+item.Version]; !ok {
			skipped++
		}
	}
	completeness := snap.InventoryCompleteness
	if !completeness.Valid() {
		completeness = sbom.InventoryUnknown
	}
	authoritative := snap.InventoryAuthoritative && !legacyAdmission
	reason := snap.InventoryAuthorityReason
	if legacyAdmission {
		reason = "legacy_writer_without_admission"
	}
	publication := sbom.InventoryPublication{InventoryAdmission: admission, SBOMID: sbomID, Completeness: completeness,
		Authoritative: authoritative, AuthorityReason: reason, Coverage: coverage, PublishedAt: createdAt}
	publication, err := r.inventory.publishSnapshot(records, publication)
	if err != nil {
		return ports.ScanSaveResult{}, err
	}
	return ports.ScanSaveResult{SkippedVulnerabilities: skipped, Publication: publication}, nil
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
