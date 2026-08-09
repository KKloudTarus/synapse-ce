package asset

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type BusinessAssetType string

const (
	BusinessAssetProduct         BusinessAssetType = "product"
	BusinessAssetApplication     BusinessAssetType = "application"
	BusinessAssetSystem          BusinessAssetType = "system"
	BusinessAssetBusinessService BusinessAssetType = "business_service"
)

func (t BusinessAssetType) Valid() bool {
	return t == BusinessAssetProduct || t == BusinessAssetApplication || t == BusinessAssetSystem || t == BusinessAssetBusinessService
}

type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
)

func (c Criticality) Valid() bool {
	return c == CriticalityCritical || c == CriticalityHigh || c == CriticalityMedium || c == CriticalityLow
}

type BusinessAssetLifecycle string

const (
	BusinessAssetDraft           BusinessAssetLifecycle = "draft"
	BusinessAssetActive          BusinessAssetLifecycle = "active"
	BusinessAssetDecommissioning BusinessAssetLifecycle = "decommissioning"
	BusinessAssetRetired         BusinessAssetLifecycle = "retired"
)

func (l BusinessAssetLifecycle) Valid() bool {
	return l == BusinessAssetDraft || l == BusinessAssetActive || l == BusinessAssetDecommissioning || l == BusinessAssetRetired
}

func (l BusinessAssetLifecycle) canTransitionTo(to BusinessAssetLifecycle) bool {
	switch l {
	case BusinessAssetDraft:
		return to == BusinessAssetActive
	case BusinessAssetActive:
		return to == BusinessAssetDecommissioning
	case BusinessAssetDecommissioning:
		return to == BusinessAssetRetired
	default:
		return false
	}
}

type BusinessAsset struct {
	ID          shared.ID
	TenantID    shared.ID
	Key         string
	Name        string
	Description string
	Type        BusinessAssetType
	Criticality Criticality
	Lifecycle   BusinessAssetLifecycle
	Owner       string
	Metadata    map[string]string
	Version     int
	Audit       shared.Audit
}

func NewBusinessAsset(id, tenantID shared.ID, key, name, description string, assetType BusinessAssetType, criticality Criticality, owner string, metadata map[string]string, actor string, now time.Time) (*BusinessAsset, error) {
	a := &BusinessAsset{
		ID: id, TenantID: tenantID, Key: strings.TrimSpace(key), Name: strings.TrimSpace(name),
		Description: strings.TrimSpace(description), Type: assetType, Criticality: criticality,
		Lifecycle: BusinessAssetDraft, Owner: strings.TrimSpace(owner), Metadata: copyAttrs(metadata), Version: 1,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now, CreatedBy: strings.TrimSpace(actor), UpdatedBy: strings.TrimSpace(actor)},
	}
	return a, a.Validate()
}

func (a *BusinessAsset) Validate() error {
	if a.ID.IsZero() || a.TenantID.IsZero() || a.Key == "" || utf8.RuneCountInString(a.Key) > 128 || a.Name == "" || utf8.RuneCountInString(a.Name) > 256 {
		return fmt.Errorf("%w: business asset id, tenant, bounded key and name are required", shared.ErrValidation)
	}
	if utf8.RuneCountInString(a.Description) > 4000 || a.Owner == "" || utf8.RuneCountInString(a.Owner) > 256 {
		return fmt.Errorf("%w: business asset description or owner is invalid", shared.ErrValidation)
	}
	if !a.Type.Valid() || !a.Criticality.Valid() || !a.Lifecycle.Valid() || a.Version < 1 {
		return fmt.Errorf("%w: business asset type, criticality, lifecycle or version is invalid", shared.ErrValidation)
	}
	if len(a.Metadata) > 32 {
		return fmt.Errorf("%w: business asset metadata exceeds 32 entries", shared.ErrValidation)
	}
	for key, value := range a.Metadata {
		if strings.TrimSpace(key) == "" || utf8.RuneCountInString(key) > 64 || utf8.RuneCountInString(value) > 512 {
			return fmt.Errorf("%w: business asset metadata is invalid", shared.ErrValidation)
		}
	}
	return nil
}

func (a *BusinessAsset) Update(name, description string, assetType BusinessAssetType, criticality Criticality, owner string, metadata map[string]string, expectedVersion int, actor string, now time.Time) error {
	if expectedVersion != a.Version {
		return fmt.Errorf("%w: business asset version changed", shared.ErrConflict)
	}
	a.Name, a.Description, a.Type, a.Criticality, a.Owner, a.Metadata = strings.TrimSpace(name), strings.TrimSpace(description), assetType, criticality, strings.TrimSpace(owner), copyAttrs(metadata)
	a.Version++
	a.Audit.UpdatedAt, a.Audit.UpdatedBy = now, strings.TrimSpace(actor)
	return a.Validate()
}

func (a *BusinessAsset) Transition(to BusinessAssetLifecycle, expectedVersion int, actor string, now time.Time) error {
	if expectedVersion != a.Version {
		return fmt.Errorf("%w: business asset version changed", shared.ErrConflict)
	}
	if a.Lifecycle == to {
		return nil
	}
	if !to.Valid() || !a.Lifecycle.canTransitionTo(to) {
		return fmt.Errorf("%w: business asset cannot transition from %s to %s", shared.ErrValidation, a.Lifecycle, to)
	}
	a.Lifecycle, a.Version = to, a.Version+1
	a.Audit.UpdatedAt, a.Audit.UpdatedBy = now, strings.TrimSpace(actor)
	return nil
}

func (a BusinessAsset) AcceptsAssignments() bool { return a.Lifecycle != BusinessAssetRetired }

type MembershipRole string

const (
	MembershipPrimary    MembershipRole = "primary"
	MembershipSupporting MembershipRole = "supporting"
	MembershipDependency MembershipRole = "dependency"
)

func (r MembershipRole) Valid() bool {
	return r == MembershipPrimary || r == MembershipSupporting || r == MembershipDependency
}

type ComponentMembership struct {
	TenantID    shared.ID
	AssetID     shared.ID
	ComponentID shared.ID
	Role        MembershipRole
	Provenance  string
}

func (m ComponentMembership) Validate() error {
	if m.TenantID.IsZero() || m.AssetID.IsZero() || m.ComponentID.IsZero() || !m.Role.Valid() || strings.TrimSpace(m.Provenance) == "" || utf8.RuneCountInString(m.Provenance) > 256 {
		return fmt.Errorf("%w: invalid business asset membership", shared.ErrValidation)
	}
	return nil
}
