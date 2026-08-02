// Package asset models the bounded, tenant-owned AppSec inventory. It is not a
// general CMDB: identities are security-relevant and intentionally constrained.
package asset

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Category string

const (
	CategoryApplication    Category = "application"
	CategoryRepository     Category = "repository"
	CategoryService        Category = "service"
	CategoryAPI            Category = "api"
	CategoryEndpoint       Category = "endpoint"
	CategoryDomain         Category = "domain"
	CategoryCloudResource  Category = "cloud_resource"
	CategoryContainerImage Category = "container_image"
	CategoryArtifact       Category = "artifact"
	CategorySBOM           Category = "sbom"
	CategoryInfrastructure Category = "infrastructure"
	CategoryIaCModule      Category = "iac_module"
)

func (c Category) Valid() bool {
	switch c {
	case CategoryApplication, CategoryRepository, CategoryService, CategoryAPI, CategoryEndpoint,
		CategoryDomain, CategoryCloudResource, CategoryContainerImage, CategoryArtifact, CategorySBOM,
		CategoryInfrastructure, CategoryIaCModule:
		return true
	default:
		return false
	}
}

type Lifecycle string

const (
	LifecyclePlanned Lifecycle = "planned"
	LifecycleActive  Lifecycle = "active"
	LifecycleRetired Lifecycle = "retired"
)

func (l Lifecycle) Valid() bool {
	return l == LifecyclePlanned || l == LifecycleActive || l == LifecycleRetired
}

type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

func (c Criticality) Valid() bool {
	return c == CriticalityLow || c == CriticalityMedium || c == CriticalityHigh || c == CriticalityCritical
}

type Exposure string

const (
	ExposureInternal Exposure = "internal"
	ExposurePartner  Exposure = "partner"
	ExposurePublic   Exposure = "public"
)

func (e Exposure) Valid() bool {
	return e == ExposureInternal || e == ExposurePartner || e == ExposurePublic
}

// Identity is the stable, unique security identifier for an asset within a tenant.
// It must never contain a credential, access token, or other secret.
type Identity struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// AssetIdentity is the explicit inventory name for Identity.
type AssetIdentity = Identity

func (i Identity) Validate(category Category) error {
	kind, value := strings.TrimSpace(i.Kind), strings.TrimSpace(i.Value)
	if kind == "" || value == "" || utf8.RuneCountInString(kind) > 64 || utf8.RuneCountInString(value) > 2048 {
		return fmt.Errorf("%w: asset identity is required and bounded", shared.ErrValidation)
	}
	if strings.ContainsAny(value, "\r\n\x00") || hasCredential(value) {
		return fmt.Errorf("%w: asset identity must not contain credentials or controls", shared.ErrValidation)
	}
	switch category {
	case CategoryRepository:
		return validateRepositoryIdentity(value)
	case CategoryEndpoint, CategoryAPI:
		return validateURLIdentity(value)
	case CategoryDomain:
		if strings.Contains(value, "/") || strings.Contains(value, ":") || !strings.Contains(value, ".") {
			return fmt.Errorf("%w: domain identity is invalid", shared.ErrValidation)
		}
	case CategoryContainerImage:
		if !strings.Contains(value, "@sha256:") || len(value) < len("x@sha256:")+64 {
			return fmt.Errorf("%w: container image identity requires an immutable sha256 digest", shared.ErrValidation)
		}
	case CategorySBOM:
		if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
			return fmt.Errorf("%w: SBOM identity requires a sha256 digest", shared.ErrValidation)
		}
	}
	return nil
}

func hasCredential(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "password=") || strings.Contains(lower, "token=") || strings.Contains(lower, "apikey=")
}

func validateRepositoryIdentity(value string) error {
	if strings.HasPrefix(value, "git@") {
		return nil
	}
	return validateURLIdentity(value)
}

func validateURLIdentity(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "ssh") {
		return fmt.Errorf("%w: URL identity is invalid", shared.ErrValidation)
	}
	return nil
}

type Asset struct {
	ID             shared.ID
	TenantID       shared.ID
	Name           string
	Category       Category
	Identity       Identity
	Lifecycle      Lifecycle
	Criticality    Criticality
	Exposure       Exposure
	Classification string
	Version        int
	Audit          shared.Audit
}

func New(id, tenantID shared.ID, name string, category Category, identity Identity, now time.Time) (Asset, error) {
	a := Asset{ID: id, TenantID: tenantID, Name: strings.TrimSpace(name), Category: category, Identity: identity, Lifecycle: LifecyclePlanned, Criticality: CriticalityMedium, Exposure: ExposureInternal, Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	return a, a.Validate()
}

func (a Asset) Validate() error {
	if a.ID.IsZero() || strings.TrimSpace(a.Name) == "" || utf8.RuneCountInString(a.Name) > 256 || !a.Category.Valid() || !a.Lifecycle.Valid() || !a.Criticality.Valid() || !a.Exposure.Valid() || a.Version < 1 {
		return fmt.Errorf("%w: invalid asset", shared.ErrValidation)
	}
	if utf8.RuneCountInString(a.Classification) > 128 {
		return fmt.Errorf("%w: asset classification exceeds limit", shared.ErrValidation)
	}
	return a.Identity.Validate(a.Category)
}

// Version is an immutable audit record made whenever an asset's mutable posture
// changes. Snapshot is application-owned JSON; repositories cap its size.
type Version struct {
	ID        shared.ID
	TenantID  shared.ID
	AssetID   shared.ID
	Number    int
	Snapshot  []byte
	CreatedAt time.Time
	CreatedBy string
}

func (v Version) Validate() error {
	if v.ID.IsZero() || v.AssetID.IsZero() || v.Number < 1 || len(v.Snapshot) == 0 || len(v.Snapshot) > 64<<10 || !json.Valid(v.Snapshot) || v.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid asset version", shared.ErrValidation)
	}
	return nil
}

// AssetVersion is the explicit inventory name for Version.
type AssetVersion = Version

type RelationshipType string

const (
	RelationshipContains      RelationshipType = "contains"
	RelationshipPartOf        RelationshipType = "part_of"
	RelationshipDependsOn     RelationshipType = "depends_on"
	RelationshipRunsOn        RelationshipType = "runs_on"
	RelationshipDeployedTo    RelationshipType = "deployed_to"
	RelationshipExposes       RelationshipType = "exposes"
	RelationshipBuiltFrom     RelationshipType = "built_from"
	RelationshipManagedBy     RelationshipType = "managed_by"
	RelationshipProcessesData RelationshipType = "processes_data"
)

func (r RelationshipType) Valid() bool {
	switch r {
	case RelationshipContains, RelationshipPartOf, RelationshipDependsOn, RelationshipRunsOn, RelationshipDeployedTo, RelationshipExposes, RelationshipBuiltFrom, RelationshipManagedBy, RelationshipProcessesData:
		return true
	default:
		return false
	}
}

type Relationship struct {
	ID          shared.ID
	TenantID    shared.ID
	FromAssetID shared.ID
	ToAssetID   shared.ID
	Type        RelationshipType
	CreatedAt   time.Time
	CreatedBy   string
}

func (r Relationship) Validate() error {
	if r.ID.IsZero() || r.FromAssetID.IsZero() || r.ToAssetID.IsZero() || r.FromAssetID == r.ToAssetID || !r.Type.Valid() || r.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid asset relationship", shared.ErrValidation)
	}
	return nil
}

type BusinessService struct {
	ID          shared.ID
	TenantID    shared.ID
	Name        string
	Description string
	Criticality Criticality
	Lifecycle   Lifecycle
	Audit       shared.Audit
}

func (b BusinessService) Validate() error {
	if b.ID.IsZero() || strings.TrimSpace(b.Name) == "" || utf8.RuneCountInString(b.Name) > 256 || utf8.RuneCountInString(b.Description) > 4000 || !b.Criticality.Valid() || !b.Lifecycle.Valid() {
		return fmt.Errorf("%w: invalid business service", shared.ErrValidation)
	}
	return nil
}

type AssetLinkRole string

const (
	AssetLinkOwns     AssetLinkRole = "owns"
	AssetLinkUses     AssetLinkRole = "uses"
	AssetLinkSupports AssetLinkRole = "supports"
)

func (r AssetLinkRole) Valid() bool {
	return r == AssetLinkOwns || r == AssetLinkUses || r == AssetLinkSupports
}

type BusinessServiceAssetLink struct {
	BusinessServiceID shared.ID
	AssetID           shared.ID
	Role              AssetLinkRole
	CreatedAt         time.Time
	CreatedBy         string
}

func (l BusinessServiceAssetLink) Validate() error {
	if l.BusinessServiceID.IsZero() || l.AssetID.IsZero() || !l.Role.Valid() || l.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid business-service asset link", shared.ErrValidation)
	}
	return nil
}

type OwnershipAssignment struct {
	ID        shared.ID
	TenantID  shared.ID
	AssetID   shared.ID
	Principal string
	Role      string
	CreatedAt time.Time
	CreatedBy string
}

func (o OwnershipAssignment) Validate() error {
	if o.ID.IsZero() || o.AssetID.IsZero() || strings.TrimSpace(o.Principal) == "" || utf8.RuneCountInString(o.Principal) > 256 || strings.TrimSpace(o.Role) == "" || utf8.RuneCountInString(o.Role) > 64 || o.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid asset ownership assignment", shared.ErrValidation)
	}
	return nil
}
