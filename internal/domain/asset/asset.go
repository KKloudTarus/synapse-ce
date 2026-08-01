// Package asset defines durable, tenant-scoped AppSec inventory records.
package asset

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Category classifies an AppSec-relevant technical asset.
type Category string

const (
	CategoryApplication    Category = "application"
	CategoryRepository     Category = "repository"
	CategoryPipeline       Category = "pipeline"
	CategoryService        Category = "service"
	CategoryAPI            Category = "api"
	CategoryEndpoint       Category = "endpoint"
	CategoryDomain         Category = "domain"
	CategoryIPRange        Category = "ip_range"
	CategoryCloudAccount   Category = "cloud_account"
	CategoryCloudProject   Category = "cloud_project"
	CategoryCloudResource  Category = "cloud_resource"
	CategoryCluster        Category = "cluster"
	CategoryWorkload       Category = "workload"
	CategoryContainerImage Category = "container_image"
	CategoryArtifact       Category = "artifact"
	CategorySBOM           Category = "sbom"
	CategoryDatabase       Category = "database"
	CategoryQueue          Category = "queue"
	CategoryStorage        Category = "storage"
	CategoryInfrastructure Category = "infrastructure"
	CategoryIaCModule      Category = "iac_module"
)

func (c Category) Valid() bool {
	switch c {
	case CategoryApplication, CategoryRepository, CategoryPipeline, CategoryService, CategoryAPI, CategoryEndpoint, CategoryDomain, CategoryIPRange, CategoryCloudAccount, CategoryCloudProject, CategoryCloudResource, CategoryCluster, CategoryWorkload, CategoryContainerImage, CategoryArtifact, CategorySBOM, CategoryDatabase, CategoryQueue, CategoryStorage, CategoryInfrastructure, CategoryIaCModule:
		return true
	}
	return false
}

// Lifecycle records whether an asset remains managed by the organization.
type Lifecycle string

const (
	LifecycleActive   Lifecycle = "active"
	LifecycleRetired  Lifecycle = "retired"
	LifecyclePlanned  Lifecycle = "planned"
	LifecycleUnknown  Lifecycle = "unknown"
)

func (l Lifecycle) Valid() bool {
	switch l {
	case LifecycleActive, LifecycleRetired, LifecyclePlanned, LifecycleUnknown:
		return true
	}
	return false
}

// RelationshipType describes a directed, AppSec-relevant edge between Assets.
type RelationshipType string

const (
	RelationshipContains     RelationshipType = "contains"
	RelationshipPartOf       RelationshipType = "part_of"
	RelationshipDependsOn    RelationshipType = "depends_on"
	RelationshipRunsOn       RelationshipType = "runs_on"
	RelationshipDeployedTo   RelationshipType = "deployed_to"
	RelationshipExposes      RelationshipType = "exposes"
	RelationshipBuiltFrom    RelationshipType = "built_from"
	RelationshipManagedBy    RelationshipType = "managed_by"
	RelationshipProcessesData RelationshipType = "processes_data"
)

func (r RelationshipType) Valid() bool {
	switch r {
	case RelationshipContains, RelationshipPartOf, RelationshipDependsOn, RelationshipRunsOn, RelationshipDeployedTo, RelationshipExposes, RelationshipBuiltFrom, RelationshipManagedBy, RelationshipProcessesData:
		return true
	}
	return false
}

// BusinessServiceRole describes why a Business Service references an Asset.
type BusinessServiceRole string

const (
	BusinessServiceOwns     BusinessServiceRole = "owns"
	BusinessServiceUses     BusinessServiceRole = "uses"
	BusinessServiceSupports BusinessServiceRole = "supports"
)

func (r BusinessServiceRole) Valid() bool {
	switch r {
	case BusinessServiceOwns, BusinessServiceUses, BusinessServiceSupports:
		return true
	}
	return false
}

var (
	digestPattern = regexp.MustCompile(`^[a-z0-9]+:[a-fA-F0-9]{32,128}$`)
	namePattern   = regexp.MustCompile(`^[[:print:]]{1,200}$`)
)

// Identity is a stable, category-appropriate external identifier. It never holds a credential.
type Identity struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (i Identity) Validate(category Category) (Identity, error) {
	i.Kind, i.Value = strings.TrimSpace(strings.ToLower(i.Kind)), strings.TrimSpace(i.Value)
	if i.Kind == "" || i.Value == "" || len(i.Kind) > 64 || len(i.Value) > 2048 {
		return Identity{}, fmt.Errorf("%w: asset identity kind and value are required", shared.ErrValidation)
	}
	if strings.ContainsAny(i.Value, "\r\n\x00") || strings.Contains(i.Value, "@") && strings.Contains(i.Value, "://") {
		return Identity{}, fmt.Errorf("%w: invalid asset identity", shared.ErrValidation)
	}
	switch category {
	case CategoryRepository:
		if i.Kind != "url" {
			return Identity{}, fmt.Errorf("%w: repository identity must use kind url", shared.ErrValidation)
		}
		u, err := url.Parse(i.Value)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return Identity{}, fmt.Errorf("%w: repository identity must be an https URL without credentials", shared.ErrValidation)
		}
	case CategoryEndpoint:
		if i.Kind != "url" {
			return Identity{}, fmt.Errorf("%w: endpoint identity must use kind url", shared.ErrValidation)
		}
		u, err := url.Parse(i.Value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return Identity{}, fmt.Errorf("%w: endpoint identity must be an http(s) URL without credentials", shared.ErrValidation)
		}
	case CategoryContainerImage, CategoryArtifact, CategorySBOM:
		if i.Kind != "digest" || !digestPattern.MatchString(i.Value) {
			return Identity{}, fmt.Errorf("%w: %s identity must be a digest", shared.ErrValidation, category)
		}
	case CategoryDomain:
		if i.Kind != "domain" || strings.Contains(i.Value, "/") || net.ParseIP(i.Value) != nil || !strings.Contains(i.Value, ".") {
			return Identity{}, fmt.Errorf("%w: domain identity must be a DNS name", shared.ErrValidation)
		}
	case CategoryIPRange:
		if i.Kind != "cidr" {
			return Identity{}, fmt.Errorf("%w: ip range identity must use kind cidr", shared.ErrValidation)
		}
		if _, _, err := net.ParseCIDR(i.Value); err != nil {
			return Identity{}, fmt.Errorf("%w: invalid CIDR", shared.ErrValidation)
		}
	default:
		if i.Kind != "external_id" && i.Kind != "package" && i.Kind != "cloud_id" && i.Kind != "name" {
			return Identity{}, fmt.Errorf("%w: unsupported identity kind %q for %s", shared.ErrValidation, i.Kind, category)
		}
	}
	return i, nil
}

// Asset is a durable technical inventory record.
type Asset struct {
	ID             shared.ID
	TenantID       shared.ID
	Name           string
	Category       Category
	Identity       Identity
	Lifecycle      Lifecycle
	Owner          string
	Criticality    string
	Exposure       string
	Classification string
	Audit          shared.Audit
}

func New(id, tenantID shared.ID, name string, category Category, identity Identity, lifecycle Lifecycle, owner, criticality, exposure, classification string, now time.Time) (*Asset, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("%w: asset name is required and must be at most 200 printable characters", shared.ErrValidation)
	}
	if !category.Valid() || !lifecycle.Valid() {
		return nil, fmt.Errorf("%w: invalid asset category or lifecycle", shared.ErrValidation)
	}
	identity, err := identity.Validate(category)
	if err != nil {
		return nil, err
	}
	for _, value := range []string{owner, criticality, exposure, classification} {
		if len(strings.TrimSpace(value)) > 200 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("%w: invalid asset metadata", shared.ErrValidation)
		}
	}
	return &Asset{ID: id, TenantID: tenantID, Name: name, Category: category, Identity: identity, Lifecycle: lifecycle, Owner: strings.TrimSpace(owner), Criticality: strings.TrimSpace(criticality), Exposure: strings.TrimSpace(exposure), Classification: strings.TrimSpace(classification), Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}, nil
}

// Relationship is a directed edge between two tenant-scoped Assets.
type Relationship struct {
	FromAssetID shared.ID
	ToAssetID   shared.ID
	Type        RelationshipType
	Audit       shared.Audit
}

func NewRelationship(from, to shared.ID, kind RelationshipType, now time.Time) (Relationship, error) {
	if from.IsZero() || to.IsZero() || from == to || !kind.Valid() {
		return Relationship{}, fmt.Errorf("%w: invalid asset relationship", shared.ErrValidation)
	}
	return Relationship{FromAssetID: from, ToAssetID: to, Type: kind, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}, nil
}

// BusinessServiceLink associates a durable Asset with a Business Service.
type BusinessServiceLink struct {
	BusinessServiceID shared.ID
	AssetID           shared.ID
	Role              BusinessServiceRole
	Audit             shared.Audit
}

func NewBusinessServiceLink(serviceID, assetID shared.ID, role BusinessServiceRole, now time.Time) (BusinessServiceLink, error) {
	if serviceID.IsZero() || assetID.IsZero() || !role.Valid() {
		return BusinessServiceLink{}, fmt.Errorf("%w: invalid business service asset link", shared.ErrValidation)
	}
	return BusinessServiceLink{BusinessServiceID: serviceID, AssetID: assetID, Role: role, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}, nil
}

// Version is an observed or managed version of a durable Asset.
type Version struct {
	ID      shared.ID
	AssetID shared.ID
	Value   string
	Source  string
	Audit   shared.Audit
}

func NewVersion(id, assetID shared.ID, value, source string, now time.Time) (Version, error) {
	value, source = strings.TrimSpace(value), strings.TrimSpace(source)
	if id.IsZero() || assetID.IsZero() || value == "" || len(value) > 512 || len(source) > 100 || strings.ContainsAny(value+source, "\r\n\x00") {
		return Version{}, fmt.Errorf("%w: invalid asset version", shared.ErrValidation)
	}
	return Version{ID: id, AssetID: assetID, Value: value, Source: source, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}, nil
}