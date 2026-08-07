// Package asset is the epic-#405 fleet asset model: one canonical identity per real thing (a
// host, a workload, an image, a cloud resource), the typed relationships between them, and a
// business-service grouping. It is pure domain: it imports only shared and the stdlib.
//
// Tenancy invariant: every aggregate carries a NON-EMPTY TenantID. Under Row Level Security
// (migration 0057) the empty string means DENY, not the default tenant, so an empty tenant id is
// rejected at construction. The default single-tenant deployment supplies a non-empty tenant id.
package asset

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Kind is the closed set of asset kinds. It is extended deliberately, never by free string.
type Kind string

const (
	KindHost         Kind = "host"
	KindWorkload     Kind = "workload"
	KindImage        Kind = "image"
	KindCloudAccount Kind = "cloud_account"
	KindStorage      Kind = "storage"
	KindExposure     Kind = "exposure"
	KindIdentity     Kind = "identity"
	KindNamespace    Kind = "namespace"
	KindCluster      Kind = "cluster"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindHost, KindWorkload, KindImage, KindCloudAccount, KindStorage,
		KindExposure, KindIdentity, KindNamespace, KindCluster:
		return true
	default:
		return false
	}
}

// Asset is one canonical thing in the estate. (TenantID, Kind, Key) is its natural identity: the
// same real thing observed by two producers resolves to one asset via that tuple.
type Asset struct {
	ID         shared.ID
	TenantID   shared.ID
	Kind       Kind
	Key        string // deterministic natural key per kind (e.g. an image digest)
	Name       string
	Attributes map[string]string
	Audit      shared.Audit
}

// New validates and constructs an Asset. Name defaults to Key when empty. Attributes are copied
// so the caller cannot mutate the aggregate's map after construction.
func New(id, tenantID shared.ID, kind Kind, key, name string, attributes map[string]string, now time.Time) (*Asset, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: asset tenant id is required (empty tenant is DENY under RLS)", shared.ErrValidation)
	}
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: invalid asset kind %q", shared.ErrValidation, kind)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, fmt.Errorf("%w: asset key is required", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = key
	}
	return &Asset{
		ID:         id,
		TenantID:   tenantID,
		Kind:       kind,
		Key:        key,
		Name:       name,
		Attributes: copyAttrs(attributes),
		Audit:      shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

// EdgeKind is the closed set of typed relationships between assets.
type EdgeKind string

const (
	EdgeRuns       EdgeKind = "runs"        // host/cluster runs workload
	EdgeExposes    EdgeKind = "exposes"     // exposure exposes workload
	EdgeDependsOn  EdgeKind = "depends_on"  // workload depends on component
	EdgeCanAssume  EdgeKind = "can_assume"  // identity can assume identity
	EdgeReaches    EdgeKind = "reaches"     // reachability edge
	EdgeAffectedBy EdgeKind = "affected_by" // asset affected by a finding
	EdgeMounts     EdgeKind = "mounts"      // workload mounts identity/secret
	EdgeMemberOf   EdgeKind = "member_of"   // asset is a member of a business service
)

// Valid reports whether e is a known edge kind.
func (e EdgeKind) Valid() bool {
	switch e {
	case EdgeRuns, EdgeExposes, EdgeDependsOn, EdgeCanAssume, EdgeReaches,
		EdgeAffectedBy, EdgeMounts, EdgeMemberOf:
		return true
	default:
		return false
	}
}

// Edge is a typed, provenance-carrying relationship. Provenance references the observation that
// produced the edge; an edge without provenance is invalid, because an unattributable edge cannot
// be trusted by the attack-path traversal that consumes it.
type Edge struct {
	TenantID   shared.ID
	From       shared.ID
	To         shared.ID
	Kind       EdgeKind
	Provenance shared.ID
}

// NewEdge validates and constructs an Edge.
func NewEdge(tenantID, from, to shared.ID, kind EdgeKind, provenance shared.ID) (*Edge, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: edge tenant id is required (empty tenant is DENY under RLS)", shared.ErrValidation)
	}
	if from.IsZero() || to.IsZero() {
		return nil, fmt.Errorf("%w: edge from and to asset ids are required", shared.ErrValidation)
	}
	if !kind.Valid() {
		return nil, fmt.Errorf("%w: invalid edge kind %q", shared.ErrValidation, kind)
	}
	if provenance.IsZero() {
		return nil, fmt.Errorf("%w: edge provenance is required", shared.ErrValidation)
	}
	return &Edge{TenantID: tenantID, From: from, To: to, Kind: kind, Provenance: provenance}, nil
}

// BusinessService groups assets into a named service with an owner so findings and risk can be
// rolled up to something a stakeholder recognises. Membership is expressed as an EdgeMemberOf
// edge from an asset to the service.
type BusinessService struct {
	ID       shared.ID
	TenantID shared.ID
	Name     string
	Owner    string
	Audit    shared.Audit
}

// NewBusinessService validates and constructs a BusinessService.
func NewBusinessService(id, tenantID shared.ID, name, owner string, now time.Time) (*BusinessService, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: business service id is required", shared.ErrValidation)
	}
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: business service tenant id is required (empty tenant is DENY under RLS)", shared.ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("%w: business service name is required", shared.ErrValidation)
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("%w: business service owner is required", shared.ErrValidation)
	}
	return &BusinessService{
		ID:       id,
		TenantID: tenantID,
		Name:     name,
		Owner:    owner,
		Audit:    shared.Audit{CreatedAt: now, UpdatedAt: now},
	}, nil
}

func copyAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
