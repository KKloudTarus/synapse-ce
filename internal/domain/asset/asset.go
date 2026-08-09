// Package asset contains the technical fleet Asset and business-level BusinessAsset models. It is
// pure domain: it imports only shared and the stdlib.
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
)

// Valid reports whether e is a known edge kind.
func (e EdgeKind) Valid() bool {
	switch e {
	case EdgeRuns, EdgeExposes, EdgeDependsOn, EdgeCanAssume, EdgeReaches,
		EdgeAffectedBy, EdgeMounts:
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
