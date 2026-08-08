// Package clusterinventory is the pure-domain core of the Kubernetes cluster agent (#411, epic
// #405): it maps a vendor-neutral snapshot of a cluster to the fleet asset model (domain/asset).
//
// It is deliberately free of any Kubernetes type. The dependency rule (see CLAUDE.md) forbids a k8s
// type in a domain package; the live client-go informer lives in infrastructure (a follow-up) and
// converts API objects into the neutral Snapshot defined here, then this package maps that Snapshot
// to asset kinds. Keeping the mapping pure makes the normative asset table testable without a cluster.
//
// Two invariants this package exists to hold:
//   - Multi-cluster identity. Cluster identity is part of every non-image asset key, so two clusters
//     with identical namespace/workload names never collide (requirement 9). Image keys are the bare
//     digest, shared with image scanning (requirement 2).
//   - Coverage honesty. A running image digest that was never scanned, a container whose digest could
//     not be resolved, and a namespace outside the configured scope are all emitted as explicit
//     coverage gaps naming the workload — never silently omitted or reported as clean (requirements
//     2 and 8).
package clusterinventory

import (
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
)

// GapKind classifies a cluster-inventory coverage gap.
type GapKind string

const (
	// GapUnscannedDigest: a running container's image digest has no prior scan in the engine.
	GapUnscannedDigest GapKind = "unscanned-digest"
	// GapUnresolvedDigest: a running container exposes only a mutable tag; its digest is unknown, so
	// what is actually running cannot be identified.
	GapUnresolvedDigest GapKind = "unresolved-digest"
	// GapOutOfScopeNamespace: a namespace exists on the cluster but is outside the configured scope,
	// so it is reported out of scope rather than as clean.
	GapOutOfScopeNamespace GapKind = "out-of-scope-namespace"
	// GapNoContainers: a workload was observed with no containers, so what it runs could not be
	// enumerated. Reported so "couldn't read the pod template" is never indistinguishable from
	// "assessed and running nothing".
	GapNoContainers GapKind = "no-containers"
	// GapNamespaceNotObserved: a namespace the operator put in scope was never seen in the snapshot,
	// so an expected-but-unobserved namespace is not mistaken for "in scope and empty".
	GapNamespaceNotObserved GapKind = "namespace-not-observed"
)

// Valid reports whether g is a known gap kind.
func (g GapKind) Valid() bool {
	switch g {
	case GapUnscannedDigest, GapUnresolvedDigest, GapOutOfScopeNamespace, GapNoContainers, GapNamespaceNotObserved:
		return true
	default:
		return false
	}
}

// CoverageGap is one reason the cluster inventory is not fully trustworthy. Workload names the
// affected workload (or namespace) so an operator can act; empty when not workload-scoped.
type CoverageGap struct {
	Kind     GapKind
	Workload string // "<namespace>/<kind>/<name>" or a namespace, whichever the gap concerns
	Detail   string
}

// AssetRef is a natural-key reference to an asset: the mapper does not mint surrogate ids or resolve
// edge endpoints (those come from the store's upsert-by-(kind,key)); it emits (Kind, Key) references
// that a usecase later resolves to ids when persisting.
type AssetRef struct {
	Kind asset.Kind
	Key  string
}

// ObservedAsset is an asset the mapper observed, addressed by its natural key. A usecase upserts it
// via (TenantID, Kind, Key); Name defaults to Key downstream when empty.
type ObservedAsset struct {
	Kind       asset.Kind
	Key        string
	Name       string
	Attributes map[string]string
}

// Ref returns the natural-key reference to this observed asset.
func (o ObservedAsset) Ref() AssetRef { return AssetRef{Kind: o.Kind, Key: o.Key} }

// ObservedEdge is a typed relationship between two observed assets, addressed by natural key.
type ObservedEdge struct {
	From AssetRef
	To   AssetRef
	Kind asset.EdgeKind
}

// Inventory is the mapper's output: the observed assets, their relationships, and the coverage gaps.
type Inventory struct {
	Cluster string
	Assets  []ObservedAsset
	Edges   []ObservedEdge
	Gaps    []CoverageGap
}
