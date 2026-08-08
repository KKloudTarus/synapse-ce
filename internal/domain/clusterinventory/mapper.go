package clusterinventory

import (
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Snapshot is the vendor-neutral view of a cluster the infrastructure informer produces and this
// package maps. No Kubernetes type appears here — that is the whole point of the boundary.
//
// The json tags are the explicit wire contract shared by the agent (which encodes a Snapshot) and the
// control-plane ingest endpoint (which decodes it): the tag, not the Go field name, is the API, so a
// field rename never silently changes the wire format, and the keys stay snake_case like the rest of
// the fleet transport.
type Snapshot struct {
	Cluster    string      `json:"cluster"`              // cluster identity; part of every non-image asset key
	InScope    []string    `json:"in_scope,omitempty"`   // namespaces in scope; empty means all in scope
	Namespaces []Namespace `json:"namespaces,omitempty"` // observed namespaces (both in and out of scope)
}

// Namespace is one observed namespace and its contents.
type Namespace struct {
	Name             string     `json:"name"`
	HasNetworkPolicy bool       `json:"has_network_policy"` // any NetworkPolicy present (exposure posture)
	Workloads        []Workload `json:"workloads,omitempty"`
	Exposures        []Exposure `json:"exposures,omitempty"`
	ServiceAccounts  []string   `json:"service_accounts,omitempty"` // SA names declared in the namespace
}

// Workload is a controller (Deployment/StatefulSet/DaemonSet/...) and its containers.
type Workload struct {
	Kind           string      `json:"kind"` // controller kind
	Name           string      `json:"name"`
	ServiceAccount string      `json:"service_account,omitempty"` // pods' SA; empty means "default"
	Containers     []Container `json:"containers,omitempty"`
}

// Container is one running container, with the resolved image digest when known.
type Container struct {
	Name   string `json:"name"`
	Image  string `json:"image"`            // image reference as declared (may be a mutable tag)
	Digest string `json:"digest,omitempty"` // resolved image digest; empty means unresolved
}

// Exposure is a Service or Ingress and the workloads it fronts.
type Exposure struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`              // ClusterIP / NodePort / LoadBalancer / Ingress
	Hosts   []string `json:"hosts,omitempty"`   // ingress hosts, when any
	Targets []Target `json:"targets,omitempty"` // workloads this exposure fronts
}

// Target references the workload an exposure fronts, by controller kind + name (same namespace).
type Target struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Validate reports whether the snapshot can be mapped: cluster identity is mandatory because it is
// part of every asset key, and an empty tenant/cluster would poison the multi-cluster invariant.
func (s Snapshot) Validate() error {
	c := strings.TrimSpace(s.Cluster)
	if c == "" {
		return fmt.Errorf("%w: cluster identity is required (it keys every asset)", shared.ErrValidation)
	}
	// Cluster identity is the one operator-controlled key segment; a '/' in it would let a crafted
	// cluster name forge another cluster's namespaced keys, so the separator is rejected here rather
	// than relying on the key builder to escape.
	if strings.Contains(c, "/") {
		return fmt.Errorf("%w: cluster identity must not contain '/'", shared.ErrValidation)
	}
	return nil
}

// Map maps a snapshot to observed assets, edges, and coverage gaps. scannedDigests is the set of
// image digests the engine has already scanned; a running digest absent from it is a coverage gap.
// Map assumes the snapshot is valid (see Validate); it is a pure, total function of its inputs, so
// two calls on an unchanged snapshot yield identical, normalized output (idempotency).
func Map(snap Snapshot, scannedDigests map[string]bool) Inventory {
	cluster := strings.TrimSpace(snap.Cluster)
	m := &mapping{
		cluster:  cluster,
		scanned:  scannedDigests,
		assets:   map[AssetRef]ObservedAsset{},
		edgeSeen: map[string]struct{}{},
		gapSeen:  map[string]struct{}{},
		inScope:  scopeSet(snap.InScope),
	}

	// The cluster itself.
	clusterRef := m.addAsset(asset.KindCluster, cluster, cluster, map[string]string{})

	observed := map[string]bool{}
	for _, ns := range snap.Namespaces {
		observed[ns.Name] = true
		if !m.namespaceInScope(ns.Name) {
			m.addGap(GapOutOfScopeNamespace, ns.Name, "namespace outside the configured scope; reported out of scope, not clean")
			continue
		}
		m.mapNamespace(clusterRef, ns)
	}
	// A namespace the operator put in scope but the snapshot never contained is expected-but-unobserved,
	// not "in scope and empty" — record it so a missed namespace is never mistaken for a clean one.
	for ns := range m.inScope {
		if !observed[ns] {
			m.addGap(GapNamespaceNotObserved, ns, "namespace is in scope but was not observed in the cluster snapshot")
		}
	}

	inv := Inventory{Cluster: cluster}
	for _, a := range m.assets {
		inv.Assets = append(inv.Assets, a)
	}
	inv.Edges = m.edges
	inv.Gaps = m.gaps
	return inv.Normalize()
}

type mapping struct {
	cluster  string
	scanned  map[string]bool
	inScope  map[string]bool // nil means all in scope
	assets   map[AssetRef]ObservedAsset
	edges    []ObservedEdge
	edgeSeen map[string]struct{}
	gaps     []CoverageGap
	gapSeen  map[string]struct{}
}

func (m *mapping) namespaceInScope(name string) bool {
	if m.inScope == nil {
		return true
	}
	return m.inScope[name]
}

func (m *mapping) mapNamespace(clusterRef AssetRef, ns Namespace) {
	nsKey := joinKey(m.cluster, ns.Name)
	m.addAsset(asset.KindNamespace, nsKey, ns.Name, map[string]string{
		"cluster":        m.cluster,
		"network_policy": presentAbsent(ns.HasNetworkPolicy),
	})

	// Identity assets for every declared service account, even ones no workload mounts.
	for _, sa := range ns.ServiceAccounts {
		m.addServiceAccount(ns.Name, sa)
	}

	for _, w := range ns.Workloads {
		wlLabel := workloadLabel(ns.Name, w.Kind, w.Name)
		wlKey := joinKey(m.cluster, ns.Name, w.Kind, w.Name)
		wlRef := m.addAsset(asset.KindWorkload, wlKey, w.Name, map[string]string{
			"cluster":         m.cluster,
			"namespace":       ns.Name,
			"controller_kind": w.Kind,
			"service_account": defaultSA(w.ServiceAccount),
		})
		// cluster runs workload.
		m.addEdge(clusterRef, wlRef, asset.EdgeRuns)

		// workload mounts its service account identity.
		idRef := m.addServiceAccount(ns.Name, defaultSA(w.ServiceAccount))
		m.addEdge(wlRef, idRef, asset.EdgeMounts)

		// A workload observed with no containers means what it runs could not be enumerated; record it
		// so "couldn't read the pod template" is never indistinguishable from "running nothing".
		if len(w.Containers) == 0 {
			m.addGap(GapNoContainers, wlLabel, "workload has no observed containers; what it runs is unknown")
		}
		for _, c := range w.Containers {
			digest := strings.TrimSpace(c.Digest)
			if digest == "" {
				m.addGap(GapUnresolvedDigest, wlLabel, "container "+c.Name+" image "+c.Image+" has no resolved digest")
				continue
			}
			// The image asset is keyed by the bare digest and shared across clusters. The "image"
			// attribute is a display hint only and is first-writer-wins on dedup — two references to the
			// same digest under different tags keep whichever was mapped first; the digest is the identity.
			imgRef := m.addAsset(asset.KindImage, digest, digest, map[string]string{"image": c.Image})
			m.addEdge(wlRef, imgRef, asset.EdgeDependsOn)
			if !m.scanned[digest] {
				m.addGap(GapUnscannedDigest, wlLabel, "running digest "+digest+" ("+c.Image+") has no prior scan")
			}
		}
	}

	for _, e := range ns.Exposures {
		// The exposure type is part of the key: a Service and an Ingress in one namespace may share a
		// name, and without the type discriminator they would collide into one exposure asset.
		exKey := joinKey(m.cluster, ns.Name, e.Type, e.Name)
		exRef := m.addAsset(asset.KindExposure, exKey, e.Name, map[string]string{
			"cluster":   m.cluster,
			"namespace": ns.Name,
			"type":      e.Type,
			"hosts":     strings.Join(e.Hosts, ","),
		})
		for _, t := range e.Targets {
			targetRef := AssetRef{Kind: asset.KindWorkload, Key: joinKey(m.cluster, ns.Name, t.Kind, t.Name)}
			// exposure exposes workload — only when the target workload was actually observed, so the
			// emitted graph is self-consistent (no edge to an asset that was never mapped). A stale or
			// cross-namespace selector target is intentionally skipped rather than emitting a dangling edge.
			if _, ok := m.assets[targetRef]; ok {
				m.addEdge(exRef, targetRef, asset.EdgeExposes)
			}
		}
	}
}

func (m *mapping) addServiceAccount(namespace, sa string) AssetRef {
	sa = defaultSA(sa)
	key := joinKey(m.cluster, namespace, sa)
	return m.addAsset(asset.KindIdentity, key, sa, map[string]string{
		"cluster":         m.cluster,
		"namespace":       namespace,
		"service_account": sa,
	})
}

// addAsset registers an observed asset, deduplicating by natural key, and returns its ref.
func (m *mapping) addAsset(kind asset.Kind, key, name string, attrs map[string]string) AssetRef {
	ref := AssetRef{Kind: kind, Key: key}
	if _, ok := m.assets[ref]; !ok {
		m.assets[ref] = ObservedAsset{Kind: kind, Key: key, Name: name, Attributes: attrs}
	}
	return ref
}

// addEdge registers an edge, deduplicating by (from, to, kind).
func (m *mapping) addEdge(from, to AssetRef, kind asset.EdgeKind) {
	sig := string(from.Kind) + "|" + from.Key + "=>" + string(to.Kind) + "|" + to.Key + "#" + string(kind)
	if _, ok := m.edgeSeen[sig]; ok {
		return
	}
	m.edgeSeen[sig] = struct{}{}
	m.edges = append(m.edges, ObservedEdge{From: from, To: to, Kind: kind})
}

func (m *mapping) addGap(kind GapKind, workload, detail string) {
	sig := string(kind) + "|" + workload + "|" + detail
	if _, ok := m.gapSeen[sig]; ok {
		return
	}
	m.gapSeen[sig] = struct{}{}
	m.gaps = append(m.gaps, CoverageGap{Kind: kind, Workload: workload, Detail: detail})
}

// Normalize deterministically orders assets, edges, and gaps so the mapping is idempotent: the same
// snapshot always produces byte-identical output, which is what lets a re-sync avoid asset churn.
func (inv Inventory) Normalize() Inventory {
	out := inv
	out.Assets = append([]ObservedAsset(nil), inv.Assets...)
	sort.Slice(out.Assets, func(i, j int) bool {
		if out.Assets[i].Kind != out.Assets[j].Kind {
			return out.Assets[i].Kind < out.Assets[j].Kind
		}
		return out.Assets[i].Key < out.Assets[j].Key
	})
	out.Edges = append([]ObservedEdge(nil), inv.Edges...)
	sort.Slice(out.Edges, func(i, j int) bool {
		return edgeSortKey(out.Edges[i]) < edgeSortKey(out.Edges[j])
	})
	out.Gaps = append([]CoverageGap(nil), inv.Gaps...)
	sort.Slice(out.Gaps, func(i, j int) bool {
		if out.Gaps[i].Kind != out.Gaps[j].Kind {
			return out.Gaps[i].Kind < out.Gaps[j].Kind
		}
		if out.Gaps[i].Workload != out.Gaps[j].Workload {
			return out.Gaps[i].Workload < out.Gaps[j].Workload
		}
		return out.Gaps[i].Detail < out.Gaps[j].Detail
	})
	return out
}

func edgeSortKey(e ObservedEdge) string {
	return string(e.From.Kind) + "|" + e.From.Key + "=>" + string(e.To.Kind) + "|" + e.To.Key + "#" + string(e.Kind)
}

// --- helpers ---

func scopeSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil // empty = all in scope
	}
	s := make(map[string]bool, len(in))
	for _, n := range in {
		if n = strings.TrimSpace(n); n != "" {
			s[n] = true
		}
	}
	if len(s) == 0 {
		return nil
	}
	return s
}

// joinKey builds a '/'-separated asset key. Each segment is escaped so the join is INJECTIVE: a
// crafted name containing '/' (or '%') cannot collide with a different tuple. Real Kubernetes names
// are DNS-1123 (no '/' or '%'), so escaping is a no-op for legitimate input and keys are unchanged;
// it only defends against an agent that reports a malformed name within its own tenant.
func joinKey(parts ...string) string {
	clean := make([]string, 0, len(parts))
	for _, p := range parts {
		clean = append(clean, escapeSegment(strings.TrimSpace(p)))
	}
	return strings.Join(clean, "/")
}

// escapeSegment percent-escapes '%' then '/' so no segment can introduce or forge a separator. '%'
// must be escaped first to keep the mapping reversible/injective.
func escapeSegment(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	return strings.ReplaceAll(s, "/", "%2F")
}

func workloadLabel(namespace, kind, name string) string { return joinKey(namespace, kind, name) }

func defaultSA(sa string) string {
	if sa = strings.TrimSpace(sa); sa != "" {
		return sa
	}
	return "default"
}

func presentAbsent(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}
