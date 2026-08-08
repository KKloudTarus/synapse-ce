package clusterinventory

import (
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// sample builds a representative one-namespace snapshot for the given cluster.
func sample(cluster string) Snapshot {
	return Snapshot{
		Cluster: cluster,
		Namespaces: []Namespace{{
			Name:             "payments",
			HasNetworkPolicy: false,
			ServiceAccounts:  []string{"default", "payments-sa"},
			Workloads: []Workload{{
				Kind:           "Deployment",
				Name:           "api",
				ServiceAccount: "payments-sa",
				Containers: []Container{
					{Name: "api", Image: "reg/api:v1", Digest: "sha256:aaa"},
					{Name: "sidecar", Image: "reg/proxy:latest", Digest: ""}, // unresolved
				},
			}},
			Exposures: []Exposure{{
				Name:    "api-lb",
				Type:    "LoadBalancer",
				Hosts:   []string{"api.example.com"},
				Targets: []Target{{Kind: "Deployment", Name: "api"}},
			}},
		}},
	}
}

func assetByKind(inv Inventory, kind asset.Kind) []ObservedAsset {
	var out []ObservedAsset
	for _, a := range inv.Assets {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func hasGap(inv Inventory, kind GapKind, workload string) bool {
	for _, g := range inv.Gaps {
		if g.Kind == kind && g.Workload == workload {
			return true
		}
	}
	return false
}

func hasEdge(inv Inventory, k asset.EdgeKind, fromKind asset.Kind, toKind asset.Kind) bool {
	for _, e := range inv.Edges {
		if e.Kind == k && e.From.Kind == fromKind && e.To.Kind == toKind {
			return true
		}
	}
	return false
}

func TestMapAssetsAndEdges(t *testing.T) {
	inv := Map(sample("prod-eu"), map[string]bool{"sha256:aaa": true})

	// One of each kind we expect.
	for _, k := range []asset.Kind{asset.KindCluster, asset.KindNamespace, asset.KindWorkload, asset.KindImage, asset.KindExposure, asset.KindIdentity} {
		if len(assetByKind(inv, k)) == 0 {
			t.Errorf("expected at least one %q asset", k)
		}
	}
	// The normative edges.
	if !hasEdge(inv, asset.EdgeRuns, asset.KindCluster, asset.KindWorkload) {
		t.Error("cluster runs workload edge missing")
	}
	if !hasEdge(inv, asset.EdgeDependsOn, asset.KindWorkload, asset.KindImage) {
		t.Error("workload depends_on image edge missing")
	}
	if !hasEdge(inv, asset.EdgeExposes, asset.KindExposure, asset.KindWorkload) {
		t.Error("exposure exposes workload edge missing")
	}
	if !hasEdge(inv, asset.EdgeMounts, asset.KindWorkload, asset.KindIdentity) {
		t.Error("workload mounts identity edge missing")
	}
	// The workload key carries cluster + namespace + kind + name.
	wls := assetByKind(inv, asset.KindWorkload)
	if wls[0].Key != "prod-eu/payments/Deployment/api" {
		t.Errorf("workload key = %q", wls[0].Key)
	}
	// The image key is the bare digest (shared with image scanning), NOT cluster-scoped.
	imgs := assetByKind(inv, asset.KindImage)
	if imgs[0].Key != "sha256:aaa" {
		t.Errorf("image key must be the bare digest, got %q", imgs[0].Key)
	}
}

func TestUnscannedAndUnresolvedDigestsAreGaps(t *testing.T) {
	// api container's digest is NOT in the scanned set -> unscanned gap; sidecar has no digest ->
	// unresolved gap. Both name the workload.
	inv := Map(sample("prod-eu"), map[string]bool{}) // nothing scanned
	if !hasGap(inv, GapUnscannedDigest, "payments/Deployment/api") {
		t.Fatalf("a running digest with no prior scan must be a coverage gap naming the workload: %+v", inv.Gaps)
	}
	if !hasGap(inv, GapUnresolvedDigest, "payments/Deployment/api") {
		t.Fatalf("a container with no resolved digest must be a coverage gap: %+v", inv.Gaps)
	}
	// When the digest IS scanned, no unscanned gap for it.
	inv2 := Map(sample("prod-eu"), map[string]bool{"sha256:aaa": true})
	if hasGap(inv2, GapUnscannedDigest, "payments/Deployment/api") {
		t.Fatalf("a scanned digest must not be reported as unscanned: %+v", inv2.Gaps)
	}
}

func TestOutOfScopeNamespaceReportedNotClean(t *testing.T) {
	snap := sample("prod-eu")
	snap.Namespaces = append(snap.Namespaces, Namespace{
		Name:      "kube-system",
		Workloads: []Workload{{Kind: "DaemonSet", Name: "kproxy", Containers: []Container{{Name: "c", Digest: "sha256:zzz"}}}},
	})
	snap.InScope = []string{"payments"} // kube-system is out of scope

	inv := Map(snap, map[string]bool{})
	if !hasGap(inv, GapOutOfScopeNamespace, "kube-system") {
		t.Fatalf("an out-of-scope namespace must be reported as a gap, not silently clean: %+v", inv.Gaps)
	}
	// Its contents must NOT be mapped to assets (no kproxy workload, no sha256:zzz image).
	for _, a := range inv.Assets {
		if a.Kind == asset.KindWorkload && a.Name == "kproxy" {
			t.Fatalf("out-of-scope workload must not be mapped: %+v", a)
		}
		if a.Kind == asset.KindImage && a.Key == "sha256:zzz" {
			t.Fatalf("out-of-scope image must not be mapped: %+v", a)
		}
	}
}

func TestMultiClusterAssetsDoNotCollide(t *testing.T) {
	// Two clusters with identical namespace + workload names must produce DISTINCT workload/namespace
	// assets (cluster-scoped keys), but SHARE the image asset (bare digest).
	a := Map(sample("prod-eu"), map[string]bool{"sha256:aaa": true})
	b := Map(sample("prod-us"), map[string]bool{"sha256:aaa": true})

	keyA := assetByKind(a, asset.KindWorkload)[0].Key
	keyB := assetByKind(b, asset.KindWorkload)[0].Key
	if keyA == keyB {
		t.Fatalf("workload keys from different clusters must differ: %q == %q", keyA, keyB)
	}
	if got := assetByKind(a, asset.KindImage)[0].Key; got != assetByKind(b, asset.KindImage)[0].Key {
		t.Fatalf("the same digest across clusters must be one shared image asset key")
	}
}

func TestIdempotentMapping(t *testing.T) {
	// Two syncs of an unchanged snapshot must produce identical output (no asset churn on resync).
	scanned := map[string]bool{"sha256:aaa": true}
	first := Map(sample("prod-eu"), scanned)
	second := Map(sample("prod-eu"), scanned)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("mapping must be deterministic/idempotent")
	}
}

func TestEmittedAssetsAreValidDomainAssets(t *testing.T) {
	// Every observed asset must be constructible via asset.New (non-empty key, valid kind), so the
	// downstream upsert cannot reject a mapped asset.
	inv := Map(sample("prod-eu"), map[string]bool{"sha256:aaa": true})
	tenant := shared.ID("tenant-1")
	now := time.Unix(0, 0).UTC()
	for _, oa := range inv.Assets {
		if _, err := asset.New(shared.ID("id-x"), tenant, oa.Kind, oa.Key, oa.Name, oa.Attributes, now); err != nil {
			t.Errorf("observed asset %+v is not a valid domain asset: %v", oa, err)
		}
	}
}

func TestValidateRequiresCluster(t *testing.T) {
	if err := (Snapshot{Cluster: "  "}).Validate(); err == nil {
		t.Fatal("a blank cluster identity must be rejected")
	}
	if err := (Snapshot{Cluster: "prod-eu"}).Validate(); err != nil {
		t.Fatalf("a valid cluster must pass: %v", err)
	}
	// A '/' in the cluster identity is rejected so it cannot forge another cluster's namespaced keys.
	if err := (Snapshot{Cluster: "prod/evil"}).Validate(); err == nil {
		t.Fatal("a cluster identity containing '/' must be rejected")
	}
}

func TestServiceAndIngressSameNameDoNotCollide(t *testing.T) {
	// A Service and an Ingress named "api" in one namespace must produce two distinct exposure assets.
	snap := Snapshot{
		Cluster: "prod-eu",
		Namespaces: []Namespace{{
			Name: "payments",
			Exposures: []Exposure{
				{Name: "api", Type: "ClusterIP"},
				{Name: "api", Type: "Ingress"},
			},
		}},
	}
	inv := Map(snap, map[string]bool{})
	if got := len(assetByKind(inv, asset.KindExposure)); got != 2 {
		t.Fatalf("a Service and an Ingress named api must be 2 exposure assets, got %d: %+v", got, assetByKind(inv, asset.KindExposure))
	}
}

func TestEmptyContainersWorkloadIsAGap(t *testing.T) {
	snap := Snapshot{
		Cluster: "prod-eu",
		Namespaces: []Namespace{{
			Name:      "payments",
			Workloads: []Workload{{Kind: "Deployment", Name: "ghost", Containers: nil}},
		}},
	}
	inv := Map(snap, map[string]bool{})
	if !hasGap(inv, GapNoContainers, "payments/Deployment/ghost") {
		t.Fatalf("a workload with no containers must be a coverage gap, not silently clean: %+v", inv.Gaps)
	}
}

func TestInScopeButUnobservedNamespaceIsAGap(t *testing.T) {
	snap := sample("prod-eu")
	snap.InScope = []string{"payments", "billing"} // billing is in scope but not in the snapshot
	inv := Map(snap, map[string]bool{"sha256:aaa": true})
	if !hasGap(inv, GapNamespaceNotObserved, "billing") {
		t.Fatalf("an in-scope namespace never observed must be a coverage gap: %+v", inv.Gaps)
	}
	if hasGap(inv, GapNamespaceNotObserved, "payments") {
		t.Fatalf("an observed in-scope namespace must not be flagged unobserved: %+v", inv.Gaps)
	}
}

func TestExposesEdgeOnlyToObservedWorkload(t *testing.T) {
	// An exposure targeting a workload that was never observed must NOT emit a dangling edge.
	snap := Snapshot{
		Cluster: "prod-eu",
		Namespaces: []Namespace{{
			Name: "payments",
			Exposures: []Exposure{{
				Name:    "api-lb",
				Type:    "LoadBalancer",
				Targets: []Target{{Kind: "Deployment", Name: "does-not-exist"}},
			}},
		}},
	}
	inv := Map(snap, map[string]bool{})
	for _, e := range inv.Edges {
		if e.Kind == asset.EdgeExposes {
			t.Fatalf("no exposes edge should be emitted to an unobserved workload: %+v", e)
		}
	}
}

func TestGapsAreDeduplicated(t *testing.T) {
	// Two identical containers (same name/image/digest, unscanned) must not double the gap.
	snap := Snapshot{
		Cluster: "prod-eu",
		Namespaces: []Namespace{{
			Name: "payments",
			Workloads: []Workload{{Kind: "Deployment", Name: "api", Containers: []Container{
				{Name: "c", Image: "reg/x:1", Digest: "sha256:dup"},
				{Name: "c", Image: "reg/x:1", Digest: "sha256:dup"},
			}}},
		}},
	}
	inv := Map(snap, map[string]bool{})
	n := 0
	for _, g := range inv.Gaps {
		if g.Kind == GapUnscannedDigest {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("identical unscanned-digest gaps must be deduplicated, got %d", n)
	}
}

func TestJoinKeyIsInjectiveAgainstCraftedSeparators(t *testing.T) {
	// A '/' (or '%') in a segment must not let one tuple forge another's key.
	if joinKey("a/b", "c") == joinKey("a", "b/c") {
		t.Fatal("joinKey must escape '/' so segments cannot be re-partitioned into a colliding key")
	}
	if joinKey("a%2Fb", "c") == joinKey("a", "b", "c") {
		t.Fatal("a literal '%2F' must not collide with an escaped '/'")
	}
	// Legitimate DNS-1123 names (no '/' or '%') are unchanged.
	if joinKey("prod-eu", "payments", "Deployment", "api") != "prod-eu/payments/Deployment/api" {
		t.Fatalf("normal names must be unescaped, got %q", joinKey("prod-eu", "payments", "Deployment", "api"))
	}
}

func TestGapKindValid(t *testing.T) {
	for _, g := range []GapKind{GapUnscannedDigest, GapUnresolvedDigest, GapOutOfScopeNamespace} {
		if !g.Valid() {
			t.Errorf("%q should be valid", g)
		}
	}
	if GapKind("bogus").Valid() {
		t.Error("bogus gap kind should be invalid")
	}
}
