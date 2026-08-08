package clusterinventory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dci "github.com/KKloudTarus/synapse-ce/internal/domain/clusterinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeAssetWriter resolves a stable id per (kind,key) so re-observation reuses ids (idempotency),
// and records edges.
type fakeAssetWriter struct {
	ids      map[string]shared.ID
	next     int
	upserts  int
	edges    []assetuc.EdgeInput
	edgeKeys map[string]bool // mirrors the store's idempotent edge natural key
}

func newFakeWriter() *fakeAssetWriter {
	return &fakeAssetWriter{ids: map[string]shared.ID{}, edgeKeys: map[string]bool{}}
}

func (f *fakeAssetWriter) UpsertAsset(_ context.Context, _ string, in assetuc.UpsertAssetInput) (*asset.Asset, error) {
	f.upserts++
	k := string(in.Kind) + "|" + in.Key
	id, ok := f.ids[k]
	if !ok {
		f.next++
		id = shared.ID("id-" + itoa(f.next))
		f.ids[k] = id
	}
	return &asset.Asset{ID: id, TenantID: in.TenantID, Kind: in.Kind, Key: in.Key, Name: in.Name}, nil
}

func (f *fakeAssetWriter) UpsertEdge(_ context.Context, _ string, in assetuc.EdgeInput) error {
	// Mirror assetuc/store idempotency: an edge is identified by (tenant, from, to, kind, provenance).
	key := in.TenantID.String() + "|" + in.From.String() + "|" + in.To.String() + "|" + string(in.Kind) + "|" + in.Provenance.String()
	if !f.edgeKeys[key] {
		f.edgeKeys[key] = true
		f.edges = append(f.edges, in)
	}
	return nil
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	return nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func sample() dci.Snapshot {
	return dci.Snapshot{
		Cluster: "prod-eu",
		Namespaces: []dci.Namespace{{
			Name:            "payments",
			ServiceAccounts: []string{"payments-sa"},
			Workloads: []dci.Workload{{
				Kind:           "Deployment",
				Name:           "api",
				ServiceAccount: "payments-sa",
				Containers: []dci.Container{
					{Name: "api", Image: "reg/api:v1", Digest: "sha256:aaa"},
					{Name: "side", Image: "reg/x:latest", Digest: ""}, // unresolved -> gap
				},
			}},
			Exposures: []dci.Exposure{{
				Name: "api", Type: "LoadBalancer", Targets: []dci.Target{{Kind: "Deployment", Name: "api"}},
			}},
		}},
	}
}

func newService(t *testing.T, w AssetWriter, a ports.AuditLogger) *Service {
	t.Helper()
	s, err := NewService(w, a, fixedClock{t: time.Unix(1700000000, 0).UTC()})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return s
}

func TestSyncUpsertsAssetsEdgesAndReturnsGaps(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)

	res, err := s.Sync(context.Background(), "agent-1", SyncInput{
		TenantID:       "tenant-1",
		Snapshot:       sample(),
		ScannedDigests: map[string]bool{}, // nothing scanned -> sha256:aaa is an unscanned gap
		Provenance:     "sync-1",
	})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if res.Assets == 0 || res.Edges == 0 {
		t.Fatalf("expected assets and edges, got %+v", res)
	}
	// Edges must reference resolved (non-zero) ids and carry the provenance.
	for _, e := range w.edges {
		if e.From.IsZero() || e.To.IsZero() {
			t.Fatalf("edge endpoints must be resolved ids: %+v", e)
		}
		if e.Provenance != "sync-1" {
			t.Fatalf("edge must carry provenance, got %q", e.Provenance)
		}
	}
	// Gaps returned: unscanned digest + unresolved digest, both present.
	kinds := map[dci.GapKind]bool{}
	for _, g := range res.Gaps {
		kinds[g.Kind] = true
	}
	if !kinds[dci.GapUnscannedDigest] || !kinds[dci.GapUnresolvedDigest] {
		t.Fatalf("expected unscanned + unresolved digest gaps, got %+v", res.Gaps)
	}
	// Every gap is audited.
	audited := 0
	for _, e := range a.entries {
		if e.Action == "cluster_inventory.coverage_gap" {
			audited++
			if e.At.IsZero() {
				t.Fatalf("audit entry must carry a timestamp")
			}
		}
	}
	if audited != len(res.Gaps) {
		t.Fatalf("every coverage gap must be audited: audited=%d gaps=%d", audited, len(res.Gaps))
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	in := SyncInput{TenantID: "tenant-1", Snapshot: sample(), ScannedDigests: map[string]bool{"sha256:aaa": true}, Provenance: "sync-1"}

	first, err := s.Sync(context.Background(), "agent-1", in)
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	idsAfterFirst := len(w.ids)
	second, err := s.Sync(context.Background(), "agent-1", in)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	edgesAfterFirst := len(w.edges)
	// Same distinct assets, no new ids minted on the second sync (no churn).
	if len(w.ids) != idsAfterFirst {
		t.Fatalf("re-sync must not mint new asset ids: %d -> %d", idsAfterFirst, len(w.ids))
	}
	// With a STABLE provenance, the edge set converges: no new edge rows on the second sync.
	if len(w.edges) != edgesAfterFirst {
		t.Fatalf("re-sync with stable provenance must not mint new edges: %d -> %d", edgesAfterFirst, len(w.edges))
	}
	if first.Assets != second.Assets || first.Edges != second.Edges {
		t.Fatalf("re-sync must produce identical counts: %+v vs %+v", first, second)
	}
}

func TestDifferentProvenanceMintsNewEdges(t *testing.T) {
	// A per-sync (changing) provenance is part of the edge natural key, so it churns edge rows — this
	// documents WHY Provenance must be stable per cluster source.
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "t", Snapshot: sample(), Provenance: "sync-1"}); err != nil {
		t.Fatal(err)
	}
	after1 := len(w.edges)
	if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "t", Snapshot: sample(), Provenance: "sync-2"}); err != nil {
		t.Fatal(err)
	}
	if len(w.edges) <= after1 {
		t.Fatalf("a changed provenance must create new edge rows (that is why stable provenance matters)")
	}
}

func TestSyncValidation(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	ctx := context.Background()

	cases := []struct {
		name  string
		actor string
		in    SyncInput
	}{
		{"empty actor", "", SyncInput{TenantID: "t", Snapshot: sample(), Provenance: "p"}},
		{"empty tenant", "agent-1", SyncInput{Snapshot: sample(), Provenance: "p"}},
		{"empty provenance", "agent-1", SyncInput{TenantID: "t", Snapshot: sample()}},
		{"invalid snapshot", "agent-1", SyncInput{TenantID: "t", Provenance: "p", Snapshot: dci.Snapshot{Cluster: ""}}},
	}
	for _, c := range cases {
		if _, err := s.Sync(ctx, c.actor, c.in); err == nil {
			t.Errorf("%s: expected a validation error", c.name)
		}
	}
	if w.upserts != 0 {
		t.Fatalf("no asset should be upserted when validation fails, got %d", w.upserts)
	}
}

func TestNewServiceValidatesDeps(t *testing.T) {
	if _, err := NewService(nil, &fakeAudit{}, fixedClock{}); err == nil {
		t.Error("nil asset writer must be rejected")
	}
	if _, err := NewService(newFakeWriter(), nil, fixedClock{}); err == nil {
		t.Error("nil audit logger must be rejected")
	}
	if _, err := NewService(newFakeWriter(), &fakeAudit{}, nil); err == nil {
		t.Error("nil clock must be rejected")
	}
}
