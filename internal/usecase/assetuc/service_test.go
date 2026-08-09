package assetuc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeClock struct{ t time.Time }

func (c fakeClock) Now() time.Time { return c.t }

type fakeIDs struct{ n int }

func (g *fakeIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("id-%d", g.n))
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func newTestService(t *testing.T) (*Service, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	svc, err := NewService(memory.NewAssetStore(), audit, fakeClock{t: time.Unix(1000, 0).UTC()}, &fakeIDs{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, audit
}

func TestNewServiceRejectsNilDeps(t *testing.T) {
	if _, err := NewService(nil, &fakeAudit{}, fakeClock{}, &fakeIDs{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected ErrValidation for nil repo, got %v", err)
	}
}

func TestUpsertAssetIsIdempotent(t *testing.T) {
	svc, audit := newTestService(t)
	ctx := context.Background()
	in := UpsertAssetInput{TenantID: "t1", Kind: asset.KindImage, Key: "sha256:abc", Name: "img"}

	first, err := svc.UpsertAsset(ctx, "actor", in)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	second, err := svc.UpsertAsset(ctx, "actor", in)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("re-observed asset must keep its id: %q vs %q", first.ID, second.ID)
	}
	list, err := svc.ListAssets(ctx, "t1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("idempotent upsert must not churn: got %d assets", len(list))
	}
	if len(audit.entries) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(audit.entries))
	}
	if audit.entries[0].Action != "asset.upserted" {
		t.Fatalf("unexpected audit action %q", audit.entries[0].Action)
	}
}

func TestUpsertEdgeRequiresProvenance(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	err := svc.UpsertEdge(ctx, "actor", EdgeInput{TenantID: "t1", From: "a1", To: "a2", Kind: asset.EdgeRuns, Confidence: asset.EdgeObserved})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("edge without provenance must fail validation, got %v", err)
	}
}

func TestUpsertEdgePersistsAndAudits(t *testing.T) {
	svc, audit := newTestService(t)
	ctx := context.Background()
	if err := svc.UpsertEdge(ctx, "actor", EdgeInput{TenantID: "t1", From: "a1", To: "a2", Kind: asset.EdgeRuns, Provenance: "obs1", Confidence: asset.EdgeInferred}); err != nil {
		t.Fatalf("upsert edge: %v", err)
	}
	edges, err := svc.ListEdges(ctx, "t1")
	if err != nil {
		t.Fatalf("list edges: %v", err)
	}
	if len(edges) != 1 || edges[0].Kind != asset.EdgeRuns || edges[0].Confidence != asset.EdgeInferred {
		t.Fatalf("expected one inferred runs edge, got %+v", edges)
	}
	if len(audit.entries) != 1 || audit.entries[0].Action != "asset.edge_upserted" {
		t.Fatalf("expected edge audit entry, got %+v", audit.entries)
	}
}

func TestListAssetsTenantScoped(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.UpsertAsset(ctx, "actor", UpsertAssetInput{TenantID: "t1", Kind: asset.KindHost, Key: "h1"}); err != nil {
		t.Fatalf("t1: %v", err)
	}
	if _, err := svc.UpsertAsset(ctx, "actor", UpsertAssetInput{TenantID: "t2", Kind: asset.KindHost, Key: "h2"}); err != nil {
		t.Fatalf("t2: %v", err)
	}
	list, err := svc.ListAssets(ctx, "t1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].Key != "h1" {
		t.Fatalf("tenant t1 should see only its asset, got %+v", list)
	}
}
