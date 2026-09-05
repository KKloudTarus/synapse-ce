package sca

import (
	"context"
	"errors"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// hiddenContextRepo behaves like the real repositories: GetByIDInTenant hides internal contexts,
// GetByID does not.
type hiddenContextRepo struct {
	fakeEngRepo
}

func (r *hiddenContextRepo) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engdom.Engagement, error) {
	if r.eng == nil || r.eng.ID != id || r.eng.Internal() || shared.TenantOrDefault(r.eng.TenantID) != shared.TenantOrDefault(tenantID) {
		return nil, shared.ErrNotFound
	}
	return r.eng, nil
}

const hostContextSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"host://machine-id/abc"}},"components":[{"name":"openssl","version":"3.0.11-1~deb12u2","purl":"pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12"}]}`

func newContextImportService(t *testing.T, eng *engdom.Engagement) (*Service, *memory.ImportedSBOMStore) {
	t.Helper()
	store := memory.NewImportedSBOMStore()
	svc := NewService(&hiddenContextRepo{fakeEngRepo{eng: eng}}, nil, nil, nil, nil, nil, nil, fakeIDs{}, ports.Provenance{}, fakeClock{t: time.Unix(200, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0, &fakeAcquirer{}, &fakeDetector{}, fakeSBOM{}, nil, nil, fakeLic{}, nil)
	svc.SetImportedSBOMStore(store)
	return svc, store
}

// A fleet host context is hidden from the tenant-scoped read, so the operator import route cannot
// reach it, while the context entry point records the document on it.
func TestImportContextSBOMReachesHiddenHostContext(t *testing.T) {
	eng := engagementWithScope(t, "host://machine-id/abc")
	eng.TenantID, eng.HostAssetID = "tenant-1", "asset-1"
	svc, store := newContextImportService(t, eng)
	ctx := context.Background()

	if _, err := svc.ImportSBOMFile(ctx, "agent-1", "tenant-1", "e1", "host-inventory.cdx.json", []byte(hostContextSBOM)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("operator import reached an internal context: %v", err)
	}
	res, err := svc.ImportContextSBOM(ctx, "agent-1", "tenant-1", "e1", "host-inventory.cdx.json", []byte(hostContextSBOM))
	if err != nil {
		t.Fatalf("ImportContextSBOM: %v", err)
	}
	if res.Target != "host://machine-id/abc" || len(res.SBOM.Components) != 1 {
		t.Fatalf("result = target %q components %d", res.Target, len(res.SBOM.Components))
	}
	rec, err := store.LatestByEngagement(ctx, "tenant-1", "e1")
	if err != nil || rec.TargetRef != "host://machine-id/abc" || rec.ComponentCount != 1 {
		t.Fatalf("record = %+v, %v", rec, err)
	}
}

// The context entry point is not a wider read: another tenant's context and an operator engagement
// are both refused as not found.
func TestImportContextSBOMRefusesOtherTenantsAndOperatorEngagements(t *testing.T) {
	ctx := context.Background()
	hostCtx := engagementWithScope(t, "host://machine-id/abc")
	hostCtx.TenantID, hostCtx.HostAssetID = "tenant-1", "asset-1"
	svc, _ := newContextImportService(t, hostCtx)
	if _, err := svc.ImportContextSBOM(ctx, "agent-1", "tenant-2", "e1", "f.json", []byte(hostContextSBOM)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant context import = %v, want ErrNotFound", err)
	}

	operator := engagementWithScope(t, "myrepo")
	operator.TenantID = "tenant-1"
	svc, _ = newContextImportService(t, operator)
	if _, err := svc.ImportContextSBOM(ctx, "agent-1", "tenant-1", "e1", "f.json", []byte(hostContextSBOM)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("operator engagement reached through the context entry point: %v", err)
	}
	if _, err := svc.ImportSBOMFile(ctx, "operator", "tenant-1", "e1", "f.json", []byte(hostContextSBOM)); err != nil {
		t.Fatalf("operator import of an operator engagement: %v", err)
	}
}
