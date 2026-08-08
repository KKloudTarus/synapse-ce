package hostinventory

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	dhi "github.com/KKloudTarus/synapse-ce/internal/domain/hostinventory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeAssetWriter struct {
	ids     map[string]shared.ID
	next    int
	upserts int
	last    assetuc.UpsertAssetInput
}

func newFakeWriter() *fakeAssetWriter { return &fakeAssetWriter{ids: map[string]shared.ID{}} }

func (f *fakeAssetWriter) UpsertAsset(_ context.Context, _ string, in assetuc.UpsertAssetInput) (*asset.Asset, error) {
	f.upserts++
	f.last = in
	k := string(in.Kind) + "|" + in.Key
	id, ok := f.ids[k]
	if !ok {
		f.next++
		id = shared.ID("id-" + itoa(f.next))
		f.ids[k] = id
	}
	return &asset.Asset{ID: id, TenantID: in.TenantID, Kind: in.Kind, Key: in.Key, Name: in.Name}, nil
}

type fakeAudit struct{ gaps int }

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if e.Action == "host_inventory.coverage_gap" {
		f.gaps++
	}
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

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

func newService(t *testing.T, w AssetWriter, a ports.AuditLogger) *Service {
	t.Helper()
	s, err := NewService(w, a, fixedClock{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return s
}

func completeHost() dhi.HostInventory {
	return dhi.HostInventory{
		Facts:    dhi.HostFacts{Hostname: "web01", OS: "linux", OSVersion: "12", MachineID: "abc123"},
		Packages: []sbom.Component{{Name: "acl", Version: "1"}, {Name: "zlib", Version: "2"}},
	}
}

func TestSyncPersistsHostAsset(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	res, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if w.upserts != 1 || w.last.Kind != asset.KindHost {
		t.Fatalf("expected one host asset upsert, got %d kind=%s", w.upserts, w.last.Kind)
	}
	// Machine-id keys the host (survives hostname changes).
	if w.last.Key != "machine-id/abc123" {
		t.Fatalf("host key = %q", w.last.Key)
	}
	if w.last.Attributes["packages"] != "2" || w.last.Attributes["os_version"] != "12" {
		t.Fatalf("facts/package count not in attributes: %+v", w.last.Attributes)
	}
	if !res.Complete || res.Degraded {
		t.Fatalf("a clean host must be complete + not degraded: %+v", res)
	}
}

func TestSyncFallsBackToHostnameKey(t *testing.T) {
	w := newFakeWriter()
	s := newService(t, w, &fakeAudit{})
	inv := dhi.HostInventory{Facts: dhi.HostFacts{Hostname: "web01", OS: "linux"}}
	if _, err := s.Sync(context.Background(), "a", SyncInput{TenantID: "t", Inventory: inv}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if w.last.Key != "hostname/web01" {
		t.Fatalf("without a machine id the host must key by hostname, got %q", w.last.Key)
	}
}

func TestSyncNoIdentityRejected(t *testing.T) {
	w := newFakeWriter()
	s := newService(t, w, &fakeAudit{})
	inv := dhi.HostInventory{Facts: dhi.HostFacts{OS: "linux"}} // no machine id, no hostname
	if _, err := s.Sync(context.Background(), "a", SyncInput{TenantID: "t", Inventory: inv}); err == nil {
		t.Fatal("a host with no stable identity must be rejected")
	}
	if w.upserts != 0 {
		t.Fatal("nothing must be persisted when the host is unidentifiable")
	}
}

func TestSyncCoverageAuditedAndDegraded(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	inv := completeHost()
	inv.AddIssue(dhi.CoverageUnreadableDB, "/var/lib/rpm unreadable")
	inv.AddIssue(dhi.CoverageNotCollected, "listening-sockets")
	res, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "t", Inventory: inv})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !res.Degraded || res.Complete {
		t.Fatalf("an unreadable DB must be degraded + incomplete: %+v", res)
	}
	if a.gaps != 2 {
		t.Fatalf("every coverage gap must be audited, got %d", a.gaps)
	}
	if w.last.Attributes["degraded"] != "true" {
		t.Fatalf("the host asset must record degraded=true, got %v", w.last.Attributes)
	}
}

func TestSyncIdempotent(t *testing.T) {
	w := newFakeWriter()
	s := newService(t, w, &fakeAudit{})
	in := SyncInput{TenantID: "t", Inventory: completeHost()}
	first, _ := s.Sync(context.Background(), "a", in)
	ids := len(w.ids)
	second, _ := s.Sync(context.Background(), "a", in)
	if len(w.ids) != ids {
		t.Fatalf("re-sync must reuse the host asset id (no churn): %d -> %d", ids, len(w.ids))
	}
	if first.AssetID != second.AssetID {
		t.Fatalf("re-sync must resolve the same asset id")
	}
}

func TestSyncValidation(t *testing.T) {
	s := newService(t, newFakeWriter(), &fakeAudit{})
	ctx := context.Background()
	if _, err := s.Sync(ctx, "", SyncInput{TenantID: "t", Inventory: completeHost()}); err == nil {
		t.Error("empty actor must be rejected")
	}
	if _, err := s.Sync(ctx, "a", SyncInput{Inventory: completeHost()}); err == nil {
		t.Error("empty tenant must be rejected")
	}
}

func TestNewServiceValidatesDeps(t *testing.T) {
	if _, err := NewService(nil, &fakeAudit{}, fixedClock{}); err == nil {
		t.Error("nil asset writer must be rejected")
	}
	if _, err := NewService(newFakeWriter(), nil, fixedClock{}); err == nil {
		t.Error("nil audit must be rejected")
	}
	if _, err := NewService(newFakeWriter(), &fakeAudit{}, nil); err == nil {
		t.Error("nil clock must be rejected")
	}
}
