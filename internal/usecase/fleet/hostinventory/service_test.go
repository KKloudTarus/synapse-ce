package hostinventory

import (
	"context"
	"errors"
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
	assets  map[string]*asset.Asset
	next    int
	upserts int
	last    assetuc.UpsertAssetInput
}

func newFakeWriter() *fakeAssetWriter {
	return &fakeAssetWriter{ids: map[string]shared.ID{}, assets: map[string]*asset.Asset{}}
}

func (f *fakeAssetWriter) GetAssetByKey(_ context.Context, _ shared.ID, kind asset.Kind, key string) (*asset.Asset, error) {
	a, ok := f.assets[string(kind)+"|"+key]
	if !ok {
		return nil, shared.ErrNotFound
	}
	copyAsset := *a
	copyAsset.Attributes = cloneStringMap(a.Attributes)
	return &copyAsset, nil
}

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
	a := &asset.Asset{ID: id, TenantID: in.TenantID, Kind: in.Kind, Key: in.Key, Name: in.Name, Attributes: cloneStringMap(in.Attributes)}
	f.assets[k] = a
	copyAsset := *a
	copyAsset.Attributes = cloneStringMap(a.Attributes)
	return &copyAsset, nil
}

func (f *fakeAssetWriter) ListAssets(_ context.Context, _ shared.ID) ([]*asset.Asset, error) {
	out := make([]*asset.Asset, 0, len(f.assets))
	for _, a := range f.assets {
		copyAsset := *a
		copyAsset.Attributes = cloneStringMap(a.Attributes)
		out = append(out, &copyAsset)
	}
	return out, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

type fakeAudit struct {
	gaps    int
	entries []ports.AuditEntry
}

func (f *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	f.entries = append(f.entries, e)
	if e.Action == "host_inventory.coverage_gap" {
		f.gaps++
	}
	return nil
}

func (f *fakeAudit) entry(action string) (ports.AuditEntry, bool) {
	for _, e := range f.entries {
		if e.Action == action {
			return e, true
		}
	}
	return ports.AuditEntry{}, false
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

func TestSyncBlocksCrossAgentAssetTakeoverAndAlerts(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	in := SyncInput{TenantID: "tenant-1", Inventory: completeHost()}
	first, err := s.Sync(context.Background(), "agent-a", in)
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	_, err = s.Sync(context.Background(), "agent-b", in)
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("cross-agent takeover error = %v, want conflict", err)
	}
	if w.upserts != 1 {
		t.Fatalf("blocked takeover mutated the asset: upserts=%d want 1", w.upserts)
	}
	stored, err := w.GetAssetByKey(context.Background(), "tenant-1", asset.KindHost, "machine-id/abc123")
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != first.AssetID || stored.Attributes["reporting_agent_id"] != "agent-a" {
		t.Fatalf("blocked takeover changed owner: id=%s attrs=%v", stored.ID, stored.Attributes)
	}

	auditEntry, ok := a.entry("host_inventory.asset_binding_takeover_blocked")
	if !ok {
		t.Fatal("blocked takeover was not audited")
	}
	alertEntry, ok := a.entry("security.alert")
	if !ok {
		t.Fatal("blocked takeover did not emit a security alert")
	}
	for name, entry := range map[string]ports.AuditEntry{"audit": auditEntry, "alert": alertEntry} {
		if entry.Metadata["tenant_id"] != "tenant-1" || entry.Metadata["asset_id"] != first.AssetID.String() ||
			entry.Metadata["old_agent_id"] != "agent-a" || entry.Metadata["new_agent_id"] != "agent-b" {
			t.Fatalf("%s context = %+v", name, entry.Metadata)
		}
	}
	if alertEntry.Metadata["alert_type"] != "telemetry_asset_binding_takeover" || alertEntry.Metadata["severity"] != "high" {
		t.Fatalf("security alert classification = %+v", alertEntry.Metadata)
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

// fakeBinder records the agent→asset telemetry binding a sync establishes. errOn, when non-nil, makes
// BindTelemetryAsset fail so the sync's hard-fail-on-binding-error path can be exercised.
type fakeBinder struct {
	last  ports.TelemetryAssetBinding
	calls int
	errOn error
}

func (f *fakeBinder) BindTelemetryAsset(_ context.Context, b ports.TelemetryAssetBinding) error {
	f.calls++
	if f.errOn != nil {
		return f.errOn
	}
	f.last = b
	return nil
}

func (f *fakeBinder) ResolveTelemetryAsset(_ context.Context, _ shared.ID) (shared.ID, error) {
	if f.last.AssetID.IsZero() {
		return "", shared.ErrNotFound
	}
	return f.last.AssetID, nil
}

// A wired binder is what makes telemetry ingest able to resolve the agent's asset; without this the whole
// EDR detection pipeline is unreachable. A successful sync must establish it from the server-authoritative
// actor + reconciled asset id.
func TestSyncEstablishesTelemetryBindingWhenBinderSet(t *testing.T) {
	w, a := newFakeWriter(), &fakeAudit{}
	s := newService(t, w, a)
	binder := &fakeBinder{}
	s.SetTelemetryBinder(binder)

	res, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if binder.calls != 1 {
		t.Fatalf("expected exactly one bind call, got %d", binder.calls)
	}
	if binder.last.AgentID != "agent-1" || binder.last.AssetID != res.AssetID || binder.last.TenantID != "tenant-1" {
		t.Fatalf("binding must map the authenticated agent to the reconciled asset in-tenant: %+v (asset=%s)", binder.last, res.AssetID)
	}
	if binder.last.UpdatedAt.IsZero() {
		t.Fatal("binding must carry a server-stamped update time")
	}
	// The binding is a first-class trust action and must be auditable.
	e, ok := a.entry("host_inventory.telemetry_binding_established")
	if !ok {
		t.Fatal("establishing a telemetry binding must be audited")
	}
	if e.Actor != "agent-1" || e.Metadata["asset_id"] != res.AssetID.String() {
		t.Fatalf("binding audit must attribute the actor + asset: %+v", e)
	}
}

// The binder is optional: a telemetry-less composition (nil binder) must sync unchanged.
func TestSyncWithoutBinderIsUnchanged(t *testing.T) {
	s := newService(t, newFakeWriter(), &fakeAudit{})
	if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()}); err != nil {
		t.Fatalf("sync without a binder must succeed: %v", err)
	}
}

// A binding failure (e.g. the asset is already bound to a different agent) must hard-fail the sync, never
// be swallowed — a host whose telemetry cannot be attributed must not report success.
func TestSyncFailsWhenBindingConflicts(t *testing.T) {
	s := newService(t, newFakeWriter(), &fakeAudit{})
	s.SetTelemetryBinder(&fakeBinder{errOn: shared.ErrConflict})
	if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a binding conflict must fail the sync, got %v", err)
	}
}

// fakeRecorder is the vulnerability recorder the sync hands the package list to.
type fakeRecorder struct {
	calls   int
	last    dhi.HostInventory
	lastID  shared.ID
	actor   string
	outcome VulnerabilityOutcome
	err     error
}

func (f *fakeRecorder) Record(_ context.Context, actor string, _ shared.ID, host *asset.Asset, inv dhi.HostInventory) (VulnerabilityOutcome, error) {
	f.calls++
	f.actor, f.lastID, f.last = actor, host.ID, inv
	if f.err != nil {
		return VulnerabilityOutcome{}, f.err
	}
	return f.outcome, nil
}

// With a recorder wired, a sync hands the persisted host and its packages to the recorder and reports
// the recorder's outcome. The actor is the authenticated agent, never anything from the inventory.
func TestSyncRecordsPackagesForVulnerabilityCorrelation(t *testing.T) {
	w := newFakeWriter()
	s := newService(t, w, &fakeAudit{})
	rec := &fakeRecorder{outcome: VulnerabilityOutcome{EngagementID: "ctx-1", JobID: "job-1", Components: 2}}
	s.SetVulnerabilityRecorder(rec)

	res, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if rec.calls != 1 || rec.actor != "agent-1" || rec.lastID != res.AssetID || len(rec.last.Packages) != 2 {
		t.Fatalf("recorder call = %+v", rec)
	}
	if res.VulnerabilityScan == nil || res.VulnerabilityScan.JobID != "job-1" || res.VulnerabilityScan.EngagementID != "ctx-1" {
		t.Fatalf("result outcome = %+v", res.VulnerabilityScan)
	}
}

// A recorder failure is audited with its cause and reported in the result; the inventory sync itself
// succeeded and must not be reported as failed to the agent.
func TestSyncAuditsRecorderFailureWithoutFailingTheSync(t *testing.T) {
	audit := &fakeAudit{}
	s := newService(t, newFakeWriter(), audit)
	s.SetVulnerabilityRecorder(&fakeRecorder{err: errors.New("queue unavailable")})

	res, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()})
	if err != nil {
		t.Fatalf("recorder failure must not fail the sync: %v", err)
	}
	if res.VulnerabilityScan == nil || !res.VulnerabilityScan.Failed || !res.VulnerabilityScan.Skipped || res.VulnerabilityScan.Reason != ReasonQueueError || res.VulnerabilityScan.Components != 2 {
		t.Fatalf("failed outcome = %+v", res.VulnerabilityScan)
	}
	e, ok := audit.entry("host_inventory.vulnerability_scan_failed")
	if !ok {
		t.Fatalf("failure not audited: %+v", audit.entries)
	}
	if e.Actor != "agent-1" || e.Target != res.AssetID.String() || e.Metadata["error"] != "queue unavailable" || e.Metadata["packages"] != "2" {
		t.Fatalf("failure audit = %+v", e)
	}
}

// Without a recorder the sync is unchanged: no outcome, packages only counted.
func TestSyncWithoutRecorderReportsNoScan(t *testing.T) {
	s := newService(t, newFakeWriter(), &fakeAudit{})
	res, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: completeHost()})
	if err != nil {
		t.Fatal(err)
	}
	if res.VulnerabilityScan != nil {
		t.Fatalf("outcome without recorder = %+v", res.VulnerabilityScan)
	}
}

// One agent identity may create MaxHostsPerAgent hosts; the next new key is refused and audited, while
// re-syncing an existing host is unaffected.
func TestSyncCapsHostsPerAgent(t *testing.T) {
	w := newFakeWriter()
	audit := &fakeAudit{}
	s := newService(t, w, audit)
	for i := 0; i < MaxHostsPerAgent; i++ {
		inv := dhi.HostInventory{Facts: dhi.HostFacts{Hostname: "h", OS: "linux", MachineID: "id-" + itoa(i)}}
		if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: inv}); err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	extra := dhi.HostInventory{Facts: dhi.HostFacts{Hostname: "h", OS: "linux", MachineID: "id-extra"}}
	if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: extra}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("host beyond the cap accepted: %v", err)
	}
	if _, ok := audit.entry("host_inventory.host_cap_reached"); !ok {
		t.Fatalf("cap refusal not audited: %+v", audit.entries)
	}
	// An existing host still syncs.
	again := dhi.HostInventory{Facts: dhi.HostFacts{Hostname: "h", OS: "linux", MachineID: "id-0"}}
	if _, err := s.Sync(context.Background(), "agent-1", SyncInput{TenantID: "tenant-1", Inventory: again}); err != nil {
		t.Fatalf("existing host refused: %v", err)
	}
	// Another agent has its own budget.
	other := dhi.HostInventory{Facts: dhi.HostFacts{Hostname: "h", OS: "linux", MachineID: "id-other"}}
	if _, err := s.Sync(context.Background(), "agent-2", SyncInput{TenantID: "tenant-1", Inventory: other}); err != nil {
		t.Fatalf("second agent refused: %v", err)
	}
}
