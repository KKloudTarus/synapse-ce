package processreport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeResolver struct {
	asset shared.ID
	err   error
	sawT  shared.ID
}

func (f *fakeResolver) ResolveTelemetryAsset(ctx context.Context, _ shared.ID) (shared.ID, error) {
	f.sawT, _ = shared.TenantFrom(ctx)
	return f.asset, f.err
}

type fakeStore struct {
	saved        []ports.ProcessSnapshot
	tenant       shared.ID
	err          error
	replaced     bool
	replaceAsset shared.ID
}

func (f *fakeStore) SaveProcesses(ctx context.Context, snaps []ports.ProcessSnapshot) error {
	f.tenant, _ = shared.TenantFrom(ctx)
	if f.err != nil {
		return f.err
	}
	f.saved = append(f.saved, snaps...)
	return nil
}

func (f *fakeStore) ReplaceRunningProcesses(ctx context.Context, assetID shared.ID, snaps []ports.ProcessSnapshot) error {
	f.tenant, _ = shared.TenantFrom(ctx)
	f.replaced = true
	f.replaceAsset = assetID
	if f.err != nil {
		return f.err
	}
	f.saved = append(f.saved, snaps...)
	return nil
}

type fakeLearner struct {
	calls int
	asset shared.ID
	actor string
	err   error
}

func (f *fakeLearner) Learn(_ context.Context, actor string, assetID shared.ID) error {
	f.calls++
	f.actor, f.asset = actor, assetID
	return f.err
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

func newSvc(t *testing.T, r AssetResolver, s ProcessStore, l Learner) *Service {
	t.Helper()
	svc, err := NewService(r, s, l, fixedClock{t: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestReportResolvesAssetReplacesAndLearns(t *testing.T) {
	res := &fakeResolver{asset: "asset-1"}
	store := &fakeStore{}
	learner := &fakeLearner{}
	svc := newSvc(t, res, store, learner)

	out, err := svc.Report(context.Background(), "tenant-a", "agent-9", []Process{
		{PID: 1, Comm: "systemd", Path: "/usr/lib/systemd/systemd", Running: true},
		{PID: 42, Comm: "sshd", Path: "/usr/sbin/sshd", Running: true},
		{PID: -1, Comm: "bogus"},
	}, true)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if out.AssetID != "asset-1" || out.Saved != 2 || !out.Learned {
		t.Fatalf("result = %+v, want asset-1 / 2 saved / learned", out)
	}
	if res.sawT != "tenant-a" || store.tenant != "tenant-a" {
		t.Fatalf("resolve/save must run under the agent tenant, got resolve=%q save=%q", res.sawT, store.tenant)
	}
	if len(store.saved) != 2 || store.saved[0].AssetID != "asset-1" || store.saved[0].EntityID != "proc:1" {
		t.Fatalf("saved snapshots = %+v", store.saved)
	}
	if !store.replaced || store.replaceAsset != "asset-1" {
		t.Fatalf("a complete report must replace the running set for the asset: replaced=%v asset=%q", store.replaced, store.replaceAsset)
	}
	if learner.calls != 1 || learner.asset != "asset-1" || learner.actor != "agent-9" {
		t.Fatalf("learner = %+v", learner)
	}
}

func TestReportTruncatedUpsertsNotReplaces(t *testing.T) {
	store := &fakeStore{}
	svc := newSvc(t, &fakeResolver{asset: "asset-1"}, store, nil)
	if _, err := svc.Report(context.Background(), "t", "a", []Process{{PID: 1}}, false); err != nil {
		t.Fatal(err)
	}
	if store.replaced {
		t.Fatal("a truncated report must upsert, never replace the running set")
	}
	if len(store.saved) != 1 {
		t.Fatalf("the snapshot must still be saved: %+v", store.saved)
	}
}

func TestReportRejectsAnAgentWithNoBinding(t *testing.T) {
	res := &fakeResolver{err: shared.ErrNotFound}
	store := &fakeStore{}
	svc := newSvc(t, res, store, &fakeLearner{})
	if _, err := svc.Report(context.Background(), "tenant-a", "agent-9", []Process{{PID: 1}}, true); err == nil {
		t.Fatal("a report from an unbound agent must fail")
	}
	if len(store.saved) != 0 {
		t.Fatal("nothing may be saved when the asset cannot be resolved")
	}
}

func TestReportWithoutLearnerStillSaves(t *testing.T) {
	store := &fakeStore{}
	svc := newSvc(t, &fakeResolver{asset: "asset-1"}, store, nil)
	out, err := svc.Report(context.Background(), "t", "a", []Process{{PID: 1}}, true)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if out.Learned || out.Saved != 1 {
		t.Fatalf("result = %+v, want 1 saved, not learned", out)
	}
}

func TestReportCapsProcesses(t *testing.T) {
	store := &fakeStore{}
	svc := newSvc(t, &fakeResolver{asset: "asset-1"}, store, nil)
	procs := make([]Process, MaxProcesses+50)
	for i := range procs {
		procs[i] = Process{PID: i + 1}
	}
	out, err := svc.Report(context.Background(), "t", "a", procs, false)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if out.Saved != MaxProcesses {
		t.Fatalf("saved %d, want the cap %d", out.Saved, MaxProcesses)
	}
}

func TestReportLearnFailureIsBestEffort(t *testing.T) {
	store := &fakeStore{}
	learner := &fakeLearner{err: errors.New("baseline sealed")}
	svc := newSvc(t, &fakeResolver{asset: "asset-1"}, store, learner)
	out, err := svc.Report(context.Background(), "t", "a", []Process{{PID: 1}}, true)
	if err != nil {
		t.Fatalf("a learn failure must not fail the report: %v", err)
	}
	if out.Saved != 1 || len(store.saved) != 1 {
		t.Fatalf("the snapshot must still be saved: %+v", out)
	}
	if out.Learned || out.LearnErr == "" {
		t.Fatalf("the learn failure must be recorded (Learned=false, LearnErr set): %+v", out)
	}
}
