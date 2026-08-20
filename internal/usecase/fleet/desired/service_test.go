package fleetdesired_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type testClock struct {
	now   time.Time
	calls int
}

func (c *testClock) Now() time.Time { c.calls++; return c.now }

type testAudit struct{ entries []ports.AuditEntry }

func (a *testAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

type testAssets struct {
	rows  map[shared.ID]*asset.Asset
	calls int
}

func (r *testAssets) GetAssetByID(_ context.Context, tenantID, assetID shared.ID) (*asset.Asset, error) {
	r.calls++
	a, ok := r.rows[assetID]
	if !ok || a.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

type testBindings struct {
	rows  []desireduc.CurrentBinding
	calls int
	err   error
}

func (r *testBindings) ListCurrentBindings(context.Context, shared.ID) ([]desireduc.CurrentBinding, error) {
	r.calls++
	return append([]desireduc.CurrentBinding(nil), r.rows...), r.err
}

type testAgents struct {
	rows  []*fleetagent.Agent
	calls int
	err   error
}

func (r *testAgents) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	r.calls++
	return append([]*fleetagent.Agent(nil), r.rows...), r.err
}

func technicalAsset(id string, kind asset.Kind) *asset.Asset {
	return &asset.Asset{ID: shared.ID(id), TenantID: "tenant-1", Kind: kind, Key: id, Name: id}
}

func observedAgent(id string, caps []string, at time.Time, state fleetagent.State) *fleetagent.Agent {
	return &fleetagent.Agent{
		ID: shared.ID(id), TenantID: "tenant-1", Capabilities: caps, LastSeenAt: at, State: state,
	}
}

func newTestService(t *testing.T, store ports.FleetDesiredStore, assets desireduc.AssetReader, bindings desireduc.BindingReader, agents desireduc.AgentReader, audit ports.AuditLogger, clock ports.Clock, stale time.Duration) *desireduc.Service {
	t.Helper()
	svc, err := desireduc.NewService(store, assets, bindings, agents, audit, clock, &testIDGenerator{}, stale)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestSetDesiredCapabilitiesNormalizesAuditsPreservesCreatedAtAndIncrementsVersion(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	assets := &testAssets{rows: map[shared.ID]*asset.Asset{"asset-1": technicalAsset("asset-1", asset.KindHost)}}
	store := memory.NewFleetDesiredStore()
	audit := &testAudit{}
	svc := newTestService(t, store, assets, &testBindings{}, &testAgents{}, audit, clock, 5*time.Minute)

	first, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: "tenant-1", AssetID: "asset-1", Actor: "operator-1",
		Capabilities: []string{" telemetry.process ", "inventory.host", "telemetry.process"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.PolicyID.IsZero() || first.Version != 1 || len(first.Capabilities) != 2 || first.Capabilities[0] != "inventory.host" || first.Capabilities[1] != "telemetry.process" {
		t.Fatalf("state not canonical/versioned: %+v", first)
	}
	clock.now = now.Add(time.Minute)
	second, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: "tenant-1", AssetID: "asset-1", Actor: "operator-2", Capabilities: []string{"telemetry.network"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Version != 2 || second.PolicyID != first.PolicyID {
		t.Fatalf("second lifecycle=%s@%d want %s@2", second.PolicyID, second.Version, first.PolicyID)
	}
	if !second.Audit.CreatedAt.Equal(first.Audit.CreatedAt) || !second.Audit.UpdatedAt.Equal(clock.now) {
		t.Fatalf("audit timestamps not preserved/moved: first=%v second=%v", first.Audit, second.Audit)
	}
	if len(audit.entries) != 2 || audit.entries[1].Action != "fleet.desired_capabilities.set" || audit.entries[1].Actor != "operator-2" || audit.entries[1].Metadata["policy_version"] != "2" || audit.entries[1].Metadata["policy_id"] != first.PolicyID.String() {
		t.Fatalf("unexpected audit entries: %#v", audit.entries)
	}
	if assets.calls != 2 {
		t.Fatalf("changed writes should validate canonical asset each time; calls=%d", assets.calls)
	}
}

func TestSetDesiredCapabilitiesRequiresExistingSupportedCanonicalAsset(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Now().UTC()}
	store := memory.NewFleetDesiredStore()
	assets := &testAssets{rows: map[shared.ID]*asset.Asset{
		"workload": technicalAsset("workload", asset.KindWorkload),
	}}
	svc := newTestService(t, store, assets, &testBindings{}, &testAgents{}, &testAudit{}, clock, time.Minute)

	for _, tc := range []struct {
		name    string
		assetID shared.ID
	}{
		{name: "missing", assetID: "missing"},
		{name: "unsupported kind", assetID: "workload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
				TenantID: "tenant-1", AssetID: tc.assetID, Actor: "operator", Capabilities: []string{"process"},
			})
			if err == nil {
				t.Fatal("expected mutation rejection")
			}
			if _, getErr := store.Get(ctx, "tenant-1", tc.assetID); !errors.Is(getErr, shared.ErrNotFound) {
				t.Fatalf("rejected mutation wrote desired state: %v", getErr)
			}
		})
	}
	if _, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: "tenant-1", AssetID: "workload", Actor: "operator", Capabilities: nil,
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty Set error=%v, want validation", err)
	}
}

func TestClearDesiredCapabilitiesIsExplicitAndIdempotent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)
	store := memory.NewFleetDesiredStore()
	if err := store.Put(ctx, &desireddom.State{
		TenantID: "tenant-1", AssetID: "asset-1", PolicyID: "policy-clear", Capabilities: []string{"process"}, UpdatedBy: "operator", Version: 1,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
	assets := &testAssets{rows: map[shared.ID]*asset.Asset{}}
	audit := &testAudit{}
	clock := &testClock{now: now.Add(time.Minute)}
	svc := newTestService(t, store, assets, &testBindings{}, &testAgents{}, audit, clock, time.Minute)

	if err := svc.ClearDesiredCapabilities(ctx, desireduc.ClearInput{TenantID: "tenant-1", AssetID: "asset-1", Actor: "operator-2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "tenant-1", "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cleared policy still exists: %v", err)
	}
	if assets.calls != 0 || len(audit.entries) != 1 || clock.calls != 1 || audit.entries[0].Metadata["policy_version"] != "1" || audit.entries[0].Metadata["policy_id"] != "policy-clear" {
		t.Fatalf("clear side effects: asset_reads=%d audits=%#v clock=%d", assets.calls, audit.entries, clock.calls)
	}
	if err := svc.ClearDesiredCapabilities(ctx, desireduc.ClearInput{TenantID: "tenant-1", AssetID: "asset-1", Actor: "operator-2"}); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 1 || clock.calls != 1 {
		t.Fatalf("idempotent absent clear caused side effects: audits=%d clock=%d", len(audit.entries), clock.calls)
	}
}

func TestReenrolledReplacementAgentSatisfiesExistingAssetPolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	store := memory.NewFleetDesiredStore()
	if err := store.Put(ctx, &desireddom.State{
		TenantID: "tenant-1", AssetID: "host-asset", PolicyID: "policy-host", Capabilities: []string{"network", "process"}, UpdatedBy: "operator", Version: 1,
		Audit: shared.Audit{CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}
	bindings := &testBindings{rows: []desireduc.CurrentBinding{{TenantID: "tenant-1", AssetID: "host-asset", AgentID: "agent-new"}}}
	agents := &testAgents{rows: []*fleetagent.Agent{observedAgent("agent-new", []string{"process", "network"}, now, fleetagent.StateActive)}}
	svc := newTestService(t, store, &testAssets{rows: map[shared.ID]*asset.Asset{}}, bindings, agents, &testAudit{}, &testClock{now: now}, 5*time.Minute)

	rows, err := svc.Reconcile(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !rows[0].Covered || !rows[1].Covered || rows[0].AgentID != "agent-new" || rows[1].AgentID != "agent-new" || rows[0].PolicyID != "policy-host" || rows[1].PolicyID != "policy-host" {
		t.Fatalf("replacement agent did not satisfy existing asset policy: %#v", rows)
	}
}

func TestReconcileSurfacesHealthCapabilityAndBindingGaps(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	store := memory.NewFleetDesiredStore()
	put := func(assetID string, caps ...string) {
		t.Helper()
		if err := store.Put(ctx, &desireddom.State{
			TenantID: "tenant-1", AssetID: shared.ID(assetID), PolicyID: shared.ID("policy-" + assetID), Capabilities: caps,
			UpdatedBy: "operator", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("asset-healthy", "file", "network", "process")
	put("asset-stale", "process")
	put("asset-revoked", "process")
	put("asset-decommissioned", "process")
	put("asset-unbound", "process")
	put("asset-agent-row-missing", "process")

	bindings := &testBindings{rows: []desireduc.CurrentBinding{
		{TenantID: "tenant-1", AssetID: "asset-healthy", AgentID: "agent-healthy"},
		{TenantID: "tenant-1", AssetID: "asset-stale", AgentID: "agent-stale"},
		{TenantID: "tenant-1", AssetID: "asset-revoked", AgentID: "agent-revoked"},
		{TenantID: "tenant-1", AssetID: "asset-decommissioned", AgentID: "agent-decommissioned"},
		{TenantID: "tenant-1", AssetID: "asset-agent-row-missing", AgentID: "agent-missing"},
	}}
	agents := &testAgents{rows: []*fleetagent.Agent{
		observedAgent("agent-healthy", []string{" network ", "process"}, now, fleetagent.StateActive),
		observedAgent("agent-stale", []string{"process"}, now.Add(-10*time.Minute), fleetagent.StateActive),
		observedAgent("agent-revoked", []string{"process"}, now, fleetagent.StateRevoked),
		observedAgent("agent-decommissioned", []string{"process"}, now, fleetagent.StateDecommissioned),
	}}
	svc := newTestService(t, store, &testAssets{rows: map[shared.ID]*asset.Asset{}}, bindings, agents, &testAudit{}, &testClock{now: now}, 5*time.Minute)

	rows, err := svc.Reconcile(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	wantGaps := map[string]desireddom.GapReason{
		"asset-healthy/file":              desireddom.GapCapabilityMissing,
		"asset-stale/process":             desireddom.GapAgentStale,
		"asset-revoked/process":           desireddom.GapAgentRevoked,
		"asset-decommissioned/process":    desireddom.GapAgentDecommissioned,
		"asset-unbound/process":           desireddom.GapAgentMissing,
		"asset-agent-row-missing/process": desireddom.GapAgentMissing,
	}
	covered := 0
	for _, row := range rows {
		key := row.AssetID + "/" + row.Capability
		if row.PolicyID == "" || row.PolicyVersion != 1 {
			t.Fatalf("row %s lost desired policy identity: %+v", key, row)
		}
		if row.Covered {
			covered++
			if row.GapReason != "" {
				t.Fatalf("covered row %s carries gap %q", key, row.GapReason)
			}
			continue
		}
		want, ok := wantGaps[key]
		if !ok || row.GapReason != want {
			t.Fatalf("row %s gap=%q want=%q known=%v", key, row.GapReason, want, ok)
		}
	}
	if covered != 2 {
		t.Fatalf("covered=%d want 2; rows=%#v", covered, rows)
	}
	gaps, err := svc.Gaps(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != len(wantGaps) {
		t.Fatalf("gaps=%d want %d: %#v", len(gaps), len(wantGaps), gaps)
	}
}
