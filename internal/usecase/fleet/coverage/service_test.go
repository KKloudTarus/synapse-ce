package coverage

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetcoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
)

var now = time.Unix(1_700_000_000, 0).UTC()

type fixedClock struct{}

func (fixedClock) Now() time.Time { return now }

type fakeAgents map[shared.ID][]*fleetagent.Agent

func (f fakeAgents) ListAgents(_ context.Context, t shared.ID) ([]*fleetagent.Agent, error) {
	return f[t], nil
}

type fakeOrders map[shared.ID][]*workorder.WorkOrder

func (f fakeOrders) ListByTenant(_ context.Context, t shared.ID) ([]*workorder.WorkOrder, error) {
	return f[t], nil
}

type fakeAssets map[shared.ID][]*asset.Asset

func (f fakeAssets) ListAssets(_ context.Context, t shared.ID) ([]*asset.Asset, error) {
	return f[t], nil
}

func wo(id, assetID, agentID, cap string, st workorder.State, reason string, updated time.Time) *workorder.WorkOrder {
	return &workorder.WorkOrder{
		ID: shared.ID(id), TenantID: "t1", AssetID: shared.ID(assetID), AgentID: shared.ID(agentID),
		Capability: cap, State: st, RefuseReason: reason, Audit: shared.Audit{UpdatedAt: updated},
	}
}

func healthyAgent(id, cap string) *fleetagent.Agent {
	return &fleetagent.Agent{ID: shared.ID(id), TenantID: "t1", Capabilities: []string{cap}, LastSeenAt: now, AgentVersion: "1.0.0"}
}

func asst(id string) *asset.Asset {
	return &asset.Asset{ID: shared.ID(id), TenantID: "t1", Kind: asset.KindHost, Key: id}
}

func newSvc(t *testing.T, ag fakeAgents, or fakeOrders, as fakeAssets) *Service {
	t.Helper()
	s, err := NewService(ag, or, as, fixedClock{}, time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

func TestCoverageVerdicts(t *testing.T) {
	agents := fakeAgents{"t1": {healthyAgent("ag1", "scan.host")}}
	orders := fakeOrders{"t1": {
		// covered: authorized asset, live agent for cap, succeeded fresh
		wo("o-cov", "a-cov", "ag1", "scan.host", workorder.StateSucceeded, "", now.Add(-1*time.Hour)),
		// stale: succeeded but older than 24h target
		wo("o-stl", "a-stl", "ag1", "scan.host", workorder.StateSucceeded, "", now.Add(-48*time.Hour)),
		// never: authorized + live agent, only an issued (never succeeded) order
		wo("o-nev", "a-nev", "ag1", "scan.host", workorder.StateIssued, "", now.Add(-2*time.Hour)),
		// refused: latest order refused (agent available)
		wo("o-ref", "a-ref", "ag1", "scan.host", workorder.StateRefused, "out of scope", now.Add(-30*time.Minute)),
		// agent_missing: a capability no live agent advertises (even though succeeded+authorized)
		wo("o-am", "a-am", "ag1", "scan.cluster", workorder.StateSucceeded, "", now.Add(-1*time.Hour)),
		// unauthorized: asset not in the tenant asset model
		wo("o-un", "a-ghost", "ag1", "scan.host", workorder.StateSucceeded, "", now.Add(-1*time.Hour)),
	}}
	assets := fakeAssets{"t1": {asst("a-cov"), asst("a-stl"), asst("a-nev"), asst("a-ref"), asst("a-am")}} // a-ghost absent

	rows, err := newSvc(t, agents, orders, assets).Coverage(context.Background(), "t1")
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	got := map[string]fleetcoverage.Verdict{}
	detail := map[string]string{}
	for _, r := range rows {
		got[r.AssetID] = r.Verdict
		detail[r.AssetID] = r.Detail
	}
	want := map[string]fleetcoverage.Verdict{
		"a-cov":   fleetcoverage.VerdictCovered,
		"a-stl":   fleetcoverage.VerdictStale,
		"a-nev":   fleetcoverage.VerdictNever,
		"a-ref":   fleetcoverage.VerdictRefused,
		"a-am":    fleetcoverage.VerdictAgentMissing,
		"a-ghost": fleetcoverage.VerdictUnauthorized,
	}
	for a, v := range want {
		if got[a] != v {
			t.Errorf("asset %s: verdict = %q, want %q", a, got[a], v)
		}
	}
	if detail["a-ref"] != "out of scope" {
		t.Errorf("refused must carry its reason, got %q", detail["a-ref"])
	}
	// No asset is ever rendered covered unless it truly is.
	for _, r := range rows {
		if r.Verdict == fleetcoverage.VerdictCovered && r.AssetID != "a-cov" {
			t.Errorf("only a-cov may be covered, but %s is", r.AssetID)
		}
	}
}

func TestSummaryReconcilesWithDetail(t *testing.T) {
	agents := fakeAgents{"t1": {healthyAgent("ag1", "scan.host")}}
	orders := fakeOrders{"t1": {
		wo("o1", "a1", "ag1", "scan.host", workorder.StateSucceeded, "", now.Add(-1*time.Hour)),
		wo("o2", "a2", "ag1", "scan.host", workorder.StateRefused, "nope", now),
		wo("o3", "a3", "ag1", "scan.cluster", workorder.StateSucceeded, "", now), // agent_missing (no cluster agent)
	}}
	assets := fakeAssets{"t1": {asst("a1"), asst("a2"), asst("a3")}}
	s := newSvc(t, agents, orders, assets)

	rows, _ := s.Coverage(context.Background(), "t1")
	sum, err := s.Summary(context.Background(), "t1")
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	total := 0
	for _, n := range sum.RowsByVerdict {
		total += n
	}
	if total != len(rows) {
		t.Fatalf("summary RowsByVerdict (%d) must reconcile with detail rows (%d)", total, len(rows))
	}
	if sum.AssetsWithoutAgent != 1 { // a3 (scan.cluster) has no live agent
		t.Fatalf("assets_without_agent = %d, want 1", sum.AssetsWithoutAgent)
	}
}

func TestAgentsViewHealthAndCurrentWork(t *testing.T) {
	healthy := healthyAgent("ag1", "scan.host")
	stale := &fleetagent.Agent{ID: "ag2", TenantID: "t1", Capabilities: []string{"scan.host"}, LastSeenAt: now.Add(-2 * time.Hour)}
	agents := fakeAgents{"t1": {healthy, stale}}
	orders := fakeOrders{"t1": {
		wo("o1", "a1", "ag1", "scan.host", workorder.StateIssued, "", now), // live work for ag1
	}}
	s := newSvc(t, agents, orders, fakeAssets{"t1": {asst("a1")}})

	all, err := s.Agents(context.Background(), "t1", "")
	if err != nil {
		t.Fatalf("agents: %v", err)
	}
	byID := map[string]AgentRow{}
	for _, a := range all {
		byID[a.ID] = a
	}
	if byID["ag1"].Health != fleetcoverage.AgentHealthy || byID["ag1"].CurrentWork != 1 {
		t.Fatalf("ag1 should be healthy with 1 live order, got %+v", byID["ag1"])
	}
	if byID["ag2"].Health != fleetcoverage.AgentStale {
		t.Fatalf("ag2 (last seen 2h ago, 1h threshold) should be stale, got %q", byID["ag2"].Health)
	}
	// state filter
	staleOnly, _ := s.Agents(context.Background(), "t1", fleetcoverage.AgentStale)
	if len(staleOnly) != 1 || staleOnly[0].ID != "ag2" {
		t.Fatalf("state filter should return only ag2, got %+v", staleOnly)
	}
}

func TestAssetWithoutAnyWorkOrderIsSurfacedNotHidden(t *testing.T) {
	// The core anti-goal: an in-scope asset that was never assessed must appear as a distinct,
	// non-passing verdict — never silently absent (which would read as "fully covered").
	t.Run("no live agent -> agent_missing", func(t *testing.T) {
		agents := fakeAgents{"t1": {}} // no agents at all
		orders := fakeOrders{"t1": {}} // no work orders at all
		assets := fakeAssets{"t1": {asst("a-orphan")}}
		rows, err := newSvc(t, agents, orders, assets).Coverage(context.Background(), "t1")
		if err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if len(rows) != 1 || rows[0].AssetID != "a-orphan" {
			t.Fatalf("orphan asset must produce exactly one row, got %+v", rows)
		}
		if rows[0].Verdict != fleetcoverage.VerdictAgentMissing {
			t.Fatalf("orphan asset with no live agent must be agent_missing, got %q", rows[0].Verdict)
		}
		if rows[0].Verdict.Passing() {
			t.Fatalf("an unassessed asset must never render as passing")
		}
	})
	t.Run("live agent but never assessed -> never", func(t *testing.T) {
		agents := fakeAgents{"t1": {healthyAgent("ag1", "scan.host")}}
		orders := fakeOrders{"t1": {}}
		assets := fakeAssets{"t1": {asst("a-neverrun")}}
		rows, err := newSvc(t, agents, orders, assets).Coverage(context.Background(), "t1")
		if err != nil {
			t.Fatalf("coverage: %v", err)
		}
		if len(rows) != 1 || rows[0].Verdict != fleetcoverage.VerdictNever {
			t.Fatalf("in-scope asset with a live agent but no run must be never, got %+v", rows)
		}
	})
	t.Run("summary still reconciles with the synthetic rows", func(t *testing.T) {
		agents := fakeAgents{"t1": {healthyAgent("ag1", "scan.host")}}
		orders := fakeOrders{"t1": {wo("o1", "a1", "ag1", "scan.host", workorder.StateSucceeded, "", now.Add(-time.Hour))}}
		assets := fakeAssets{"t1": {asst("a1"), asst("a-orphan")}} // a-orphan has no order
		s := newSvc(t, agents, orders, assets)
		rows, _ := s.Coverage(context.Background(), "t1")
		sum, _ := s.Summary(context.Background(), "t1")
		total := 0
		for _, n := range sum.RowsByVerdict {
			total += n
		}
		if total != len(rows) {
			t.Fatalf("summary (%d) must reconcile with detail rows (%d) including synthetic rows", total, len(rows))
		}
	})
}

func TestTenantIsolation(t *testing.T) {
	// Tenant t2's data must never appear in a t1 query (the fakes are per-tenant, mirroring RLS).
	agents := fakeAgents{"t1": {healthyAgent("ag1", "scan.host")}}
	orders := fakeOrders{
		"t1": {wo("o1", "a1", "ag1", "scan.host", workorder.StateSucceeded, "", now)},
		"t2": {wo("o2", "a2", "ag9", "scan.host", workorder.StateSucceeded, "", now)},
	}
	assets := fakeAssets{"t1": {asst("a1")}}
	s := newSvc(t, agents, orders, assets)
	rows, _ := s.Coverage(context.Background(), "t1")
	for _, r := range rows {
		if r.AssetID == "a2" {
			t.Fatalf("t1 coverage must not include t2's asset a2")
		}
	}
	if len(rows) != 1 {
		t.Fatalf("t1 should see exactly its own row, got %d", len(rows))
	}
}
