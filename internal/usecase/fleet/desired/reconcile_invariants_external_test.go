package fleetdesired_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	desireddom "github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type reconcileClock struct{ now time.Time }

func (c reconcileClock) Now() time.Time { return c.now }

type reconcileAudit struct{}

func (reconcileAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type reconcileDesiredStore struct{ rows []*desireddom.State }

func (s reconcileDesiredStore) Get(context.Context, shared.ID, shared.ID) (*desireddom.State, error) {
	return nil, shared.ErrNotFound
}
func (s reconcileDesiredStore) Put(context.Context, *desireddom.State) error { return nil }
func (s reconcileDesiredStore) Delete(context.Context, shared.ID, shared.ID, shared.ID, int64) error {
	return nil
}
func (s reconcileDesiredStore) List(context.Context, shared.ID) ([]*desireddom.State, error) {
	return s.rows, nil
}

type reconcileAssets struct{ calls int }

func (r *reconcileAssets) GetAssetByID(context.Context, shared.ID, shared.ID) (*asset.Asset, error) {
	r.calls++
	return nil, errors.New("reconciliation must not read asset catalog")
}

type reconcileBindings struct{ rows []desireduc.CurrentBinding }

func (s reconcileBindings) ListCurrentBindings(context.Context, shared.ID) ([]desireduc.CurrentBinding, error) {
	return s.rows, nil
}

type reconcileAgentReader struct{ rows []*fleetagent.Agent }

func (s reconcileAgentReader) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	return s.rows, nil
}

func desiredFixture(id string, caps []string, now time.Time) *desireddom.State {
	return &desireddom.State{
		TenantID: "tenant", AssetID: shared.ID(id), PolicyID: shared.ID("policy-" + id), Capabilities: caps,
		UpdatedBy: "operator", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func bindingFixture(assetID, agentID string) desireduc.CurrentBinding {
	return desireduc.CurrentBinding{TenantID: "tenant", AssetID: shared.ID(assetID), AgentID: shared.ID(agentID)}
}

func agentFixture(id string, caps []string, lastSeen time.Time) *fleetagent.Agent {
	return &fleetagent.Agent{
		ID: shared.ID(id), TenantID: "tenant", Capabilities: caps,
		LastSeenAt: lastSeen, State: fleetagent.StateActive,
	}
}

func reconcileService(t testing.TB, desired []*desireddom.State, bindings []desireduc.CurrentBinding, agents []*fleetagent.Agent, now time.Time) *desireduc.Service {
	t.Helper()
	svc, err := desireduc.NewService(
		reconcileDesiredStore{rows: desired}, &reconcileAssets{}, reconcileBindings{rows: bindings},
		reconcileAgentReader{rows: agents}, reconcileAudit{}, reconcileClock{now}, &testIDGenerator{}, 5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestReconcileCanonicalizesObservedCapabilitiesAndDoesNotMutateDesiredOrder(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	z := desiredFixture("z-asset", []string{"process"}, now)
	a := desiredFixture("a-asset", []string{"network", "process"}, now)
	desired := []*desireddom.State{z, a}
	bindings := []desireduc.CurrentBinding{bindingFixture("a-asset", "agent-a")}
	agents := []*fleetagent.Agent{agentFixture("agent-a", []string{" process ", "network", "irrelevant"}, now)}
	svc := reconcileService(t, desired, bindings, agents, now)

	rows, err := svc.Reconcile(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"a-asset/policy-a-asset/agent-a/network/true/",
		"a-asset/policy-a-asset/agent-a/process/true/",
		"z-asset/policy-z-asset//process/false/agent_missing",
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows: %#v", len(rows), rows)
	}
	for i, row := range rows {
		got := fmt.Sprintf("%s/%s/%s/%s/%t/%s", row.AssetID, row.PolicyID, row.AgentID, row.Capability, row.Covered, row.GapReason)
		if got != want[i] {
			t.Fatalf("row[%d]=%q want %q", i, got, want[i])
		}
	}
	if desired[0] != z || desired[1] != a {
		t.Fatal("reconciliation mutated the store-owned desired slice")
	}
}

func TestReconcileAllowsMultipleAgentsForOneAssetAndChoosesDeterministicWitness(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	desired := []*desireddom.State{desiredFixture("cluster", []string{"process"}, now)}
	// Deliberately reverse the binding and observed-agent order. agent-b covers process; agent-a is
	// healthy but does not. Reverse uniqueness AssetID -> AgentID is not part of the binding contract.
	bindings := []desireduc.CurrentBinding{
		bindingFixture("cluster", "agent-b"),
		bindingFixture("cluster", "agent-a"),
	}
	agents := []*fleetagent.Agent{
		agentFixture("agent-b", []string{"process"}, now),
		agentFixture("agent-a", []string{"network"}, now),
	}
	svc := reconcileService(t, desired, bindings, agents, now)
	rows, err := svc.Reconcile(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].Covered || rows[0].AgentID != "agent-b" || rows[0].GapReason != "" {
		t.Fatalf("multi-agent covered result=%+v", rows)
	}

	// If no healthy bound agent advertises the capability, choose the lexicographically first healthy
	// witness and return one asset-level capability gap rather than inventing a reverse-unique binding.
	agents[0].Capabilities = []string{"file"}
	rows, err = svc.Reconcile(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Covered || rows[0].AgentID != "agent-a" || rows[0].GapReason != desireddom.GapCapabilityMissing {
		t.Fatalf("multi-agent uncovered result=%+v", rows)
	}
}

func TestReconcileFailsClosedOnMalformedSnapshots(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	valid := desiredFixture("asset", []string{"process"}, now)
	validBinding := bindingFixture("asset", "agent")
	cases := []struct {
		name     string
		desired  []*desireddom.State
		bindings []desireduc.CurrentBinding
		agents   []*fleetagent.Agent
	}{
		{name: "nil desired", desired: []*desireddom.State{nil}},
		{name: "cross-tenant desired", desired: []*desireddom.State{{
			TenantID: "other", AssetID: "asset", PolicyID: "policy-asset", Capabilities: []string{"process"}, UpdatedBy: "operator", Version: 1,
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}}},
		{name: "duplicate desired", desired: []*desireddom.State{valid, valid}},
		{name: "empty binding identity", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{{TenantID: "tenant", AssetID: "asset"}}},
		{name: "cross-tenant binding", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{{TenantID: "other", AssetID: "asset", AgentID: "agent"}}},
		{name: "duplicate agent-asset binding", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{validBinding, validBinding}},
		{name: "agent bound to two assets", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{
			validBinding, bindingFixture("other-asset", "agent"),
		}},
		{name: "nil observed", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{validBinding}, agents: []*fleetagent.Agent{nil}},
		{name: "cross-tenant observed", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{validBinding}, agents: []*fleetagent.Agent{{
			ID: "agent", TenantID: "other", LastSeenAt: now, State: fleetagent.StateActive,
		}}},
		{name: "invalid observed lifecycle", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{validBinding}, agents: []*fleetagent.Agent{{
			ID: "agent", TenantID: "tenant", LastSeenAt: now, State: fleetagent.State("corrupt"),
		}}},
		{name: "duplicate observed", desired: []*desireddom.State{valid}, bindings: []desireduc.CurrentBinding{validBinding}, agents: []*fleetagent.Agent{
			agentFixture("agent", nil, now), agentFixture("agent", nil, now),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := reconcileService(t, tc.desired, tc.bindings, tc.agents, now)
			_, err := svc.Reconcile(context.Background(), "tenant")
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Reconcile error=%v, want validation error", err)
			}
		})
	}
}

func BenchmarkReconcileTenThousandAssets(b *testing.B) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	caps := []string{"file", "network", "privilege", "process"}
	desired := make([]*desireddom.State, 0, 10_000)
	bindings := make([]desireduc.CurrentBinding, 0, 10_000)
	agents := make([]*fleetagent.Agent, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		assetID := fmt.Sprintf("asset-%05d", i)
		agentID := fmt.Sprintf("agent-%05d", i)
		desired = append(desired, desiredFixture(assetID, caps, now))
		bindings = append(bindings, bindingFixture(assetID, agentID))
		agents = append(agents, agentFixture(agentID, caps, now))
	}
	svc := reconcileService(b, desired, bindings, agents, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := svc.Reconcile(context.Background(), "tenant")
		if err != nil || len(rows) != 40_000 {
			b.Fatalf("rows=%d err=%v", len(rows), err)
		}
	}
}

func BenchmarkGapsHealthyTenThousandAssets(b *testing.B) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	caps := []string{"file", "network", "privilege", "process"}
	desired := make([]*desireddom.State, 0, 10_000)
	bindings := make([]desireduc.CurrentBinding, 0, 10_000)
	agents := make([]*fleetagent.Agent, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		assetID := fmt.Sprintf("asset-%05d", i)
		agentID := fmt.Sprintf("agent-%05d", i)
		desired = append(desired, desiredFixture(assetID, caps, now))
		bindings = append(bindings, bindingFixture(assetID, agentID))
		agents = append(agents, agentFixture(agentID, caps, now))
	}
	svc := reconcileService(b, desired, bindings, agents, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rows, err := svc.Gaps(context.Background(), "tenant")
		if err != nil || len(rows) != 0 {
			b.Fatalf("rows=%d err=%v", len(rows), err)
		}
	}
}
