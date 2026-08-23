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
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type setInvariantStore struct {
	current              *desireddom.State
	getErr               error
	puts                 int
	deletes              int
	deleteExpectedPolicy shared.ID
	deleteExpected       int64
	written              *desireddom.State
}

func (s *setInvariantStore) Get(context.Context, shared.ID, shared.ID) (*desireddom.State, error) {
	return s.current, s.getErr
}
func (s *setInvariantStore) Put(_ context.Context, state *desireddom.State) error {
	s.puts++
	s.written = state
	s.current = state
	s.getErr = nil
	return nil
}
func (s *setInvariantStore) Delete(_ context.Context, _ shared.ID, _ shared.ID, expectedPolicyID shared.ID, expectedVersion int64) error {
	s.deletes++
	s.deleteExpectedPolicy = expectedPolicyID
	s.deleteExpected = expectedVersion
	s.current = nil
	s.getErr = shared.ErrNotFound
	return nil
}
func (*setInvariantStore) List(context.Context, shared.ID) ([]*desireddom.State, error) {
	return nil, nil
}

type setInvariantAssetReader struct {
	asset *asset.Asset
	err   error
	calls int
}

func (r *setInvariantAssetReader) GetAssetByID(context.Context, shared.ID, shared.ID) (*asset.Asset, error) {
	r.calls++
	return r.asset, r.err
}

type setInvariantBindings struct{ calls int }

func (r *setInvariantBindings) ListCurrentBindings(context.Context, shared.ID) ([]desireduc.CurrentBinding, error) {
	r.calls++
	return nil, nil
}

type setInvariantAgents struct{ calls int }

func (r *setInvariantAgents) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	r.calls++
	return nil, nil
}

type setInvariantAudit struct{ records int }

func (a *setInvariantAudit) Record(context.Context, ports.AuditEntry) error {
	a.records++
	return nil
}

type setInvariantClock struct {
	now   time.Time
	calls int
}

func (c *setInvariantClock) Now() time.Time {
	c.calls++
	return c.now
}

func setInvariantState(now time.Time) *desireddom.State {
	return &desireddom.State{
		TenantID: "tenant", AssetID: "asset", PolicyID: "policy-current", Capabilities: []string{"network", "process"},
		UpdatedBy: "operator", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func setInvariantService(t *testing.T, store *setInvariantStore, assets *setInvariantAssetReader, audit *setInvariantAudit, clock *setInvariantClock, ids *testIDGenerator) *desireduc.Service {
	t.Helper()
	svc, err := desireduc.NewService(store, assets, &setInvariantBindings{}, &setInvariantAgents{}, audit, clock, ids, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestDesiredMutationRejectsBlankActorBeforeSideEffects(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		run  func(*desireduc.Service) error
	}{
		{name: "set", run: func(svc *desireduc.Service) error {
			_, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
				TenantID: "tenant", AssetID: "asset", Actor: "   ", Capabilities: []string{"process"},
			})
			return err
		}},
		{name: "clear", run: func(svc *desireduc.Service) error {
			return svc.ClearDesiredCapabilities(context.Background(), desireduc.ClearInput{
				TenantID: "tenant", AssetID: "asset", Actor: "   ",
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &setInvariantStore{current: setInvariantState(now)}
			assets := &setInvariantAssetReader{}
			audit := &setInvariantAudit{}
			clock := &setInvariantClock{now: now}
			ids := &testIDGenerator{}
			svc := setInvariantService(t, store, assets, audit, clock, ids)
			if err := tc.run(svc); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error=%v, want validation", err)
			}
			if store.puts != 0 || store.deletes != 0 || assets.calls != 0 || audit.records != 0 || clock.calls != 0 || ids.calls != 0 {
				t.Fatalf("blank actor caused side effects: puts=%d deletes=%d asset_reads=%d audit=%d clock=%d ids=%d",
					store.puts, store.deletes, assets.calls, audit.records, clock.calls, ids.calls)
			}
		})
	}
}

func TestSetDesiredCapabilitiesIdenticalReapplyIsSideEffectFree(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	current := setInvariantState(now)
	store := &setInvariantStore{current: current}
	assets := &setInvariantAssetReader{err: errors.New("identical reapply must not read asset")}
	audit := &setInvariantAudit{}
	clock := &setInvariantClock{now: now.Add(time.Hour)}
	ids := &testIDGenerator{}
	svc := setInvariantService(t, store, assets, audit, clock, ids)

	got, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
		TenantID: "tenant", AssetID: "asset", Actor: "another-operator",
		Capabilities: []string{" process ", "network", "process"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.puts != 0 || store.deletes != 0 || assets.calls != 0 || audit.records != 0 || clock.calls != 0 || ids.calls != 0 {
		t.Fatalf("identical reapply caused side effects: puts=%d deletes=%d asset_reads=%d audit=%d clock=%d ids=%d",
			store.puts, store.deletes, assets.calls, audit.records, clock.calls, ids.calls)
	}
	if got != current || got.PolicyID != "policy-current" || got.Version != 1 || !got.Audit.UpdatedAt.Equal(now) {
		t.Fatalf("identical reapply did not return unchanged state: %+v", got)
	}
}

func TestSetDesiredCapabilitiesFailsClosedOnMalformedAssetReaderResult(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		asset *asset.Asset
	}{
		{name: "nil", asset: nil},
		{name: "wrong tenant", asset: &asset.Asset{ID: "asset", TenantID: "other", Kind: asset.KindHost}},
		{name: "wrong asset", asset: &asset.Asset{ID: "other", TenantID: "tenant", Kind: asset.KindHost}},
		{name: "unsupported kind", asset: &asset.Asset{ID: "asset", TenantID: "tenant", Kind: asset.KindWorkload}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &setInvariantStore{getErr: shared.ErrNotFound}
			assets := &setInvariantAssetReader{asset: tc.asset}
			audit := &setInvariantAudit{}
			clock := &setInvariantClock{now: now}
			ids := &testIDGenerator{}
			svc := setInvariantService(t, store, assets, audit, clock, ids)
			_, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
				TenantID: "tenant", AssetID: "asset", Actor: "operator", Capabilities: []string{"process"},
			})
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("error=%v, want validation", err)
			}
			if store.puts != 0 || audit.records != 0 || clock.calls != 0 || ids.calls != 0 {
				t.Fatalf("malformed asset result caused side effects: puts=%d audit=%d clock=%d ids=%d", store.puts, audit.records, clock.calls, ids.calls)
			}
		})
	}
}

func TestSetDesiredCapabilitiesAllowsPolicyBeforeAgentBindingExists(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store := &setInvariantStore{getErr: shared.ErrNotFound}
	assets := &setInvariantAssetReader{asset: &asset.Asset{ID: "asset", TenantID: "tenant", Kind: asset.KindHost}}
	audit := &setInvariantAudit{}
	clock := &setInvariantClock{now: now}
	bindings := &setInvariantBindings{}
	agents := &setInvariantAgents{}
	ids := &testIDGenerator{}
	svc, err := desireduc.NewService(store, assets, bindings, agents, audit, clock, ids, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
		TenantID: "tenant", AssetID: "asset", Actor: "operator", Capabilities: []string{"process"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.AssetID != "asset" || got.PolicyID.IsZero() || got.Version != 1 || store.puts != 1 || store.written.Version != 1 ||
		bindings.calls != 0 || agents.calls != 0 || audit.records != 1 || clock.calls != 1 || ids.calls != 1 {
		t.Fatalf("pre-binding desired write mismatch: got=%+v written=%+v puts=%d bindings=%d agents=%d audit=%d clock=%d ids=%d",
			got, store.written, store.puts, bindings.calls, agents.calls, audit.records, clock.calls, ids.calls)
	}
}

func TestSetDesiredCapabilitiesIncrementsCurrentVersionExactlyOnce(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	current := setInvariantState(now)
	current.Version = 41
	store := &setInvariantStore{current: current}
	assets := &setInvariantAssetReader{asset: &asset.Asset{ID: "asset", TenantID: "tenant", Kind: asset.KindHost}}
	ids := &testIDGenerator{}
	svc := setInvariantService(t, store, assets, &setInvariantAudit{}, &setInvariantClock{now: now.Add(time.Minute)}, ids)
	got, err := svc.SetDesiredCapabilities(context.Background(), desireduc.SetInput{
		TenantID: "tenant", AssetID: "asset", Actor: "operator", Capabilities: []string{"file"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 42 || store.written.Version != 42 || got.PolicyID != current.PolicyID || ids.calls != 0 {
		t.Fatalf("semantic update got=%+v written=%+v ids=%d; want version 42 with preserved policy id and no new id", got, store.written, ids.calls)
	}
}

func TestClearDesiredCapabilitiesDoesNotDependOnAssetOrAgentExistence(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store := &setInvariantStore{current: setInvariantState(now)}
	assets := &setInvariantAssetReader{err: errors.New("clear must not read asset")}
	audit := &setInvariantAudit{}
	clock := &setInvariantClock{now: now.Add(time.Hour)}
	ids := &testIDGenerator{}
	svc := setInvariantService(t, store, assets, audit, clock, ids)

	if err := svc.ClearDesiredCapabilities(context.Background(), desireduc.ClearInput{
		TenantID: "tenant", AssetID: "asset", Actor: "operator",
	}); err != nil {
		t.Fatal(err)
	}
	if assets.calls != 0 || store.deletes != 1 || store.deleteExpectedPolicy != "policy-current" || store.deleteExpected != 1 ||
		audit.records != 1 || clock.calls != 1 || ids.calls != 0 {
		t.Fatalf("clear side effects mismatch: asset_reads=%d deletes=%d policy=%s expected=%d audit=%d clock=%d ids=%d",
			assets.calls, store.deletes, store.deleteExpectedPolicy, store.deleteExpected, audit.records, clock.calls, ids.calls)
	}
}
