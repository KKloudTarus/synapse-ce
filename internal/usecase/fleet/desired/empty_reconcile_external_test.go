package fleetdesired_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
)

type noAssetRead struct{ calls int }

func (r *noAssetRead) GetAssetByID(context.Context, shared.ID, shared.ID) (*asset.Asset, error) {
	r.calls++
	return nil, errors.New("unexpected asset read")
}

type noBindingRead struct{ calls int }

func (r *noBindingRead) ListCurrentBindings(context.Context, shared.ID) ([]desireduc.CurrentBinding, error) {
	r.calls++
	return nil, errors.New("unexpected binding read")
}

type noObservedRead struct{ calls int }

func (r *noObservedRead) ListAgents(context.Context, shared.ID) ([]*fleetagent.Agent, error) {
	r.calls++
	return nil, errors.New("unexpected agent read")
}

type noClockRead struct{ calls int }

func (c *noClockRead) Now() time.Time { c.calls++; return time.Now() }

func TestReconcileNoDesiredPolicyDoesNotReadOtherFleetState(t *testing.T) {
	assets := &noAssetRead{}
	bindings := &noBindingRead{}
	agents := &noObservedRead{}
	clock := &noClockRead{}
	ids := &testIDGenerator{}
	svc, err := desireduc.NewService(reconcileDesiredStore{rows: nil}, assets, bindings, agents, reconcileAudit{}, clock, ids, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := svc.Reconcile(context.Background(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 || rows == nil {
		t.Fatalf("rows=%#v, want non-nil empty projection", rows)
	}
	if assets.calls != 0 || bindings.calls != 0 || agents.calls != 0 || clock.calls != 0 || ids.calls != 0 {
		t.Fatalf("empty policy performed unnecessary reads: assets=%d bindings=%d agents=%d clock=%d ids=%d",
			assets.calls, bindings.calls, agents.calls, clock.calls, ids.calls)
	}
}
