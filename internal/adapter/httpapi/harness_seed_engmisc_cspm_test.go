package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// engmiscCloudRuns reads tenantA's runs for every caller. The in-memory run store already refuses a
// run that belongs to another tenant, so on its own it would hide a missing route guard; pinning the
// tenant here keeps the run reachable by anyone who gets past the engagement check.
type engmiscCloudRuns struct{ *memory.CloudRunStore }

func (r engmiscCloudRuns) GetCloudRun(ctx context.Context, _, id shared.ID) (cloudposture.Run, error) {
	return r.CloudRunStore.GetCloudRun(ctx, "tenantA", id)
}

// engmiscCloudConnector and engmiscCloudAssets exist only because the CSPM service refuses to be built
// without a connector and an asset writer. Nothing in the harness submits a run, so neither is called.
type engmiscCloudConnector struct{}

func (engmiscCloudConnector) Enumerate(context.Context, ports.CloudScope) (cloudposture.Inventory, []cloudposture.CoverageIssue, error) {
	return cloudposture.Inventory{}, nil, fmt.Errorf("%w: the harness never enumerates a cloud account", shared.ErrForbidden)
}

func (engmiscCloudConnector) Evaluate(context.Context, cloudposture.Inventory) ([]cloudposture.PostureFinding, error) {
	return nil, fmt.Errorf("%w: the harness never evaluates a cloud inventory", shared.ErrForbidden)
}

type engmiscCloudAssets struct{}

func (engmiscCloudAssets) UpsertCloudAsset(context.Context, string, ports.CloudAssetInput) (*asset.Asset, error) {
	return nil, fmt.Errorf("%w: the harness never writes a cloud asset", shared.ErrForbidden)
}

func (engmiscCloudAssets) UpsertCloudEdge(context.Context, string, ports.CloudEdgeInput) error {
	return fmt.Errorf("%w: the harness never writes a cloud edge", shared.ErrForbidden)
}

// seedEngmiscCSPM wires the CSPM service with durable execution over the in-memory run store and
// records one finished run of tenantA under run id r1, attributed to the marker.
func seedEngmiscCSPM(w *harnessWorld) {
	service, err := cspm.NewService(
		map[cloudposture.Provider]ports.CloudConnector{cloudposture.ProviderAWS: engmiscCloudConnector{}},
		engmiscCloudAssets{}, memory.NewFindingRepository(), w.engagements, &harnessAudit{}, engmiscClock{})
	if err != nil {
		w.t.Fatalf("cspm service: %v", err)
	}
	ids := &engmiscIDs{}
	runs := engmiscCloudRuns{memory.NewCloudRunStore()}
	queue := memory.NewJobQueue(ids, func() time.Time { return engmiscNow })
	if err := service.SetDurableExecution(runs, queue, ids); err != nil {
		w.t.Fatalf("cspm durable execution: %v", err)
	}
	finished := engmiscNow.Add(time.Minute)
	run := cloudposture.Run{
		ID: engmiscRun, TenantID: "tenantA", EngagementID: engmiscEngagement, Actor: engmiscMarker,
		Status: cloudposture.RunSucceeded, Complete: true, Assets: 3, Findings: 1, StartedAt: engmiscNow, FinishedAt: &finished,
	}
	if err := runs.SaveCloudRun(engmiscTenantCtx(), run); err != nil {
		w.t.Fatalf("seed cspm run: %v", err)
	}
	w.rt.SetCSPM(service)
}
