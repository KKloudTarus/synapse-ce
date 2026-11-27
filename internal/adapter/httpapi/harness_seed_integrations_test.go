package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	projectdom "github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
)

// integrationsMarker appears in the body of an integration route only when tenantA's own record was
// served: it names the integration, the binding, the external run and the actor of the operation. It
// is distinct from every identifier the other seeds plant, and a tenantB response must never
// contain it.
const integrationsMarker = "tenantA-integrations-marker"

// integrationsNow is the instant every record planted by this seed carries.
var integrationsNow = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

// The service takes its ids from the seed's own generator, in the order Run plants the records, so
// the ids the routes are addressed with are known before the records exist. Run fails if a record
// comes back under another id, rather than leaving the routes addressed at nothing.
const (
	integrationsIntegration = shared.ID("integrations-seed-id-1")
	integrationsBinding     = shared.ID("integrations-seed-id-2")
	integrationsOperation   = shared.ID("integrations-seed-id-3")
	integrationsProject     = shared.ID("integrations-seed-project")
	integrationsProvider    = integration.Provider("harness-ci")
)

func init() {
	byID := []string{
		"GET /api/v1/integrations/{id}",
		"GET /api/v1/integrations/{id}/bindings",
		"GET /api/v1/integrations/{id}/external-runs",
		"GET /api/v1/integrations/{id}/operations",
	}
	operation := "GET /api/v1/integration-operations/{operationID}"
	values := map[string]map[string]string{operation: {"{operationID}": integrationsOperation.String()}}
	// "{id}" is an engagement on most routes; on these it is the integration.
	for _, route := range byID {
		values[route] = map[string]string{"{id}": integrationsIntegration.String()}
	}
	values["DELETE /api/v1/integrations/{id}/bindings/{bindingID}"] = map[string]string{
		"{id}": integrationsIntegration.String(), "{bindingID}": integrationsBinding.String(),
	}
	registerHarnessSeed(harnessSeed{
		Name:            "integrations",
		Routes:          append(byID, operation),
		RoutePathValues: values,
		Run:             seedIntegrations,
	})
}

// seedIntegrations wires the real integration service over the in-memory integration store and
// plants one tenantA integration with a project binding, then runs one poll through the service's
// own job handler, so the operation history and the external run are the ones a worker records.
//
// No route here has a guard of its own: every handler passes the caller's tenant to the service,
// and the store keys every record by it. That key is what stands between tenantB and these records.
func seedIntegrations(w *harnessWorld) []string {
	t := w.t
	t.Helper()
	ctx := shared.WithTenant(context.Background(), "tenantA")
	ids := &integrationsIDs{prefix: "integrations-seed-id"}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("integration cipher: %v", err)
	}
	clock := fixedClock{t: integrationsNow}
	queue := memory.NewJobQueue(&integrationsIDs{prefix: "integrations-seed-job"}, clock.Now)
	registry := integration.NewRegistry()
	// Reading runs is the only capability, so enabling needs neither a credential nor a passed
	// connection test, and the poll below is the one operation the seed has to run.
	descriptor := integration.ProviderDescriptor{Provider: integrationsProvider, Name: "Harness CI", Capabilities: []integration.Capability{integration.CapabilityReadRuns}}
	if err := registry.Register(descriptor, func(integration.Integration, integration.CredentialBundle, selfhosted.Rules) (integration.Adapter, error) {
		return integrationsAdapter{descriptor: descriptor}, nil
	}); err != nil {
		t.Fatalf("register integration provider: %v", err)
	}
	// The binding must name a tenantA project; a private repository keeps this seed off the
	// fixture's projects.
	projects := memory.NewProjectRepository()
	project, err := projectdom.New(integrationsProject, "tenantA", "Integrations project", "integrations-project",
		projectdom.SourceBinding{Kind: projectdom.SourceLocal, Value: "/repo"}, nil, "", integrationsNow)
	if err != nil {
		t.Fatalf("build integration project: %v", err)
	}
	if err := projects.Create(ctx, project); err != nil {
		t.Fatalf("store integration project: %v", err)
	}
	service, err := integrationuc.NewService(memory.NewIntegrationStore(queue, cipher, clock, &fakeAudit{}), registry, projects,
		memory.MissingIntegrationAnalysisMatcher{}, ids, clock)
	if err != nil {
		t.Fatalf("integration service: %v", err)
	}
	service.SetRunLock(memory.NewRunLock())

	item, err := service.Create(ctx, integrationuc.CreateInput{
		TenantID: "tenantA", Provider: string(integrationsProvider), Name: "integration " + integrationsMarker,
		Endpoint: "https://ci-a.example", Actor: integrationsMarker,
	})
	if err != nil {
		t.Fatalf("seed integration: %v", err)
	}
	binding, err := service.CreateBinding(ctx, "tenantA", item.ID, integrationsProject, "pipelines/"+integrationsMarker, "pipeline "+integrationsMarker, integrationsMarker)
	if err != nil {
		t.Fatalf("seed integration binding: %v", err)
	}
	if binding.ID != integrationsBinding {
		t.Fatalf("seed integration binding id = %s, want %s", binding.ID, integrationsBinding)
	}
	enabled, err := service.SetEnabled(ctx, "tenantA", item.ID, true, item.Version, integrationsMarker)
	if err != nil {
		t.Fatalf("enable integration: %v", err)
	}
	operation, err := service.StartOperation(ctx, "tenantA", enabled.ID, integration.OperationPoll, integrationsMarker)
	if err != nil {
		t.Fatalf("start integration poll: %v", err)
	}
	payload, err := json.Marshal(integrationuc.Job{OperationID: operation.ID})
	if err != nil {
		t.Fatalf("encode integration job: %v", err)
	}
	if err := service.HandleJob(ctx, operation.JobID, payload); err != nil {
		t.Fatalf("run integration poll: %v", err)
	}
	if item.ID != integrationsIntegration || operation.ID != integrationsOperation {
		t.Fatalf("planted integration %s and operation %s, but the routes are addressed with %s and %s", item.ID, operation.ID, integrationsIntegration, integrationsOperation)
	}
	w.rt.SetIntegrations(service)
	return []string{integrationsMarker}
}

// integrationsAdapter reports one finished run for every binding it is asked about. The run's
// provider key carries the marker, so the external run list answers a body only tenantA's run fills.
type integrationsAdapter struct {
	descriptor integration.ProviderDescriptor
}

func (a integrationsAdapter) Descriptor() integration.ProviderDescriptor { return a.descriptor }

func (integrationsAdapter) ReadRuns(_ context.Context, binding integration.Binding, _ string) ([]integration.ExternalRun, string, error) {
	return []integration.ExternalRun{{
		ProviderKey: "run-" + integrationsMarker, PipelineKey: binding.ExternalKey, Number: "1",
		Lifecycle: integration.RunCompleted, Result: integration.ResultSuccess, ProviderUpdatedAt: integrationsNow,
	}}, "checkpoint-1", nil
}

// integrationsIDs hands out distinct, predictable ids under one prefix.
type integrationsIDs struct {
	prefix string
	n      int
}

func (g *integrationsIDs) NewID() shared.ID {
	g.n++
	return shared.ID(fmt.Sprintf("%s-%d", g.prefix, g.n))
}
