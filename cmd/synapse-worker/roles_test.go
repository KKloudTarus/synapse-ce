package main

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/composition/workerroles"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
)

type stubHandler struct{}

func (stubHandler) Handle(context.Context, ports.QueuedJob) error { return nil }

func handlersFor(kinds ...string) map[string]worker.Handler {
	out := map[string]worker.Handler{}
	for _, kind := range kinds {
		out[kind] = stubHandler{}
	}
	return out
}

// TestAssertClaimSetPinsTheRoleContracts (#1559): a role may claim only its own kinds, and must claim every
// one of them whose feature is enabled; the two roles never overlap.
func TestAssertClaimSetPinsTheRoleContracts(t *testing.T) {
	control := config.Config{WorkerProfile: config.WorkerProfileControl, NotificationEnabled: true, OwnershipMode: "shadow"}
	execution := config.Config{WorkerProfile: config.WorkerProfileExecution, CSPMEnabled: true, AgentEnabled: true, LLMModel: "m"}

	if err := assertClaimSet(control, handlersFor(workerroles.ControlKinds()...), nil); err != nil {
		t.Fatalf("complete control set: %v", err)
	}
	if err := assertClaimSet(execution, handlersFor(workerroles.ExecutionKinds()...), nil); err != nil {
		t.Fatalf("complete execution set: %v", err)
	}
	// A control worker that also registered an execution kind would steal tool work from the execution tier.
	mixed := handlersFor(workerroles.ControlKinds()...)
	mixed["sca"] = stubHandler{}
	if err := assertClaimSet(control, mixed, nil); err == nil || !strings.Contains(err.Error(), `"sca" is not a control kind`) {
		t.Fatalf("control claiming sca: %v", err)
	}
	// A missing kind whose feature is on leaves jobs unclaimed.
	partial := handlersFor(workerroles.ControlKinds()...)
	delete(partial, "integration.operation")
	if err := assertClaimSet(control, partial, nil); err == nil || !strings.Contains(err.Error(), `"integration.operation" has no handler`) {
		t.Fatalf("control missing integration.operation: %v", err)
	}
	// A missing kind whose feature is off is allowed.
	off := config.Config{WorkerProfile: config.WorkerProfileControl, NotificationEnabled: false, OwnershipMode: "off"}
	trimmed := handlersFor(workerroles.ControlKinds()...)
	for kind := range disabledKinds(off) {
		delete(trimmed, kind)
	}
	if err := assertClaimSet(off, trimmed, nil); err != nil {
		t.Fatalf("control with notifications and ownership off: %v", err)
	}
	// The execution role without CSPM or the agent claims the three always-on tool kinds.
	plain := config.Config{WorkerProfile: config.WorkerProfileExecution}
	if err := assertClaimSet(plain, handlersFor("sca", "recon", "dast_run"), nil); err != nil {
		t.Fatalf("plain execution set: %v", err)
	}
	// Execution owns no singleton: a maintenance task registered on it is refused.
	if err := assertClaimSet(plain, handlersFor("sca", "recon", "dast_run"), []func(context.Context){func(context.Context) {}}); err == nil || !strings.Contains(err.Error(), "execution owns no singleton") {
		t.Fatalf("execution with a maintenance task: %v", err)
	}
	// The default profile is checked against the union of both sets.
	all := config.Config{WorkerProfile: config.WorkerProfileAll, NotificationEnabled: true, OwnershipMode: "shadow", CSPMEnabled: true, AgentEnabled: true, LLMModel: "m"}
	union := handlersFor(append(workerroles.ControlKinds(), workerroles.ExecutionKinds()...)...)
	if err := assertClaimSet(all, union, nil); err != nil {
		t.Fatalf("complete all set: %v", err)
	}
	delete(union, "vulnerability_sync")
	if err := assertClaimSet(all, union, nil); err == nil || !strings.Contains(err.Error(), `"vulnerability_sync" has no handler`) {
		t.Fatalf("all missing a control kind: %v", err)
	}
	// The retired profiles are not checked.
	if err := assertClaimSet(config.Config{WorkerProfile: config.WorkerProfileIntegrations}, handlersFor("anything"), nil); err != nil {
		t.Fatalf("retired profile must not be checked: %v", err)
	}
}
