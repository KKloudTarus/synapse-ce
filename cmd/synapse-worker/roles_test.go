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

	if err := assertClaimSet(control, handlersFor(workerroles.ControlKinds()...)); err != nil {
		t.Fatalf("complete control set: %v", err)
	}
	if err := assertClaimSet(execution, handlersFor(workerroles.ExecutionKinds()...)); err != nil {
		t.Fatalf("complete execution set: %v", err)
	}
	// A control worker that also registered an execution kind would steal tool work from the execution tier.
	mixed := handlersFor(workerroles.ControlKinds()...)
	mixed["sca"] = stubHandler{}
	if err := assertClaimSet(control, mixed); err == nil || !strings.Contains(err.Error(), `"sca" is not a control kind`) {
		t.Fatalf("control claiming sca: %v", err)
	}
	// A missing kind whose feature is on leaves jobs unclaimed.
	partial := handlersFor(workerroles.ControlKinds()...)
	delete(partial, "integration.operation")
	if err := assertClaimSet(control, partial); err == nil || !strings.Contains(err.Error(), `"integration.operation" has no handler`) {
		t.Fatalf("control missing integration.operation: %v", err)
	}
	// A missing kind whose feature is off is allowed.
	off := config.Config{WorkerProfile: config.WorkerProfileControl, NotificationEnabled: false, OwnershipMode: "off"}
	trimmed := handlersFor(workerroles.ControlKinds()...)
	for kind := range disabledKinds(off) {
		delete(trimmed, kind)
	}
	if err := assertClaimSet(off, trimmed); err != nil {
		t.Fatalf("control with notifications and ownership off: %v", err)
	}
	// The execution role without CSPM or the agent claims the three always-on tool kinds.
	plain := config.Config{WorkerProfile: config.WorkerProfileExecution}
	if err := assertClaimSet(plain, handlersFor("sca", "recon", "dast_run")); err != nil {
		t.Fatalf("plain execution set: %v", err)
	}
	// Legacy profiles are not checked.
	if err := assertClaimSet(config.Config{WorkerProfile: config.WorkerProfileAll}, handlersFor("anything")); err != nil {
		t.Fatalf("legacy profile must not be checked: %v", err)
	}
}
