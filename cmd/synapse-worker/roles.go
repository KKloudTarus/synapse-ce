package main

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/composition/workerroles"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	cspmuc "github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/inbox"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/orchestrator"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/usercontacts"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
)

// ownsSingletons reports whether a profile owns singleton work and campaigns for the maintenance lease.
// The execution role never does (#1559); every other profile keeps its lease.
func ownsSingletons(cfg config.Config) bool {
	return cfg.WorkerProfile != config.WorkerProfileExecution
}

// assertClaimSet checks a role's handler map against the role's kind set (#1559): a handler outside the
// set would claim work the other role owns, and a missing kind would leave its jobs unclaimed, unless
// the feature that produces it is off. The execution role must also own no maintenance task. The `all`
// profile is checked against both sets; the three retired profiles are subsets and are not checked.
func assertClaimSet(cfg config.Config, handlers map[string]worker.Handler, maintenance []func(context.Context)) error {
	var want []string
	var problems []string
	switch cfg.WorkerProfile {
	case config.WorkerProfileControl:
		want = workerroles.ControlKinds()
	case config.WorkerProfileExecution:
		want = workerroles.ExecutionKinds()
		if len(maintenance) > 0 {
			problems = append(problems, fmt.Sprintf("execution owns no singleton but %d maintenance tasks were registered", len(maintenance)))
		}
	case config.WorkerProfileAll:
		want = append(workerroles.ControlKinds(), workerroles.ExecutionKinds()...)
	default:
		return nil
	}
	disabled := disabledKinds(cfg)
	wanted := map[string]bool{}
	for _, kind := range want {
		wanted[kind] = true
	}
	for kind := range handlers {
		if !wanted[kind] {
			problems = append(problems, fmt.Sprintf("%q is not a %s kind", kind, cfg.WorkerProfile))
		}
	}
	for _, kind := range want {
		if _, ok := handlers[kind]; ok || disabled[kind] {
			continue
		}
		problems = append(problems, fmt.Sprintf("%q has no handler and its feature is enabled", kind))
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}

// disabledKinds names the kinds a role may leave unclaimed because the feature that enqueues them is off.
func disabledKinds(cfg config.Config) map[string]bool {
	out := map[string]bool{}
	if !cfg.NotificationEnabled {
		for _, kind := range []string{notificationuc.JobKind, usercontacts.JobKind, inbox.JobKind, inbox.SlackJobKind, inbox.TeamsJobKind} {
			out[kind] = true
		}
	}
	if cfg.OwnershipMode == "off" {
		out[ownershipuc.RouteJobKind] = true
	}
	if !cfg.CSPMEnabled {
		out[cspmuc.JobKind] = true
	}
	if !cfg.AgentEnabled || strings.TrimSpace(cfg.LLMModel) == "" {
		out[orchestrator.JobKind] = true
	}
	return out
}
