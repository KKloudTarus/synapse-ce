package main

import (
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

// assertClaimSet checks a role's handler map against the role's kind set (#1559): a handler outside the
// set would claim work the other role owns, and a missing kind would leave its jobs unclaimed, unless
// the feature that produces it is off. The legacy profiles are not checked; they are retired by the
// control and execution roles.
func assertClaimSet(cfg config.Config, handlers map[string]worker.Handler) error {
	var want []string
	switch cfg.WorkerProfile {
	case config.WorkerProfileControl:
		want = workerroles.ControlKinds()
	case config.WorkerProfileExecution:
		want = workerroles.ExecutionKinds()
	default:
		return nil
	}
	disabled := disabledKinds(cfg)
	wanted := map[string]bool{}
	for _, kind := range want {
		wanted[kind] = true
	}
	var problems []string
	for kind := range handlers {
		if !wanted[kind] {
			problems = append(problems, fmt.Sprintf("%q is not a %s kind", kind, cfg.WorkerProfile))
		}
	}
	for _, kind := range want {
		if _, ok := handlers[kind]; ok {
			continue
		}
		if reason, off := disabled[kind]; off {
			continue
		} else {
			_ = reason
		}
		problems = append(problems, fmt.Sprintf("%q has no handler and its feature is enabled", kind))
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%s", strings.Join(problems, "; "))
}

// disabledKinds names the kinds a role may leave unclaimed because the feature that enqueues them is
// off, with the setting that turns it on.
func disabledKinds(cfg config.Config) map[string]string {
	out := map[string]string{}
	if !cfg.NotificationEnabled {
		for _, kind := range []string{notificationuc.JobKind, usercontacts.JobKind, inbox.JobKind, inbox.SlackJobKind, inbox.TeamsJobKind} {
			out[kind] = "SYNAPSE_NOTIFICATIONS_ENABLED"
		}
	}
	if cfg.OwnershipMode == "off" {
		out[ownershipuc.RouteJobKind] = "SYNAPSE_OWNERSHIP_MODE"
	}
	if !cfg.CSPMEnabled {
		out[cspmuc.JobKind] = "SYNAPSE_CSPM_ENABLED"
	}
	if !cfg.AgentEnabled || strings.TrimSpace(cfg.LLMModel) == "" {
		out[orchestrator.JobKind] = "SYNAPSE_AGENT_ENABLED"
	}
	return out
}
