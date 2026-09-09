// Package responseactuator executes the deliberately narrow endpoint response protocol.
package responseactuator

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type processController interface {
	StopProcess(context.Context, shared.ID) (alreadyStopped bool, err error)
	RestartProcess(context.Context, shared.ID) (alreadyRestarted bool, err error)
}

// Actuator maps a validated protocol command to a direct kernel/process API. It never executes the
// command's display argv and never invokes a shell.
type Actuator struct {
	processes processController
}

var _ ports.ResponseActuator = (*Actuator)(nil)

func New(processes processController) (*Actuator, error) {
	if processes == nil {
		return nil, fmt.Errorf("%w: response actuator requires a live process controller", shared.ErrValidation)
	}
	return &Actuator{processes: processes}, nil
}

func (a *Actuator) ExecuteResponse(ctx context.Context, command fleetagent.ResponseCommand) (ports.ResponseActuatorOutcome, error) {
	if err := ctx.Err(); err != nil {
		return ports.ResponseActuatorOutcome{}, err
	}
	if err := command.Validate(); err != nil {
		return ports.ResponseActuatorOutcome{}, err
	}
	if command.Action.Kind != rdom.KindStopProcess || command.Target.Kind != responsesaga.FingerprintProcess ||
		command.Action.Reversibility != responsesaga.ReversibilityBestEffort {
		return ports.ResponseActuatorOutcome{}, fmt.Errorf("%w: endpoint actuator supports only best-effort reversible process stop", shared.ErrValidation)
	}
	if command.Reversal {
		alreadyRestarted, err := a.processes.RestartProcess(ctx, command.Target.ProcessEntityID)
		if err != nil {
			return ports.ResponseActuatorOutcome{}, fmt.Errorf("restart process target: %w", err)
		}
		affected := 1
		if alreadyRestarted {
			affected = 0
		}
		return ports.ResponseActuatorOutcome{
			ObservedRadius: offensivepolicy.RadiusStateChanging,
			AffectedCount:  affected,
			AlreadyApplied: alreadyRestarted,
		}, nil
	}
	alreadyStopped, err := a.processes.StopProcess(ctx, command.Target.ProcessEntityID)
	if err != nil {
		return ports.ResponseActuatorOutcome{}, fmt.Errorf("stop process target: %w", err)
	}
	affected := 1
	if alreadyStopped {
		affected = 0
	}
	return ports.ResponseActuatorOutcome{
		ObservedRadius: offensivepolicy.RadiusStateChanging,
		AffectedCount:  affected,
		AlreadyApplied: alreadyStopped,
	}, nil
}
