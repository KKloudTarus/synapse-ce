// Package emulationexec is the sandboxed benign step executor an adversary-emulation run uses (#421).
// Each production-safe technique maps to a benign, read-only observable command (the same signal the
// technique's expected detection matches on) that the executor runs through the confined tool runner,
// argv-only, in a network-isolated sandbox. It NEVER performs a real effect: emulation proves the
// observable, not the attack. A technique with no benign command here is reported not-observed rather
// than fabricated.
package emulationexec

import (
	"context"
	"fmt"

	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	exploituc "github.com/KKloudTarus/synapse-ce/internal/usecase/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxProofBytes = 4 << 10

// SandboxExecutor runs an emulation technique's benign observable through a confined tool runner.
type SandboxExecutor struct {
	runner   ports.ToolRunner
	commands map[string][]string
}

var _ exploituc.StepExecutor = (*SandboxExecutor)(nil)

// New constructs the executor over a sandboxed tool runner (a *sandbox.Runner). The runner must confine
// execution: the caller passes the same isolated sandbox the SCA/recon paths use, so the benign command
// runs argv-only with no egress.
func New(runner ports.ToolRunner) (*SandboxExecutor, error) {
	if runner == nil {
		return nil, fmt.Errorf("%w: emulation executor needs a sandboxed tool runner", shared.ErrValidation)
	}
	return &SandboxExecutor{runner: runner, commands: benignCommands()}, nil
}

// benignCommands maps each production-safe emulation technique to the benign, read-only command whose
// telemetry the technique's expected detection matches on. A lab-only technique (no benign proof) is
// intentionally absent, so it is refused before it reaches here or reported not-observed.
func benignCommands() map[string][]string {
	return map[string][]string{
		"emu.process_discovery":               {"ps", "-e"},                       // T1057 -> det.process_enumeration (comm=ps)
		"emu.system_network_config_discovery": {"ip", "addr"},                     // T1016 -> det.network_config_discovery (comm=ip)
		"emu.dns_beacon_benign":               {"getent", "hosts", "localhost"},   // T1071.004 -> det.suspicious_dns_beacon (a benign resolve)
		"emu.credential_file_read":            {"head", "-c", "1", "/etc/shadow"}, // T1552.001 -> det.credential_file_access (a benign read of a credential path)
	}
}

// Execute runs the technique's benign observable and reports whether the observable was produced. It
// never returns an error for a technique-level failure: a command that will not run in the sandbox is a
// not-observed outcome, not a run-ending error, so one un-runnable technique does not blind the rest of
// the coverage measurement.
func (x *SandboxExecutor) Execute(ctx context.Context, _ *dexploit.Chain, step dexploit.Step) (exploituc.StepOutcome, error) {
	argv, ok := x.commands[step.Technique]
	if !ok {
		return exploituc.StepOutcome{ObservedRadius: offensivepolicy.RadiusReadOnly, Observation: "no benign observable defined for technique " + step.Technique}, nil
	}
	res, err := x.runner.Run(ctx, ports.ToolSpec{Name: argv[0], Args: argv[1:], MaxOutputBytes: maxProofBytes})
	if err != nil {
		return exploituc.StepOutcome{ObservedRadius: offensivepolicy.RadiusReadOnly, Observation: fmt.Sprintf("benign observable %v did not run: %v", argv, err)}, nil
	}
	proof := res.Stdout
	if len(proof) > maxProofBytes {
		proof = proof[:maxProofBytes]
	}
	return exploituc.StepOutcome{
		Succeeded:      res.ExitCode == 0,
		ObservedRadius: offensivepolicy.RadiusReadOnly,
		Proof:          proof,
		Observation:    fmt.Sprintf("ran benign observable %v (exit %d)", argv, res.ExitCode),
	}, nil
}
