package reachbench

import (
	"context"
	"errors"
)

// RunFromEnvironment is the single no-argument production entrypoint. Production capture wiring is deliberately
// unavailable until a package-local adapter can observe derived export effects and missing provenance.
func RunFromEnvironment(ctx context.Context, args []string) (Result, error) {
	runner, err := NewRunner(DefaultDependencies(), unavailableCapture{})
	if err != nil {
		return Result{}, err
	}
	return runner.Run(ctx, args)
}

type unavailableCapture struct{}

func (unavailableCapture) Capture(context.Context, CaptureRequest) (CaptureResult, error) {
	return CaptureResult{}, errors.New("reachability production capture adapter is not installed")
}
