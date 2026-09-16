package benchcycle

import (
	"context"
	"errors"
)

// ExecuteRepeated invokes capture in stable repetition and cell order, then compares each cell.
func ExecuteRepeated[C any, O any](
	ctx context.Context,
	repetitions int,
	cells []C,
	capture func(context.Context, int, C) (O, error),
	compare func(context.Context, C, []O) error,
) ([][]O, error) {
	if repetitions < 1 {
		return nil, errors.New("repetitions must be positive")
	}
	if capture == nil {
		return nil, errors.New("repeated capture callback is required")
	}
	outcomes := make([][]O, repetitions)
	for repetition := 1; repetition <= repetitions; repetition++ {
		outcomes[repetition-1] = make([]O, 0, len(cells))
		for _, cell := range cells {
			outcome, err := capture(ctx, repetition, cell)
			if err != nil {
				return nil, err
			}
			outcomes[repetition-1] = append(outcomes[repetition-1], outcome)
		}
	}
	if compare == nil {
		return outcomes, nil
	}
	for cellIndex, cell := range cells {
		cellOutcomes := make([]O, repetitions)
		for repetition := range outcomes {
			cellOutcomes[repetition] = outcomes[repetition][cellIndex]
		}
		if err := compare(ctx, cell, cellOutcomes); err != nil {
			return nil, err
		}
	}
	return outcomes, nil
}
