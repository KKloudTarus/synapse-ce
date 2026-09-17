package benchcycle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
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

const (
	// DefaultTwoPassWorkers preserves serial execution unless callers explicitly opt in.
	DefaultTwoPassWorkers = 1
	// MaxTwoPassCells bounds the fixed two-pass execution plan.
	MaxTwoPassCells = 10000
	// MaxTwoPassCellKeyBytes bounds one opaque stable cell identity.
	MaxTwoPassCellKeyBytes = 512
	// MaxTwoPassWorkers bounds the fixed worker pool for a two-pass execution.
	MaxTwoPassWorkers = 64
)

// PlanCell is one keyed execution cell supplied by a benchmark domain.
type PlanCell[C any] struct {
	Key  string
	Cell C
}

// TwoPassPlan defines a bounded, keyed execution plan.
type TwoPassPlan[C any] struct {
	Cells   []PlanCell[C]
	Workers int
}

// AttemptAddress identifies one preassigned cell and repetition.
type AttemptAddress struct {
	CellKey    string
	Repetition int
}

// Attempt is the work supplied to one capture callback.
type Attempt[C any] struct {
	Address AttemptAddress
	Cell    C
}

// AttemptOutcome is a capture result whose address must match its planned attempt.
type AttemptOutcome[O any] struct {
	Address AttemptAddress
	Outcome O
}

// PairOutcome is the canonical, explicitly keyed result for both repetitions of one cell.
type PairOutcome[C any, O any] struct {
	Cell     PlanCell[C]
	Outcomes [2]AttemptOutcome[O]
}

// ExecuteTwoPass captures every keyed cell once in each of two separated passes.
func ExecuteTwoPass[C any, O any](
	ctx context.Context,
	plan TwoPassPlan[C],
	capture func(context.Context, Attempt[C]) (AttemptOutcome[O], error),
	compare func(context.Context, PairOutcome[C, O]) error,
) ([]PairOutcome[C, O], error) {
	if ctx == nil {
		return nil, errors.New("execution context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	workers, err := validateTwoPassPlan(plan)
	if err != nil {
		return nil, err
	}
	if capture == nil {
		return nil, errors.New("two-pass capture callback is required")
	}

	first, err := executePass(ctx, workers, plan.Cells, 1, capture)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	second, err := executePass(ctx, workers, plan.Cells, 2, capture)
	if err != nil {
		return nil, err
	}

	pairs := make([]PairOutcome[C, O], len(plan.Cells))
	for index, cell := range plan.Cells {
		pairs[index] = PairOutcome[C, O]{
			Cell:     cell,
			Outcomes: [2]AttemptOutcome[O]{first[index], second[index]},
		}
	}
	if compare == nil {
		return pairs, nil
	}
	for _, pair := range pairs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := compare(ctx, pair); err != nil {
			return nil, fmt.Errorf("compare cell %q: %w", pair.Cell.Key, err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return pairs, nil
}

func validateTwoPassPlan[C any](plan TwoPassPlan[C]) (int, error) {
	if len(plan.Cells) == 0 {
		return 0, errors.New("two-pass plan must contain at least one cell")
	}
	if len(plan.Cells) > MaxTwoPassCells {
		return 0, fmt.Errorf("two-pass plan exceeds %d cells", MaxTwoPassCells)
	}
	keys := make(map[string]struct{}, len(plan.Cells))
	for _, cell := range plan.Cells {
		if err := ValidateTwoPassCellKey(cell.Key); err != nil {
			return 0, err
		}
		if _, exists := keys[cell.Key]; exists {
			return 0, fmt.Errorf("two-pass cell key %q is duplicated", cell.Key)
		}
		keys[cell.Key] = struct{}{}
	}
	workers := plan.Workers
	if workers == 0 {
		workers = DefaultTwoPassWorkers
	}
	if workers < 1 || workers > MaxTwoPassWorkers {
		return 0, fmt.Errorf("two-pass worker count must be between 1 and %d", MaxTwoPassWorkers)
	}
	if workers > len(plan.Cells) {
		workers = len(plan.Cells)
	}
	return workers, nil
}

// ValidateTwoPassCellKey verifies one bounded opaque stable cell identity.
func ValidateTwoPassCellKey(key string) error {
	if key == "" || key != strings.TrimSpace(key) || len(key) > MaxTwoPassCellKeyBytes || !utf8.ValidString(key) {
		return fmt.Errorf("two-pass cell key %q is unsafe", key)
	}
	for _, character := range key {
		if unicode.IsControl(character) {
			return fmt.Errorf("two-pass cell key %q is unsafe", key)
		}
	}
	return nil
}

type twoPassJob[C any] struct {
	index   int
	attempt Attempt[C]
}

func executePass[C any, O any](
	ctx context.Context,
	workers int,
	cells []PlanCell[C],
	repetition int,
	capture func(context.Context, Attempt[C]) (AttemptOutcome[O], error),
) ([]AttemptOutcome[O], error) {
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()

	outcomes := make([]AttemptOutcome[O], len(cells))
	jobs := make(chan twoPassJob[C])
	var waitGroup sync.WaitGroup
	var errorLock sync.Mutex
	var firstError error
	recordError := func(err error) {
		errorLock.Lock()
		if firstError == nil {
			firstError = err
			cancel()
		}
		errorLock.Unlock()
	}
	for range workers {
		waitGroup.Go(func() {
			for {
				select {
				case <-runContext.Done():
					return
				case job, open := <-jobs:
					if !open {
						return
					}
					if err := runContext.Err(); err != nil {
						return
					}
					outcome, err := capture(runContext, job.attempt)
					if err != nil {
						recordError(fmt.Errorf("capture cell %q repetition %d: %w", job.attempt.Address.CellKey, repetition, err))
						return
					}
					if outcome.Address != job.attempt.Address {
						recordError(fmt.Errorf("capture cell %q repetition %d returned a mismatched attempt address", job.attempt.Address.CellKey, repetition))
						return
					}
					outcomes[job.index] = outcome
				}
			}
		})
	}

	for index, cell := range cells {
		job := twoPassJob[C]{
			index: index,
			attempt: Attempt[C]{
				Address: AttemptAddress{CellKey: cell.Key, Repetition: repetition},
				Cell:    cell.Cell,
			},
		}
		select {
		case <-runContext.Done():
			close(jobs)
			waitGroup.Wait()
			return nil, passError(ctx, &errorLock, &firstError)
		case jobs <- job:
		}
	}
	close(jobs)
	waitGroup.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	errorLock.Lock()
	err := firstError
	errorLock.Unlock()
	if err != nil {
		return nil, err
	}
	return outcomes, nil
}

func passError(ctx context.Context, errorLock *sync.Mutex, firstError *error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	errorLock.Lock()
	err := *firstError
	errorLock.Unlock()
	if err != nil {
		return err
	}
	return errors.New("two-pass execution stopped")
}
