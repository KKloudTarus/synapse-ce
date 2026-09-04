package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var ErrOperationBudgetExceeded = errors.New("integration operation budget exceeded")

type operationBudgetContextKey struct{}

type operationBudget struct {
	mu          sync.Mutex
	requests    int
	bytes       int64
	maxRequests int
	maxBytes    int64
}

// WithOperationBudget attaches an aggregate provider request/response budget to
// every adapter call made for one integration operation.
func WithOperationBudget(ctx context.Context, maxRequests int, maxBytes int64) context.Context {
	return context.WithValue(ctx, operationBudgetContextKey{}, &operationBudget{maxRequests: maxRequests, maxBytes: maxBytes})
}

func ConsumeOperationRequest(ctx context.Context) error {
	budget, _ := ctx.Value(operationBudgetContextKey{}).(*operationBudget)
	if budget == nil {
		return nil
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.maxRequests <= 0 || budget.requests >= budget.maxRequests {
		return fmt.Errorf("%w: request limit reached", ErrOperationBudgetExceeded)
	}
	budget.requests++
	return nil
}

func ConsumeOperationBytes(ctx context.Context, count int64) error {
	budget, _ := ctx.Value(operationBudgetContextKey{}).(*operationBudget)
	if budget == nil {
		return nil
	}
	if count < 0 {
		return fmt.Errorf("%w: invalid response size", ErrOperationBudgetExceeded)
	}
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.maxBytes <= 0 || count > budget.maxBytes-budget.bytes {
		return fmt.Errorf("%w: response byte limit reached", ErrOperationBudgetExceeded)
	}
	budget.bytes += count
	return nil
}
