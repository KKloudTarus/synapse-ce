package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentCycleRequestRepository struct {
	mu       sync.Mutex
	requests map[string]ports.AssessmentCycleRequest
}

func NewAssessmentCycleRequestRepository() *AssessmentCycleRequestRepository {
	return &AssessmentCycleRequestRepository{requests: map[string]ports.AssessmentCycleRequest{}}
}

var _ ports.AssessmentCycleRequestStore = (*AssessmentCycleRequestRepository)(nil)

func (repository *AssessmentCycleRequestRepository) BeginAssessmentCycleRequest(ctx context.Context, request ports.AssessmentCycleRequest) (ports.AssessmentCycleRequest, bool, error) {
	if request.ExpiresAt.IsZero() {
		request.ExpiresAt = request.CreatedAt.Add(24 * time.Hour)
	}
	if err := validateAssessmentCycleRequest(request); err != nil {
		return ports.AssessmentCycleRequest{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.registerRollback(ctx)
	for storedKey, stored := range repository.requests {
		if !stored.ExpiresAt.After(request.CreatedAt) {
			delete(repository.requests, storedKey)
		}
	}
	key := assessmentCycleRequestKey(request.Scope)
	if stored, exists := repository.requests[key]; exists {
		return cloneAssessmentCycleRequest(stored), false, nil
	}
	repository.requests[key] = cloneAssessmentCycleRequest(request)
	return cloneAssessmentCycleRequest(request), true, nil
}

func (repository *AssessmentCycleRequestRepository) CompleteAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, requestHash string, statusCode int, responseBody []byte, completedAt time.Time) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := assessmentCycleRequestKey(scope)
	stored, exists := repository.requests[key]
	if !exists {
		return fmt.Errorf("%w: assessment cycle request reservation not found", shared.ErrNotFound)
	}
	if stored.RequestHash != requestHash || stored.CompletedAt != nil {
		return fmt.Errorf("%w: assessment cycle request completion conflict", shared.ErrConflict)
	}
	repository.registerRollback(ctx)
	completedAt = completedAt.UTC()
	stored.StatusCode, stored.ResponseBody, stored.CompletedAt = statusCode, append([]byte(nil), responseBody...), &completedAt
	repository.requests[key] = stored
	return nil
}

func (repository *AssessmentCycleRequestRepository) AbortAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, requestHash string) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := assessmentCycleRequestKey(scope)
	stored, exists := repository.requests[key]
	if exists && stored.RequestHash == requestHash && stored.CompletedAt == nil {
		repository.registerRollback(ctx)
		delete(repository.requests, key)
	}
	return nil
}

func validateAssessmentCycleRequest(request ports.AssessmentCycleRequest) error {
	if shared.TenantOrDefault(request.Scope.TenantID).IsZero() || strings.TrimSpace(request.Scope.Actor) == "" || strings.TrimSpace(request.Scope.Route) == "" || strings.TrimSpace(request.Scope.IdempotencyKey) == "" || len(request.Scope.IdempotencyKey) > 128 || len(request.RequestHash) != 64 || request.CreatedAt.IsZero() || !request.ExpiresAt.After(request.CreatedAt) {
		return fmt.Errorf("%w: assessment cycle idempotency request is invalid", shared.ErrValidation)
	}
	return nil
}

func (repository *AssessmentCycleRequestRepository) registerRollback(ctx context.Context) {
	previous := make(map[string]ports.AssessmentCycleRequest, len(repository.requests))
	for key, request := range repository.requests {
		previous[key] = cloneAssessmentCycleRequest(request)
	}
	registerTenantRollback(ctx, func() {
		repository.mu.Lock()
		defer repository.mu.Unlock()
		repository.requests = previous
	})
}

func assessmentCycleRequestKey(scope ports.AssessmentCycleRequestScope) string {
	return strings.Join([]string{shared.TenantOrDefault(scope.TenantID).String(), scope.Actor, scope.Route, scope.IdempotencyKey}, "\x00")
}

func cloneAssessmentCycleRequest(request ports.AssessmentCycleRequest) ports.AssessmentCycleRequest {
	request.ResponseBody = append([]byte(nil), request.ResponseBody...)
	if request.CompletedAt != nil {
		completedAt := *request.CompletedAt
		request.CompletedAt = &completedAt
	}
	return request
}
