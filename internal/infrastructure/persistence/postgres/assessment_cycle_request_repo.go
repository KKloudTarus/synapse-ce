package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxAssessmentCycleResponseBytes = 2 << 20

type AssessmentCycleRequestRepository struct{ pool *pgxpool.Pool }

func NewAssessmentCycleRequestRepository(pool *pgxpool.Pool) *AssessmentCycleRequestRepository {
	return &AssessmentCycleRequestRepository{pool: pool}
}

var _ ports.AssessmentCycleRequestStore = (*AssessmentCycleRequestRepository)(nil)

func (repository *AssessmentCycleRequestRepository) BeginAssessmentCycleRequest(ctx context.Context, request ports.AssessmentCycleRequest) (ports.AssessmentCycleRequest, bool, error) {
	if err := validatePostgresAssessmentCycleRequest(request); err != nil {
		return ports.AssessmentCycleRequest{}, false, err
	}
	tenantID := shared.TenantOrDefault(request.Scope.TenantID)
	var stored ports.AssessmentCycleRequest
	created := false
	err := WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO assessment_cycle_api_requests
			(tenant_id, actor, route, idempotency_key, request_hash, created_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (tenant_id, actor, route, idempotency_key) DO NOTHING`,
			tenantID.String(), request.Scope.Actor, request.Scope.Route, request.Scope.IdempotencyKey, request.RequestHash, request.CreatedAt.UTC())
		if err != nil {
			return fmt.Errorf("reserve assessment cycle request: %w", err)
		}
		if tag.RowsAffected() == 1 {
			stored, created = clonePostgresAssessmentCycleRequest(request), true
			return nil
		}
		loaded, err := scanAssessmentCycleRequest(tx.QueryRow(ctx, `SELECT tenant_id, actor, route, idempotency_key, request_hash,
			status_code, response_body, created_at, completed_at
			FROM assessment_cycle_api_requests
			WHERE tenant_id=$1 AND actor=$2 AND route=$3 AND idempotency_key=$4`,
			tenantID.String(), request.Scope.Actor, request.Scope.Route, request.Scope.IdempotencyKey))
		if err != nil {
			return err
		}
		stored = loaded
		return nil
	})
	return stored, created, err
}

func (repository *AssessmentCycleRequestRepository) CompleteAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, requestHash string, statusCode int, responseBody []byte, completedAt time.Time) error {
	if err := validatePostgresAssessmentCycleRequest(ports.AssessmentCycleRequest{Scope: scope, RequestHash: requestHash, CreatedAt: completedAt}); err != nil || statusCode < 200 || statusCode > 599 || len(responseBody) == 0 || len(responseBody) > maxAssessmentCycleResponseBytes {
		return fmt.Errorf("%w: assessment cycle request completion is invalid", shared.ErrValidation)
	}
	tenantID := shared.TenantOrDefault(scope.TenantID)
	return WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE assessment_cycle_api_requests
			SET status_code=$6, response_body=$7, completed_at=$8
			WHERE tenant_id=$1 AND actor=$2 AND route=$3 AND idempotency_key=$4
			  AND request_hash=$5 AND completed_at IS NULL`, tenantID.String(), scope.Actor, scope.Route, scope.IdempotencyKey, requestHash, statusCode, responseBody, completedAt.UTC())
		if err != nil {
			return fmt.Errorf("complete assessment cycle request: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: assessment cycle request completion conflict", shared.ErrConflict)
		}
		return nil
	})
}

func (repository *AssessmentCycleRequestRepository) AbortAssessmentCycleRequest(ctx context.Context, scope ports.AssessmentCycleRequestScope, requestHash string) error {
	tenantID := shared.TenantOrDefault(scope.TenantID)
	if tenantID.IsZero() || strings.TrimSpace(scope.Actor) == "" || strings.TrimSpace(scope.Route) == "" || strings.TrimSpace(scope.IdempotencyKey) == "" || len(requestHash) != 64 {
		return fmt.Errorf("%w: assessment cycle request abort is invalid", shared.ErrValidation)
	}
	return WithTenant(ctx, repository.pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM assessment_cycle_api_requests
			WHERE tenant_id=$1 AND actor=$2 AND route=$3 AND idempotency_key=$4
			  AND request_hash=$5 AND completed_at IS NULL`, tenantID.String(), scope.Actor, scope.Route, scope.IdempotencyKey, requestHash)
		return err
	})
}

func scanAssessmentCycleRequest(row rowScanner) (ports.AssessmentCycleRequest, error) {
	var (
		request     ports.AssessmentCycleRequest
		statusCode  pgtype.Int4
		completedAt pgtype.Timestamptz
	)
	if err := row.Scan(&request.Scope.TenantID, &request.Scope.Actor, &request.Scope.Route, &request.Scope.IdempotencyKey,
		&request.RequestHash, &statusCode, &request.ResponseBody, &request.CreatedAt, &completedAt); err != nil {
		return ports.AssessmentCycleRequest{}, fmt.Errorf("scan assessment cycle request: %w", err)
	}
	if statusCode.Valid {
		request.StatusCode = int(statusCode.Int32)
	}
	if completedAt.Valid {
		value := completedAt.Time.UTC()
		request.CompletedAt = &value
	}
	return request, nil
}

func validatePostgresAssessmentCycleRequest(request ports.AssessmentCycleRequest) error {
	if shared.TenantOrDefault(request.Scope.TenantID).IsZero() || strings.TrimSpace(request.Scope.Actor) == "" || len(request.Scope.Actor) > 256 || strings.TrimSpace(request.Scope.Route) == "" || len(request.Scope.Route) > 256 || strings.TrimSpace(request.Scope.IdempotencyKey) == "" || len(request.Scope.IdempotencyKey) > 128 || len(request.RequestHash) != 64 || request.CreatedAt.IsZero() {
		return fmt.Errorf("%w: assessment cycle idempotency request is invalid", shared.ErrValidation)
	}
	return nil
}

func clonePostgresAssessmentCycleRequest(request ports.AssessmentCycleRequest) ports.AssessmentCycleRequest {
	request.ResponseBody = append([]byte(nil), request.ResponseBody...)
	return request
}
