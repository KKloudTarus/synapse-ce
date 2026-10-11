package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CloudRunStore persists the tenant-scoped CSPM lifecycle under RLS.
type CloudRunStore struct{ pool *pgxpool.Pool }

var _ ports.CloudRunStore = (*CloudRunStore)(nil)
var _ ports.CloudRunEnqueuer = (*CloudRunStore)(nil)

func NewCloudRunStore(pool *pgxpool.Pool) *CloudRunStore { return &CloudRunStore{pool: pool} }

func (s *CloudRunStore) SaveCloudRun(ctx context.Context, run cloudposture.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	coverage, err := json.Marshal(run.CoverageIssues)
	if err != nil {
		return fmt.Errorf("marshal CSPM coverage: %w", err)
	}
	evidenceRefs, err := json.Marshal(run.EvidenceRefs)
	if err != nil {
		return fmt.Errorf("marshal CSPM evidence refs: %w", err)
	}
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		var prior, storedEngagement string
		var storedProviders []byte
		err := tx.QueryRow(ctx, `SELECT status,engagement_id,providers FROM cspm_runs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, run.TenantID.String(), run.ID.String()).Scan(&prior, &storedEngagement, &storedProviders)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil && storedEngagement != run.EngagementID.String() {
			return fmt.Errorf("%w: CSPM run engagement does not match stored run", shared.ErrValidation)
		}
		providers := []string(nil)
		if len(storedProviders) != 0 && err == nil {
			if err := json.Unmarshal(storedProviders, &providers); err != nil {
				return fmt.Errorf("decode CSPM run providers: %w", err)
			}
		}
		if len(providers) == 0 {
			var providerErr error
			providers, providerErr = cloudRunProvidersFromJob(ctx, tx, run.TenantID, run.ID)
			if providerErr != nil {
				return providerErr
			}
		}
		if providers == nil {
			providers = []string{}
		}
		for _, provider := range providers {
			if !cloudposture.Provider(provider).Valid() {
				return fmt.Errorf("%w: stored CSPM run has invalid provider", shared.ErrValidation)
			}
		}
		providersJSON, err := json.Marshal(providers)
		if err != nil {
			return fmt.Errorf("marshal CSPM run providers: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO cspm_runs
			(tenant_id,id,engagement_id,actor,status,complete,assets,findings,coverage,error_code,evidence_refs,providers,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			ON CONFLICT (tenant_id,id) DO UPDATE SET status=EXCLUDED.status, complete=EXCLUDED.complete,
			assets=EXCLUDED.assets, findings=EXCLUDED.findings, coverage=EXCLUDED.coverage,
			error_code=EXCLUDED.error_code, evidence_refs=EXCLUDED.evidence_refs,
			providers=CASE WHEN jsonb_array_length(cspm_runs.providers)=0 THEN EXCLUDED.providers ELSE cspm_runs.providers END,
			finished_at=EXCLUDED.finished_at`,
			run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.Actor, string(run.Status), run.Complete,
			run.Assets, run.Findings, coverage, run.ErrorCode, evidenceRefs, providersJSON, run.StartedAt, run.FinishedAt)
		if err != nil {
			return err
		}
		if run.Status.Terminal() && !cloudposture.RunStatus(prior).Terminal() {
			return appendCSPMRunNotification(ctx, tx, run, providers)
		}
		return nil
	})
}

func appendCSPMRunNotification(ctx context.Context, tx pgx.Tx, run cloudposture.Run, providers []string) error {
	return appendRunFinishedNotification(ctx, tx, run.TenantID, run.EngagementID, notification.EventCSPMRunFinished,
		"cspm_run", run.ID.String(), "cspm", string(run.Status), providers, "", run.ErrorCode, run.Findings, *run.FinishedAt)
}

func (s *CloudRunStore) EnqueueCloudRun(ctx context.Context, run cloudposture.Run, kind string, payload []byte) error {
	if err := run.Validate(); err != nil {
		return err
	}
	coverage, err := json.Marshal(run.CoverageIssues)
	if err != nil {
		return err
	}
	evidenceRefs, err := json.Marshal(run.EvidenceRefs)
	if err != nil {
		return err
	}
	providers, err := cloudRunProvidersFromPayload(payload)
	if err != nil {
		return err
	}
	providersJSON, err := json.Marshal(providers)
	if err != nil {
		return fmt.Errorf("marshal CSPM providers: %w", err)
	}
	jobID := run.ID.String() + "-job"
	return WithTenant(ctx, s.pool, run.TenantID.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO cspm_runs
			(tenant_id,id,engagement_id,actor,status,complete,assets,findings,coverage,error_code,evidence_refs,providers,started_at,finished_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, run.TenantID.String(), run.ID.String(), run.EngagementID.String(), run.Actor, string(run.Status), run.Complete, run.Assets, run.Findings, coverage, run.ErrorCode, evidenceRefs, providersJSON, run.StartedAt, run.FinishedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO jobs (id,tenant_id,kind,payload,status,available_at) VALUES ($1,$2,$3,$4,'queued',now())`, jobID, run.TenantID.String(), kind, payload)
		return err
	})
}

type cloudRunJobPayload struct {
	Scopes []struct {
		Provider cloudposture.Provider `json:"provider"`
	} `json:"scopes"`
}

func cloudRunProvidersFromPayload(payload []byte) ([]string, error) {
	var job cloudRunJobPayload
	if err := json.Unmarshal(payload, &job); err != nil {
		return nil, fmt.Errorf("decode CSPM job providers: %w", err)
	}
	providers := make([]string, 0, len(job.Scopes))
	for _, scope := range job.Scopes {
		if !scope.Provider.Valid() {
			return nil, fmt.Errorf("%w: CSPM job has invalid provider", shared.ErrValidation)
		}
		providers = append(providers, string(scope.Provider))
	}
	providers = canonicalCloudProviders(providers)
	if len(providers) == 0 {
		return nil, fmt.Errorf("%w: CSPM job has no providers", shared.ErrValidation)
	}
	return providers, nil
}

func cloudRunProvidersFromJob(ctx context.Context, tx pgx.Tx, tenantID, runID shared.ID) ([]string, error) {
	var payload []byte
	err := tx.QueryRow(ctx, `SELECT payload FROM jobs WHERE tenant_id=$1 AND id=$2`, tenantID, runID.String()+"-job").Scan(&payload)
	if err == pgx.ErrNoRows {
		return nil, nil // a pre-snapshot job may already have been retained away
	}
	if err != nil {
		return nil, fmt.Errorf("read CSPM job providers: %w", err)
	}
	return cloudRunProvidersFromPayload(payload)
}

func canonicalCloudProviders(providers []string) []string {
	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		seen[provider] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for provider := range seen {
		out = append(out, provider)
	}
	sort.Strings(out)
	return out
}

func (s *CloudRunStore) GetCloudRun(ctx context.Context, tenantID, id shared.ID) (out cloudposture.Run, err error) {
	err = WithTenant(ctx, s.pool, tenantID.String(), func(tx pgx.Tx) error {
		var status string
		var coverage, evidenceRefs []byte
		err := tx.QueryRow(ctx, `SELECT id,tenant_id,engagement_id,actor,status,complete,assets,findings,coverage,error_code,evidence_refs,started_at,finished_at
			FROM cspm_runs WHERE tenant_id=$1 AND id=$2`, tenantID.String(), id.String()).Scan(
			&out.ID, &out.TenantID, &out.EngagementID, &out.Actor, &status, &out.Complete, &out.Assets, &out.Findings,
			&coverage, &out.ErrorCode, &evidenceRefs, &out.StartedAt, &out.FinishedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				return fmt.Errorf("%w: CSPM run", shared.ErrNotFound)
			}
			return err
		}
		out.Status = cloudposture.RunStatus(status)
		if err := json.Unmarshal(coverage, &out.CoverageIssues); err != nil {
			return err
		}
		return json.Unmarshal(evidenceRefs, &out.EvidenceRefs)
	})
	if err != nil {
		return cloudposture.Run{}, fmt.Errorf("get CSPM run: %w", err)
	}
	return out, nil
}
