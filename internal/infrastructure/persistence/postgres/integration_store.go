package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type IntegrationStore struct {
	pool   *pgxpool.Pool
	cipher *vault.Cipher
}

func NewIntegrationStore(pool *pgxpool.Pool, cipher *vault.Cipher) *IntegrationStore {
	return &IntegrationStore{pool: pool, cipher: cipher}
}

var _ ports.IntegrationStore = (*IntegrationStore)(nil)
var _ ports.IntegrationAnalysisMatcher = (*IntegrationStore)(nil)

func (store *IntegrationStore) CreateIntegration(ctx context.Context, item integration.Integration, audit ports.AuditEntry) error {
	if err := item.Normalize(); err != nil {
		return err
	}
	return WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO integrations
			(id,tenant_id,provider,display_name,endpoint,config,allow_private_network,poll_interval_seconds,enabled,archived,version,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			item.ID.String(), item.TenantID.String(), string(item.Provider), item.Name, item.Endpoint, item.Config, item.AllowPrivateNetwork,
			int64(item.PollInterval/time.Second), item.Enabled, item.Archived, item.Version, item.CreatedAt.UTC(), item.UpdatedAt.UTC())
		if integrationConflict(err) {
			return shared.ErrConflict
		}
		if err != nil {
			return fmt.Errorf("create integration: %w", err)
		}
		return appendTenantAudit(ctx, tx, item.TenantID.String(), audit)
	})
}

func (store *IntegrationStore) ListIntegrations(ctx context.Context, includeArchived bool) (items []integration.Integration, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, integrationSelect+` WHERE ($1 OR archived=FALSE) ORDER BY display_name COLLATE "C",id COLLATE "C"`, includeArchived)
		if queryErr != nil {
			return fmt.Errorf("list integrations: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			item, scanErr := scanIntegration(rows)
			if scanErr != nil {
				return scanErr
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

func (store *IntegrationStore) GetIntegration(ctx context.Context, id shared.ID) (item integration.Integration, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		var scanErr error
		item, scanErr = scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1`, id.String()))
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("get integration: %w", scanErr)
		}
		return nil
	})
	return item, err
}

func (store *IntegrationStore) UpdateIntegration(ctx context.Context, item integration.Integration, expectedVersion int, audit ports.AuditEntry) (updated integration.Integration, err error) {
	if err := item.Normalize(); err != nil {
		return integration.Integration{}, err
	}
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		current, loadErr := scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1 FOR UPDATE`, item.ID.String()))
		if errors.Is(loadErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if loadErr != nil {
			return fmt.Errorf("lock integration for update: %w", loadErr)
		}
		if current.Archived || current.Version != expectedVersion {
			return shared.ErrConflict
		}
		material := current.Endpoint != item.Endpoint || string(current.Config) != string(item.Config) || current.AllowPrivateNetwork != item.AllowPrivateNetwork
		originChanged := current.Endpoint != item.Endpoint
		enabled, connectionRevision, credentialRevision := current.Enabled, current.ConnectionRevision, current.CredentialRevision
		if material {
			if err := invalidateIntegrationOperations(ctx, tx, item.ID, time.Now().UTC()); err != nil {
				return err
			}
			enabled = false
			connectionRevision++
			if originChanged {
				if _, err := tx.Exec(ctx, `DELETE FROM integration_credentials WHERE integration_id=$1`, item.ID.String()); err != nil {
					return fmt.Errorf("invalidate credentials after integration origin change: %w", err)
				}
				credentialRevision++
			}
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE integrations SET display_name=$2,endpoint=$3,config=$4,allow_private_network=$5,poll_interval_seconds=$6,enabled=$7,connection_revision=$8,credential_revision=$9,version=version+1,updated_at=now()
			WHERE id=$1 AND version=$10 AND archived=FALSE`, item.ID.String(), item.Name, item.Endpoint, item.Config, item.AllowPrivateNetwork, int64(item.PollInterval/time.Second), enabled, connectionRevision, credentialRevision, expectedVersion)
		if integrationConflict(updateErr) {
			return shared.ErrConflict
		}
		if updateErr != nil {
			return fmt.Errorf("update integration: %w", updateErr)
		}
		if tag.RowsAffected() == 0 {
			return classifyIntegrationMiss(ctx, tx, item.ID, expectedVersion)
		}
		var scanErr error
		updated, scanErr = scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1`, item.ID.String()))
		if scanErr != nil {
			return scanErr
		}
		return appendTenantAudit(ctx, tx, item.TenantID.String(), audit)
	})
	return updated, err
}

func (store *IntegrationStore) SetIntegrationEnabled(ctx context.Context, id shared.ID, enabled bool, expectedVersion int, audit ports.AuditEntry) (updated integration.Integration, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		tag, updateErr := tx.Exec(ctx, `UPDATE integrations AS target SET enabled=$2,version=version+1,updated_at=now()
			WHERE target.id=$1 AND target.version=$3 AND target.archived=FALSE AND (NOT $2 OR (
				EXISTS(SELECT 1 FROM integration_credentials credential WHERE credential.integration_id=target.id AND credential.credential_id='default')
				AND EXISTS(SELECT 1 FROM integration_operations operation WHERE operation.integration_id=target.id AND operation.operation_type='test'
					AND operation.state='succeeded' AND operation.connection_revision=target.connection_revision AND operation.credential_revision=target.credential_revision)
			))`, id.String(), enabled, expectedVersion)
		if updateErr != nil {
			return fmt.Errorf("set integration enabled: %w", updateErr)
		}
		if tag.RowsAffected() == 0 {
			return classifyIntegrationMiss(ctx, tx, id, expectedVersion)
		}
		var scanErr error
		updated, scanErr = scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1`, id.String()))
		if scanErr != nil {
			return scanErr
		}
		return appendTenantAudit(ctx, tx, updated.TenantID.String(), audit)
	})
	return updated, err
}

func (store *IntegrationStore) ArchiveIntegration(ctx context.Context, id shared.ID, expectedVersion int, audit ports.AuditEntry) error {
	return WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		current, loadErr := scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1 FOR UPDATE`, id.String()))
		if errors.Is(loadErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if loadErr != nil {
			return fmt.Errorf("lock integration for archive: %w", loadErr)
		}
		if current.Archived || current.Version != expectedVersion {
			return shared.ErrConflict
		}
		if err := invalidateIntegrationOperations(ctx, tx, id, time.Now().UTC()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM integration_credentials WHERE integration_id=$1`, id.String()); err != nil {
			return fmt.Errorf("delete archived integration credentials: %w", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE integrations SET enabled=FALSE,archived=TRUE,version=version+1,updated_at=now() WHERE id=$1 AND version=$2 AND archived=FALSE`, id.String(), expectedVersion)
		if err != nil {
			return fmt.Errorf("archive integration: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return classifyIntegrationMiss(ctx, tx, id, expectedVersion)
		}
		return appendTenantAudit(ctx, tx, current.TenantID.String(), audit)
	})
}

func (store *IntegrationStore) PutIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, plaintext []byte, expectedVersion, expectedConnectionRevision int, audit ports.AuditEntry) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || credentialID == "" || len(plaintext) == 0 || len(plaintext) > integration.MaxCredentialBytes {
		return fmt.Errorf("%w: integration credential is invalid", shared.ErrValidation)
	}
	ciphertext, err := store.cipher.Seal(plaintext, integrationCredentialAAD(tenantID, integrationID, credentialID))
	if err != nil {
		return err
	}
	return WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		item, lockErr := scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1 FOR UPDATE`, integrationID.String()))
		if errors.Is(lockErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if lockErr != nil {
			return fmt.Errorf("lock integration for credential change: %w", lockErr)
		}
		if item.Archived || item.Version != expectedVersion || item.ConnectionRevision != expectedConnectionRevision {
			return shared.ErrConflict
		}
		if err := invalidateIntegrationOperations(ctx, tx, integrationID, time.Now().UTC()); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE integrations SET enabled=FALSE,credential_revision=credential_revision+1,version=version+1,updated_at=now() WHERE id=$1 AND version=$2 AND connection_revision=$3 AND archived=FALSE`, integrationID.String(), expectedVersion, expectedConnectionRevision)
		if err != nil {
			return fmt.Errorf("invalidate integration after credential change: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		_, err = tx.Exec(ctx, `INSERT INTO integration_credentials(tenant_id,integration_id,credential_id,ciphertext,created_at,updated_at)
			VALUES($1,$2,$3,$4,now(),now()) ON CONFLICT(tenant_id,integration_id,credential_id)
			DO UPDATE SET ciphertext=EXCLUDED.ciphertext,updated_at=now()`, tenantID.String(), integrationID.String(), credentialID, ciphertext)
		if err != nil {
			return fmt.Errorf("put integration credential: %w", err)
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), audit)
	})
}

func (store *IntegrationStore) DeleteIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, expectedVersion, expectedConnectionRevision int, audit ports.AuditEntry) error {
	return WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		item, lockErr := scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1 FOR UPDATE`, integrationID.String()))
		if errors.Is(lockErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if lockErr != nil {
			return fmt.Errorf("lock integration for credential deletion: %w", lockErr)
		}
		if item.Archived || item.Version != expectedVersion || item.ConnectionRevision != expectedConnectionRevision {
			return shared.ErrConflict
		}
		if err := invalidateIntegrationOperations(ctx, tx, integrationID, time.Now().UTC()); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM integration_credentials WHERE integration_id=$1 AND credential_id=$2`, integrationID.String(), credentialID)
		if err != nil {
			return fmt.Errorf("delete integration credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		tag, err = tx.Exec(ctx, `UPDATE integrations SET enabled=FALSE,credential_revision=credential_revision+1,version=version+1,updated_at=now() WHERE id=$1 AND version=$2 AND connection_revision=$3 AND archived=FALSE`, integrationID.String(), expectedVersion, expectedConnectionRevision)
		if err != nil {
			return fmt.Errorf("invalidate integration after credential deletion: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return appendTenantAudit(ctx, tx, item.TenantID.String(), audit)
	})
}

func (store *IntegrationStore) ResolveIntegrationCredential(ctx context.Context, integrationID shared.ID, credentialID string, expectedRevision int) (plaintext []byte, err error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	var ciphertext string
	var currentRevision int
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		queryErr := tx.QueryRow(ctx, `SELECT credential.ciphertext,target.credential_revision FROM integration_credentials credential
			JOIN integrations target ON target.tenant_id=credential.tenant_id AND target.id=credential.integration_id
			WHERE credential.integration_id=$1 AND credential.credential_id=$2`, integrationID.String(), credentialID).Scan(&ciphertext, &currentRevision)
		if errors.Is(queryErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return queryErr
	})
	if err != nil {
		return nil, err
	}
	if currentRevision != expectedRevision {
		return nil, shared.ErrConflict
	}
	return store.cipher.Open(ciphertext, integrationCredentialAAD(tenantID, integrationID, credentialID))
}

func (store *IntegrationStore) IntegrationCredentialConfigured(ctx context.Context, integrationID shared.ID, credentialID string) (configured bool, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM integration_credentials WHERE integration_id=$1 AND credential_id=$2)`, integrationID.String(), credentialID).Scan(&configured)
	})
	return configured, err
}

func (store *IntegrationStore) CreateIntegrationBinding(ctx context.Context, binding integration.Binding, audit ports.AuditEntry) error {
	if err := binding.Normalize(); err != nil {
		return err
	}
	return WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		var archived bool
		if err := tx.QueryRow(ctx, `SELECT archived FROM integrations WHERE id=$1 FOR SHARE`, binding.IntegrationID.String()).Scan(&archived); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock integration for binding creation: %w", err)
		}
		if archived {
			return shared.ErrConflict
		}
		_, err := tx.Exec(ctx, `INSERT INTO integration_bindings(id,tenant_id,integration_id,project_id,external_key,external_name,version,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, binding.ID.String(), binding.TenantID.String(), binding.IntegrationID.String(), binding.ProjectID.String(), binding.ExternalKey, binding.ExternalName, binding.Version, binding.CreatedAt.UTC(), binding.UpdatedAt.UTC())
		if integrationConflict(err) {
			return shared.ErrConflict
		}
		if err != nil {
			return fmt.Errorf("create integration binding: %w", err)
		}
		return appendTenantAudit(ctx, tx, binding.TenantID.String(), audit)
	})
}

func (store *IntegrationStore) ListIntegrationBindings(ctx context.Context, integrationID shared.ID) (bindings []integration.Binding, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, `SELECT id,tenant_id,integration_id,project_id,external_key,external_name,version,created_at,updated_at FROM integration_bindings WHERE integration_id=$1 ORDER BY external_name COLLATE "C",id COLLATE "C"`, integrationID.String())
		if queryErr != nil {
			return fmt.Errorf("list integration bindings: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			var binding integration.Binding
			if scanErr := rows.Scan(&binding.ID, &binding.TenantID, &binding.IntegrationID, &binding.ProjectID, &binding.ExternalKey, &binding.ExternalName, &binding.Version, &binding.CreatedAt, &binding.UpdatedAt); scanErr != nil {
				return fmt.Errorf("scan integration binding: %w", scanErr)
			}
			bindings = append(bindings, binding)
		}
		return rows.Err()
	})
	return bindings, err
}

func (store *IntegrationStore) DeleteIntegrationBinding(ctx context.Context, integrationID, bindingID shared.ID, audit ports.AuditEntry) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM integration_bindings WHERE id=$1 AND integration_id=$2`, bindingID.String(), integrationID.String())
		if err != nil {
			return fmt.Errorf("delete integration binding: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrNotFound
		}
		return appendTenantAudit(ctx, tx, tenantID.String(), audit)
	})
}

func (store *IntegrationStore) StartIntegrationOperation(ctx context.Context, operation integration.Operation, jobKind string, payload []byte, audit ports.AuditEntry) (integration.Operation, error) {
	if operation.ID.IsZero() || operation.JobID == "" || operation.IntegrationID.IsZero() || operation.State != integration.OperationQueued || !operation.Type.Valid() || jobKind == "" {
		return integration.Operation{}, fmt.Errorf("%w: integration operation is invalid", shared.ErrValidation)
	}
	counts, _ := json.Marshal(operation.Counts)
	errorsJSON, _ := json.Marshal([]string{})
	pipelines, _ := json.Marshal([]integration.Pipeline{})
	err := WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		var connectionRevision, credentialRevision int
		var archived, enabled bool
		if err := tx.QueryRow(ctx, `SELECT connection_revision,credential_revision,archived,enabled FROM integrations WHERE id=$1 FOR SHARE`, operation.IntegrationID.String()).Scan(&connectionRevision, &credentialRevision, &archived, &enabled); errors.Is(err, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock integration operation revision: %w", err)
		}
		if archived || connectionRevision != operation.ConnectionRevision || credentialRevision != operation.CredentialRevision || (operation.Type == integration.OperationPoll && !enabled) {
			return shared.ErrConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,$3,$4,'queued',now())`, operation.JobID, operation.TenantID.String(), jobKind, payload); err != nil {
			return fmt.Errorf("enqueue integration operation: %w", err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO integration_operations
			(id,tenant_id,integration_id,operation_type,state,checkpoint,counts,errors,pipelines,job_id,actor,connection_revision,credential_revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, operation.ID.String(), operation.TenantID.String(), operation.IntegrationID.String(), string(operation.Type), string(operation.State), operation.Checkpoint, counts, errorsJSON, pipelines, operation.JobID, operation.Actor, operation.ConnectionRevision, operation.CredentialRevision, operation.CreatedAt.UTC(), operation.UpdatedAt.UTC())
		if integrationConflict(err) {
			return shared.ErrConflict
		}
		if err != nil {
			return fmt.Errorf("create integration operation: %w", err)
		}
		return appendTenantAudit(ctx, tx, operation.TenantID.String(), audit)
	})
	return operation, err
}

func (store *IntegrationStore) GetIntegrationOperation(ctx context.Context, id shared.ID) (operation integration.Operation, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		var scanErr error
		operation, scanErr = scanIntegrationOperation(tx.QueryRow(ctx, integrationOperationSelect+` WHERE id=$1`, id.String()))
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		return scanErr
	})
	return operation, err
}

func (store *IntegrationStore) ListIntegrationOperations(ctx context.Context, integrationID shared.ID, limit int) (operations []integration.Operation, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, integrationOperationSelect+` WHERE integration_id=$1 ORDER BY created_at DESC,id COLLATE "C" DESC LIMIT $2`, integrationID.String(), limit)
		if queryErr != nil {
			return fmt.Errorf("list integration operations: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			operation, scanErr := scanIntegrationOperation(rows)
			if scanErr != nil {
				return scanErr
			}
			operations = append(operations, operation)
		}
		return rows.Err()
	})
	return operations, err
}

func (store *IntegrationStore) BeginIntegrationOperation(ctx context.Context, id shared.ID, startedAt time.Time) (operation integration.Operation, execute bool, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		current, scanErr := scanIntegrationOperation(tx.QueryRow(ctx, integrationOperationSelect+` WHERE id=$1 FOR UPDATE`, id.String()))
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		if current.State.Terminal() {
			operation, execute = current, false
			return nil
		}
		if current.State == integration.OperationQueued {
			if _, updateErr := tx.Exec(ctx, `UPDATE integration_operations SET state='running',started_at=COALESCE(started_at,$2),updated_at=$2 WHERE id=$1`, id.String(), startedAt.UTC()); updateErr != nil {
				return fmt.Errorf("begin integration operation: %w", updateErr)
			}
			current.State = integration.OperationRunning
			current.StartedAt = &startedAt
			current.UpdatedAt = startedAt
		}
		operation, execute = current, true
		return nil
	})
	return operation, execute, err
}

func (store *IntegrationStore) FinishIntegrationOperation(ctx context.Context, id shared.ID, state integration.OperationState, checkpoint string, counts integration.OperationCounts, errorsIn []string, pipelines []integration.Pipeline, finishedAt time.Time) (operation integration.Operation, err error) {
	if !state.Terminal() || state == integration.OperationCancelled {
		return integration.Operation{}, fmt.Errorf("%w: terminal integration operation state is invalid", shared.ErrValidation)
	}
	if pipelines == nil {
		pipelines = []integration.Pipeline{}
	}
	countsJSON, _ := json.Marshal(counts)
	boundedErrors := integration.BoundedErrors(errorsIn)
	if boundedErrors == nil {
		boundedErrors = []string{}
	}
	errorsJSON, _ := json.Marshal(boundedErrors)
	pipelinesJSON, _ := json.Marshal(pipelines)
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		tag, updateErr := tx.Exec(ctx, `UPDATE integration_operations SET state=$2,checkpoint=$3,counts=$4,errors=$5,pipelines=$6,finished_at=$7,updated_at=$7 WHERE id=$1 AND state IN ('queued','running')`, id.String(), string(state), checkpoint, countsJSON, errorsJSON, pipelinesJSON, finishedAt.UTC())
		if updateErr != nil {
			return fmt.Errorf("finish integration operation: %w", updateErr)
		}
		var scanErr error
		operation, scanErr = scanIntegrationOperation(tx.QueryRow(ctx, integrationOperationSelect+` WHERE id=$1`, id.String()))
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		if tag.RowsAffected() == 0 && !operation.State.Terminal() {
			return shared.ErrConflict
		}
		return nil
	})
	return operation, err
}

func (store *IntegrationStore) FinishIntegrationPoll(ctx context.Context, id shared.ID, state integration.OperationState, checkpoint string, counts integration.OperationCounts, errorsIn []string, runs []integration.ExternalRun, finishedAt time.Time) (operation integration.Operation, err error) {
	if state != integration.OperationSucceeded && state != integration.OperationPartial {
		return integration.Operation{}, fmt.Errorf("%w: terminal poll state is invalid", shared.ErrValidation)
	}
	for index := range runs {
		if err := runs[index].Normalize(); err != nil {
			return integration.Operation{}, err
		}
	}
	countsJSON, _ := json.Marshal(counts)
	boundedErrors := integration.BoundedErrors(errorsIn)
	if boundedErrors == nil {
		boundedErrors = []string{}
	}
	errorsJSON, _ := json.Marshal(boundedErrors)
	emptyPipelines, _ := json.Marshal([]integration.Pipeline{})
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		var integrationID shared.ID
		if loadErr := tx.QueryRow(ctx, `SELECT integration_id FROM integration_operations WHERE id=$1`, id.String()).Scan(&integrationID); errors.Is(loadErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		} else if loadErr != nil {
			return fmt.Errorf("load integration poll fence: %w", loadErr)
		}
		item, lockErr := scanIntegration(tx.QueryRow(ctx, integrationSelect+` WHERE id=$1 FOR SHARE`, integrationID.String()))
		if errors.Is(lockErr, pgx.ErrNoRows) {
			return shared.ErrNotFound
		}
		if lockErr != nil {
			return fmt.Errorf("lock integration poll publication fence: %w", lockErr)
		}
		current, lockErr := scanIntegrationOperation(tx.QueryRow(ctx, integrationOperationSelect+` WHERE id=$1 FOR UPDATE`, id.String()))
		if lockErr != nil {
			return fmt.Errorf("lock integration poll operation: %w", lockErr)
		}
		if current.State != integration.OperationRunning || current.Type != integration.OperationPoll || item.Archived || !item.Enabled || item.ConnectionRevision != current.ConnectionRevision || item.CredentialRevision != current.CredentialRevision {
			return shared.ErrConflict
		}
		for _, run := range runs {
			if run.TenantID != current.TenantID || run.IntegrationID != integrationID {
				return fmt.Errorf("%w: external run integration mismatch", shared.ErrValidation)
			}
			if err := upsertIntegrationExternalRun(ctx, tx, run); err != nil {
				return err
			}
		}
		if _, updateErr := tx.Exec(ctx, `UPDATE integration_operations SET state=$2,checkpoint=$3,counts=$4,errors=$5,pipelines=$6,finished_at=$7,updated_at=$7 WHERE id=$1 AND state='running'`, id.String(), string(state), checkpoint, countsJSON, errorsJSON, emptyPipelines, finishedAt.UTC()); updateErr != nil {
			return fmt.Errorf("finish integration poll: %w", updateErr)
		}
		operation, lockErr = scanIntegrationOperation(tx.QueryRow(ctx, integrationOperationSelect+` WHERE id=$1`, id.String()))
		return lockErr
	})
	return operation, err
}

func (store *IntegrationStore) CancelIntegrationOperation(ctx context.Context, id shared.ID, finishedAt time.Time, audit ports.AuditEntry) (operation integration.Operation, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		if _, updateErr := tx.Exec(ctx, `UPDATE jobs SET status='done',claimed_until=NULL,claim_fence=claim_fence+1,updated_at=$2
			WHERE id=(SELECT job_id FROM integration_operations WHERE id=$1 AND state IN ('queued','running')) AND status IN ('queued','claimed')`, id.String(), finishedAt.UTC()); updateErr != nil {
			return fmt.Errorf("invalidate cancelled integration job: %w", updateErr)
		}
		tag, updateErr := tx.Exec(ctx, `UPDATE integration_operations SET state='cancelled',finished_at=$2,updated_at=$2 WHERE id=$1 AND state IN ('queued','running')`, id.String(), finishedAt.UTC())
		if updateErr != nil {
			return fmt.Errorf("cancel integration operation: %w", updateErr)
		}
		if tag.RowsAffected() == 0 {
			return shared.ErrConflict
		}
		var scanErr error
		operation, scanErr = scanIntegrationOperation(tx.QueryRow(ctx, integrationOperationSelect+` WHERE id=$1`, id.String()))
		if scanErr != nil {
			return scanErr
		}
		return appendTenantAudit(ctx, tx, operation.TenantID.String(), audit)
	})
	return operation, err
}

func (store *IntegrationStore) ListDueIntegrations(ctx context.Context, now time.Time, limit int) (items []integration.Integration, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, integrationSelect+` WHERE enabled=TRUE AND archived=FALSE
			AND NOT EXISTS(SELECT 1 FROM integration_operations active WHERE active.integration_id=integrations.id AND active.state IN ('queued','running'))
			AND COALESCE((SELECT max(done.updated_at) FROM integration_operations done WHERE done.integration_id=integrations.id AND done.operation_type='poll' AND done.state IN ('succeeded','partial','failed','cancelled')), '-infinity'::timestamptz)
				<= $1 - make_interval(secs=>poll_interval_seconds)
			ORDER BY updated_at,id COLLATE "C" LIMIT $2`, now.UTC(), limit)
		if queryErr != nil {
			return fmt.Errorf("list due integrations: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			item, scanErr := scanIntegration(rows)
			if scanErr != nil {
				return scanErr
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

func upsertIntegrationExternalRun(ctx context.Context, tx pgx.Tx, run integration.ExternalRun) error {
	_, err := tx.Exec(ctx, `INSERT INTO integration_external_runs
		(id,tenant_id,integration_id,binding_id,provider_key,pipeline_key,run_number,run_url,lifecycle,result,revision,branch,analysis_id,correlation,queued_at,started_at,finished_at,provider_updated_at,created_at,updated_at)
		VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,''),$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT(tenant_id,integration_id,provider_key) DO UPDATE SET
		binding_id=EXCLUDED.binding_id,pipeline_key=EXCLUDED.pipeline_key,run_number=EXCLUDED.run_number,run_url=EXCLUDED.run_url,lifecycle=EXCLUDED.lifecycle,
		result=EXCLUDED.result,revision=EXCLUDED.revision,branch=EXCLUDED.branch,analysis_id=EXCLUDED.analysis_id,correlation=EXCLUDED.correlation,
		queued_at=EXCLUDED.queued_at,started_at=EXCLUDED.started_at,finished_at=EXCLUDED.finished_at,provider_updated_at=EXCLUDED.provider_updated_at,updated_at=EXCLUDED.updated_at`,
		run.ID.String(), run.TenantID.String(), run.IntegrationID.String(), run.BindingID.String(), run.ProviderKey, run.PipelineKey, run.Number, run.URL, string(run.Lifecycle), string(run.Result), run.Revision, run.Branch, run.AnalysisID.String(), string(run.Correlation), run.QueuedAt, run.StartedAt, run.FinishedAt, run.ProviderUpdatedAt.UTC(), run.CreatedAt.UTC(), run.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("upsert integration external run: %w", err)
	}
	return nil
}

func (store *IntegrationStore) ListIntegrationExternalRuns(ctx context.Context, integrationID shared.ID, limit int) (runs []integration.ExternalRun, err error) {
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, integrationRunSelect+` WHERE integration_id=$1 ORDER BY provider_updated_at DESC,id COLLATE "C" DESC LIMIT $2`, integrationID.String(), limit)
		if queryErr != nil {
			return fmt.Errorf("list integration external runs: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			run, scanErr := scanIntegrationRun(rows)
			if scanErr != nil {
				return scanErr
			}
			runs = append(runs, run)
		}
		return rows.Err()
	})
	return runs, err
}

func (store *IntegrationStore) MatchIntegrationAnalysis(ctx context.Context, projectID shared.ID, revision string) (analysisID shared.ID, state integration.CorrelationState, err error) {
	tenantID, ok := shared.TenantFrom(ctx)
	revision = strings.TrimSpace(revision)
	if !ok || projectID.IsZero() || revision == "" {
		return "", integration.CorrelationMissing, nil
	}
	var matches []shared.ID
	err = WithContextTenant(ctx, store.pool, func(tx pgx.Tx) error {
		rows, queryErr := tx.Query(ctx, `SELECT id FROM project_analyses WHERE tenant_id=$1 AND project_id=$2
			AND ((payload->>'source_commit')=$3 OR (payload#>>'{source_revision,head}')=$3)
			ORDER BY created_at DESC,id COLLATE "C" DESC LIMIT 2`, tenantID.String(), projectID.String(), revision)
		if queryErr != nil {
			return fmt.Errorf("match integration analysis: %w", queryErr)
		}
		defer rows.Close()
		for rows.Next() {
			var id shared.ID
			if scanErr := rows.Scan(&id); scanErr != nil {
				return scanErr
			}
			matches = append(matches, id)
		}
		return rows.Err()
	})
	if err != nil {
		return "", "", err
	}
	switch len(matches) {
	case 0:
		return "", integration.CorrelationMissing, nil
	case 1:
		return matches[0], integration.CorrelationLinked, nil
	default:
		return "", integration.CorrelationAmbiguous, nil
	}
}

const integrationSelect = `SELECT id,tenant_id,provider,display_name,endpoint,config,allow_private_network,poll_interval_seconds,enabled,archived,version,connection_revision,credential_revision,created_at,updated_at FROM integrations`

type integrationRow interface{ Scan(...any) error }

func scanIntegration(row integrationRow) (integration.Integration, error) {
	var item integration.Integration
	var provider string
	var pollSeconds int64
	if err := row.Scan(&item.ID, &item.TenantID, &provider, &item.Name, &item.Endpoint, &item.Config, &item.AllowPrivateNetwork, &pollSeconds, &item.Enabled, &item.Archived, &item.Version, &item.ConnectionRevision, &item.CredentialRevision, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return integration.Integration{}, err
	}
	item.Provider = integration.Provider(provider)
	item.PollInterval = time.Duration(pollSeconds) * time.Second
	return item, nil
}

const integrationOperationSelect = `SELECT id,tenant_id,integration_id,operation_type,state,checkpoint,counts,errors,pipelines,job_id,actor,connection_revision,credential_revision,started_at,finished_at,created_at,updated_at FROM integration_operations`

func scanIntegrationOperation(row integrationRow) (integration.Operation, error) {
	var operation integration.Operation
	var operationType, state string
	var countsJSON, errorsJSON, pipelinesJSON []byte
	if err := row.Scan(&operation.ID, &operation.TenantID, &operation.IntegrationID, &operationType, &state, &operation.Checkpoint, &countsJSON, &errorsJSON, &pipelinesJSON, &operation.JobID, &operation.Actor, &operation.ConnectionRevision, &operation.CredentialRevision, &operation.StartedAt, &operation.FinishedAt, &operation.CreatedAt, &operation.UpdatedAt); err != nil {
		return integration.Operation{}, err
	}
	operation.Type, operation.State = integration.OperationType(operationType), integration.OperationState(state)
	if err := json.Unmarshal(countsJSON, &operation.Counts); err != nil {
		return integration.Operation{}, fmt.Errorf("decode integration operation counts: %w", err)
	}
	if err := json.Unmarshal(errorsJSON, &operation.Errors); err != nil {
		return integration.Operation{}, fmt.Errorf("decode integration operation errors: %w", err)
	}
	if err := json.Unmarshal(pipelinesJSON, &operation.Pipelines); err != nil {
		return integration.Operation{}, fmt.Errorf("decode integration operation pipelines: %w", err)
	}
	return operation, nil
}

const integrationRunSelect = `SELECT id,tenant_id,integration_id,COALESCE(binding_id,''),provider_key,pipeline_key,run_number,run_url,lifecycle,result,revision,branch,COALESCE(analysis_id,''),correlation,queued_at,started_at,finished_at,provider_updated_at,created_at,updated_at FROM integration_external_runs`

func scanIntegrationRun(row integrationRow) (integration.ExternalRun, error) {
	var run integration.ExternalRun
	var lifecycle, result, correlation string
	if err := row.Scan(&run.ID, &run.TenantID, &run.IntegrationID, &run.BindingID, &run.ProviderKey, &run.PipelineKey, &run.Number, &run.URL, &lifecycle, &result, &run.Revision, &run.Branch, &run.AnalysisID, &correlation, &run.QueuedAt, &run.StartedAt, &run.FinishedAt, &run.ProviderUpdatedAt, &run.CreatedAt, &run.UpdatedAt); err != nil {
		return integration.ExternalRun{}, err
	}
	run.Lifecycle, run.Result, run.Correlation = integration.RunLifecycle(lifecycle), integration.RunResult(result), integration.CorrelationState(correlation)
	return run, nil
}

func classifyIntegrationMiss(ctx context.Context, tx pgx.Tx, id shared.ID, expectedVersion int) error {
	var version int
	err := tx.QueryRow(ctx, `SELECT version FROM integrations WHERE id=$1`, id.String()).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return shared.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("classify integration update: %w", err)
	}
	if version != expectedVersion {
		return shared.ErrConflict
	}
	return shared.ErrConflict
}

func integrationCredentialAAD(tenantID, integrationID shared.ID, credentialID string) []byte {
	return []byte("synapse:integration-credential:" + tenantID.String() + ":" + integrationID.String() + ":" + credentialID)
}

func invalidateIntegrationOperations(ctx context.Context, tx pgx.Tx, integrationID shared.ID, at time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='done',claimed_until=NULL,claim_fence=claim_fence+1,updated_at=$2
		WHERE id IN (SELECT job_id FROM integration_operations WHERE integration_id=$1 AND state IN ('queued','running'))
		AND status IN ('queued','claimed')`, integrationID.String(), at.UTC()); err != nil {
		return fmt.Errorf("invalidate integration jobs: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE integration_operations SET state='cancelled',finished_at=$2,updated_at=$2
		WHERE integration_id=$1 AND state IN ('queued','running')`, integrationID.String(), at.UTC()); err != nil {
		return fmt.Errorf("cancel integration operations: %w", err)
	}
	return nil
}

func integrationConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
