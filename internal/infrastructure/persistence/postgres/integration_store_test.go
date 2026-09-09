package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func integrationOperationAudit(operation integration.Operation) ports.AuditEntry {
	return ports.AuditEntry{
		Actor: operation.Actor, Action: "integration.operation_started", Target: operation.ID.String(), At: operation.CreatedAt,
		Metadata: map[string]string{"integration_id": operation.IntegrationID.String(), "operation": string(operation.Type)},
	}
}

func integrationMutationAudit(action string, target shared.ID, at time.Time) ports.AuditEntry {
	return ports.AuditEntry{Actor: "admin", Action: action, Target: target.String(), At: at}
}

func isolatedIntegrationDatabase(t *testing.T, ctx context.Context, sharedDSN string) string {
	t.Helper()
	adminConfig, err := pgx.ParseConfig(sharedDSN)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := fmt.Sprintf("synapse_integration_%s", randHex(t))
	quotedDatabase := pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quotedDatabase); err != nil {
		admin.Close(ctx)
		t.Fatalf("create isolated integration database: %v", err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		_, _ = admin.Exec(cleanup, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, databaseName)
		_, _ = admin.Exec(cleanup, "DROP DATABASE IF EXISTS "+quotedDatabase)
		_ = admin.Close(cleanup)
	})
	isolationURL, err := url.Parse(sharedDSN)
	if err != nil {
		t.Fatalf("parse shared PostgreSQL DSN: %v", err)
	}
	isolationURL.Path = "/" + databaseName
	isolationURL.RawPath = ""
	return isolationURL.String()
}

func TestMigration0137DefinesBoundedProviderNeutralRLSSchema(t *testing.T) {
	contents, err := migrations.FS.ReadFile("0137_integration_framework.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, table := range []string{"integrations", "integration_credentials", "integration_bindings", "integration_operations", "integration_external_runs"} {
		if !strings.Contains(sql, "CREATE TABLE "+table) || !strings.Contains(sql, "CALL synapse_enable_tenant_rls('"+table+"')") {
			t.Errorf("migration missing table/RLS for %s", table)
		}
	}
	for _, invariant := range []string{"integration_operations_one_active_idx", "octet_length(config::text) <= 32768", "UNIQUE (tenant_id, integration_id, provider_key)", "FOREIGN KEY (tenant_id, project_id)", "FOREIGN KEY (tenant_id, analysis_id)", "project_analyses_tenant_id_id_unique"} {
		if !strings.Contains(sql, invariant) {
			t.Errorf("migration missing invariant %q", invariant)
		}
	}
	if strings.Contains(sql, "provider IN (") || strings.Contains(sql, "provider = 'jenkins'") {
		t.Fatal("migration closes provider identity instead of keeping it opaque")
	}
}

func TestPostgresIntegrationStoreAtomicityRLSCredentialsAndUpsert(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	dsn = isolatedIntegrationDatabase(t, ctx, dsn)
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	tenantA, tenantB := shared.ID("integration-a-"+suffix), shared.ID("integration-b-"+suffix)
	projectA := shared.ID("project-a-" + suffix)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA.String(), tenantB.String()}},
		{`INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES($1,$2,'Project A',$3,'{"kind":"local","value":"/tmp/a"}')`, []any{projectA.String(), tenantA.String(), "project-a-" + suffix}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	cipher, err := vault.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := NewIntegrationStore(pool, cipher)
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	item := integration.Integration{ID: shared.ID("integration-" + suffix), TenantID: tenantA, Provider: "jenkins", Name: "Jenkins", Endpoint: "https://jenkins.example.com", Config: []byte(`{"nested":{"a":1,"b":2},"scope":"all"}`), PollInterval: time.Minute, Version: 1, CreatedAt: now, UpdatedAt: now}
	actx := shared.WithTenant(ctx, tenantA)
	if err := store.CreateIntegration(actx, item, integrationMutationAudit("integration.created", item.ID, now)); err != nil {
		t.Fatal(err)
	}
	secret := []byte(`{"username":"reader","api_token":"secret-token"}`)
	if err := store.PutIntegrationCredential(actx, item.ID, "default", secret, item.Version, 1, integrationMutationAudit("integration.credential_replaced", item.ID, now)); err != nil {
		t.Fatal(err)
	}
	var ciphertext string
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM integration_credentials WHERE tenant_id=$1 AND integration_id=$2`, tenantA.String(), item.ID.String()).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ciphertext, "secret-token") {
		t.Fatal("credential plaintext persisted")
	}
	current, err := store.GetIntegration(actx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveIntegrationCredential(actx, item.ID, "default", current.CredentialRevision)
	if err != nil || string(resolved) != string(secret) {
		t.Fatalf("resolved credential=%q err=%v", resolved, err)
	}
	if err := store.PutIntegrationCredential(actx, item.ID, "default", secret, item.Version, item.ConnectionRevision, integrationMutationAudit("integration.credential_replaced", item.ID, now)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale credential replacement error=%v, want conflict", err)
	}
	if err := store.DeleteIntegrationCredential(actx, item.ID, "default", current.Version-1, current.ConnectionRevision, integrationMutationAudit("integration.credential_deleted", item.ID, now)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale credential deletion error=%v, want conflict", err)
	}
	renameOnly := current
	renameOnly.Name = "Jenkins renamed"
	renameOnly.Config = []byte(`{"scope":"all","nested":{"b":2,"a":1}}`)
	renamed, err := store.UpdateIntegration(actx, renameOnly, current.Version, integrationMutationAudit("integration.updated", item.ID, now))
	if err != nil {
		t.Fatal(err)
	}
	if renamed.ConnectionRevision != current.ConnectionRevision || renamed.CredentialRevision != current.CredentialRevision {
		t.Fatalf("semantic rename advanced connection revisions: before=%+v after=%+v", current, renamed)
	}
	current = renamed
	staleAdmission := integration.Operation{ID: shared.ID("operation-stale-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationTest, State: integration.OperationQueued, JobID: "job-stale-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision - 1, CredentialRevision: current.CredentialRevision, CreatedAt: now, UpdatedAt: now}
	if _, err := store.StartIntegrationOperation(actx, staleAdmission, "integration.operation", []byte(`{}`), integrationOperationAudit(staleAdmission)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale operation admission error=%v, want conflict", err)
	}
	var staleJobCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE id=$1`, staleAdmission.JobID).Scan(&staleJobCount); err != nil || staleJobCount != 0 {
		t.Fatalf("stale admission job count=%d err=%v", staleJobCount, err)
	}

	operation := integration.Operation{ID: shared.ID("operation-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationTest, State: integration.OperationQueued, JobID: "job-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision, CredentialRevision: current.CredentialRevision, CreatedAt: now, UpdatedAt: now}
	jobKind := "integration.operation." + suffix
	if _, err := store.StartIntegrationOperation(actx, operation, jobKind, []byte(`{"operation_id":"`+operation.ID.String()+`"}`), integrationOperationAudit(operation)); err != nil {
		t.Fatal(err)
	}
	conflicting := operation
	conflicting.ID, conflicting.JobID = shared.ID("operation-conflict-"+suffix), "job-conflict-"+suffix
	if _, err := store.StartIntegrationOperation(actx, conflicting, "integration.operation", []byte(`{}`), integrationOperationAudit(conflicting)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("active operation conflict error=%v", err)
	}
	var jobCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE id IN ($1,$2)`, operation.JobID, conflicting.JobID).Scan(&jobCount); err != nil || jobCount != 1 {
		t.Fatalf("atomic operation jobs=%d err=%v", jobCount, err)
	}
	queue := NewJobQueue(pool, idgen.RandomID{})
	firstClaim, err := queue.Claim(ctx, time.Second, jobKind)
	if err != nil || firstClaim == nil || firstClaim.ID != operation.JobID {
		t.Fatalf("first claim=%+v err=%v", firstClaim, err)
	}
	restartedStore := NewIntegrationStore(pool, cipher)
	if begun, execute, beginErr := restartedStore.BeginIntegrationOperation(actx, operation.ID, now.Add(time.Second)); beginErr != nil || !execute || begun.State != integration.OperationRunning {
		t.Fatalf("begin after restart=%+v execute=%v err=%v", begun, execute, beginErr)
	}
	if _, err := pool.Exec(ctx, `UPDATE jobs SET claimed_until=now()-interval '1 second' WHERE id=$1`, operation.JobID); err != nil {
		t.Fatal(err)
	}
	secondClaim, err := queue.Claim(ctx, time.Second, jobKind)
	if err != nil || secondClaim == nil || secondClaim.ID != operation.JobID || secondClaim.Fence <= firstClaim.Fence {
		t.Fatalf("redelivery claim=%+v first=%+v err=%v", secondClaim, firstClaim, err)
	}
	if err := queue.Complete(actx, firstClaim.ID, firstClaim.Fence); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale claim completion error=%v", err)
	}
	if _, execute, err := restartedStore.BeginIntegrationOperation(actx, operation.ID, now.Add(2*time.Second)); err != nil || !execute {
		t.Fatalf("redelivered operation execute=%v err=%v", execute, err)
	}
	finished, err := restartedStore.FinishIntegrationOperation(actx, operation.ID, integration.OperationSucceeded, "checkpoint", integration.OperationCounts{}, nil, nil, now.Add(3*time.Second))
	if err != nil || finished.State != integration.OperationSucceeded {
		t.Fatalf("finish redelivered operation=%+v err=%v", finished, err)
	}
	if duplicate, err := restartedStore.FinishIntegrationOperation(actx, operation.ID, integration.OperationFailed, "overwritten", integration.OperationCounts{Errors: 1}, []string{"late worker"}, nil, now.Add(4*time.Second)); err != nil || duplicate.State != integration.OperationSucceeded || duplicate.Checkpoint != "checkpoint" {
		t.Fatalf("late duplicate changed terminal operation=%+v err=%v", duplicate, err)
	}
	if err := queue.Complete(actx, secondClaim.ID, secondClaim.Fence); err != nil {
		t.Fatal(err)
	}

	cancelledOperation := integration.Operation{ID: shared.ID("operation-cancelled-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationDiscover, State: integration.OperationQueued, JobID: "job-cancelled-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision, CredentialRevision: current.CredentialRevision, CreatedAt: now.Add(5 * time.Second), UpdatedAt: now.Add(5 * time.Second)}
	if _, err := store.StartIntegrationOperation(actx, cancelledOperation, jobKind, []byte(`{"operation_id":"`+cancelledOperation.ID.String()+`"}`), integrationOperationAudit(cancelledOperation)); err != nil {
		t.Fatal(err)
	}
	cancelled, err := store.CancelIntegrationOperation(actx, cancelledOperation.ID, now.Add(6*time.Second), integrationMutationAudit("integration.operation_cancelled", cancelledOperation.ID, now.Add(6*time.Second)))
	if err != nil || cancelled.State != integration.OperationCancelled || cancelled.Checkpoint != "" {
		t.Fatalf("cancelled operation=%+v err=%v", cancelled, err)
	}
	cancelledClaim, err := queue.Claim(ctx, time.Second, jobKind)
	if err != nil || cancelledClaim != nil {
		t.Fatalf("cancelled job remained claimable: claim=%+v err=%v", cancelledClaim, err)
	}
	if afterCancel, execute, beginErr := restartedStore.BeginIntegrationOperation(actx, cancelledOperation.ID, now.Add(7*time.Second)); beginErr != nil || execute || afterCancel.State != integration.OperationCancelled {
		t.Fatalf("cancelled redelivery=%+v execute=%v err=%v", afterCancel, execute, beginErr)
	}
	if lateFinish, finishErr := restartedStore.FinishIntegrationOperation(actx, cancelledOperation.ID, integration.OperationSucceeded, "advanced", integration.OperationCounts{Pipelines: 1}, nil, []integration.Pipeline{{ExternalKey: "/job/late", Name: "late", FullName: "late", Kind: "job"}}, now.Add(8*time.Second)); finishErr != nil || lateFinish.State != integration.OperationCancelled || lateFinish.Checkpoint != "" {
		t.Fatalf("cancelled operation was materialized=%+v err=%v", lateFinish, finishErr)
	}
	deadLetterOperation := integration.Operation{ID: shared.ID("operation-dead-letter-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationTest, State: integration.OperationQueued, JobID: "job-dead-letter-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision, CredentialRevision: current.CredentialRevision, CreatedAt: now.Add(9 * time.Second), UpdatedAt: now.Add(9 * time.Second)}
	if _, err := store.StartIntegrationOperation(actx, deadLetterOperation, jobKind, []byte(`{"operation_id":"`+deadLetterOperation.ID.String()+`"}`), integrationOperationAudit(deadLetterOperation)); err != nil {
		t.Fatal(err)
	}
	deadLetterClaim, err := queue.Claim(ctx, time.Second, jobKind)
	if err != nil || deadLetterClaim == nil || deadLetterClaim.ID != deadLetterOperation.JobID {
		t.Fatalf("dead-letter claim=%+v err=%v", deadLetterClaim, err)
	}
	if begun, execute, beginErr := store.BeginIntegrationOperation(actx, deadLetterOperation.ID, now.Add(10*time.Second)); beginErr != nil || !execute || begun.State != integration.OperationRunning {
		t.Fatalf("dead-letter begin=%+v execute=%v err=%v", begun, execute, beginErr)
	}
	if err := queue.Deadletter(actx, deadLetterClaim.ID, deadLetterClaim.Fence); err != nil {
		t.Fatal(err)
	}
	deadLettered, err := store.FinishIntegrationOperation(actx, deadLetterOperation.ID, integration.OperationFailed, "", integration.OperationCounts{}, []string{"provider operation exhausted retries"}, nil, now.Add(11*time.Second))
	if err != nil || deadLettered.State != integration.OperationFailed || len(deadLettered.Errors) != 1 {
		t.Fatalf("dead-letter operation=%+v err=%v", deadLettered, err)
	}
	afterDeadLetterRestart, err := NewIntegrationStore(pool, cipher).GetIntegrationOperation(actx, deadLetterOperation.ID)
	if err != nil || afterDeadLetterRestart.State != integration.OperationFailed || afterDeadLetterRestart.Errors[0] != "provider operation exhausted retries" {
		t.Fatalf("dead-letter restart operation=%+v err=%v", afterDeadLetterRestart, err)
	}
	if duplicate, finishErr := restartedStore.FinishIntegrationOperation(actx, deadLetterOperation.ID, integration.OperationSucceeded, "overwritten", integration.OperationCounts{Runs: 1}, nil, nil, now.Add(12*time.Second)); finishErr != nil || duplicate.State != integration.OperationFailed || duplicate.Checkpoint != "" {
		t.Fatalf("dead-letter duplicate changed terminal operation=%+v err=%v", duplicate, finishErr)
	}

	binding := integration.Binding{ID: shared.ID("binding-" + suffix), TenantID: tenantA, IntegrationID: item.ID, ProjectID: projectA, ExternalKey: "/job/main", ExternalName: "main", Version: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.CreateIntegrationBinding(actx, binding, integrationMutationAudit("integration.binding_created", binding.ID, now)); err != nil {
		t.Fatal(err)
	}
	run := integration.ExternalRun{ID: shared.ID("run-1-" + suffix), TenantID: tenantA, IntegrationID: item.ID, BindingID: binding.ID, ProviderKey: "build:1", PipelineKey: binding.ExternalKey, Lifecycle: integration.RunCompleted, Result: integration.ResultSuccess, Correlation: integration.CorrelationMissing, ProviderUpdatedAt: now, CreatedAt: now, UpdatedAt: now}
	current, err = store.GetIntegration(actx, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	current, err = store.SetIntegrationEnabled(actx, item.ID, true, current.Version, integrationMutationAudit("integration.enabled", item.ID, now))
	if err != nil {
		t.Fatal(err)
	}
	due, err := store.ListDueIntegrations(actx, time.Now().UTC().Add(2*time.Hour), 10)
	if err != nil || len(due) != 1 || due[0].ID != item.ID {
		t.Fatalf("due integrations=%+v err=%v", due, err)
	}
	cancelFencePoll := integration.Operation{ID: shared.ID("operation-poll-cancel-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationPoll, State: integration.OperationQueued, JobID: "job-poll-cancel-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision, CredentialRevision: current.CredentialRevision, CreatedAt: now.Add(12 * time.Second), UpdatedAt: now.Add(12 * time.Second)}
	if _, err := store.StartIntegrationOperation(actx, cancelFencePoll, jobKind, []byte(`{}`), integrationOperationAudit(cancelFencePoll)); err != nil {
		t.Fatal(err)
	}
	if _, execute, err := store.BeginIntegrationOperation(actx, cancelFencePoll.ID, now.Add(13*time.Second)); err != nil || !execute {
		t.Fatalf("begin cancel-fence poll execute=%v err=%v", execute, err)
	}
	if _, err := store.CancelIntegrationOperation(actx, cancelFencePoll.ID, now.Add(14*time.Second), integrationMutationAudit("integration.operation_cancelled", cancelFencePoll.ID, now)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FinishIntegrationPoll(actx, cancelFencePoll.ID, integration.OperationSucceeded, "late", integration.OperationCounts{Runs: 1}, nil, []integration.ExternalRun{run}, now.Add(15*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("cancelled poll publication error=%v, want conflict", err)
	}
	var cancelledRunCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM integration_external_runs WHERE tenant_id=$1 AND integration_id=$2 AND provider_key=$3`, tenantA.String(), item.ID.String(), run.ProviderKey).Scan(&cancelledRunCount); err != nil || cancelledRunCount != 0 {
		t.Fatalf("cancelled poll run count=%d err=%v", cancelledRunCount, err)
	}
	pollOperation := integration.Operation{ID: shared.ID("operation-poll-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationPoll, State: integration.OperationQueued, JobID: "job-poll-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision, CredentialRevision: current.CredentialRevision, CreatedAt: now.Add(13 * time.Second), UpdatedAt: now.Add(13 * time.Second)}
	pollOperation, err = store.StartIntegrationOperation(actx, pollOperation, jobKind, []byte(`{}`), integrationOperationAudit(pollOperation))
	if err != nil {
		t.Fatal(err)
	}
	pollOperation, execute, err := store.BeginIntegrationOperation(actx, pollOperation.ID, now.Add(14*time.Second))
	if err != nil || !execute {
		t.Fatalf("begin poll materialization fence=%+v execute=%v err=%v", pollOperation, execute, err)
	}
	if _, err := store.FinishIntegrationPoll(actx, pollOperation.ID, integration.OperationSucceeded, "1", integration.OperationCounts{Runs: 1}, nil, []integration.ExternalRun{run}, now.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	run.ID, run.Result, run.UpdatedAt = shared.ID("run-2-"+suffix), integration.ResultFailure, now.Add(time.Second)
	secondPoll := integration.Operation{ID: shared.ID("operation-poll-2-" + suffix), TenantID: tenantA, IntegrationID: item.ID, Type: integration.OperationPoll, State: integration.OperationQueued, JobID: "job-poll-2-" + suffix, Actor: "admin", ConnectionRevision: current.ConnectionRevision, CredentialRevision: current.CredentialRevision, CreatedAt: now.Add(16 * time.Second), UpdatedAt: now.Add(16 * time.Second)}
	secondPoll, err = store.StartIntegrationOperation(actx, secondPoll, jobKind, []byte(`{}`), integrationOperationAudit(secondPoll))
	if err != nil {
		t.Fatal(err)
	}
	if secondPoll, execute, err = store.BeginIntegrationOperation(actx, secondPoll.ID, now.Add(17*time.Second)); err != nil || !execute {
		t.Fatalf("begin second poll=%+v execute=%v err=%v", secondPoll, execute, err)
	}
	if _, err := store.FinishIntegrationPoll(actx, secondPoll.ID, integration.OperationSucceeded, "1", integration.OperationCounts{Runs: 1}, nil, []integration.ExternalRun{run}, now.Add(18*time.Second)); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListIntegrationExternalRuns(actx, item.ID, 10)
	if err != nil || len(runs) != 1 || runs[0].Result != integration.ResultFailure || runs[0].ID == run.ID {
		t.Fatalf("idempotent runs=%+v err=%v", runs, err)
	}
	analysisOne := shared.ID("analysis-one-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO project_analyses(id,tenant_id,project_id,created_at,payload) VALUES($1,$2,$3,$4,$5)`, analysisOne.String(), tenantA.String(), projectA.String(), now, []byte(`{"source_commit":"abc123"}`)); err != nil {
		t.Fatal(err)
	}
	matcher := NewProjectAnalysisStore(pool)
	matched, correlation, err := matcher.MatchIntegrationAnalysis(actx, projectA, "abc123")
	if err != nil || matched != analysisOne || correlation != integration.CorrelationLinked {
		t.Fatalf("linked analysis=%q correlation=%q err=%v", matched, correlation, err)
	}
	analysisTwo := shared.ID("analysis-two-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO project_analyses(id,tenant_id,project_id,created_at,payload) VALUES($1,$2,$3,$4,$5)`, analysisTwo.String(), tenantA.String(), projectA.String(), now.Add(time.Second), []byte(`{"source_revision":{"head":"abc123"}}`)); err != nil {
		t.Fatal(err)
	}
	matched, correlation, err = matcher.MatchIntegrationAnalysis(actx, projectA, "abc123")
	if err != nil || !matched.IsZero() || correlation != integration.CorrelationAmbiguous {
		t.Fatalf("ambiguous analysis=%q correlation=%q err=%v", matched, correlation, err)
	}
	matched, correlation, err = matcher.MatchIntegrationAnalysis(shared.WithTenant(ctx, tenantB), projectA, "abc123")
	if err != nil || !matched.IsZero() || correlation != integration.CorrelationMissing {
		t.Fatalf("cross-tenant analysis=%q correlation=%q err=%v", matched, correlation, err)
	}

	role := "integration_runtime_" + suffix
	quotedRole := pgx.Identifier{role}.Sanitize()
	for _, query := range []string{
		"CREATE ROLE " + quotedRole + " NOSUPERUSER NOBYPASSRLS",
		"GRANT USAGE ON SCHEMA public TO " + quotedRole,
		"GRANT SELECT ON integrations,integration_credentials,integration_bindings,integration_operations,integration_external_runs TO " + quotedRole,
	} {
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+quotedRole)
		_, _ = pool.Exec(context.Background(), "DROP ROLE IF EXISTS "+quotedRole)
	})
	for tenant, want := range map[shared.ID]int{tenantA: 1, tenantB: 0} {
		var count int
		if err := WithTenant(shared.WithTenant(ctx, tenant), pool, tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+quotedRole); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT count(*) FROM integrations WHERE id=$1`, item.ID.String()).Scan(&count)
		}); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("tenant %s sees %d integrations, want %d", tenant, count, want)
		}
	}
}
