package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0139ResponseAttemptInvariants(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}
	id := fmt.Sprint(time.Now().UnixNano())
	role := "rsp_migrator_" + id
	database := "rsp_migration_0139_" + id
	password := "migration-test-password"
	admin, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test database administrator: %v", err)
	}
	quotedRole := pgx.Identifier{role}.Sanitize()
	quotedDatabase := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+quotedRole+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOBYPASSRLS"); err != nil {
		admin.Close()
		t.Fatalf("create non-superuser migration owner: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quotedDatabase+" OWNER "+quotedRole); err != nil {
		_, _ = admin.Exec(ctx, "DROP ROLE "+quotedRole)
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, database)
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quotedDatabase); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		if _, err := admin.Exec(cleanupCtx, "DROP ROLE "+quotedRole); err != nil {
			t.Errorf("drop non-superuser migration owner: %v", err)
		}
		admin.Close()
	})
	isolated := *u
	isolated.Path = "/" + database
	isolated.RawPath = ""
	isolated.User = url.UserPassword(role, password)
	db, err := sql.Open("pgx", dsnForMigrate(isolated.String()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 138); err != nil {
		t.Fatalf("migrate isolated database to 0138: %v", err)
	}
	var haltFencesExist bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.tables
		WHERE table_schema='public' AND table_name='response_halt_fences'
	)`).Scan(&haltFencesExist); err != nil {
		t.Fatalf("inspect 0138 response halt fences: %v", err)
	}
	if haltFencesExist {
		t.Fatal("0138 unexpectedly defines response_halt_fences; 0139 must remain its owner")
	}

	tenantID := "rsp-upgrade-tenant-" + id
	engagementID := "rsp-upgrade-engagement-" + id
	actionID := "rsp-upgrade-action-" + id
	seed, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = seed.Rollback() }()
	if _, err := seed.ExecContext(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantID); err != nil {
		t.Fatalf("scope legacy seed transaction: %v", err)
	}
	if _, err := seed.ExecContext(ctx, `INSERT INTO tenants(id, name) VALUES ($1, $1)`, tenantID); err != nil {
		t.Fatalf("seed legacy tenant: %v", err)
	}
	if _, err := seed.ExecContext(ctx, `INSERT INTO engagements(id, tenant_id, name) VALUES ($2, $1, 'response upgrade')`, tenantID, engagementID); err != nil {
		t.Fatalf("seed legacy engagement: %v", err)
	}
	if _, err := seed.ExecContext(ctx, `INSERT INTO response_actions
		(tenant_id, id, engagement_id, kind, target, blast_radius, argv, reversal, state, verification)
		VALUES ($1, $3, $2, 'isolate_host', 'host-1', 'state_changing', '[]'::jsonb,
			'{"kind":"restore_host","argv":["synapse-agent-response","restore-host","host-1"]}'::jsonb,
			'applied', 'succeeded')`, tenantID, engagementID, actionID); err != nil {
		t.Fatalf("seed legacy response action: %v", err)
	}
	if err := seed.Commit(); err != nil {
		t.Fatalf("commit legacy response seed: %v", err)
	}

	if err := goose.UpTo(db, ".", 139); err != nil {
		t.Fatalf("migrate legacy response action through 0139: %v", err)
	}
	readTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = readTx.Rollback() }()
	if _, err := readTx.ExecContext(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantID); err != nil {
		t.Fatalf("scope migrated response read: %v", err)
	}
	var state, verification, reversibility string
	if err := readTx.QueryRowContext(ctx, `SELECT state, verification, reversibility_class FROM response_actions WHERE tenant_id=$1 AND id=$2`, tenantID, actionID).Scan(&state, &verification, &reversibility); err != nil {
		t.Fatalf("read migrated legacy action: %v", err)
	}
	if state != "violation" || verification != "unknown" || reversibility != "compensating" {
		t.Fatalf("legacy response action state=%q verification=%q reversibility=%q, want violation/unknown/compensating", state, verification, reversibility)
	}
	if err := readTx.Commit(); err != nil {
		t.Fatal(err)
	}

	// This is the exact response_actions INSERT list from upstream/main before 0139.
	// A main API binary must keep writing safely after the database has expanded.
	compatibilityActions := []struct {
		kind          rdom.Kind
		reversibility string
	}{
		{kind: rdom.KindIsolateHost, reversibility: "compensating"},
		{kind: rdom.KindQuarantineFile, reversibility: "compensating"},
		{kind: rdom.KindStopProcess, reversibility: "best_effort"},
	}
	compatTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = compatTx.Rollback() }()
	if _, err := compatTx.ExecContext(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenantID); err != nil {
		t.Fatalf("scope main compatibility transaction: %v", err)
	}
	for _, action := range compatibilityActions {
		actionID := "rsp-main-" + id + "-" + string(action.kind)
		if _, err := compatTx.ExecContext(ctx, `INSERT INTO response_actions
			(tenant_id, id, engagement_id, kind, target, blast_radius, argv, reversal, state, approved_by, approval_evidence_id, applied_at, updated_at, verification)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10,$11,$12,$13,$14)`,
			tenantID, actionID, engagementID, string(action.kind), "host-main-compat", "state_changing",
			`["synapse-agent-response","compat"]`, `{"kind":"restore_host","argv":["synapse-agent-response","restore-host"]}`,
			"pending", "", nil, nil, time.Now().UTC(), "unknown"); err != nil {
			t.Fatalf("insert upstream/main response action %s after 0139: %v", action.kind, err)
		}
		var got string
		if err := compatTx.QueryRowContext(ctx, `SELECT reversibility_class FROM response_actions WHERE tenant_id=$1 AND id=$2`, tenantID, actionID).Scan(&got); err != nil {
			t.Fatalf("read derived reversibility for %s: %v", action.kind, err)
		}
		if got != action.reversibility {
			t.Fatalf("derived reversibility for %s=%q, want %q", action.kind, got, action.reversibility)
		}
	}
	if err := compatTx.Commit(); err != nil {
		t.Fatalf("commit main compatibility response actions: %v", err)
	}

	pool, err := Connect(ctx, dsnForMigrate(isolated.String()))
	if err != nil {
		t.Fatalf("connect repository to isolated database: %v", err)
	}
	t.Cleanup(pool.Close)
	compatibilityID := shared.ID("rsp-main-" + id + "-" + string(rdom.KindStopProcess))
	record, found, err := NewResponseRepository(pool).Get(shared.WithTenant(ctx, shared.ID(tenantID)), compatibilityID)
	if err != nil || !found {
		t.Fatalf("read upstream/main response action through repository: found=%t err=%v", found, err)
	}
	if record.Action.Kind != rdom.KindStopProcess || string(record.Action.Reversibility) != "best_effort" {
		t.Fatalf("repository read incompatible response action: %+v", record.Action)
	}

	constraints := map[string]string{
		"response_attempts_deadline_check":        "deadline_at > created_at",
		"response_attempts_terminal_reason_check": "manual_intervention_required",
		"response_attempts_operation_key":         "UNIQUE",
	}
	rows, err := db.Query(`SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='response_attempts'::regclass AND conname = ANY($1::text[])`, []string{"response_attempts_deadline_check", "response_attempts_terminal_reason_check", "response_attempts_operation_key"})
	if err != nil {
		t.Fatalf("inspect response attempt constraints: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(definition, constraints[name]) {
			t.Fatalf("response attempt constraint %s=%q, want fragment %q", name, definition, constraints[name])
		}
		delete(constraints, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(constraints) != 0 {
		t.Fatalf("0139 did not install response attempt constraints: %v", constraints)
	}
	var triggerCount int
	if err := db.QueryRow(`SELECT count(*) FROM pg_trigger WHERE tgrelid='response_attempts'::regclass AND tgname='response_attempt_deadline_immutable' AND NOT tgisinternal`).Scan(&triggerCount); err != nil {
		t.Fatalf("inspect response attempt deadline trigger: %v", err)
	}
	if triggerCount != 1 {
		t.Fatalf("response attempt deadline trigger count=%d, want 1", triggerCount)
	}

	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("migrate consolidated database to head: %v", err)
	}
	finalColumns := map[string]string{
		"authorization_target":  "jsonb",
		"target_fingerprint":    "jsonb",
		"submitted_by":          "text",
		"reversal_requested_by": "text",
	}
	rows, err = db.Query(`
		SELECT column_name, data_type
		FROM information_schema.columns
		WHERE table_schema='public' AND table_name='response_actions'
		  AND column_name = ANY($1::text[])`, []string{"authorization_target", "target_fingerprint", "submitted_by", "reversal_requested_by"})
	if err != nil {
		t.Fatalf("inspect final response action columns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, dataType string
		if err := rows.Scan(&name, &dataType); err != nil {
			t.Fatal(err)
		}
		if dataType != finalColumns[name] {
			t.Fatalf("final response action column %s type=%s, want %s", name, dataType, finalColumns[name])
		}
		delete(finalColumns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(finalColumns) != 0 {
		t.Fatalf("consolidated migrations did not install response action columns: %v", finalColumns)
	}

	for _, table := range []string{
		"response_audit_intents", "response_halt_dispatches", "response_verification_observations",
		"response_observer_bindings", "correlation_checkpoints", "correlation_assignments", "incident_response_links",
	} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, table).Scan(&exists); err != nil {
			t.Fatalf("inspect final table %s: %v", table, err)
		}
		if !exists {
			t.Fatalf("consolidated migrations did not install final table %s", table)
		}
	}
	var assignmentMutationTriggers int
	if err := db.QueryRow(`SELECT count(*) FROM pg_trigger
		WHERE tgrelid='correlation_assignments'::regclass
		  AND tgname = ANY($1::text[]) AND NOT tgisinternal`,
		[]string{"correlation_assignments_immutable", "correlation_assignments_no_truncate"}).Scan(&assignmentMutationTriggers); err != nil {
		t.Fatalf("inspect correlation assignment mutation triggers: %v", err)
	}
	if assignmentMutationTriggers != 2 {
		t.Fatalf("correlation assignment mutation trigger count=%d, want 2", assignmentMutationTriggers)
	}

	if err := goose.DownTo(db, ".", 138); err != nil {
		t.Fatalf("roll back consolidated response migrations to 0138: %v", err)
	}
	for _, table := range []string{
		"response_halt_fences", "response_attempts", "response_audit_intents", "response_halt_dispatches",
		"response_verification_observations", "response_observer_bindings", "correlation_checkpoints",
		"correlation_assignments", "incident_response_links",
	} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, table).Scan(&exists); err != nil {
			t.Fatalf("inspect rolled-back table %s: %v", table, err)
		}
		if exists {
			t.Fatalf("rollback through 0139-0144 retained table %s", table)
		}
	}
	for _, column := range []string{"reversibility_class", "authorization_target", "target_fingerprint", "submitted_by", "reversal_requested_by"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='response_actions' AND column_name=$1
		)`, column).Scan(&exists); err != nil {
			t.Fatalf("inspect rolled-back response action column %s: %v", column, err)
		}
		if exists {
			t.Fatalf("rollback through 0139 retained response_actions.%s", column)
		}
	}
	for _, column := range []string{"source_agent_id", "source_agent_session_id"} {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema='public' AND table_name='endpoint_timeline' AND column_name=$1
		)`, column).Scan(&exists); err != nil {
			t.Fatalf("inspect rolled-back endpoint timeline column %s: %v", column, err)
		}
		if exists {
			t.Fatalf("rollback through 0142 retained endpoint_timeline.%s", column)
		}
	}
}
