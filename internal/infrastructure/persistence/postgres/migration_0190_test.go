package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

const migration0190Tenant = "t-migration-0190"

// TestMigration0190OpensTheNotificationSchema seeds notification rows the way the pre-0190 code
// writes them, applies 0190, and checks that those rows keep working with the new columns'
// defaults, that well-formed new event and channel types are accepted and malformed ones refused,
// and that the migration rolls back and forward cleanly.
func TestMigration0190OpensTheNotificationSchema(t *testing.T) {
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigrationDSN(t, sharedDSN, "0190")
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := openLockedGooseDB(t, dsn)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.DownTo(db, ".", 186); err != nil {
		t.Fatalf("down to 186 (before 0190): %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	seedPre0190NotificationRows(ctx, t, pool)
	if err := goose.UpTo(db, ".", 190); err != nil {
		t.Fatalf("up to 190: %v", err)
	}

	t.Run("existing rows get the new defaults", func(t *testing.T) { checkMigration0190Defaults(ctx, t, pool) })
	t.Run("shape checks replace the enums", func(t *testing.T) { checkMigration0190ShapeChecks(ctx, t, pool) })
	t.Run("new columns are bounded", func(t *testing.T) { checkMigration0190ColumnBounds(ctx, t, pool) })
	t.Run("row level security stays forced", func(t *testing.T) { checkMigration0190ForcedRLS(ctx, t, pool) })

	if err := goose.DownTo(db, ".", 186); err != nil {
		t.Fatalf("down to 186 after apply: %v", err)
	}
	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("up after down: %v", err)
	}
}

func seedPre0190NotificationRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	statements := []struct {
		name string
		sql  string
	}{
		{"tenant", `INSERT INTO tenants (id, name) VALUES ($1,$1)`},
		{"channel", `INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES($1,'ch-1','Ops','slack',$2,$2)`},
		{"channel version", `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'ch-1',1,'sealed',$2)`},
		{"rule", `INSERT INTO notification_rules(tenant_id,id,name,event_type,created_at,updated_at) VALUES($1,'rule-1','Scans','scan.completed',$2,$2)`},
		{"event", `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data) VALUES($1,'ev-1','scan.completed','scan_job','scan-1',1,$2,'{}')`},
		{"delivery", `INSERT INTO notification_deliveries(tenant_id,id,event_id,channel_id,channel_version,channel_type,matched_rules,state,created_at,updated_at) VALUES($1,'del-1','ev-1','ch-1',1,'slack','[]','pending',$2,$2)`},
		{"attempt", `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,'att-1','del-1',1,$2,'started')`},
		{"source record", `INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data) VALUES($1,'scan_job','scan-2','scan.completed',$2,'{}')`},
	}
	for _, statement := range statements {
		args := []any{migration0190Tenant}
		if strings.Contains(statement.sql, "$2") {
			args = append(args, at)
		}
		if _, err := pool.Exec(ctx, statement.sql, args...); err != nil {
			t.Fatalf("seed %s: %v", statement.name, err)
		}
	}
}

func checkMigration0190Defaults(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	var version int
	var subjectKind, subjectID, snapshot string
	if err := pool.QueryRow(ctx, `SELECT schema_version,subject_kind,subject_id,context::text FROM notification_source_records WHERE tenant_id=$1`, migration0190Tenant).
		Scan(&version, &subjectKind, &subjectID, &snapshot); err != nil {
		t.Fatalf("read source record: %v", err)
	}
	if version != 1 || subjectKind != "" || subjectID != "" || snapshot != "{}" {
		t.Errorf("source record defaults = %d %q %q %s", version, subjectKind, subjectID, snapshot)
	}
	if err := pool.QueryRow(ctx, `SELECT subject_kind,subject_id,context::text FROM notification_events WHERE tenant_id=$1 AND id='ev-1'`, migration0190Tenant).
		Scan(&subjectKind, &subjectID, &snapshot); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if subjectKind != "" || subjectID != "" || snapshot != "{}" {
		t.Errorf("event defaults = %q %q %s", subjectKind, subjectID, snapshot)
	}
	var remoteRef, deliveryTemplate, attemptTemplate string
	if err := pool.QueryRow(ctx, `SELECT d.remote_ref,d.template_ref,a.template_ref FROM notification_deliveries d JOIN notification_delivery_attempts a ON a.tenant_id=d.tenant_id AND a.delivery_id=d.id WHERE d.tenant_id=$1`, migration0190Tenant).
		Scan(&remoteRef, &deliveryTemplate, &attemptTemplate); err != nil {
		t.Fatalf("read delivery: %v", err)
	}
	if remoteRef != "" || deliveryTemplate != "" || attemptTemplate != "" {
		t.Errorf("delivery defaults = %q %q %q", remoteRef, deliveryTemplate, attemptTemplate)
	}
	// The 0163 finalize guard still lets a started attempt be finished.
	if _, err := pool.Exec(ctx, `UPDATE notification_delivery_attempts SET outcome='delivered',finished_at=now(),response_code=200 WHERE tenant_id=$1 AND id='att-1'`, migration0190Tenant); err != nil {
		t.Errorf("finalize a pre-0190 attempt: %v", err)
	}
}

func checkMigration0190ShapeChecks(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
	for eventType, want := range map[string]bool{
		"jira.issue_created": true, "ticket.linked": true, "a.b.c": true,
		"Scan.Completed": false, "scan": false, "a..b": false, "scan.completed.": false, "scan-completed.x": false, "": false,
	} {
		err := execRolledBack(ctx, pool, `INSERT INTO notification_rules(tenant_id,id,name,event_type,created_at,updated_at) VALUES($1,'rule-shape','Shape',$2,$3,$3)`, migration0190Tenant, eventType, at)
		if (err == nil) != want {
			t.Errorf("rule event_type %q: err = %v, want accepted=%v", eventType, err, want)
		}
	}
	for channelType, want := range map[string]bool{
		"teams": true, "pagerduty": true, "slack_bot": true,
		"Slack": false, "slack-bot": false, "slack.bot": false, "": false,
	} {
		err := execRolledBack(ctx, pool, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES($1,'ch-shape','Shape',$2,$3,$3)`, migration0190Tenant, channelType, at)
		if (err == nil) != want {
			t.Errorf("channel_type %q: err = %v, want accepted=%v", channelType, err, want)
		}
		err = execRolledBack(ctx, pool, `INSERT INTO notification_deliveries(tenant_id,id,event_id,channel_id,channel_version,channel_type,recipient,matched_rules,state,created_at,updated_at) VALUES($1,'del-shape','ev-1','ch-1',1,$2,'shape@example.com','[]','pending',$3,$3)`, migration0190Tenant, channelType, at)
		if (err == nil) != want {
			t.Errorf("delivery channel_type %q: err = %v, want accepted=%v", channelType, err, want)
		}
	}
	for version, want := range map[int]bool{2: true, 1: true, 0: false} {
		err := execRolledBack(ctx, pool, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data) VALUES($1,'ev-version','scan.completed','scan_job','scan-version',$2,$3,'{}')`, migration0190Tenant, version, at)
		if (err == nil) != want {
			t.Errorf("event schema_version %d: err = %v, want accepted=%v", version, err, want)
		}
	}
}

func checkMigration0190ColumnBounds(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	at := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
	insertEvent := `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data,subject_kind,subject_id,context) VALUES($1,'ev-bounds','scan.completed','scan_job','scan-bounds',1,$2,'{}',$3,$4,$5::jsonb)`
	cases := []struct {
		name                   string
		subjectKind, subjectID string
		context                string
		want                   bool
	}{
		{"subject and context", "incident", "inc-1", `{"title":"x"}`, true},
		{"upper-case subject kind", "Incident", "inc-1", `{}`, false},
		{"dotted subject kind", "fleet.agent", "a-1", `{}`, false},
		{"subject id too long", "incident", strings.Repeat("x", 513), `{}`, false},
		{"context not an object", "incident", "inc-1", `[]`, false},
		{"context over 1 MiB", "incident", "inc-1", `{"v":"` + strings.Repeat("x", 1<<20) + `"}`, false},
	}
	for _, tc := range cases {
		err := execRolledBack(ctx, pool, insertEvent, migration0190Tenant, at, tc.subjectKind, tc.subjectID, tc.context)
		if (err == nil) != tc.want {
			t.Errorf("event %s: err = %v, want accepted=%v", tc.name, err, tc.want)
		}
	}
	for ref, want := range map[string]bool{strings.Repeat("r", 512): true, strings.Repeat("r", 513): false} {
		err := execRolledBack(ctx, pool, `UPDATE notification_deliveries SET remote_ref=$2 WHERE tenant_id=$1 AND id='del-1'`, migration0190Tenant, ref)
		if (err == nil) != want {
			t.Errorf("remote_ref of %d bytes: err = %v, want accepted=%v", len(ref), err, want)
		}
	}
	for ref, want := range map[string]bool{"builtin:scan.completed:slack:en@1": true, strings.Repeat("t", 257): false} {
		err := execRolledBack(ctx, pool, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome,template_ref) VALUES($1,'att-bounds','del-1',2,$2,'started',$3)`, migration0190Tenant, at, ref)
		if (err == nil) != want {
			t.Errorf("attempt template_ref %q: err = %v, want accepted=%v", ref[:min(len(ref), 40)], err, want)
		}
	}
}

func checkMigration0190ForcedRLS(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	for _, table := range []string{"notification_channels", "notification_rules", "notification_events", "notification_deliveries", "notification_delivery_attempts", "notification_source_records"} {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forced); err != nil {
			t.Fatalf("inspect RLS on %s: %v", table, err)
		}
		if !forced {
			t.Errorf("%s lost FORCE ROW LEVEL SECURITY", table)
		}
	}
}

// execRolledBack runs one statement in a transaction it always rolls back, so each check starts
// from the seeded rows and a refused statement does not abort the next one.
func execRolledBack(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, sql, args...)
	return err
}
