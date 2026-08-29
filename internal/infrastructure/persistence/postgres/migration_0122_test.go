package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMigration0122TelemetryEventAttributionIsImmutable(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var constraintExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM pg_constraint
		WHERE conrelid='telemetry_batch_events'::regclass
		  AND conname='telemetry_batch_events_redaction_policy_digest_sha256'
	)`).Scan(&constraintExists); err != nil {
		t.Fatalf("inspect redaction-policy digest constraint: %v", err)
	}
	if !constraintExists {
		t.Fatal("migration 0122 did not install the redaction-policy digest constraint")
	}

	for _, trigger := range []string{"telemetry_batch_events_immutable_attribution", "telemetry_batch_events_no_truncate"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_trigger
			WHERE tgrelid='telemetry_batch_events'::regclass
			  AND tgname=$1
			  AND NOT tgisinternal
		)`, trigger).Scan(&exists); err != nil {
			t.Fatalf("inspect trigger %s: %v", trigger, err)
		}
		if !exists {
			t.Fatalf("migration 0122 did not install %s", trigger)
		}
	}

	// Row-level triggers only fire when a row actually matches, so a real retained
	// event must exist before an UPDATE attempt proves anything.
	tenant := "mig0122-" + randHex(t)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM telemetry_batch_events WHERE tenant_id=$1`, tenant)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO telemetry_batch_events
		(tenant_id,agent_id,stream_id,asset_id,epoch,sequence,event_id,class,digest,schema_version,payload,observed_at,redaction_policy_digest)
		VALUES ($1,'agent-1','stream-1','asset-1',1,1,'event-1','process',$2,2,'\x70',now(),$2)`,
		tenant, strings.Repeat("a", 64)); err != nil {
		t.Fatalf("seed retained telemetry event: %v", err)
	}

	// A detection's provenance binds to this digest, so rewriting accepted attribution
	// would forge the privacy policy the telemetry was admitted under.
	if _, err := pool.Exec(ctx, `UPDATE telemetry_batch_events SET redaction_policy_digest=$2 WHERE tenant_id=$1`,
		tenant, strings.Repeat("b", 64)); err == nil {
		t.Fatal("rewriting accepted redaction-policy attribution unexpectedly succeeded")
	}
	if _, err := pool.Exec(ctx, `UPDATE telemetry_batch_events SET digest=digest WHERE tenant_id=$1`, tenant); err == nil {
		t.Fatal("updating a retained telemetry event unexpectedly succeeded")
	}
	// TRUNCATE is never a legitimate retention path: it would erase every tenant's events at once.
	if _, err := pool.Exec(ctx, `TRUNCATE telemetry_batch_events`); err == nil {
		t.Fatal("TRUNCATE telemetry_batch_events unexpectedly succeeded")
	}

	var digest string
	if err := pool.QueryRow(ctx, `SELECT redaction_policy_digest FROM telemetry_batch_events WHERE tenant_id=$1`, tenant).Scan(&digest); err != nil {
		t.Fatalf("read retained attribution: %v", err)
	}
	if digest != strings.Repeat("a", 64) {
		t.Fatalf("retained attribution = %q, want the originally accepted digest", digest)
	}

	// Raw telemetry is retention-bound, NOT chained evidence: pruning must stay possible so a
	// retention sweep is not blocked. A pruned reference then resolves as Missing, which is honest.
	if _, err := pool.Exec(ctx, `DELETE FROM telemetry_batch_events WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatalf("retention pruning of raw telemetry must remain possible: %v", err)
	}
}
