package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityaction"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityoccurrence"
	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0095ActionOutboxIsolationAndIdempotency(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if err := MigrateLocked(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 94); err != nil {
		t.Fatalf("down to 0094: %v", err)
	}
	if err := goose.UpTo(db, ".", 95); err != nil {
		t.Fatalf("up 0095: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	for _, table := range []string{"vulnerability_risk_transitions", "vulnerability_actions", "vulnerability_action_outbox"} {
		var exists, forced bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table %s exists=%v err=%v", table, exists, err)
		}
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname=$1`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("FORCE RLS %s=%v err=%v", table, forced, err)
		}
	}

	prefix := "m95-" + randHex(t)
	tenantA, tenantB := prefix+"-ta", prefix+"-tb"
	engagementA, engagementB := prefix+"-ea", prefix+"-eb"
	sbomA, sbomB := prefix+"-sa", prefix+"-sb"
	componentA, componentB := prefix+"-ca", prefix+"-cb"
	advisoryID := prefix + "-cve"
	occurrenceA, occurrenceB := prefix+"-oa", prefix+"-ob"
	assessmentA, assessmentB := prefix+"-aa", prefix+"-ab"
	findingA, findingB := prefix+"-fa", prefix+"-fb"
	now := time.Now().UTC().Truncate(time.Microsecond)

	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, []any{tenantA, tenantB}},
		{`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'A'),($3,$4,'B')`, []any{engagementA, tenantA, engagementB, tenantB}},
		{`INSERT INTO advisories(id,data) VALUES($1,'{}')`, []any{advisoryID}},
		{`INSERT INTO sboms(id,tenant_id,engagement_id,target_ref,source) VALUES($1,$2,$3,'a','test'),($4,$5,$6,'b','test')`, []any{sbomA, tenantA, engagementA, sbomB, tenantB, engagementB}},
		{`INSERT INTO components(id,tenant_id,sbom_id,name,version,purl,ecosystem,package_name,identity_hash,identity_status) VALUES($1,$2,$3,'pkg','1.0','pkg:npm/pkg@1.0','npm','pkg','fp-a','resolved'),($4,$5,$6,'pkg','1.0','pkg:npm/pkg@1.0','npm','pkg','fp-b','resolved')`, []any{componentA, tenantA, sbomA, componentB, tenantB, sbomB}},
		{`INSERT INTO vulnerability_occurrences(tenant_id,id,engagement_id,advisory_id,component_id,sbom_id,component_fingerprint,ecosystem,package_name,component_version,match_method,confidence,advisory_revision,state) VALUES($1,$2,$3,$4,$5,$6,'fp-a','npm','pkg','1.0','package_range','high',1,'detected'),($7,$8,$9,$4,$10,$11,'fp-b','npm','pkg','1.0','package_range','high',1,'detected')`, []any{tenantA, occurrenceA, engagementA, advisoryID, componentA, sbomA, tenantB, occurrenceB, engagementB, componentB, sbomB}},
		{`INSERT INTO vulnerability_risk_assessments(tenant_id,id,engagement_id,occurrence_id,advisory_id,component_fingerprint,advisory_revision,severity,occurrence_state,risk_score,priority,model_version,input_hash,assessed_at) VALUES($1,$2,$3,$4,$5,'fp-a',1,'high','detected',8,1,'risk-v1',$6,$7),($8,$9,$10,$11,$5,'fp-b',1,'high','detected',8,1,'risk-v1',$12,$7)`, []any{tenantA, assessmentA, engagementA, occurrenceA, advisoryID, prefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now, tenantB, assessmentB, engagementB, occurrenceB, prefix + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},
		{`INSERT INTO findings(id,tenant_id,engagement_id,title,advisory_id,occurrence_id,component_fingerprint,risk_assessment_id) VALUES($1,$2,$3,'A',$4,$5,'fp-a',$6),($7,$8,$9,'B',$4,$10,'fp-b',$11)`, []any{findingA, tenantA, engagementA, advisoryID, occurrenceA, assessmentA, findingB, tenantB, engagementB, occurrenceB, assessmentB}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed 0095 fixture: %v", err)
		}
	}

	role := "m95_runtime_" + randHex(t)
	for _, statement := range []string{
		`CREATE ROLE ` + role + ` NOSUPERUSER NOBYPASSRLS`,
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT,INSERT,UPDATE ON vulnerability_risk_transitions,vulnerability_actions,vulnerability_action_outbox TO ` + role,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("role setup: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM vulnerability_action_outbox WHERE tenant_id IN ($1,$2)`, tenantA, tenantB)
		_, _ = pool.Exec(bg, `DELETE FROM vulnerability_actions WHERE tenant_id IN ($1,$2)`, tenantA, tenantB)
		_, _ = pool.Exec(bg, `DELETE FROM vulnerability_risk_transitions WHERE tenant_id IN ($1,$2)`, tenantA, tenantB)
		_, _ = pool.Exec(bg, `DELETE FROM findings WHERE id IN ($1,$2)`, findingA, findingB)
		_, _ = pool.Exec(bg, `DELETE FROM vulnerability_risk_assessments WHERE id IN ($1,$2)`, assessmentA, assessmentB)
		_, _ = pool.Exec(bg, `DELETE FROM vulnerability_occurrences WHERE id IN ($1,$2)`, occurrenceA, occurrenceB)
		_, _ = pool.Exec(bg, `DELETE FROM advisories WHERE id=$1`, advisoryID)
		_, _ = pool.Exec(bg, `DELETE FROM sboms WHERE id IN ($1,$2)`, sbomA, sbomB)
		_, _ = pool.Exec(bg, `DELETE FROM engagements WHERE id IN ($1,$2)`, engagementA, engagementB)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantA, tenantB)
		_, _ = pool.Exec(bg, `DROP OWNED BY `+role)
		_, _ = pool.Exec(bg, `DROP ROLE IF EXISTS `+role)
	})

	change := vulnerabilityaction.Change{
		Transition: vulnerabilityaction.Transition{
			TenantID: shared.ID(tenantA), ID: shared.ID(prefix + "-transition"), EngagementID: shared.ID(engagementA), OccurrenceID: shared.ID(occurrenceA), AdvisoryID: advisoryID,
			Type: vulnerabilityaction.TransitionNewExposure, AfterAssessmentID: shared.ID(assessmentA), AfterOccurrenceState: vulnerabilityoccurrence.StateDetected, ReasonCodes: []string{"first_detected"}, CreatedAt: now,
		},
		Action: vulnerabilityaction.Action{
			TenantID: shared.ID(tenantA), ID: shared.ID(prefix + "-action"), EngagementID: shared.ID(engagementA), OccurrenceID: shared.ID(occurrenceA), FindingID: shared.ID(findingA), TransitionID: shared.ID(prefix + "-transition"),
			Type: vulnerabilityaction.ActionNewExposure, Status: vulnerabilityaction.ActionOpen, Title: "Review new exposure " + advisoryID, ReasonCodes: []string{"first_detected"}, CreatedAt: now, UpdatedAt: now,
		},
		Outbox: vulnerabilityaction.OutboxEvent{
			TenantID: shared.ID(tenantA), ID: shared.ID(prefix + "-outbox"), ActionID: shared.ID(prefix + "-action"), IdempotencyKey: prefix + "-outbox", EventType: "vulnerability_action.created",
			Payload: []byte(`{"action_id":"` + prefix + `-action"}`), State: vulnerabilityaction.OutboxPending, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		},
	}
	store := NewVulnerabilityActionStore(pool)
	tenantACtx := shared.WithTenant(ctx, shared.ID(tenantA))
	created, err := store.RecordChange(tenantACtx, change)
	if err != nil || !created {
		t.Fatalf("record action change created=%v err=%v", created, err)
	}
	created, err = store.RecordChange(tenantACtx, change)
	if err != nil || created {
		t.Fatalf("replay action change created=%v err=%v", created, err)
	}
	for table, id := range map[string]string{
		"vulnerability_risk_transitions": change.Transition.ID.String(),
		"vulnerability_actions":          change.Action.ID.String(),
		"vulnerability_action_outbox":    change.Outbox.ID.String(),
	} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND id=$2`, tenantA, id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count=%d err=%v, want 1", table, count, err)
		}
	}

	underRole := func(tenant string, fn func(pgx.Tx) error) error {
		return WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
				return err
			}
			return fn(tx)
		})
	}
	if err := underRole(tenantB, func(tx pgx.Tx) error {
		for table, id := range map[string]string{
			"vulnerability_actions":       change.Action.ID.String(),
			"vulnerability_action_outbox": change.Outbox.ID.String(),
		} {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE id=$1`, id).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatalf("hostile tenant read %s by known id", table)
			}
			tag, err := tx.Exec(ctx, `UPDATE `+table+` SET updated_at=$1 WHERE id=$2`, now.Add(time.Minute), id)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Fatalf("hostile tenant mutated %s by known id", table)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("hostile tenant probe: %v", err)
	}

	crossTransition := prefix + "-cross-transition"
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_risk_transitions(tenant_id,id,engagement_id,occurrence_id,advisory_id,transition_type,after_assessment_id,after_occurrence_state,created_at) VALUES($1,$2,$3,$4,$5,'risk_review',$6,'detected',$7)`, tenantA, crossTransition, engagementA, occurrenceA, advisoryID, assessmentA, now); err == nil {
		t.Fatal("invalid transition type unexpectedly accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_risk_transitions(tenant_id,id,engagement_id,occurrence_id,advisory_id,transition_type,after_assessment_id,after_occurrence_state,created_at) VALUES($1,$2,$3,$4,$5,'escalation',$6,'detected',$7)`, tenantA, crossTransition, engagementA, occurrenceA, advisoryID, assessmentA, now); err != nil {
		t.Fatalf("seed cross-tenant transition: %v", err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO vulnerability_actions(tenant_id,id,engagement_id,occurrence_id,finding_id,transition_id,action_type,status,title,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,'escalation','open','cross',$7,$7)`, tenantA, prefix+"-cross-action", engagementA, occurrenceA, findingB, crossTransition, now)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("cross-tenant finding reference must fail with FK violation, got %v", err)
	}
}
