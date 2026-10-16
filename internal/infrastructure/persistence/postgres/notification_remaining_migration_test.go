package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestRemainingNotificationMigrationReappliesAfterEmptyRollback(t *testing.T) {
	db := remainingNotificationMigrationDB(t)
	requireMigrationTable(t, db, "finding_comment_mentions", true)
	requireMigrationRLS(t, db, "finding_comment_mentions")
	requireMigrationTable(t, db, "notification_approval_recipients", true)
	requireMigrationRLS(t, db, "notification_approval_recipients")
	requireMigrationIndexes(t, db, "idx_engagement_notification_window_start", "idx_engagement_notification_window_end")

	if err := goose.DownTo(db, ".", 237); err != nil {
		t.Fatalf("rollback empty remaining-notification migration: %v", err)
	}
	requireMigrationTable(t, db, "finding_comment_mentions", false)
	requireMigrationTable(t, db, "notification_approval_recipients", false)
	if err := goose.UpTo(db, ".", 238); err != nil {
		t.Fatalf("reapply remaining-notification migration: %v", err)
	}
	requireMigrationTable(t, db, "finding_comment_mentions", true)
	requireMigrationRLS(t, db, "finding_comment_mentions")
	requireMigrationTable(t, db, "notification_approval_recipients", true)
	requireMigrationRLS(t, db, "notification_approval_recipients")
}

func TestRemainingNotificationMigrationRollbackRetainsDurableData(t *testing.T) {
	for _, fixture := range []struct {
		name string
		seed func(t *testing.T, db *sql.DB, tenant string)
	}{
		{
			name: "immutable mention",
			seed: func(t *testing.T, db *sql.DB, tenant string) {
				withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
					if _, err := tx.Exec(`INSERT INTO finding_comment_mentions(tenant_id,comment_id,user_id) VALUES($1,$2,$3)`, tenant, tenant+"-comment", tenant+"-user-0"); err != nil {
						t.Fatalf("record immutable mention: %v", err)
					}
				})
			},
		},
		{
			name: "immutable approval recipient snapshot",
			seed: func(t *testing.T, db *sql.DB, tenant string) {
				withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
					if _, err := tx.Exec(`INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data)
						VALUES($1,'approval_requested','approval-snapshot','approval.requested',now(),'{"approver_count":1}')`, tenant); err != nil {
						t.Fatalf("record approval source: %v", err)
					}
					if _, err := tx.Exec(`INSERT INTO notification_approval_recipients(tenant_id,source_kind,source_id,user_id)
						VALUES($1,'approval_requested','approval-snapshot',$2)`, tenant, tenant+"-user-0"); err != nil {
						t.Fatalf("record approval recipient snapshot: %v", err)
					}
				})
			},
		},
		{
			name: "recipient role rule",
			seed: func(t *testing.T, db *sql.DB, tenant string) {
				withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
					if _, err := tx.Exec(`INSERT INTO notification_rules(tenant_id,id,name,event_type,recipient_roles,created_at,updated_at)
						VALUES($1,'role-rule','Role rule','scan.completed','["mentioned_user"]',now(),now())`, tenant); err != nil {
						t.Fatalf("record recipient role rule: %v", err)
					}
				})
			},
		},
		{
			name: "personal recipient facts",
			seed: func(t *testing.T, db *sql.DB, tenant string) {
				withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
					if _, err := tx.Exec(`INSERT INTO notification_events(tenant_id,id,source_kind,source_id,event_type,schema_version,occurred_at,data) VALUES($1,'personal-event','engagement','personal','engagement.created',1,now(),'{}')`, tenant); err != nil {
						t.Fatal(err)
					}
					if _, err := tx.Exec(`INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at,recipient_roles) VALUES($1,$2,'notice','personal-event','engagement.created','Created','Created','/engagements/assessment',now(),'["engagement_lead"]')`, tenant, tenant+"-user-0"); err != nil {
						t.Fatal(err)
					}
				})
			},
		},
		{
			name: "pending source capture",
			seed: func(t *testing.T, db *sql.DB, tenant string) {
				withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
					if _, err := tx.Exec(`INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data)
						VALUES($1,'engagement','pending','engagement.created',now(),'{}')`, tenant); err != nil {
						t.Fatalf("record pending source capture: %v", err)
					}
				})
			},
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			db := remainingNotificationMigrationDB(t)
			tenant := "remaining-retained-" + strings.ReplaceAll(fixture.name, " ", "-")
			seedRemainingNotificationComment(t, db, tenant, 1)
			fixture.seed(t, db, tenant)

			err := goose.DownTo(db, ".", 237)
			if err == nil || !strings.Contains(err.Error(), "remaining event captures, role rules and immutable mentions") {
				t.Fatalf("rollback with %s = %v, want durable-data refusal", fixture.name, err)
			}
		})
	}
}

func TestRemainingNotificationMigrationPersonalRecipientRolesAreImmutable(t *testing.T) {
	db := remainingNotificationMigrationDB(t)
	const tenant = "recipient-role-snapshot"
	seedRemainingNotificationComment(t, db, tenant, 1)
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO notification_events(tenant_id,id,source_kind,source_id,event_type,schema_version,occurred_at,data) VALUES($1,'event','engagement','created','engagement.created',1,now(),'{}')`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at,recipient_roles) VALUES($1,$2,'notice','event','engagement.created','Created','Created','/engagements/assessment',now(),'["engagement_lead"]')`, tenant, tenant+"-user-0"); err != nil {
			t.Fatal(err)
		}
		requireMigrationWriteRejected(t, tx, `UPDATE user_notifications SET recipient_roles='["approver"]' WHERE tenant_id=$1 AND id='notice'`, tenant)
		if _, err := tx.Exec(`UPDATE user_notifications SET read_at=now() WHERE tenant_id=$1 AND id='notice'`, tenant); err != nil {
			t.Fatalf("mark read with retained recipient facts: %v", err)
		}
		var roles string
		var read bool
		if err := tx.QueryRow(`SELECT recipient_roles::text,read_at IS NOT NULL FROM user_notifications WHERE tenant_id=$1 AND id='notice'`, tenant).Scan(&roles, &read); err != nil || roles != `["engagement_lead"]` || !read {
			t.Fatalf("stored roles=%s read=%t err=%v", roles, read, err)
		}
	})
}

func TestRemainingNotificationMigrationMentionsAreTenantScopedAndImmutable(t *testing.T) {
	db := remainingNotificationMigrationDB(t)
	const tenantA = "remaining-mentions-a"
	const tenantB = "remaining-mentions-b"
	seedRemainingNotificationComment(t, db, tenantA, 11)
	seedRemainingNotificationComment(t, db, tenantB, 1)

	withMigrationTenant(t, db, tenantA, func(tx *sql.Tx) {
		for index := 0; index < 10; index++ {
			if _, err := tx.Exec(`INSERT INTO finding_comment_mentions(tenant_id,comment_id,user_id) VALUES($1,$2,$3)`, tenantA, tenantA+"-comment", fmt.Sprintf("%s-user-%d", tenantA, index)); err != nil {
				t.Fatalf("insert mention %d: %v", index, err)
			}
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO finding_comment_mentions(tenant_id,comment_id,user_id) VALUES($1,$2,$3)`, tenantA, tenantA+"-comment", tenantA+"-user-10")
		requireMigrationWriteRejected(t, tx, `UPDATE finding_comment_mentions SET user_id=$4 WHERE tenant_id=$1 AND comment_id=$2 AND user_id=$3`, tenantA, tenantA+"-comment", tenantA+"-user-0", tenantA+"-user-10")
		requireMigrationWriteRejected(t, tx, `DELETE FROM finding_comment_mentions WHERE tenant_id=$1 AND comment_id=$2 AND user_id=$3`, tenantA, tenantA+"-comment", tenantA+"-user-0")
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM finding_comment_mentions WHERE tenant_id=$1 AND comment_id=$2`, tenantA, tenantA+"-comment").Scan(&count); err != nil || count != 10 {
			t.Fatalf("retained mentions=%d err=%v", count, err)
		}
	})

	withMigrationTenant(t, db, tenantB, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM finding_comment_mentions WHERE tenant_id=$1 AND comment_id=$2`, tenantA, tenantA+"-comment").Scan(&count); err != nil || count != 0 {
			t.Fatalf("foreign mention relation count=%d err=%v", count, err)
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO finding_comment_mentions(tenant_id,comment_id,user_id) VALUES($1,$2,$3)`, tenantA, tenantA+"-comment", tenantA+"-user-0")
	})
}

func TestRemainingNotificationMigrationApprovalRecipientsAreTenantScopedAndImmutable(t *testing.T) {
	db := remainingNotificationMigrationDB(t)
	const tenantA = "remaining-approvals-a"
	const tenantB = "remaining-approvals-b"
	seedRemainingNotificationComment(t, db, tenantA, 2)
	seedRemainingNotificationComment(t, db, tenantB, 1)

	withMigrationTenant(t, db, tenantA, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data)
			VALUES($1,'approval_requested','approval-source','approval.requested',now(),'{"approver_count":1}')`, tenantA); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO notification_approval_recipients(tenant_id,source_kind,source_id,user_id)
			VALUES($1,'approval_requested','approval-source',$2)`, tenantA, tenantA+"-user-0"); err != nil {
			t.Fatal(err)
		}
	})

	// The first transaction committed a complete one-recipient snapshot. A later
	// transaction cannot extend the same source, even with another valid user.
	withMigrationTenant(t, db, tenantA, func(tx *sql.Tx) {
		requireMigrationWriteRejected(t, tx, `INSERT INTO notification_approval_recipients(tenant_id,source_kind,source_id,user_id)
			VALUES($1,'approval_requested','approval-source',$2)`, tenantA, tenantA+"-user-1")
		requireMigrationWriteRejected(t, tx, `UPDATE notification_approval_recipients SET user_id=$4 WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenantA, "approval_requested", "approval-source", tenantA+"-user-1")
		requireMigrationWriteRejected(t, tx, `DELETE FROM notification_approval_recipients WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, tenantA, "approval_requested", "approval-source")
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM notification_approval_recipients WHERE tenant_id=$1 AND source_kind='approval_requested' AND source_id='approval-source'`, tenantA).Scan(&count); err != nil || count != 1 {
			t.Fatalf("approval recipient snapshot count=%d err=%v", count, err)
		}
	})

	withMigrationTenant(t, db, tenantB, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM notification_approval_recipients WHERE tenant_id=$1`, tenantA).Scan(&count); err != nil || count != 0 {
			t.Fatalf("foreign approval recipient snapshot count=%d err=%v", count, err)
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO notification_approval_recipients(tenant_id,source_kind,source_id,user_id)
			VALUES($1,'approval_requested','approval-source',$2)`, tenantA, tenantA+"-user-0")
	})
}

func remainingNotificationMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	isolate := newIsolatedMigrationDB(t, 238, 237)
	if err := goose.UpTo(isolate.db, ".", 238); err != nil {
		t.Fatalf("apply remaining-notification migration: %v", err)
	}
	return isolate.db
}

func seedRemainingNotificationComment(t *testing.T, db *sql.DB, tenant string, users int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, tenant+"-engagement", tenant); err != nil {
			t.Fatalf("create engagement: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($1,$2,$3,'Mention fixture')`, tenant+"-finding", tenant, tenant+"-engagement"); err != nil {
			t.Fatalf("create finding: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO finding_comments(id,tenant_id,engagement_id,finding_id,author,body) VALUES($1,$2,$3,$4,'author','body')`, tenant+"-comment", tenant, tenant+"-engagement", tenant+"-finding"); err != nil {
			t.Fatalf("create finding comment: %v", err)
		}
		for index := 0; index < users; index++ {
			id := fmt.Sprintf("%s-user-%d", tenant, index)
			if _, err := tx.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES($1,$1,'member',$2,$3,false)`, id, "key-"+id, tenant); err != nil {
				t.Fatalf("create mention user %d: %v", index, err)
			}
		}
	})
}

func TestRemainingNotificationMigrationRollbackWaitsForConcurrentMention(t *testing.T) {
	db := remainingNotificationMigrationDB(t)
	const tenant = "concurrent-mention-rollback"
	seedRemainingNotificationComment(t, db, tenant, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	writer, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback()
	if _, err = writer.ExecContext(ctx, `SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.ExecContext(ctx, `INSERT INTO finding_comment_mentions(tenant_id,comment_id,user_id) VALUES($1,$2,$3)`, tenant, tenant+"-comment", tenant+"-user-0"); err != nil {
		t.Fatal(err)
	}
	down := make(chan error, 1)
	go func() { down <- goose.DownTo(db, ".", 237) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE relation IN ('tenants'::regclass,'finding_comments'::regclass,'finding_comment_mentions'::regclass) AND mode='AccessExclusiveLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-down:
			t.Fatalf("rollback finished before writer commit: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-down:
		if err == nil || !strings.Contains(err.Error(), "remaining event captures, role rules and immutable mentions") {
			t.Fatalf("rollback=%v, want durable fact refusal", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	requireMigrationTable(t, db, "finding_comment_mentions", true)
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM finding_comment_mentions WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
			t.Fatalf("retained mentions=%d err=%v", count, err)
		}
	})
}
