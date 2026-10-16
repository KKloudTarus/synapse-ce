package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCommentMentionUsesAmbientUserLookupTransactionWithOneConnection proves that
// canonical mention validation does not acquire a second connection while the
// comment, immutable mention relation, source records, and audit share one tenant
// transaction.
func TestCommentMentionUsesAmbientUserLookupTransactionWithOneConnection(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("mention-single-connection")
	otherTenant := shared.ID("mention-single-connection-other")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenant, otherTenant); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO engagements(id,tenant_id,name) VALUES('mention-single-engagement',$1,'Mention transaction')`, []any{tenant}},
			{`INSERT INTO findings(id,tenant_id,engagement_id,title,severity,status,dedup_key,created_at,updated_at)
				VALUES('mention-single-finding',$1,'mention-single-engagement','Mention target','high','open','mention-single-dedupe',$2,$2)`, []any{tenant, at}},
			{`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled)
				VALUES('mention-single-user','Mentioned user','reviewer','mention-single-key',$1,false)`, []any{tenant}},
			{`INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
				VALUES($1,'framework','activation','v1',true,$2)`, []any{tenant, at.Add(-time.Second)}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	oneConfig := pool.Config()
	oneConfig.MaxConns = 1
	onePool, err := pgxpool.NewWithConfig(ctx, oneConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(onePool.Close)

	comments := NewCommentRepository(onePool)
	service := findingsuc.NewService(
		NewFindingRepository(onePool), comments, NewRetestRepository(onePool), NewAuditLog(onePool),
		&notificationTestClock{at: at}, &notificationTestIDs{},
	)
	service.SetEngagementTenantResolver(NewEngagementRepository(onePool))
	service.SetMentionUsers(NewUserRepository(onePool))
	if err := service.SetNotifications(NewTenantTransactionRunner(onePool), NewNotificationOutbox(onePool), NewNotificationFindingFactsReader(onePool)); err != nil {
		t.Fatal(err)
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	comment, err := service.AddCommentWithMentions(
		deadlineCtx, "mention-single-engagement", "mention-single-finding", "Please review this finding.", "author",
		[]shared.ID{"mention-single-user"},
	)
	if err != nil {
		t.Fatalf("add comment with one connection: %v", err)
	}

	persisted, err := NewCommentRepository(pool).ListByEngagementFinding(ctx, "mention-single-engagement", "mention-single-finding")
	if err != nil || len(persisted) != 1 || persisted[0].ID != comment.ID || len(persisted[0].MentionUserIDs) != 1 || persisted[0].MentionUserIDs[0] != "mention-single-user" {
		t.Fatalf("persisted comments=%+v err=%v", persisted, err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var commented, mentioned int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records
			WHERE tenant_id=$1 AND source_kind='finding_comment' AND source_id=$2 AND event_type=$3`,
			tenant, comment.ID, notification.EventFindingCommented).Scan(&commented); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_source_records
			WHERE tenant_id=$1 AND source_kind='finding_mention' AND source_id=$2 AND event_type=$3`,
			tenant, comment.ID.String()+":mention-single-user", notification.EventFindingMentioned).Scan(&mentioned); err != nil {
			return err
		}
		if commented != 1 || mentioned != 1 {
			return errors.New("comment and mention notification sources were not both persisted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	foreignCtx := shared.WithTenant(context.Background(), otherTenant)
	foreign, err := NewCommentRepository(pool).ListByEngagementFinding(foreignCtx, "mention-single-engagement", "mention-single-finding")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign tenant comments=%+v err=%v", foreign, err)
	}
	if _, err := NewUserRepository(pool).GetByID(foreignCtx, otherTenant, "mention-single-user"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign tenant user lookup error=%v, want not found", err)
	}
	if err := NewTenantTransactionRunner(pool).Run(ctx, tenant, func(txCtx context.Context) error {
		_, err := NewUserRepository(pool).GetByID(txCtx, otherTenant, "mention-single-user")
		if !errors.Is(err, shared.ErrValidation) {
			return errors.New("mismatched ambient tenant lookup did not fail closed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
