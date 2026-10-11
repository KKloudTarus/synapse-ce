package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type redriveAuditFailure struct{ next ports.AuditLogger }

func (a redriveAuditFailure) Record(ctx context.Context, entry ports.AuditEntry) error {
	if err := a.next.Record(ctx, entry); err != nil {
		return err
	}
	return errors.New("injected failure after audit append")
}

func TestNotificationPostgresRedriveEligibilityIsolationAndAuditRollback(t *testing.T) {
	pool := notificationTestPool(t) // non-superuser, NOBYPASSRLS runtime role
	ctx, cancel := context.WithTimeout(shared.WithTenant(context.Background(), "redrive-a"), 30*time.Second)
	defer cancel()
	tenant := shared.ID("redrive-a")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('redrive-a','A'),('redrive-b','B')`); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	clock := &notificationTestClock{at: time.Now().UTC()}
	ids := &notificationTestIDs{}
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("r", 32)))
	audit := NewAuditLog(pool)
	runner := NewTenantTransactionRunner(pool)
	svc, err := notificationuc.NewService(repo, cipher, nil, audit, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(runner)
	channel, err := svc.CreateChannel(ctx, "admin", notificationuc.ChannelInput{
		Name: "Hook", Type: notification.ChannelWebhook, Enabled: true,
		URL: "https://example.test/private-path", Secret: "test-signing-value",
	})
	if err != nil {
		t.Fatal(err)
	}
	did, err := svc.TestChannel(ctx, "admin", channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	queue := NewJobQueue(pool, ids)
	job, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	if err := queue.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnDeadLetter(ctx, *job, errors.New("failed")); err != nil {
		t.Fatal(err)
	}
	input := notificationuc.RedriveInput{Reason: "Receiver repaired", ExpectedFence: job.Fence}
	other := shared.WithTenant(ctx, "redrive-b")
	if _, err := svc.RedriveDelivery(other, "admin", did, input); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant service error=%v", err)
	}
	if _, _, err := repo.RedriveDelivery(other, "redrive-b", did, job.Fence); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant repository error=%v", err)
	}
	for _, tc := range []struct{ name, mutation string }{
		{"pending", `UPDATE notification_deliveries SET state='pending' WHERE tenant_id=$1 AND id=$2`},
		{"retrying", `UPDATE notification_deliveries SET state='retrying' WHERE tenant_id=$1 AND id=$2`},
		{"delivered", `UPDATE notification_deliveries SET state='delivered' WHERE tenant_id=$1 AND id=$2`},
		{"cancelled", `UPDATE notification_deliveries SET state='cancelled' WHERE tenant_id=$1 AND id=$2`},
		{"missing job", `DELETE FROM jobs WHERE tenant_id=$1 AND id='notification-'||$2`},
		{"wrong payload", `UPDATE jobs SET payload='{"delivery_id":"other"}' WHERE tenant_id=$1 AND id='notification-'||$2`},
		{"missing payload identity", `UPDATE jobs SET payload='{}' WHERE tenant_id=$1 AND id='notification-'||$2`},
		{"wrong kind", `UPDATE jobs SET kind='other' WHERE tenant_id=$1 AND id='notification-'||$2`},
		{"live lease", `UPDATE jobs SET claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id='notification-'||$2`},
		{"disabled channel", `UPDATE notification_channels SET enabled=false WHERE tenant_id=$1 AND id=(SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2)`},
		{"deleted channel", `UPDATE notification_channels SET deleted_at=now() WHERE tenant_id=$1 AND id=(SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2)`},
		{"paused channel", `UPDATE notification_channels SET paused_at=now(),paused_reason='consecutive_permanent_failures' WHERE tenant_id=$1 AND id=(SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rollback := errors.New("rollback scenario fixture")
			err := runner.Run(ctx, tenant, func(txCtx context.Context) error {
				if err := WithTenant(txCtx, pool, tenant.String(), func(tx pgx.Tx) error {
					_, err := tx.Exec(txCtx, tc.mutation, tenant, did)
					return err
				}); err != nil {
					return err
				}
				if _, _, err := repo.RedriveDelivery(txCtx, tenant, did, job.Fence); !errors.Is(err, shared.ErrConflict) {
					t.Errorf("ineligible redrive error=%v", err)
				}
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatal(err)
			}
		})
	}
	broken, err := notificationuc.NewService(repo, cipher, nil, redriveAuditFailure{audit}, clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	broken.SetTransactionRunner(runner)
	if _, err := broken.RedriveDelivery(ctx, "admin", did, input); err == nil {
		t.Fatal("accepted a failed audit append")
	}
	dead, err := repo.GetDelivery(ctx, tenant, did)
	if err != nil || dead.State != notification.DeliveryDead || dead.RedriveFence != job.Fence {
		t.Fatalf("audit failure left a delivery change: %+v %v", dead, err)
	}
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var count, attempts int
		var state string
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='notification.delivery_redriven'`, tenant).Scan(&count); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT status,attempts FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, job.ID).Scan(&state, &attempts); err != nil {
			return err
		}
		if count != 0 || state != "failed" || attempts != job.Attempts {
			t.Errorf("partial redrive committed: audits=%d state=%s attempts=%d", count, state, attempts)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RedriveDelivery(ctx, "admin", did, input); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestNotificationPostgresRedriveEmailRequiresOriginalRecipient(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := shared.WithTenant(context.Background(), "redrive-email")
	tenant := shared.ID("redrive-email")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Email')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	ids := &notificationTestIDs{}
	cipher, _ := vault.NewCipher([]byte(strings.Repeat("e", 32)))
	svc, err := notificationuc.NewService(repo, cipher, nil, NewAuditLog(pool), &notificationTestClock{at: time.Now().UTC()}, ids)
	if err != nil {
		t.Fatal(err)
	}
	svc.SetTransactionRunner(NewTenantTransactionRunner(pool))
	channel, err := svc.CreateChannel(ctx, "admin", notificationuc.ChannelInput{
		Name: "Email", Type: notification.ChannelEmail, Enabled: true, Recipients: []string{"original@example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	did, err := svc.TestChannel(ctx, "admin", channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	queue := NewJobQueue(pool, ids)
	job, err := queue.Claim(ctx, time.Minute, notificationuc.JobKind)
	if err != nil || job == nil {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	if err := queue.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	if err := svc.OnDeadLetter(ctx, *job, errors.New("failed")); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdateChannel(ctx, "admin", channel.ID, notificationuc.ChannelInput{
		Name: channel.Name, Type: channel.Type, Enabled: true, Revision: channel.Revision, Recipients: []string{"replacement@example.test"}, AllowDestinationChange: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.SecretVersion != channel.SecretVersion {
		t.Fatal("fixture no longer models recipient edits without sealed-version rotation")
	}
	input := notificationuc.RedriveInput{Reason: "Recipient edited", ExpectedFence: job.Fence}
	if _, err := svc.RedriveDelivery(ctx, "admin", did, input); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("removed recipient redrive error=%v", err)
	}
}
