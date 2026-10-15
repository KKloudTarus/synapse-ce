package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRemainingNotificationDeliveryRetainsOnlyStillAuthorizedApprovalRoles(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("remaining-approval-delivery-roles")
	at := time.Date(2026, time.October, 14, 1, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	remainingDeliveryUser(t, ctx, pool, tenant, "lead-member", "member", at)
	remainingDeliveryUser(t, ctx, pool, tenant, "approver-demoted", "reviewer", at)

	repo := NewNotificationRepository(pool)
	rule := notification.Rule{
		TenantID: tenant, ID: "approval-lead", Name: "Approval engagement lead", Enabled: true,
		EventType: notification.EventApprovalRequested, RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: at, UpdatedAt: at,
	}
	if _, err := repo.CreateRule(shared.WithTenant(ctx, tenant), rule); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"approval_id": "approval-1", "engagement_id": "engagement", "lead_user_id": "lead-member", "kind": "agent", "status": "pending",
		"approver_user_ids": []string{"approver-demoted"}, "title": "Approval requested", "summary": "A governed action needs review.",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "approval-requested", Type: notification.EventApprovalRequested, SourceKind: "approval", SourceID: "approval-1:requested", EngagementID: "engagement", SchemaVersion: 1, OccurredAt: at, Data: raw}
	if _, err := repo.Publish(shared.WithTenant(ctx, tenant), event); err != nil {
		t.Fatal(err)
	}
	remainingAssertCapturedRoles(t, ctx, pool, tenant, "lead-member", event.ID, `["engagement_lead"]`)
	remainingAssertCapturedRoles(t, ctx, pool, tenant, "approver-demoted", event.ID, `["approver"]`)
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND kind='personal.email'`, tenant); got != 2 {
		t.Fatalf("approval email jobs=%d, want 2", got)
	}

	store := NewInboxStore(pool)
	for _, user := range []shared.ID{"lead-member", "approver-demoted"} {
		if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, user, event.ID, shared.ID("email-"+user.String()), 1, notification.PersonalEmail); err != nil || !ok {
			t.Fatalf("queued approval email user=%s admitted=%v err=%v", user, ok, err)
		}
	}
	personalExec(t, ctx, pool, tenant, `UPDATE users SET role='member' WHERE ownership_tenant_id=$1 AND id='approver-demoted'`, tenant)
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "lead-member", event.ID, "email-lead-member", 1, notification.PersonalEmail); err != nil || !ok {
		t.Fatalf("member engagement lead email admitted=%v err=%v", ok, err)
	}
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "approver-demoted", event.ID, "email-approver-demoted", 1, notification.PersonalEmail); err != nil || ok {
		t.Fatalf("demoted approver email admitted=%v err=%v", ok, err)
	}
}

func TestRemainingNotificationDeliveryRejectsFormerMandatoryAdminButKeepsLead(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("remaining-evidence-delivery-roles")
	at := time.Date(2026, time.October, 14, 1, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	remainingDeliveryUser(t, ctx, pool, tenant, "lead-reviewer", "reviewer", at)
	remainingDeliveryUser(t, ctx, pool, tenant, "former-admin", "admin", at)

	repo := NewNotificationRepository(pool)
	rule := notification.Rule{
		TenantID: tenant, ID: "evidence-lead", Name: "Evidence engagement lead", Enabled: true,
		EventType: notification.EventEvidenceChainBroken, RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: at, UpdatedAt: at,
	}
	if _, err := repo.CreateRule(shared.WithTenant(ctx, tenant), rule); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"engagement_id": "engagement", "lead_user_id": "lead-reviewer", "evidence_chain_id": "chain-1", "reason_code": "hash_mismatch",
		"title": "Evidence chain broken", "summary": "Evidence verification failed.",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "evidence-broken", Type: notification.EventEvidenceChainBroken, SourceKind: "evidence_chain", SourceID: "chain-1", EngagementID: "engagement", Severity: shared.SeverityCritical, SchemaVersion: 1, OccurredAt: at, Data: raw}
	if _, err := repo.Publish(shared.WithTenant(ctx, tenant), event); err != nil {
		t.Fatal(err)
	}
	remainingAssertCapturedRoles(t, ctx, pool, tenant, "lead-reviewer", event.ID, `["engagement_lead"]`)
	remainingAssertCapturedRoles(t, ctx, pool, tenant, "former-admin", event.ID, `["tenant_admin"]`)
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND kind='personal.email'`, tenant); got != 2 {
		t.Fatalf("evidence email jobs=%d, want 2", got)
	}

	store := NewInboxStore(pool)
	for _, user := range []shared.ID{"lead-reviewer", "former-admin"} {
		if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, user, event.ID, shared.ID("email-"+user.String()), 1, notification.PersonalEmail); err != nil || !ok {
			t.Fatalf("queued evidence email user=%s admitted=%v err=%v", user, ok, err)
		}
	}
	personalExec(t, ctx, pool, tenant, `UPDATE users SET role='member' WHERE ownership_tenant_id=$1 AND id='former-admin'`, tenant)
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "lead-reviewer", event.ID, "email-lead-reviewer", 1, notification.PersonalEmail); err != nil || !ok {
		t.Fatalf("reviewer engagement lead email admitted=%v err=%v", ok, err)
	}
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "former-admin", event.ID, "email-former-admin", 1, notification.PersonalEmail); err != nil || ok {
		t.Fatalf("former mandatory admin email admitted=%v err=%v", ok, err)
	}
}

func remainingDeliveryUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, user shared.ID, role string, at time.Time) {
	t.Helper()
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES($1,$1,$2,$3,$4,false)`, user, role, "key-"+user.String(), tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES
		($1,$2,'approval.requested','email','enabled',1,$3),
		($1,$2,'evidence.chain_broken','email','enabled',1,$3)`, tenant, user, at)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES($1,$2,$3,'email','manual',$4,$5,1,$5,$5)`, tenant, "email-"+user.String(), user, user.String()+"@example.test", at)
}

func remainingAssertCapturedRoles(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, user, event shared.ID, want string) {
	t.Helper()
	var got string
	err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT recipient_roles::text FROM user_notifications WHERE tenant_id=$1 AND user_id=$2 AND event_id=$3`, tenant, user, event).Scan(&got)
	})
	if err != nil {
		t.Fatalf("load captured roles user=%s event=%s: %v", user, event, err)
	}
	if got != want {
		t.Fatalf("captured roles user=%s event=%s got=%s want=%s", user, event, got, want)
	}
}
