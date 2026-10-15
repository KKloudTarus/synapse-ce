package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
)

// The source payload, rather than a rule or a display name, is the authority for
// personal mention routing. This is deliberately an actual Postgres/RLS test.
func TestRemainingNotificationRoutingUsesCapturedCanonicalRecipients(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("remaining-routing")
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),('remaining-routing-other','Other')`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('mentioned','Mentioned','member','m',$1,false),('peer','Peer','admin','p',$1,false)`, tenant)
	personalExec(t, ctx, pool, "remaining-routing-other", `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('mentioned-other','Other','admin','o',$1,false)`, "remaining-routing-other")
	repo := NewNotificationRepository(pool)
	data, err := json.Marshal(map[string]any{"finding_id": "finding", "engagement_id": "engagement", "mentioned_user_id": "mentioned"})
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "mentioned-event", Type: notification.EventFindingMentioned, SourceKind: "finding_mention", SourceID: "comment:mentioned", EngagementID: "engagement", SchemaVersion: 1, OccurredAt: at, Data: data}
	recipients, err := repo.ResolvePersonalRecipients(shared.WithTenant(ctx, tenant), tenant, event)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 1 || recipients[0].UserID != "mentioned" || len(recipients[0].Roles) != 1 || recipients[0].Roles[0] != notification.RoleMentionedUser {
		t.Fatalf("mention recipients=%+v", recipients)
	}
	if _, err := repo.Publish(shared.WithTenant(ctx, tenant), event); err != nil {
		t.Fatal(err)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='mentioned'`, tenant); got != 1 {
		t.Fatalf("mentioned inbox rows=%d", got)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='peer'`, tenant); got != 0 {
		t.Fatalf("peer fanout=%d", got)
	}
}

// An approval carries its reviewer roster as an immutable source fact. It may queue
// a personal delivery, but the worker must decline it when the recipient subsequently
// loses review permission.
func TestRemainingNotificationRoutingRevokesQueuedApprovalDelivery(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("remaining-approval-routing")
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('reviewer','Reviewer','reviewer','reviewer-key',$1,false),('member','Member','member','member-key',$1,false)`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at)
		VALUES($1,'reviewer','approval.requested','email','enabled',1,$2)`, tenant, at)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at)
		VALUES($1,'reviewer-email','reviewer','email','manual','reviewer@example.test',$2,1,$2,$2)`, tenant, at)

	repo := NewNotificationRepository(pool)
	store := NewInboxStore(pool)
	data, err := json.Marshal(map[string]any{
		"approval_id": "approval-1", "engagement_id": "engagement", "kind": "agent", "status": "pending",
		"approver_user_ids": []string{"reviewer"}, "title": "Approval requested", "summary": "A governed action needs review.",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "approval-requested", Type: notification.EventApprovalRequested, SourceKind: "approval", SourceID: "approval-1:requested", EngagementID: "engagement", SchemaVersion: 1, OccurredAt: at, Data: data}
	if _, err := repo.Publish(shared.WithTenant(ctx, tenant), event); err != nil {
		t.Fatal(err)
	}
	if jobs := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND kind='personal.email'`, tenant); jobs != 1 {
		t.Fatalf("approval email jobs=%d, want 1", jobs)
	}
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "reviewer", event.ID, "reviewer-email", 1, notification.PersonalEmail); err != nil || !ok {
		t.Fatalf("queued approval delivery ok=%v err=%v", ok, err)
	}

	// A reviewer who is demoted after queueing no longer has PermReview. The loader
	// rechecks this at send time instead of sending a stale approval request.
	personalExec(t, ctx, pool, tenant, `UPDATE users SET role='member' WHERE ownership_tenant_id=$1 AND id='reviewer'`, tenant)
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "reviewer", event.ID, "reviewer-email", 1, notification.PersonalEmail); err != nil || ok {
		t.Fatalf("revoked reviewer delivery ok=%v err=%v", ok, err)
	}
}

// Evidence-chain failures always reach enabled tenant administrators in the inbox,
// even when the administrator explicitly disabled their preference.
func TestRemainingNotificationRoutingEvidenceChainKeepsMandatoryAdminFloor(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("remaining-evidence-floor")
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('admin','Administrator','admin','admin-key',$1,false),('member','Member','member','member-key',$1,false)`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES
		($1,'admin','evidence.chain_broken','in_app','disabled',1,$2),
		($1,'admin','evidence.chain_broken','email','disabled',1,$2),
		($1,'admin','evidence.chain_broken','slack','disabled',1,$2),
		($1,'admin','evidence.chain_broken','teams','disabled',1,$2)`, tenant, at)
	data, err := json.Marshal(map[string]any{
		"engagement_id": "engagement", "lead_user_id": "member", "evidence_chain_id": "chain-1", "reason_code": "hash_mismatch",
		"title": "Evidence chain broken", "summary": "Evidence verification failed.",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "evidence-broken", Type: notification.EventEvidenceChainBroken, SourceKind: "evidence_chain", SourceID: "chain-1", EngagementID: "engagement", Severity: shared.SeverityCritical, SchemaVersion: 1, OccurredAt: at, Data: data}
	if _, err := NewNotificationRepository(pool).Publish(shared.WithTenant(ctx, tenant), event); err != nil {
		t.Fatal(err)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='admin' AND event_id='evidence-broken'`, tenant); got != 1 {
		t.Fatalf("mandatory admin inbox rows=%d, want 1", got)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='member' AND event_id='evidence-broken'`, tenant); got != 0 {
		t.Fatalf("non-admin evidence fanout=%d", got)
	}
}

// A lifecycle event retains the lead present in its immutable snapshot. Replacing
// notification settings before projection cannot reroute that already-captured event.
func TestRemainingNotificationRoutingUsesCapturedLeadAfterSettingsChange(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("remaining-captured-lead")
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	engagement := shared.ID("engagement")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('lead-old','Old lead','reviewer','old-key',$1,false),('lead-new','New lead','reviewer','new-key',$1,false)`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Engagement')`, engagement, tenant)
	repo := NewNotificationRepository(pool)
	if _, err := repo.PutEngagementNotificationSetting(shared.WithTenant(ctx, tenant), notification.EngagementNotificationSetting{
		TenantID: tenant, EngagementID: engagement, ExternalNotifications: notification.EngagementNotificationsInherit, LeadUserID: "lead-old", Revision: 1, UpdatedAt: &at, UpdatedBy: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	rule := notification.Rule{TenantID: tenant, ID: "captured-lead-rule", Name: "Captured engagement lead", Enabled: true, EventType: notification.EventEngagementCreated,
		RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: at, UpdatedAt: at}
	if _, err := repo.CreateRule(shared.WithTenant(ctx, tenant), rule); err != nil {
		t.Fatal(err)
	}
	// The source was sealed while lead-old was authoritative. A later setting write
	// must not alter the source's captured lead ID.
	changedAt := at.Add(time.Second)
	if _, err := repo.PutEngagementNotificationSetting(shared.WithTenant(ctx, tenant), notification.EngagementNotificationSetting{
		TenantID: tenant, EngagementID: engagement, ExternalNotifications: notification.EngagementNotificationsInherit, LeadUserID: "lead-new", Revision: 2, UpdatedAt: &changedAt, UpdatedBy: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{
		"engagement_id": engagement, "lead_user_id": "lead-old", "title": "Engagement created", "summary": "An engagement was created.",
	})
	if err != nil {
		t.Fatal(err)
	}
	event := notification.Event{TenantID: tenant, ID: "engagement-created", Type: notification.EventEngagementCreated, SourceKind: "engagement", SourceID: "engagement:created", EngagementID: engagement, SchemaVersion: 1, OccurredAt: at, Data: data}
	if _, err := repo.Publish(shared.WithTenant(ctx, tenant), event); err != nil {
		t.Fatal(err)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='lead-old' AND event_id='engagement-created'`, tenant); got != 1 {
		t.Fatalf("captured old lead inbox rows=%d, want 1", got)
	}
	if got := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='lead-new' AND event_id='engagement-created'`, tenant); got != 0 {
		t.Fatalf("updated setting rerouted immutable event rows=%d", got)
	}
}

func TestCommentProducerRoutesToCapturedEngagementLead(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("comment-lead")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO engagements(id,tenant_id,name) VALUES('engagement',$1,'Assessment')`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO findings(id,tenant_id,engagement_id,title,severity,status,dedup_key) VALUES('finding',$1,'engagement','Finding','high','open','dedup')`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('old-lead','Old','member','old-key',$1),('new-lead','New','member','new-key',$1)`, tenant)
	repo := NewNotificationRepository(pool)
	repo.SetEventProjector(notificationuc.NewEventBuilders())
	source := NewNotificationSource(pool, repo, time.Minute)
	if _, err := source.Poll(ctx, at.Add(-time.Second), 100); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,lead_user_id,external_notifications,revision,updated_at,updated_by) VALUES($1,'engagement','old-lead','inherit',1,$2,'admin')`, tenant, at)
	if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: "lead-comments", Name: "Lead comments", Enabled: true, EventType: notification.EventFindingCommented, RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: at, UpdatedAt: at}); err != nil {
		t.Fatal(err)
	}
	svc := findingsuc.NewService(NewFindingRepository(pool), NewCommentRepository(pool), NewRetestRepository(pool), NewAuditLog(pool), &notificationTestClock{at}, &notificationTestIDs{})
	svc.SetEngagementTenantResolver(NewEngagementRepository(pool))
	if err := svc.SetNotifications(NewTenantTransactionRunner(pool), NewNotificationOutbox(pool), NewNotificationFindingFactsReader(pool)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddComment(ctx, "engagement", "finding", "Comment for lead", "old-lead"); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `UPDATE notification_engagement_settings SET lead_user_id='new-lead',revision=revision+1 WHERE tenant_id=$1 AND engagement_id='engagement'`, tenant)
	if _, err := source.Poll(ctx, at.Add(time.Second), 100); err != nil {
		t.Fatal(err)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND event_type='finding.commented' AND user_id='old-lead'`, tenant); n != 1 {
		t.Fatalf("captured lead notices=%d", n)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND event_type='finding.commented' AND user_id='new-lead'`, tenant); n != 0 {
		t.Fatalf("new lead got historical comment=%d", n)
	}
	if _, err := source.Poll(ctx, at.Add(2*time.Second), 100); err != nil {
		t.Fatal(err)
	}
	if n := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND event_type='finding.commented'`, tenant); n != 1 {
		t.Fatalf("comment replay notices=%d", n)
	}
}

func TestRemainingPersonalAuthorizationUsesCapturedRole(t *testing.T) {
	for _, tc := range []struct {
		event    notification.EventType
		roles    []string
		userRole string
		want     bool
	}{
		{notification.EventApprovalRequested, []string{notification.RoleApprover}, "member", false},
		{notification.EventApprovalRequested, []string{notification.RoleApprover}, "reviewer", true},
		{notification.EventApprovalRequested, []string{notification.RoleEngagementLead}, "member", true},
		{notification.EventApprovalRequested, []string{notification.RoleApprover, notification.RoleEngagementLead}, "member", true},
		{notification.EventEvidenceChainBroken, []string{notification.RoleTenantAdmin}, "reviewer", false},
		{notification.EventEvidenceChainBroken, []string{notification.RoleEngagementLead}, "reviewer", true},
	} {
		if got := personalRecipientAuthorized(tc.event, tc.roles, tc.userRole); got != tc.want {
			t.Fatalf("event=%s roles=%v currentRole=%s got=%v", tc.event, tc.roles, tc.userRole, got)
		}
	}
}

func TestWindowPersonalDeliveryRejectsRescheduledBoundary(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("window-personal")
	ctx := shared.WithTenant(context.Background(), tenant)
	at := time.Now().UTC().Truncate(time.Microsecond)
	boundary := at.Add(time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('lead','Lead','member','lead-key',$1)`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO engagements(id,tenant_id,name,authorized_from) VALUES('engagement',$1,'Assessment',$2)`, tenant, boundary)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES($1,'lead','engagement.window_starting','email','enabled',1,$2)`, tenant, at)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES($1,'email','lead','email','manual','lead@example.test',$2,1,$2,$2)`, tenant, at)
	repo := NewNotificationRepository(pool)
	if _, err := repo.CreateRule(ctx, notification.Rule{TenantID: tenant, ID: "window-lead", Name: "Window lead", Enabled: true, EventType: notification.EventEngagementWindowStarting, LeadTime: time.Hour, RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: at, UpdatedAt: at}); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"title": "Window starting", "summary": "Authorization starts soon.", "engagement_id": "engagement", "lead_user_id": "lead", "boundary": "authorized_from", "authorized_from": boundary, "lead_time_seconds": 3600})
	event := notification.Event{TenantID: tenant, ID: "warning", Type: notification.EventEngagementWindowStarting, SourceKind: "window", SourceID: "boundary", EngagementID: "engagement", SchemaVersion: 1, OccurredAt: at, Data: data}
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	store := NewInboxStore(pool)
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "lead", event.ID, "email", 1, notification.PersonalEmail); err != nil || !ok {
		t.Fatalf("current window admitted=%v err=%v", ok, err)
	}
	personalExec(t, ctx, pool, tenant, `UPDATE engagements SET authorized_from=$2 WHERE tenant_id=$1 AND id='engagement'`, tenant, boundary.Add(time.Minute))
	if _, ok, err := store.LoadPersonalDelivery(ctx, tenant, "lead", event.ID, "email", 1, notification.PersonalEmail); err != nil || ok {
		t.Fatalf("obsolete window admitted=%v err=%v", ok, err)
	}
}
