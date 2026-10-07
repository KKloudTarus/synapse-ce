package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// personalEngagement is one tenant whose member has an enabled ownership email preference and a
// verified address, for the #1360 checks of an engagement's none on personal email.
type personalEngagement struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	tenant shared.ID
	repo   *NotificationRepository
	store  *InboxStore
	now    time.Time
}

func newPersonalEngagement(t *testing.T, tenant shared.ID) *personalEngagement {
	t.Helper()
	pool := notificationTestPool(t)
	p := &personalEngagement{ctx: context.Background(), pool: pool, tenant: tenant, repo: NewNotificationRepository(pool), store: NewInboxStore(pool),
		now: time.Now().UTC().Truncate(time.Microsecond)}
	if _, err := pool.Exec(p.ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	personalExec(t, p.ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('member-1','Member','member','hash-member-1',$1,false)`, tenant)
	personalExec(t, p.ctx, pool, tenant, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Engagement')`, tenant.String()+"-eng", tenant)
	personalExec(t, p.ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at)
		VALUES($1,'member-1','finding.ownership_changed','email','enabled',1,$2)`, tenant, p.now)
	personalExec(t, p.ctx, pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at)
		VALUES($1,'contact-1','member-1','email','manual','member@example.test',$2,1,$2,$2)`, tenant, p.now)
	return p
}

func (p *personalEngagement) engagement() shared.ID { return shared.ID(p.tenant.String() + "-eng") }

// publish records an ownership change about the engagement, assigned to member-1.
func (p *personalEngagement) publish(t *testing.T, id string) shared.ID {
	t.Helper()
	data, _ := json.Marshal(notification.OwnershipChanged{DecisionID: shared.ID("decision-" + id), FindingID: shared.ID("finding-" + id), EngagementID: p.engagement(), NewAssigneeID: "member-1"})
	event := notification.Event{TenantID: p.tenant, ID: shared.ID("event-" + id), Type: notification.EventOwnershipChanged, SourceKind: "ownership_decision",
		SourceID: "decision-" + id, EngagementID: p.engagement(), SchemaVersion: 1, OccurredAt: p.now, Data: data}
	if _, err := p.repo.Publish(p.ctx, event); err != nil {
		t.Fatal(err)
	}
	return event.ID
}

func (p *personalEngagement) setNone(t *testing.T) {
	t.Helper()
	at := p.now.Add(time.Second)
	if _, err := p.repo.PutEngagementNotificationSetting(p.ctx, notification.EngagementNotificationSetting{TenantID: p.tenant, EngagementID: p.engagement(),
		ExternalNotifications: notification.EngagementNotificationsNone, Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
}

func (p *personalEngagement) mail(t *testing.T, event shared.ID) bool {
	t.Helper()
	_, _, _, ok, err := p.store.LoadPersonalMail(p.ctx, p.tenant, "member-1", event, "contact-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// TestPersonalEmailHonoursEngagementNoneAtPublication sets none before the event is published: the
// member still gets the in-app notice, but no personal email job is queued and none would send.
func TestPersonalEmailHonoursEngagementNoneAtPublication(t *testing.T) {
	p := newPersonalEngagement(t, "personal-none-first")
	p.setNone(t)
	event := p.publish(t, "first")
	if n := personalCount(t, p.ctx, p.pool, p.tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id=$1 AND user_id='member-1'`, p.tenant); n != 1 {
		t.Fatalf("in-app notices = %d, want 1: the inbox stays inside Synapse", n)
	}
	if n := personalCount(t, p.ctx, p.pool, p.tenant, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND kind='personal.email'`, p.tenant); n != 0 {
		t.Fatalf("personal email jobs = %d, want 0", n)
	}
	if p.mail(t, event) {
		t.Fatal("personal email admitted for an engagement set to none")
	}
}

// TestPersonalEmailHonoursEngagementNoneAfterQueueing queues the email while the engagement
// inherits, then commits none before the mail worker admits it: the queued job must not send.
func TestPersonalEmailHonoursEngagementNoneAfterQueueing(t *testing.T) {
	p := newPersonalEngagement(t, "personal-none-after")
	event := p.publish(t, "after")
	if n := personalCount(t, p.ctx, p.pool, p.tenant, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND kind='personal.email'`, p.tenant); n != 1 {
		t.Fatalf("personal email jobs = %d, want 1", n)
	}
	if !p.mail(t, event) {
		t.Fatal("personal email refused while the engagement inherits")
	}

	p.setNone(t)

	if p.mail(t, event) {
		t.Fatal("personal email admitted after none committed")
	}
}

// TestPersonalEmailAdmissionWaitsForTheSettingWrite holds a first settings write open and loads
// the mail meanwhile: the load waits for the write and then reads its none.
func TestPersonalEmailAdmissionWaitsForTheSettingWrite(t *testing.T) {
	p := newPersonalEngagement(t, "personal-serialized")
	event := p.publish(t, "serialized")

	writer, err := p.pool.Begin(p.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.Background()) }()
	if _, err := writer.Exec(p.ctx, `SELECT set_config('app.current_tenant',$1,true)`, p.tenant); err != nil {
		t.Fatal(err)
	}
	if err := lockEngagementSetting(p.ctx, writer, p.tenant, p.engagement(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(p.ctx, `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES($1,$2,'none',1,now(),'admin')`, p.tenant, p.engagement()); err != nil {
		t.Fatal(err)
	}

	type loaded struct {
		ok  bool
		err error
	}
	admitted := make(chan loaded, 1)
	go func() {
		_, _, _, ok, err := p.store.LoadPersonalMail(p.ctx, p.tenant, "member-1", event, "contact-1", 1)
		admitted <- loaded{ok, err}
	}()
	select {
	case got := <-admitted:
		t.Fatalf("mail admission did not wait for the open settings write: %+v", got)
	case <-time.After(300 * time.Millisecond):
	}
	if err := writer.Commit(p.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-admitted:
		if got.err != nil || got.ok {
			t.Fatalf("mail admission after the committed none = %+v, want refused", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mail admission still blocked after the write committed")
	}
}
