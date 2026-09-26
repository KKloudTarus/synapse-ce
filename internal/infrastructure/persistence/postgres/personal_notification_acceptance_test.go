package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func personalExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, query string, args ...any) {
	t.Helper()
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func personalCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant shared.ID, query string, args ...any) int {
	t.Helper()
	var count int
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, args...).Scan(&count)
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestPersonalInboxIsolationOverlapAndFanout(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("inbox")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('inbox','Inbox'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled)
		SELECT 'member-'||lpad(g::text,3,'0'), 'Member '||g, 'member', 'hash-'||g, 'inbox', false FROM generate_series(1,100) g`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('reader','Reader','readonly','hash-reader','inbox',false),
		('disabled-member','Disabled','member','hash-disabled','inbox',true),
		('ghost','Ghost','member','hash-ghost','inbox',false),
		('peer','Peer','member','hash-peer','inbox',false)`)
	personalExec(t, ctx, pool, "other", `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('eve','Eve','admin','hash-eve','other',false)`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO ownership_teams(tenant_id,id,slug,name,archived,revision,created_at,updated_at) VALUES
		('inbox','team-1','team-1','Team',false,1,$1,$1),
		('inbox','old-team','old-team','Old',true,1,$1,$1)`, now)
	personalExec(t, ctx, pool, tenant, `INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at)
		SELECT 'inbox','team-1','member-'||lpad(g::text,3,'0'),$1 FROM generate_series(1,100) g`, now)
	personalExec(t, ctx, pool, tenant, `INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at) VALUES
		('inbox','team-1','reader',$1),
		('inbox','team-1','disabled-member',$1),
		('inbox','old-team','ghost',$1)`, now)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES
		('inbox','member-001','finding.ownership_changed','email','enabled',1,$1),
		('inbox','member-002','finding.ownership_changed','email','enabled',1,$1),
		('inbox','member-004','finding.ownership_changed','in_app','disabled',1,$1)`, now)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES
		('inbox','contact-1','member-001','email','manual','ada@example.com',$1,1,$1,$1),
		('inbox','contact-2','member-002','email','manual','bob@example.com',NULL,1,$1,$1)`, now)

	data, _ := json.Marshal(notification.OwnershipChanged{DecisionID: "decision-fanout", FindingID: "finding", EngagementID: "eng", NewAssigneeID: "member-001", NewTeamID: "team-1", OldTeamID: "old-team"})
	event := notification.Event{TenantID: tenant, ID: "event-fanout", Type: notification.EventOwnershipChanged, SourceKind: "ownership_decision", SourceID: "decision-fanout", EngagementID: "eng", SchemaVersion: 1, OccurredAt: now, Data: data}
	repo := NewNotificationRepository(pool)
	recipients, err := repo.ResolvePersonalRecipients(ctx, tenant, event)
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 101 {
		t.Fatalf("resolver returned %d people", len(recipients))
	}
	var overlap bool
	for _, recipient := range recipients {
		if recipient.UserID == "member-001" {
			overlap = len(recipient.Roles) == 2 && recipient.Roles[0] == notification.RoleAssignee && recipient.Roles[1] == notification.RoleTeamMember
		}
		if recipient.UserID == "disabled-member" || recipient.UserID == "ghost" || recipient.UserID == "eve" || recipient.UserID == "peer" {
			t.Fatalf("ineligible recipient %s", recipient.UserID)
		}
	}
	if !overlap {
		t.Fatal("assignee who is also a team member was not deduped with both roles")
	}
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='inbox'`); count != 100 {
		t.Fatalf("inbox rows %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='member-001'`); count != 1 {
		t.Fatalf("overlap inbox rows %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id IN ('member-004','peer','ghost','disabled-member')`); count != 0 {
		t.Fatalf("muted or ineligible inbox rows %d", count)
	}
	if count := personalCount(t, ctx, pool, "other", `SELECT count(*) FROM user_notifications WHERE user_id='eve'`); count != 0 {
		t.Fatalf("cross-tenant inbox rows %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM jobs WHERE tenant_id='inbox' AND kind='personal.email'`); count != 1 {
		t.Fatalf("personal email jobs %d", count)
	}
	var payload string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT convert_from(payload,'UTF8') FROM jobs WHERE tenant_id='inbox' AND kind='personal.email'`).Scan(&payload)
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "member-001") || !strings.Contains(payload, "contact-1") || strings.Contains(payload, "member-002") || strings.Contains(payload, "@") {
		t.Fatalf("email job payload %s", payload)
	}
	store := NewInboxStore(pool)
	page, err := store.ListInbox(ctx, tenant, "member-002", time.Time{}, "", false, 25)
	if err != nil || len(page) != 1 || page[0].LinkPath == "" {
		t.Fatalf("owner page: %+v %v", page, err)
	}
	other, err := store.ListInbox(ctx, tenant, "peer", time.Time{}, "", false, 25)
	if err != nil || len(other) != 0 {
		t.Fatalf("same-tenant peer saw %+v %v", other, err)
	}
	foreign, err := store.ListInbox(ctx, "other", "member-002", time.Time{}, "", false, 25)
	if err != nil || len(foreign) != 0 {
		t.Fatalf("cross-tenant read saw %+v %v", foreign, err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notification_tombstones(tenant_id,user_id,event_id) VALUES('inbox','member-002','event-fanout')`)
	personalExec(t, ctx, pool, tenant, `DELETE FROM user_notifications WHERE tenant_id='inbox' AND user_id='member-002'`)
	if _, err := repo.Publish(ctx, event); err != nil {
		t.Fatal(err)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='member-002'`); count != 0 {
		t.Fatalf("tombstone replay resurrected %d", count)
	}
}

func TestInboxCursorMarkAllAndTenThousandRowPlan(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("inbox")
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('inbox','Inbox')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('ada','Ada','readonly','hash-ada','inbox',false),('bob','Bob','readonly','hash-bob','inbox',false)`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data)
		SELECT 'inbox','ev-'||g,'finding.ownership_changed','bench','src-'||g,1,now(),'{}'::jsonb FROM generate_series(1,10000) g`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at)
		SELECT 'inbox','ada','n-'||lpad(g::text,5,'0'),'ev-'||g,'finding.ownership_changed','Bench','row','/inbox', timestamptz '2026-09-26 00:00:00+00' - make_interval(secs => g)
		FROM generate_series(1,10000) g`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data) VALUES
		('inbox','ev-bob','finding.ownership_changed','bench','src-bob',1,now(),'{}'::jsonb)`)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at) VALUES
		('inbox','bob','row-b','ev-bob','finding.ownership_changed','Bob','row','/inbox','2026-09-26T00:00:00Z')`)

	store := NewInboxStore(pool)
	same := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	personalExec(t, ctx, pool, tenant, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data) VALUES
		('inbox','ev-a','finding.ownership_changed','bench','src-a',1,$1,'{}'::jsonb)`, same)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_notifications(tenant_id,user_id,id,event_id,event_type,title,summary,link_path,created_at,read_at) VALUES
		('inbox','bob','row-a','ev-a','finding.ownership_changed','Older tie','row','/inbox',$1,NULL)`, same)
	first, err := store.ListInbox(ctx, tenant, "bob", time.Time{}, "", false, 1)
	if err != nil || len(first) != 1 || first[0].ID != "row-b" {
		t.Fatalf("first page %+v %v", first, err)
	}
	second, err := store.ListInbox(ctx, tenant, "bob", first[0].CreatedAt, first[0].ID, false, 1)
	if err != nil || len(second) != 1 || second[0].ID != "row-a" {
		t.Fatalf("equal timestamp page %+v %v", second, err)
	}
	ada, err := store.ListInbox(ctx, tenant, "ada", time.Time{}, "", false, 25)
	if err != nil || len(ada) != 25 {
		t.Fatalf("ada page %d %v", len(ada), err)
	}
	hidden, err := store.ListInbox(ctx, tenant, "bob", time.Time{}, "", false, 25)
	if err != nil || len(hidden) != 2 {
		t.Fatalf("bob saw %d ada rows", len(hidden))
	}
	cutoff := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC).Add(-5000 * time.Second)
	if err := store.MarkInboxAllRead(ctx, tenant, "ada", cutoff); err != nil {
		t.Fatal(err)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='ada' AND read_at IS NULL`); count != 4999 {
		t.Fatalf("unread after watermark %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='inbox' AND user_id='bob' AND read_at IS NULL`); count != 2 {
		t.Fatalf("mark all crossed users: %d unread", count)
	}
	started := time.Now()
	if _, err := store.ListInbox(ctx, tenant, "ada", time.Time{}, "", false, 25); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("10k inbox page took %s", elapsed)
	}
	var plan string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `EXPLAIN SELECT id FROM user_notifications WHERE tenant_id=$1 AND user_id=$2 AND read_at IS NULL ORDER BY created_at DESC, id DESC LIMIT 25`, tenant, "ada")
		if err != nil {
			return err
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			lines = append(lines, line)
		}
		plan = strings.Join(lines, "\n")
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "user_notifications_unread") && !strings.Contains(plan, "user_notifications_feed") {
		t.Fatalf("unread page did not use an inbox index:\n%s", plan)
	}
}

func TestDestinationNoticeIsOncePerRevisionAndSkipsSecretRotation(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := notification.WithActor(context.Background(), "ada")
	tenant := shared.ID("notice")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('notice','Notice'),('other','Other')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('ada','Ada','admin','hash-ada','notice',false),
		('bob','Bob','member','hash-bob','notice',false),
		('old','Old','admin','hash-old','notice',true)`)
	personalExec(t, ctx, pool, "other", `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('eve','Eve','admin','hash-eve','other',false)`)
	repo := NewNotificationRepository(pool)
	repo.EnableDestinationNotices()
	rawURL := "https://user:secret@hooks.example/path?token=abc"
	channel := notification.Channel{TenantID: tenant, ID: "hook", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Destination: rawURL, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed-secret"); err != nil {
		t.Fatal(err)
	}
	events := func() int {
		return personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_events WHERE tenant_id='notice' AND event_type='notification.destination_changed'`)
	}
	if events() != 1 {
		t.Fatalf("create notices %d", events())
	}
	var stored string
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT data::text FROM notification_events WHERE tenant_id='notice' AND event_type='notification.destination_changed'`).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret", "token", "path", "user:"} {
		if strings.Contains(stored, secret) {
			t.Fatalf("notice stored %q in %s", secret, stored)
		}
	}
	if !strings.Contains(stored, "hooks.example") || !strings.Contains(stored, "ada") {
		t.Fatalf("notice dropped the safe host or actor: %s", stored)
	}
	channel.Revision = 2
	channel.UpdatedAt = now.Add(time.Second)
	if _, err := repo.UpdateChannel(ctx, channel, "rotated-secret", true); err != nil {
		t.Fatal(err)
	}
	channel.Destination = "https://hooks.example/other-path"
	channel.Revision = 3
	channel.UpdatedAt = now.Add(2 * time.Second)
	if _, err := repo.UpdateChannel(ctx, channel, "rotated-secret-2", true); err != nil {
		t.Fatal(err)
	}
	if events() != 1 {
		t.Fatalf("secret or path change created %d notices", events())
	}
	channel.Destination = "https://other.example/path"
	channel.Revision = 4
	channel.UpdatedAt = now.Add(3 * time.Second)
	if _, err := repo.UpdateChannel(ctx, channel, "rotated-secret-3", true); err != nil {
		t.Fatal(err)
	}
	channel.Destination = rawURL
	channel.Revision = 5
	channel.UpdatedAt = now.Add(4 * time.Second)
	if _, err := repo.UpdateChannel(ctx, channel, "rotated-secret-4", true); err != nil {
		t.Fatal(err)
	}
	if events() != 3 {
		t.Fatalf("host changes produced %d notices", events())
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='notice' AND user_id='ada'`); count != 3 {
		t.Fatalf("admin inbox %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM user_notifications WHERE tenant_id='notice' AND user_id IN ('bob','old')`); count != 0 {
		t.Fatalf("non-admin inbox %d", count)
	}
	if count := personalCount(t, ctx, pool, "other", `SELECT count(*) FROM user_notifications WHERE user_id='eve'`); count != 0 {
		t.Fatalf("other tenant admin inbox %d", count)
	}
	if count := personalCount(t, ctx, pool, tenant, `SELECT count(*) FROM notification_events WHERE tenant_id='notice' AND event_type='notification.destination_changed' AND (data::text LIKE '%secret%' OR data::text LIKE '%token%' OR data::text LIKE '%user:%' OR data::text LIKE '%/path%')`); count != 0 {
		t.Fatalf("%d notices stored a credential or path", count)
	}
}
