package postgres

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WS4 personal channels over PostgreSQL (migration 0229): Slack and Teams jobs from tenant defaults
// (#1418, #1419, #1420), rule recipient roles with an engagement lead (#1415), the send-time reload,
// and the Teams link offers.

func newPersonalChannels(t *testing.T, tenant shared.ID) *personalEngagement {
	t.Helper()
	p := newPersonalEngagement(t, tenant)
	personalExec(t, p.ctx, p.pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('lead-1','Lead','reviewer','hash-lead-1',$1,false)`, tenant)
	personalExec(t, p.ctx, p.pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('gone-1','Gone','member','hash-gone-1',$1,true)`, tenant)
	personalExec(t, p.ctx, p.pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at)
		VALUES($1,'slack-1','member-1','slack','manual','T0123:U0ADA',$2,1,$2,$2)`, tenant, p.now)
	return p
}

func personalJobs(t *testing.T, p *personalEngagement, kind string) []string {
	t.Helper()
	var out []string
	if err := WithTenant(p.ctx, p.pool, p.tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(p.ctx, `SELECT id FROM jobs WHERE tenant_id=$1 AND kind=$2 ORDER BY id`, p.tenant, kind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPersonalSlackJobFollowsTheTenantDefault(t *testing.T) {
	p := newPersonalChannels(t, "personal-slack-default")
	// Built-in default: Slack is off, so the ownership change queues email (explicitly enabled) only.
	p.publish(t, "before")
	if jobs := personalJobs(t, p, "personal.slack"); len(jobs) != 0 {
		t.Fatalf("slack jobs before the default: %v", jobs)
	}
	saved, err := p.store.SavePersonalDefault(p.ctx, p.tenant, "admin", notification.EventOwnershipChanged, notification.PersonalSlack, true, 0, p.now)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("save default: %+v %v", saved, err)
	}
	if _, err := p.store.SavePersonalDefault(p.ctx, p.tenant, "admin", notification.EventOwnershipChanged, notification.PersonalSlack, true, 0, p.now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale default write: %v", err)
	}
	event := p.publish(t, "after")
	jobs := personalJobs(t, p, "personal.slack")
	if len(jobs) != 1 || !strings.HasPrefix(jobs[0], "personal-slack-") {
		t.Fatalf("slack jobs = %v", jobs)
	}
	message, ok, err := p.store.LoadPersonalDelivery(p.ctx, p.tenant, "member-1", event, "slack-1", 1, notification.PersonalSlack)
	if err != nil || !ok || message.Recipient != "T0123:U0ADA" || message.Title == "" || !strings.HasPrefix(message.LinkPath, "/") {
		t.Fatalf("reload = %+v %v %v", message, ok, err)
	}
	// The person mutes Slack: the queued job no longer sends.
	personalExec(t, p.ctx, p.pool, p.tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at)
		VALUES($1,'member-1','finding.ownership_changed','slack','disabled',1,$2)`, p.tenant, p.now)
	if _, ok, err := p.store.LoadPersonalDelivery(p.ctx, p.tenant, "member-1", event, "slack-1", 1, notification.PersonalSlack); err != nil || ok {
		t.Fatalf("muted reload ok=%v err=%v", ok, err)
	}
	// A contact version that changed since the job was queued is never re-targeted.
	if _, ok, _ := p.store.LoadPersonalDelivery(p.ctx, p.tenant, "member-1", event, "slack-1", 2, notification.PersonalSlack); ok {
		t.Fatal("a stale contact version reloaded")
	}
	defaults, err := p.store.ListPersonalDefaults(p.ctx, p.tenant)
	if err != nil || len(defaults) != 1 || !defaults[0].Enabled {
		t.Fatalf("defaults = %+v %v", defaults, err)
	}
	if audited := personalCount(t, p.ctx, p.pool, p.tenant, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='notification.personal_default.updated'`, p.tenant); audited != 1 {
		t.Fatalf("audit rows = %d", audited)
	}
}

func TestPersonalPreferencesListSlackAndTeams(t *testing.T) {
	p := newPersonalChannels(t, "personal-pref-list")
	items, err := p.store.ListInboxPreferences(p.ctx, p.tenant, "member-1")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]ports.InboxPreference{}
	for _, item := range items {
		if item.EventType == string(notification.EventOwnershipChanged) {
			found[item.Channel] = item
		}
	}
	if len(found) != 4 {
		t.Fatalf("channels = %+v", found)
	}
	// No Slack bot channel yet: Slack cannot be chosen. Teams is reported available by the store;
	// the service decides with the operator configuration.
	if found["slack"].Available || found["slack"].Reason == "" || !found["teams"].Available || found["teams"].Reason == "" {
		t.Fatalf("slack = %+v teams = %+v", found["slack"], found["teams"])
	}
	if found["email"].Default || !found["in_app"].Default {
		t.Fatalf("email default = %+v", found["email"])
	}
}

func TestRuleRecipientRolesReachTheEngagementLead(t *testing.T) {
	p := newPersonalChannels(t, "personal-lead")
	at := p.now
	if _, err := p.repo.PutEngagementNotificationSetting(p.ctx, notification.EngagementNotificationSetting{TenantID: p.tenant, EngagementID: p.engagement(),
		ExternalNotifications: notification.EngagementNotificationsInherit, LeadUserID: "gone-1", Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a disabled lead: %v", err)
	}
	setting, err := p.repo.PutEngagementNotificationSetting(p.ctx, notification.EngagementNotificationSetting{TenantID: p.tenant, EngagementID: p.engagement(),
		ExternalNotifications: notification.EngagementNotificationsInherit, LeadUserID: "lead-1", Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	read, err := p.repo.GetEngagementNotificationSetting(p.ctx, p.tenant, p.engagement())
	if err != nil || read.LeadUserID != "lead-1" || setting.LeadUserID != "lead-1" {
		t.Fatalf("setting = %+v %v", read, err)
	}
	rule := notification.Rule{TenantID: p.tenant, ID: "rule-leads", Name: "Leads", Enabled: true, EventType: notification.EventScanCompleted,
		RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: p.now, UpdatedAt: p.now}
	if _, err := p.repo.CreateRule(p.ctx, rule); err != nil {
		t.Fatal(err)
	}
	stored, err := p.repo.GetRule(p.ctx, p.tenant, rule.ID)
	if err != nil || len(stored.RecipientRoles) != 1 || stored.RecipientRoles[0] != notification.RoleEngagementLead || len(stored.ChannelIDs) != 0 {
		t.Fatalf("stored rule = %+v %v", stored, err)
	}
	data, _ := json.Marshal(map[string]string{"title": "Scan completed", "summary": "A scan completed successfully.", "scan_kind": "sast"})
	event := notification.Event{TenantID: p.tenant, ID: "event-scan", Type: notification.EventScanCompleted, SourceKind: "scan_job", SourceID: "scan-1",
		EngagementID: p.engagement(), SchemaVersion: 1, OccurredAt: p.now, Data: data}
	if _, err := p.repo.Publish(p.ctx, event); err != nil {
		t.Fatal(err)
	}
	var user, title, link string
	if err := WithTenantRead(p, func(q func(string, ...any) error) error {
		return q(`SELECT user_id,title,link_path FROM user_notifications WHERE tenant_id=$1 AND event_id=$2`, &user, &title, &link)
	}); err != nil {
		t.Fatal(err)
	}
	if user != "lead-1" || title != "Scan completed" || link != "/engagements/"+p.engagement().String() {
		t.Fatalf("inbox row = %s %q %s", user, title, link)
	}
	if matched := personalCount(t, p.ctx, p.pool, p.tenant, `SELECT count(*) FROM notification_events WHERE tenant_id=$1 AND id=$2 AND matched_rules ? 'rule-leads'`, p.tenant, event.ID); matched != 1 {
		t.Fatalf("the role-only rule is not recorded as matched")
	}
	recipients, err := p.repo.ResolvePersonalRecipients(p.ctx, p.tenant, event)
	if err != nil || len(recipients) != 0 {
		t.Fatalf("without the rule's roles the scan names nobody: %+v %v", recipients, err)
	}
}

// WithTenantRead runs one row read in the fixture's tenant session.
func WithTenantRead(p *personalEngagement, read func(q func(string, ...any) error) error) error {
	ctx := p.ctx
	return WithTenant(ctx, p.pool, p.tenant.String(), func(tx pgx.Tx) error {
		return read(func(query string, dest ...any) error {
			return tx.QueryRow(ctx, query, p.tenant, "event-scan").Scan(dest...)
		})
	})
}

func TestUserContactValueShapes(t *testing.T) {
	p := newPersonalChannels(t, "personal-shapes")
	for _, bad := range [][2]string{{"slack", "ada@example.com"}, {"slack", "T0123"}, {"teams", "Ada Lovelace"}, {"teams", "29:1abc"}} {
		err := WithTenant(p.ctx, p.pool, p.tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(p.ctx, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,version,created_at,updated_at) VALUES($1,'bad','member-1',$2,'manual',$3,1,now(),now())`, p.tenant, bad[0], bad[1])
			return err
		})
		if err == nil {
			t.Errorf("%s contact %q stored", bad[0], bad[1])
		}
	}
}

func TestTeamsLinkOffersAndContacts(t *testing.T) {
	p := newPersonalChannels(t, "personal-teams")
	offers := NewTeamsLinkOffers(p.pool)
	contacts := NewUserContactStore(p.pool)
	digest := strings.Repeat("a", 64)
	conversation := strings.Repeat("c", 64)
	expires := time.Now().Add(10 * time.Minute)
	for i, d := range []string{digest, strings.Repeat("b", 64), strings.Repeat("d", 64)} {
		if ok, err := offers.OfferTeamsLink(p.ctx, d, conversation, "sealed-"+d[:1], expires); err != nil || !ok {
			t.Fatalf("offer %d: %v %v", i, ok, err)
		}
	}
	if ok, err := offers.OfferTeamsLink(p.ctx, strings.Repeat("e", 64), conversation, "sealed-e", expires); err != nil || ok {
		t.Fatalf("fourth live offer of one conversation: %v %v", ok, err)
	}
	at := p.now
	contact := ports.UserContact{TenantID: p.tenant, ID: "teams-1", UserID: "member-1", Kind: "teams", Source: "manual", Value: "0a0b0c0d-1111-2222-3333-444455556666", VerifiedAt: &at, Version: 1, CreatedAt: at, UpdatedAt: at}
	linker := func(conversationSeal string, seen *string) ports.TeamsLinker {
		return func(sealedOffer string) (ports.UserContact, string, error) {
			*seen = sealedOffer
			return contact, conversationSeal, nil
		}
	}
	// A failure after the claim rolls the claim back with the transaction: the code still works.
	var seen string
	if _, _, err := contacts.LinkTeamsContact(p.ctx, p.tenant, "member-1", digest, func(sealedOffer string) (ports.UserContact, string, error) {
		seen = sealedOffer
		return ports.UserContact{}, "", errors.New("seal failed")
	}); err == nil || seen != "sealed-a" {
		t.Fatalf("failing link: seen=%q err=%v", seen, err)
	}
	linked, found, err := contacts.LinkTeamsContact(p.ctx, p.tenant, "member-1", digest, linker("sealed-conversation", &seen))
	if err != nil || !found || seen != "sealed-a" || linked.VerifiedAt == nil || linked.Kind != "teams" {
		t.Fatalf("link = %+v found=%v err=%v", linked, found, err)
	}
	// The code was consumed with the contact, and an unknown code finds nothing.
	for _, d := range []string{digest, strings.Repeat("f", 64)} {
		if _, found, err := contacts.LinkTeamsContact(p.ctx, p.tenant, "member-1", d, linker("x", &seen)); err != nil || found {
			t.Fatalf("code %s: found=%v err=%v", d[:1], found, err)
		}
	}
	// Another person cannot take the contact of a claimed offer.
	if _, _, err := contacts.LinkTeamsContact(p.ctx, p.tenant, "lead-1", strings.Repeat("b", 64), linker("x", &seen)); err == nil {
		t.Fatal("a contact for another user was stored")
	}
	got, ok, err := contacts.TeamsConversation(p.ctx, p.tenant, "teams-1")
	if err != nil || !ok || got != "sealed-conversation" {
		t.Fatalf("conversation = %q %v %v", got, ok, err)
	}
	// Linking the same Teams account again replaces the contact and its conversation.
	contact.ID = "teams-2"
	if _, found, err := contacts.LinkTeamsContact(p.ctx, p.tenant, "member-1", strings.Repeat("d", 64), linker("sealed-again", &seen)); err != nil || !found {
		t.Fatalf("relink: found=%v err=%v", found, err)
	}
	if _, ok, _ := contacts.TeamsConversation(p.ctx, p.tenant, "teams-1"); ok {
		t.Fatal("the replaced conversation survived")
	}
	// Another tenant cannot read it.
	if _, ok, _ := contacts.TeamsConversation(p.ctx, "personal-other", "teams-2"); ok {
		t.Fatal("another tenant read the conversation")
	}
	for i := 0; i < 5; i++ {
		if err := contacts.CountTeamsLinkAttempt(p.ctx, p.tenant, "member-1", shared.ID("attempt-"+string(rune('a'+i))), time.Now()); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := contacts.CountTeamsLinkAttempt(p.ctx, p.tenant, "member-1", "attempt-z", time.Now()); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("sixth attempt: %v", err)
	}
	if err := contacts.CountTeamsLinkAttempt(p.ctx, p.tenant, "gone-1", "attempt-gone", time.Now()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("disabled user: %v", err)
	}
}

// Muting the inbox after a personal message was queued stops it: every personal message is sent
// from its inbox row (#1418).
func TestQueuedPersonalMessageStopsWhenTheInboxIsMuted(t *testing.T) {
	p := newPersonalChannels(t, "personal-inapp-mute")
	if _, err := p.store.SavePersonalDefault(p.ctx, p.tenant, "admin", notification.EventOwnershipChanged, notification.PersonalSlack, true, 0, p.now); err != nil {
		t.Fatal(err)
	}
	event := p.publish(t, "queued")
	if jobs := personalJobs(t, p, "personal.slack"); len(jobs) != 1 {
		t.Fatalf("slack jobs = %v", jobs)
	}
	if _, ok, err := p.store.LoadPersonalDelivery(p.ctx, p.tenant, "member-1", event, "slack-1", 1, notification.PersonalSlack); err != nil || !ok {
		t.Fatalf("before the mute ok=%v err=%v", ok, err)
	}
	personalExec(t, p.ctx, p.pool, p.tenant, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at)
		VALUES($1,'member-1','finding.ownership_changed','in_app','disabled',1,$2)`, p.tenant, p.now)
	for _, channel := range []string{notification.PersonalSlack, notification.PersonalEmail} {
		contact := shared.ID("slack-1")
		if channel == notification.PersonalEmail {
			contact = "contact-1"
		}
		if _, ok, err := p.store.LoadPersonalDelivery(p.ctx, p.tenant, "member-1", event, contact, 1, channel); err != nil || ok {
			t.Fatalf("%s after the in-app mute ok=%v err=%v", channel, ok, err)
		}
	}
}

// A credential in an event's own text never reaches an inbox row or a personal message: the
// generic subject reads the snapshot the event builders scrubbed (#1361), not the raw data.
func TestPersonalTextComesFromTheScrubbedSnapshot(t *testing.T) {
	p := newPersonalChannels(t, "personal-scrub")
	p.repo.SetEventProjector(notificationuc.NewEventBuilders())
	at := p.now
	if _, err := p.repo.PutEngagementNotificationSetting(p.ctx, notification.EngagementNotificationSetting{TenantID: p.tenant, EngagementID: p.engagement(),
		ExternalNotifications: notification.EngagementNotificationsInherit, LeadUserID: "lead-1", Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	personalExec(t, p.ctx, p.pool, p.tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at)
		VALUES($1,'lead-slack','lead-1','slack','manual','T0123:U0LEAD',$2,1,$2,$2)`, p.tenant, p.now)
	if _, err := p.store.SavePersonalDefault(p.ctx, p.tenant, "admin", notification.EventScanCompleted, notification.PersonalSlack, true, 0, p.now); err != nil {
		t.Fatal(err)
	}
	rule := notification.Rule{TenantID: p.tenant, ID: "rule-scrub", Name: "Leads", Enabled: true, EventType: notification.EventScanCompleted,
		RecipientRoles: []string{notification.RoleEngagementLead}, Revision: 1, CreatedAt: p.now, UpdatedAt: p.now}
	if _, err := p.repo.CreateRule(p.ctx, rule); err != nil {
		t.Fatal(err)
	}
	const secret = "hunter2-SYNTHETIC-MARKER"
	data, _ := json.Marshal(map[string]string{"title": "Scan for password=" + secret, "summary": "token=" + secret + " AKIAIOSFODNN7EXAMPLE", "scan_kind": "sast"})
	event := notification.Event{TenantID: p.tenant, ID: "event-scrub", Type: notification.EventScanCompleted, SourceKind: "scan_job", SourceID: "scan-scrub",
		EngagementID: p.engagement(), SchemaVersion: 1, OccurredAt: p.now, Data: data}
	if _, err := p.repo.Publish(p.ctx, event); err != nil {
		t.Fatal(err)
	}
	message, ok, err := p.store.LoadPersonalDelivery(p.ctx, p.tenant, "lead-1", event.ID, "lead-slack", 1, notification.PersonalSlack)
	if err != nil || !ok {
		t.Fatalf("reload ok=%v err=%v", ok, err)
	}
	if message.Title == "" || strings.Contains(message.Title+message.Summary, secret) || strings.Contains(message.Title+message.Summary, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("personal message = %q / %q", message.Title, message.Summary)
	}
}
