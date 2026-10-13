package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

type notificationEmailTestProtector struct{}

func (notificationEmailTestProtector) Seal(value, _ []byte) (string, error) {
	return string(value), nil
}
func (notificationEmailTestProtector) Open(value string, _ []byte) ([]byte, error) {
	return []byte(value), nil
}

func TestVerifiedNotificationEmailRecipientsRequireActiveUserAndMembership(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant, other := shared.ID("email-recipient"), shared.ID("email-recipient-other")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1),($2,$2)`, tenant, other); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('active','Active','member','active-hash',$1,false),
		('disabled','Disabled','member','disabled-hash',$1,true),
		('suspended','Suspended','member','suspended-hash',$1,false)`, tenant)
	personalExec(t, ctx, pool, other, `INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES
		('foreign','Foreign','member','foreign-hash',$1,false)`, other)
	if _, err := pool.Exec(ctx, `INSERT INTO identity_persons(id) VALUES
		('email-person-active'),('email-person-disabled'),('email-person-suspended')`); err != nil {
		t.Fatal(err)
	}
	personalExec(t, ctx, pool, tenant, `INSERT INTO identity_memberships(tenant_id,id,person_id,legacy_user_id,role,state,suspension_source,last_transition_source) VALUES
		($1,'email-membership-active','email-person-active','active','member','active',NULL,'legacy_projection'),
		($1,'email-membership-disabled','email-person-disabled','disabled','member','active',NULL,'legacy_projection'),
		($1,'email-membership-suspended','email-person-suspended','suspended','member','suspended','manual','legacy_projection')`, tenant)
	personalExec(t, ctx, pool, tenant, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES
		($1,'email-contact-active','active','email','manual','active@example.test',$2,1,$2,$2),
		($1,'email-contact-case','active','email','manual','A.B+tag@example.test',$2,1,$2,$2),
		($1,'email-contact-disabled','disabled','email','manual','disabled@example.test',$2,1,$2,$2),
		($1,'email-contact-suspended','suspended','email','manual','suspended@example.test',$2,1,$2,$2)`, tenant, now)
	personalExec(t, ctx, pool, other, `INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES
		($1,'email-contact-foreign','foreign','email','manual','foreign@example.test',$2,1,$2,$2)`, other, now)

	store := NewNotificationEmailSettingsStore(pool)
	found, err := store.VerifiedNotificationEmailRecipients(ctx, tenant, []string{
		"active@example.test", "A.B+tag@EXAMPLE.TEST", "disabled@example.test", "suspended@example.test", "foreign@example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || !found["active@example.test"] || !found["A.B+tag@example.test"] {
		t.Fatalf("eligible recipients = %#v, want only active same-tenant member mailboxes", found)
	}
	service, err := notificationuc.NewService(NewNotificationRepository(pool), notificationEmailTestProtector{}, nil, NewAuditLog(pool), &notificationTestClock{at: now}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	service.SetEmailSettingsStore(store)
	created, err := service.CreateChannel(shared.WithTenant(ctx, tenant), "admin", notificationuc.ChannelInput{Name: "case-preserving", Type: domain.ChannelEmail, Enabled: true, Recipients: []string{"A.B+tag@EXAMPLE.TEST"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Recipients) != 1 || created.Recipients[0] != "A.B+tag@example.test" {
		t.Fatalf("created recipients = %#v", created.Recipients)
	}
	work := ports.NotificationWork{Delivery: domain.Delivery{Recipient: created.Recipients[0]}, Channel: domain.Channel{TenantID: tenant, Type: domain.ChannelEmail}}
	if _, code := service.EmailChannelConfig(shared.WithTenant(ctx, tenant), work, ports.EmailChannelConfig{Recipients: created.Recipients}); code != "" {
		t.Fatalf("send policy refused verified case-preserving mailbox: %q", code)
	}
}

func TestNotificationEmailSettingsStoreConcurrentRevisionCAS(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("email-settings-cas")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	store := NewNotificationEmailSettingsStore(pool)
	if _, err := store.PutNotificationEmailSettings(ctx, ports.NotificationEmailSettings{TenantID: tenant, Revision: 1, UpdatedAt: now, UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for _, actor := range []string{"one", "two"} {
		wait.Add(1)
		go func(actor string) {
			defer wait.Done()
			<-start
			_, err := store.PutNotificationEmailSettings(ctx, ports.NotificationEmailSettings{TenantID: tenant, Revision: 2, UpdatedAt: now, UpdatedBy: actor})
			errs <- err
		}(actor)
	}
	close(start)
	wait.Wait()
	close(errs)
	winners, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			winners++
		} else if errors.Is(err, shared.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("CAS error = %v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("CAS winners=%d conflicts=%d", winners, conflicts)
	}
	stored, err := store.GetNotificationEmailSettings(ctx, tenant)
	if err != nil || stored.Revision != 2 {
		t.Fatalf("CAS stored settings = %+v, err=%v", stored, err)
	}
}

var errNotificationEmailAudit = errors.New("injected notification email audit failure")

type failingNotificationEmailAudit struct{}

func (failingNotificationEmailAudit) Record(context.Context, ports.AuditEntry) error {
	return errNotificationEmailAudit
}

type notificationEmailTXT map[string][]string

func (f notificationEmailTXT) LookupTXT(context.Context, string) ([]string, error) {
	return f["_synapse-email.example.test"], nil
}

func TestNotificationEmailSettingsUpdateRollsBackSettingsAndDomainsOnAuditFailure(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("email-settings-rollback")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	store := NewNotificationEmailSettingsStore(pool)
	service, err := notificationuc.NewService(NewNotificationRepository(pool), notificationEmailTestProtector{}, nil, failingNotificationEmailAudit{}, &notificationTestClock{at: now}, &notificationTestIDs{})
	if err != nil {
		t.Fatal(err)
	}
	service.SetTransactionRunner(NewTenantTransactionRunner(pool))
	service.SetEmailSettingsStore(store)
	service.SetSMTPAllowedHosts([]string{"smtp.example.test"})
	service.SetNotificationTXTResolver(notificationEmailTXT{"_synapse-email.example.test": {"synapse-email-verification=" + tenant.String()}})
	domains := []string{"example.test"}
	_, err = service.UpdateEmailSettings(shared.WithTenant(ctx, tenant), "admin", notificationuc.EmailSettingsInput{Revision: 0, Relay: &notificationuc.SMTPRelayInput{Host: "smtp.example.test", Port: 587, From: "sender@example.test", Username: "test-user", Password: "test-password"}, Domains: &domains})
	if !errors.Is(err, errNotificationEmailAudit) {
		t.Fatalf("update error = %v", err)
	}
	setting, err := store.GetNotificationEmailSettings(ctx, tenant)
	if err != nil || setting.Revision != 0 || setting.Configured {
		t.Fatalf("settings committed despite audit failure: %+v, err=%v", setting, err)
	}
	storedDomains, err := store.ListNotificationEmailDomains(ctx, tenant)
	if err != nil || len(storedDomains) != 0 {
		t.Fatalf("domains committed despite audit failure: %#v, err=%v", storedDomains, err)
	}
}

func TestNotificationEmailSettingsTablesEnforceRuntimeRLS(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	tenant, other, hostile := shared.ID("email-settings-rls"), shared.ID("email-settings-rls-other"), shared.ID("email-settings-rls-hostile")
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.tenants(t, tenant.String(), other.String(), hostile.String())
	store := NewNotificationEmailSettingsStore(f.runtime)
	for _, id := range []shared.ID{tenant, other} {
		if _, err := store.PutNotificationEmailSettings(ctx, ports.NotificationEmailSettings{TenantID: id, Revision: 1, UpdatedAt: now, UpdatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		if err := store.AddNotificationEmailDomain(ctx, id, "example.test", now); err != nil {
			t.Fatal(err)
		}
	}
	setting, err := store.GetNotificationEmailSettings(ctx, tenant)
	if err != nil || setting.Revision != 1 {
		t.Fatalf("own settings read = %+v, err=%v", setting, err)
	}
	if domains, err := store.ListNotificationEmailDomains(ctx, tenant); err != nil || len(domains) != 1 || domains[0] != "example.test" {
		t.Fatalf("own domains read = %#v, err=%v", domains, err)
	}
	if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		var settings, domains int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_email_settings WHERE tenant_id=$1`, other).Scan(&settings); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_email_domains WHERE tenant_id=$1`, other).Scan(&domains); err != nil {
			return err
		}
		if settings != 0 || domains != 0 {
			return errors.New("foreign notification email rows were visible")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_email_settings(tenant_id,revision,configured,host,port,sender,auth_mode,sealed,updated_at,updated_by)
			VALUES($1,1,false,'',0,'','none','',$2,'admin')`, hostile, now)
		return err
	}); err == nil {
		t.Fatal("runtime role wrote a foreign notification email settings row")
	}
	if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_email_domains(tenant_id,domain,created_at) VALUES($1,'hostile.example.test',$2)`, hostile, now)
		return err
	}); err == nil {
		t.Fatal("runtime role wrote a foreign notification email domain")
	}
}
