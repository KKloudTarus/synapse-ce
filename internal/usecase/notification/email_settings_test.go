package notification

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type echoEmailProtector struct{}

func (echoEmailProtector) Seal(v, _ []byte) (string, error)        { return string(v), nil }
func (echoEmailProtector) Open(v string, _ []byte) ([]byte, error) { return []byte(v), nil }

type aadEmailProtector struct{}

func (aadEmailProtector) Seal(v, aad []byte) (string, error) {
	return string(aad) + "\n" + string(v), nil
}
func (aadEmailProtector) Open(v string, aad []byte) ([]byte, error) {
	prefix := string(aad) + "\n"
	if !strings.HasPrefix(v, prefix) {
		return nil, errors.New("AAD mismatch")
	}
	return []byte(strings.TrimPrefix(v, prefix)), nil
}

type emailTXT map[string][]string

func (f emailTXT) LookupTXT(_ context.Context, name string) ([]string, error) { return f[name], nil }

type countingEmailTXT struct{ calls int }

func (f *countingEmailTXT) LookupTXT(context.Context, string) ([]string, error) {
	f.calls++
	return nil, nil
}

type blockingEmailTXT struct{ started chan struct{} }

func (f blockingEmailTXT) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	select {
	case f.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func newEmailSettingsService(t *testing.T, store ports.NotificationEmailSettingsStore, txt ports.NotificationTXTResolver) *Service {
	return newEmailSettingsServiceWithProtector(t, store, txt, echoEmailProtector{})
}

func newEmailSettingsServiceWithProtector(t *testing.T, store ports.NotificationEmailSettingsStore, txt ports.NotificationTXTResolver, protector ports.NotificationSecretProtector) *Service {
	t.Helper()
	svc, err := NewService(&fakeRepo{}, protector, nil, fakeAudit{}, fakeClock{now: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetEmailSettingsStore(store)
	svc.SetSMTPAllowedHosts([]string{"smtp.example.test", "smtp.gmail.com", "smtp.office365.com"})
	svc.SetNotificationTXTResolver(txt)
	return svc
}

func TestDomainOnlyEmailSettingsUpdateResealsRelayAtNewRevision(t *testing.T) {
	store := memory.NewNotificationEmailSettingsStore()
	svc := newEmailSettingsServiceWithProtector(t, store, emailTXT{
		"_synapse-email.one.example.test": {"synapse-email-verification=tenant"},
		"_synapse-email.two.example.test": {"synapse-email-verification=tenant"},
	}, aadEmailProtector{})
	ctx := shared.WithTenant(context.Background(), "tenant")
	initialDomains := []string{"one.example.test"}
	if _, err := svc.UpdateEmailSettings(ctx, "admin", EmailSettingsInput{Revision: 0, Relay: &SMTPRelayInput{Host: "smtp.example.test", Port: 587, From: "alerts@example.test", Username: "mailer", Password: "test-secret"}, Domains: &initialDomains}); err != nil {
		t.Fatal(err)
	}
	updatedDomains := []string{"one.example.test", "two.example.test"}
	got, err := svc.UpdateEmailSettings(ctx, "admin", EmailSettingsInput{Revision: 1, Domains: &updatedDomains})
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 2 || !got.RelayConfigured {
		t.Fatalf("domain-only update lost relay or revision: %+v", got)
	}
	work := ports.NotificationWork{Delivery: domain.Delivery{Recipient: "operator@two.example.test"}, Channel: domain.Channel{TenantID: "tenant", Type: domain.ChannelEmail}}
	config, code := svc.EmailChannelConfig(ctx, work, ports.EmailChannelConfig{Recipients: []string{"operator@two.example.test"}})
	email, ok := config.(ports.EmailChannelConfig)
	if code != "" || !ok || email.Relay == nil || email.Relay.CacheKey != "tenant:2" {
		t.Fatalf("domain-only relay decode=%+v code=%q", config, code)
	}
}

func TestEmailSettingsRejectsTooManyDistinctDomainsBeforeDNS(t *testing.T) {
	store := memory.NewNotificationEmailSettingsStore()
	txt := &countingEmailTXT{}
	svc := newEmailSettingsService(t, store, txt)
	ctx := shared.WithTenant(context.Background(), "tenant")
	domains := make([]string, maxNotificationEmailDomains+1)
	for i := range domains {
		domains[i] = fmt.Sprintf("%d.example.test", i)
	}
	_, err := svc.UpdateEmailSettings(ctx, "admin", EmailSettingsInput{Revision: 0, Domains: &domains})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error = %v, want validation", err)
	}
	if txt.calls != 0 {
		t.Fatalf("DNS lookups = %d, want none for an oversized domain set", txt.calls)
	}
}

func TestEmailSettingsDomainProofBatchRespectsCallerDeadline(t *testing.T) {
	store := memory.NewNotificationEmailSettingsStore()
	resolver := blockingEmailTXT{started: make(chan struct{}, 1)}
	svc := newEmailSettingsService(t, store, resolver)
	ctx, cancel := context.WithTimeout(shared.WithTenant(context.Background(), "tenant"), 20*time.Millisecond)
	defer cancel()
	domains := []string{"example.test"}
	_, err := svc.UpdateEmailSettings(ctx, "admin", EmailSettingsInput{Revision: 0, Domains: &domains})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("DNS timeout error = %v", err)
	}
	select {
	case <-resolver.started:
	default:
		t.Fatal("DNS resolver was not called")
	}
}

func TestUpdateEmailSettingsSealsRelayAndProvesNewDomain(t *testing.T) {
	store := memory.NewNotificationEmailSettingsStore()
	svc := newEmailSettingsService(t, store, emailTXT{"_synapse-email.example.test": {"synapse-email-verification=tenant"}})
	ctx := shared.WithTenant(context.Background(), "tenant")
	domains := []string{"Example.Test"}
	got, err := svc.UpdateEmailSettings(ctx, "admin", EmailSettingsInput{Revision: 0, Relay: &SMTPRelayInput{Host: "smtp.example.test", Port: 465, From: "alerts@example.test", Username: "mailer", Password: "only-in-sealed-value"}, Domains: &domains})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RelayConfigured || got.RelayHost != "smtp.example.test" || got.AuthMode != "password" || got.DNSValue != "synapse-email-verification=tenant" || len(got.Domains) != 1 || got.Domains[0] != "example.test" {
		t.Fatalf("safe settings = %+v", got)
	}
	stored, err := store.GetNotificationEmailSettings(ctx, "tenant")
	if err != nil || !strings.Contains(stored.Sealed, "only-in-sealed-value") {
		t.Fatalf("sealed config not persisted: %+v %v", stored, err)
	}
	if strings.Contains(got.RelayFrom+got.RelayHost+got.AuthMode, "only-in-sealed-value") {
		t.Fatal("secret leaked through settings DTO")
	}
}

func TestEmailRecipientPolicyAndRelayMergeAreExactAndRechecked(t *testing.T) {
	store := memory.NewNotificationEmailSettingsStore()
	svc := newEmailSettingsService(t, store, emailTXT{"_synapse-email.example.test": {"synapse-email-verification=tenant"}})
	ctx := shared.WithTenant(context.Background(), "tenant")
	domains := []string{"example.test"}
	if _, err := svc.UpdateEmailSettings(ctx, "admin", EmailSettingsInput{Revision: 0, Relay: &SMTPRelayInput{Host: "smtp.example.test", Port: 587, From: "alerts@example.test", Username: "mailer", Password: "secret"}, Domains: &domains}); err != nil {
		t.Fatal(err)
	}
	if err := svc.validateEmailRecipients(ctx, "tenant", []string{"operator@example.test"}); err != nil {
		t.Fatalf("proved exact domain refused: %v", err)
	}
	if err := svc.validateEmailRecipients(ctx, "tenant", []string{"operator@sub.example.test"}); err == nil {
		t.Fatal("suffix domain accepted")
	}
	work := ports.NotificationWork{Delivery: domain.Delivery{Recipient: "operator@example.test"}, Channel: domain.Channel{TenantID: "tenant", Type: domain.ChannelEmail}}
	config, code := svc.EmailChannelConfig(ctx, work, ports.EmailChannelConfig{Recipients: []string{"operator@example.test"}})
	email, ok := config.(ports.EmailChannelConfig)
	if code != "" || !ok || email.Relay == nil || email.Relay.CacheKey != "tenant:1" {
		t.Fatalf("merged config=%+v code=%q", config, code)
	}
	if err := store.DeleteNotificationEmailDomain(ctx, "tenant", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, code = svc.EmailChannelConfig(ctx, work, ports.EmailChannelConfig{}); code != "email_recipient_unverified" {
		t.Fatalf("revoked recipient code=%q", code)
	}
}

func TestVerifiedMailboxLocalPartSurvivesEmailChannelCreateAndSendPolicy(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	repo := memory.NewNotificationRepository(nil, func() time.Time { return now })
	store := memory.NewNotificationEmailSettingsStore()
	store.SetVerifiedRecipient("tenant", "A.B+tag@example.com")
	svc, err := NewService(repo, echoEmailProtector{}, nil, fakeAudit{}, fakeClock{now: now}, &fakeIDs{})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetEmailSettingsStore(store)
	ctx := shared.WithTenant(context.Background(), "tenant")
	created, err := svc.CreateChannel(ctx, "admin", ChannelInput{Name: "case-preserving", Type: domain.ChannelEmail, Enabled: true, Recipients: []string{"A.B+tag@EXAMPLE.COM"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(created.Recipients, []string{"A.B+tag@example.com"}) {
		t.Fatalf("stored recipients = %#v", created.Recipients)
	}
	work := ports.NotificationWork{Delivery: domain.Delivery{Recipient: created.Recipients[0]}, Channel: domain.Channel{TenantID: "tenant", Type: domain.ChannelEmail}}
	if _, code := svc.EmailChannelConfig(ctx, work, ports.EmailChannelConfig{Recipients: created.Recipients}); code != "" {
		t.Fatalf("send policy refused verified case-preserving mailbox: %q", code)
	}
	if err := svc.validateEmailRecipients(ctx, "tenant", []string{"a.b+tag@example.com"}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("local-part case folded without an approved domain: %v", err)
	}
}

func TestOAuthRelayRequiresMailboxAndSupportedMicrosoftPort(t *testing.T) {
	svc := newEmailSettingsService(t, memory.NewNotificationEmailSettingsStore(), nil)
	for _, provider := range []string{"google", "microsoft"} {
		host := "smtp.gmail.com"
		if provider == "microsoft" {
			host = "smtp.office365.com"
		}
		in := SMTPRelayInput{Host: host, Port: 587, From: "sender@example.test", Username: "sender@example.test", OAuth: &SMTPRelayOAuthInput{Provider: provider, ClientID: "test-client", ClientSecret: "synthetic-secret", RefreshToken: "synthetic-refresh", DirectoryID: "  AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE  "}}
		for _, invalid := range []string{"", " ", "mailer", "user@example.test\x01auth=Bearer forged"} {
			bad := in
			bad.Username = invalid
			if _, _, err := svc.validateSMTPRelay(bad); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s accepted invalid mailbox", provider)
			}
		}
		relay, _, err := svc.validateSMTPRelay(in)
		if err != nil {
			t.Fatal(err)
		}
		if provider == "microsoft" {
			if relay.OAuthDirectoryID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
				t.Fatal("directory ID was not normalized")
			}
			in.Port = 465
			if _, _, err := svc.validateSMTPRelay(in); !errors.Is(err, shared.ErrValidation) {
				t.Fatal("unsupported Microsoft 465 accepted")
			}
		}
	}
}
