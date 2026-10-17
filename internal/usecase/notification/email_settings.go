package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/idna"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// SMTPRelayOAuthInput is accepted only while replacing a sealed relay.
// It is deliberately absent from every read DTO and audit record.
type SMTPRelayOAuthInput struct {
	Provider     string `json:"provider"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token,omitempty"`
	DirectoryID  string `json:"directory_id,omitempty"`
}

// SMTPRelayInput contains tenant-owned relay material. Password and OAuth
// credentials are sealed immediately; errors expose no field values.
type SMTPRelayInput struct {
	Host     string               `json:"host"`
	Port     int                  `json:"port"`
	From     string               `json:"from"`
	Username string               `json:"username,omitempty"`
	Password string               `json:"password,omitempty"`
	OAuth    *SMTPRelayOAuthInput `json:"oauth,omitempty"`
}

// EmailSettingsInput uses a complete domain set. Nil leaves a section as-is;
// an empty domains slice explicitly revokes every previously proved domain.
type EmailSettingsInput struct {
	Revision   int             `json:"revision"`
	Relay      *SMTPRelayInput `json:"relay,omitempty"`
	ClearRelay bool            `json:"clear_relay,omitempty"`
	Domains    *[]string       `json:"domains,omitempty"`
}

// EmailSettings is the secret-free response returned to administrators.
type EmailSettings struct {
	Revision        int      `json:"revision"`
	RelayConfigured bool     `json:"relay_configured"`
	RelayHost       string   `json:"relay_host,omitempty"`
	RelayPort       int      `json:"relay_port,omitempty"`
	RelayFrom       string   `json:"relay_from,omitempty"`
	AuthMode        string   `json:"auth_mode,omitempty"`
	Domains         []string `json:"domains"`
	DNSValue        string   `json:"dns_txt_value"`
}

const (
	maxNotificationEmailDomains  = 50
	emailDomainProofBatchTimeout = 15 * time.Second
)

func (s *Service) SetEmailSettingsStore(store ports.NotificationEmailSettingsStore) {
	s.emailSettings = store
}

// SetSMTPAllowedHosts installs the exact operator allowlist for tenant relays.
// An empty list intentionally permits no tenant-supplied relay.
func (s *Service) SetSMTPAllowedHosts(hosts []string) {
	s.smtpAllowedHosts = make(map[string]bool, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host != "" {
			s.smtpAllowedHosts[host] = true
		}
	}
}

func (s *Service) SetNotificationTXTResolver(resolver ports.NotificationTXTResolver) {
	s.emailTXT = resolver
}

func (s *Service) EmailSettings(ctx context.Context) (EmailSettings, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return EmailSettings{}, err
	}
	if s.emailSettings == nil {
		return EmailSettings{}, fmt.Errorf("%w: notification email settings are unavailable", shared.ErrValidation)
	}
	setting, err := s.emailSettings.GetNotificationEmailSettings(ctx, tenant)
	if err != nil {
		return EmailSettings{}, err
	}
	domains, err := s.emailSettings.ListNotificationEmailDomains(ctx, tenant)
	if err != nil {
		return EmailSettings{}, err
	}
	return publicEmailSettings(setting, domains), nil
}

func (s *Service) UpdateEmailSettings(ctx context.Context, actor string, in EmailSettingsInput) (EmailSettings, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" || in.Revision < 0 {
		return EmailSettings{}, fmt.Errorf("%w: valid email settings update is required", shared.ErrValidation)
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return EmailSettings{}, err
	}
	if s.emailSettings == nil {
		return EmailSettings{}, fmt.Errorf("%w: notification email settings are unavailable", shared.ErrValidation)
	}
	// DNS is remote I/O. Canonicalize and bound the entire replacement set before
	// any lookup, then prove every new domain before the transaction that updates
	// settings and audit history.
	var wantedDomains map[string]struct{}
	if in.Domains != nil {
		wantedDomains, err = canonicalEmailDomains(*in.Domains)
		if err != nil {
			return EmailSettings{}, err
		}
		existing, err := s.emailSettings.ListNotificationEmailDomains(ctx, tenant)
		if err != nil {
			return EmailSettings{}, err
		}
		have := make(map[string]struct{}, len(existing))
		for _, domain := range existing {
			have[domain] = struct{}{}
		}
		proofCtx, cancel := context.WithTimeout(ctx, emailDomainProofBatchTimeout)
		defer cancel()
		for domain := range wantedDomains {
			if _, ok := have[domain]; !ok {
				if err := s.verifyEmailDomain(proofCtx, tenant, domain); err != nil {
					return EmailSettings{}, err
				}
			}
		}
	}
	return mutation(ctx, s, func(ctx context.Context) (EmailSettings, error) {
		current, err := s.emailSettings.GetNotificationEmailSettings(ctx, tenant)
		if err != nil {
			return EmailSettings{}, err
		}
		if in.Revision != current.Revision {
			return EmailSettings{}, fmt.Errorf("notification email settings revision is stale: %w", shared.ErrConflict)
		}
		if in.ClearRelay && in.Relay != nil {
			return EmailSettings{}, fmt.Errorf("%w: relay cannot be set and cleared together", shared.ErrValidation)
		}
		if in.Relay == nil && !in.ClearRelay && in.Domains == nil {
			return EmailSettings{}, fmt.Errorf("%w: email settings update is empty", shared.ErrValidation)
		}
		next := current
		next.Revision = current.Revision + 1
		next.UpdatedAt, next.UpdatedBy = s.clock.Now().UTC(), actor
		if in.Relay != nil {
			relay, mode, err := s.validateSMTPRelay(*in.Relay)
			if err != nil {
				return EmailSettings{}, err
			}
			next.Configured, next.Host, next.Port, next.From, next.AuthMode = true, relay.Host, relay.Port, relay.From, mode
			//nolint:gosec // The secret-bearing relay is immediately sealed and never logged or returned.
			raw, err := json.Marshal(relay)
			if err != nil {
				return EmailSettings{}, fmt.Errorf("encode notification email settings: %w", err)
			}
			next.Sealed, err = s.protector.Seal(raw, emailSettingsAAD(tenant, next.Revision))
			if err != nil {
				return EmailSettings{}, fmt.Errorf("seal notification email settings: %w", err)
			}
		} else if next.Configured && !in.ClearRelay {
			// The relay AAD binds the settings revision. A domain-only update still
			// advances that revision, so preserve the relay by re-sealing it for the
			// new revision rather than leaving an undecryptable ciphertext behind.
			raw, err := s.protector.Open(current.Sealed, emailSettingsAAD(tenant, current.Revision))
			if err != nil {
				return EmailSettings{}, fmt.Errorf("open notification email settings: %w", err)
			}
			next.Sealed, err = s.protector.Seal(raw, emailSettingsAAD(tenant, next.Revision))
			if err != nil {
				return EmailSettings{}, fmt.Errorf("seal notification email settings: %w", err)
			}
		}
		if in.ClearRelay {
			next.Configured, next.Host, next.Port, next.From, next.AuthMode, next.Sealed = false, "", 0, "", "none", ""
		}
		if in.Domains != nil {
			existing, err := s.emailSettings.ListNotificationEmailDomains(ctx, tenant)
			if err != nil {
				return EmailSettings{}, err
			}
			have := make(map[string]struct{}, len(existing))
			for _, domain := range existing {
				have[domain] = struct{}{}
			}
			for domain := range wantedDomains {
				if _, ok := have[domain]; ok {
					continue
				}
				if err := s.emailSettings.AddNotificationEmailDomain(ctx, tenant, domain, s.clock.Now().UTC()); err != nil {
					return EmailSettings{}, err
				}
			}
			for domain := range have {
				if _, ok := wantedDomains[domain]; ok {
					continue
				}
				if err := s.emailSettings.DeleteNotificationEmailDomain(ctx, tenant, domain); err != nil {
					return EmailSettings{}, err
				}
			}
		}
		current, err = s.emailSettings.PutNotificationEmailSettings(ctx, next)
		if err != nil {
			return EmailSettings{}, err
		}
		domains, err := s.emailSettings.ListNotificationEmailDomains(ctx, tenant)
		if err != nil {
			return EmailSettings{}, err
		}
		if err := s.record(ctx, actor, "notification.email_settings.updated", tenant.String(), map[string]string{"relay_configured": fmt.Sprintf("%t", current.Configured), "domain_count": fmt.Sprintf("%d", len(domains))}); err != nil {
			return EmailSettings{}, err
		}
		return publicEmailSettings(current, domains), nil
	})
}

// EmailChannelConfig rechecks the recipient policy at send time and merges the
// current tenant relay. Call it after decrypting a channel and before Sender.Send.
func (s *Service) EmailChannelConfig(ctx context.Context, work ports.NotificationWork, config ports.NotificationChannelConfig) (ports.NotificationChannelConfig, string) {
	if work.Channel.Type != "email" {
		return config, ""
	}
	if s.disabled[domain.ChannelEmail] {
		return nil, "provider_disabled"
	}
	email, ok := config.(ports.EmailChannelConfig)
	if !ok {
		return nil, "channel_config_invalid"
	}
	if err := s.validateEmailRecipients(ctx, work.Channel.TenantID, []string{work.Delivery.Recipient}); err != nil {
		if errors.Is(err, shared.ErrForbidden) || errors.Is(err, shared.ErrValidation) {
			return nil, "email_recipient_unverified"
		}
		return nil, "email_settings_unavailable"
	}
	if s.emailSettings == nil {
		return email, ""
	} // legacy operator relay only; production wires this store.
	setting, err := s.emailSettings.GetNotificationEmailSettings(ctx, work.Channel.TenantID)
	if err != nil {
		return nil, "email_settings_unavailable"
	}
	if !setting.Configured {
		return email, ""
	} // only an unset tenant relay may fall back to the operator relay.
	raw, err := s.protector.Open(setting.Sealed, emailSettingsAAD(work.Channel.TenantID, setting.Revision))
	if err != nil {
		return nil, "email_settings_unavailable"
	}
	var relay ports.SMTPRelayConfig
	if json.Unmarshal(raw, &relay) != nil || !s.relayAllowed(relay.Host) || !validSMTPPort(relay.Port) {
		return nil, "email_settings_invalid"
	}
	relay.CacheKey = work.Channel.TenantID.String() + ":" + fmt.Sprintf("%d", setting.Revision)
	email.Relay = &relay
	return email, ""
}

func (s *Service) validateEmailRecipients(ctx context.Context, tenant shared.ID, recipients []string) error {
	if s.emailSettings == nil {
		return nil
	}
	verified, err := s.emailSettings.VerifiedNotificationEmailRecipients(ctx, tenant, recipients)
	if err != nil {
		return err
	}
	domains, err := s.emailSettings.ListNotificationEmailDomains(ctx, tenant)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(domains))
	for _, domain := range domains {
		allowed[domain] = true
	}
	for _, recipient := range recipients {
		normalized, err := userdom.NormalizeContactEmail(recipient)
		if err != nil {
			return fmt.Errorf("%w: invalid email recipient", shared.ErrValidation)
		}
		_, domain, _ := strings.Cut(normalized, "@")
		if !verified[normalized] && !allowed[domain] {
			return fmt.Errorf("%w: email recipient is not a verified same-tenant contact or approved domain", shared.ErrForbidden)
		}
	}
	return nil
}

func (s *Service) validateSMTPRelay(in SMTPRelayInput) (ports.SMTPRelayConfig, string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Host), "."))
	if !s.relayAllowed(host) || !validSMTPPort(in.Port) {
		return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: relay host or port is not allowed", shared.ErrValidation)
	}
	from, err := userdom.NormalizeContactEmail(in.From)
	if err != nil {
		return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: invalid relay sender", shared.ErrValidation)
	}
	relay := ports.SMTPRelayConfig{Host: host, Port: in.Port, From: from, Username: strings.TrimSpace(in.Username), Password: in.Password}
	if in.OAuth == nil {
		if relay.Username == "" || relay.Password == "" {
			return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: relay username and password are required", shared.ErrValidation)
		}
		return relay, "password", nil
	}
	oauth := in.OAuth
	username, err := userdom.NormalizeContactEmail(relay.Username)
	if err != nil {
		return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: OAuth requires a mailbox username", shared.ErrValidation)
	}
	relay.Username = username
	provider := strings.ToLower(strings.TrimSpace(oauth.Provider))
	if oauth.ClientID == "" || oauth.ClientSecret == "" {
		return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: OAuth client credentials are required", shared.ErrValidation)
	}
	switch provider {
	case "google":
		if host != "smtp.gmail.com" || oauth.RefreshToken == "" {
			return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: Google OAuth requires smtp.gmail.com and a refresh token", shared.ErrValidation)
		}
	case "microsoft":
		if host != "smtp.office365.com" || in.Port != 587 || !directoryUUID(oauth.DirectoryID) {
			return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: Microsoft OAuth requires smtp.office365.com on port 587 and a directory UUID", shared.ErrValidation)
		}
	default:
		return ports.SMTPRelayConfig{}, "", fmt.Errorf("%w: unsupported SMTP OAuth provider", shared.ErrValidation)
	}
	relay.OAuthProvider, relay.OAuthClientID, relay.OAuthClientSecret, relay.OAuthRefreshToken, relay.OAuthDirectoryID = provider, oauth.ClientID, oauth.ClientSecret, oauth.RefreshToken, strings.ToLower(strings.TrimSpace(oauth.DirectoryID))
	return relay, provider + "_oauth", nil
}

func (s *Service) relayAllowed(host string) bool { return host != "" && s.smtpAllowedHosts[host] }
func validSMTPPort(port int) bool                { return port == 465 || port == 587 }

func (s *Service) verifyEmailDomain(ctx context.Context, tenant shared.ID, domain string) error {
	if s.emailTXT == nil {
		return fmt.Errorf("%w: DNS proof resolver is unavailable", shared.ErrValidation)
	}
	values, err := s.emailTXT.LookupTXT(ctx, "_synapse-email."+domain)
	if err != nil {
		return fmt.Errorf("%w: domain TXT proof could not be verified", shared.ErrValidation)
	}
	want := "synapse-email-verification=" + tenant.String()
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return nil
		}
	}
	return fmt.Errorf("%w: domain TXT proof is missing", shared.ErrForbidden)
}

func canonicalEmailDomain(raw string) (string, error) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "."))
	if raw == "" || strings.ContainsAny(raw, "@/\\ \t\r\n") || strings.Contains(raw, "*") {
		return "", fmt.Errorf("%w: invalid email domain", shared.ErrValidation)
	}
	domain, err := idna.Lookup.ToASCII(raw)
	if err != nil || domain == "" || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", fmt.Errorf("%w: invalid email domain", shared.ErrValidation)
	}
	return strings.ToLower(domain), nil
}

func canonicalEmailDomains(raw []string) (map[string]struct{}, error) {
	domains := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		domain, err := canonicalEmailDomain(value)
		if err != nil {
			return nil, err
		}
		domains[domain] = struct{}{}
		if len(domains) > maxNotificationEmailDomains {
			return nil, fmt.Errorf("%w: at most %d email domains are allowed", shared.ErrValidation, maxNotificationEmailDomains)
		}
	}
	return domains, nil
}

func directoryUUID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func emailSettingsAAD(tenant shared.ID, revision int) []byte {
	return []byte(fmt.Sprintf("synapse:notification-email:%s:%d", tenant, revision))
}

func publicEmailSettings(setting ports.NotificationEmailSettings, domains []string) EmailSettings {
	if domains == nil {
		domains = []string{}
	}
	return EmailSettings{Revision: setting.Revision, RelayConfigured: setting.Configured, RelayHost: setting.Host, RelayPort: setting.Port, RelayFrom: setting.From, AuthMode: setting.AuthMode, Domains: domains, DNSValue: "synapse-email-verification=" + setting.TenantID.String()}
}
