package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SMTPRelayConfig is the sealed tenant-owned relay configuration. It must never
// be returned by an administration API or written to an audit record.
type SMTPRelayConfig struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	From              string `json:"from"`
	Username          string `json:"username,omitempty"`
	Password          string `json:"password,omitempty"`
	OAuthProvider     string `json:"oauth_provider,omitempty"`
	OAuthClientID     string `json:"oauth_client_id,omitempty"`
	OAuthClientSecret string `json:"oauth_client_secret,omitempty"`
	OAuthRefreshToken string `json:"oauth_refresh_token,omitempty"`
	OAuthDirectoryID  string `json:"oauth_directory_id,omitempty"`
	CacheKey          string `json:"-"`
}

// NotificationEmailSettings is the safe metadata projection of the tenant relay.
// Sealed is carried only between the usecase and its persistence adapter.
type NotificationEmailSettings struct {
	TenantID   shared.ID `json:"-"`
	Revision   int       `json:"revision"`
	Configured bool      `json:"configured"`
	Host       string    `json:"host,omitempty"`
	Port       int       `json:"port,omitempty"`
	From       string    `json:"from,omitempty"`
	AuthMode   string    `json:"auth_mode,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	UpdatedBy  string    `json:"updated_by,omitempty"`
	Sealed     string    `json:"-"`
}

// NotificationEmailSettingsStore persists one revisioned tenant relay and the
// exact domains that a tenant has proven using DNS TXT.
type NotificationEmailSettingsStore interface {
	GetNotificationEmailSettings(context.Context, shared.ID) (NotificationEmailSettings, error)
	PutNotificationEmailSettings(context.Context, NotificationEmailSettings) (NotificationEmailSettings, error)
	ListNotificationEmailDomains(context.Context, shared.ID) ([]string, error)
	AddNotificationEmailDomain(context.Context, shared.ID, string, time.Time) error
	DeleteNotificationEmailDomain(context.Context, shared.ID, string) error
	VerifiedNotificationEmailRecipients(context.Context, shared.ID, []string) (map[string]bool, error)
}

// NotificationTXTResolver is deliberately small so tests and deployments can
// control DNS resolution. It returns the TXT records for the fully-qualified name.
type NotificationTXTResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}
