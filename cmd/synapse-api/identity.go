package main

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/httpapi"
	"github.com/KKloudTarus/synapse-ce/internal/domain/authz"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/notificationsender"
	oidcadapter "github.com/KKloudTarus/synapse-ce/internal/infrastructure/oidc"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityenterprise"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/identityrecovery"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5/pgxpool"
)

func wireEnterpriseIdentity(cfg config.Config, router *httpapi.Router, auth *httpapi.Authenticator, pool *pgxpool.Pool, cipher *vault.Cipher, sender *notificationsender.Sender, clock ports.Clock, ids ports.IDGenerator) error {
	if err := cfg.ValidateIdentityCutover(); err != nil {
		return err
	}
	if pool == nil {
		if cfg.IdentityCutoverEnabled {
			return fmt.Errorf("enterprise identity requires durable PostgreSQL persistence")
		}
		return nil
	}
	store, err := postgres.NewIdentityFoundationStore(pool)
	if err != nil {
		return err
	}
	tenant := shared.TenantOrDefault(shared.ID(cfg.OIDCTenantID))
	router.SetLegacyOIDCFence(func(ctx context.Context) error {
		state, err := store.CutoverState(ctx, tenant)
		if err != nil {
			return authz.ErrAuthenticationUnavailable
		}
		if state.Declared {
			return authz.ErrCredentialInvalid
		}
		return nil
	})
	auth.SetAuthorityFence(func(ctx context.Context, p httpapi.Principal) error {
		if p.Credential == authz.KindBootstrap {
			return nil
		}
		state, err := store.CutoverState(ctx, shared.TenantOrDefault(shared.ID(p.TenantID)))
		if err != nil {
			return authz.ErrAuthenticationUnavailable
		}
		if state.Declared && p.PersonID == "" {
			return authz.ErrCredentialInvalid
		}
		return nil
	})
	if !cfg.IdentityCutoverEnabled {
		return nil
	}
	base, err := url.Parse(cfg.PublicBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return fmt.Errorf("enterprise browser identity requires a fixed HTTPS SYNAPSE_PUBLIC_BASE_URL")
	}
	if cfg.IdentityLegacyBearerGraceDuration < 0 || cfg.IdentityLegacyBearerGraceDuration > 24*time.Hour {
		return fmt.Errorf("identity legacy bearer grace duration must be between zero and 24 hours")
	}
	callback := *base
	callback.Path = "/api/auth/enterprise/callback"
	callback.RawPath = ""
	protector := oidcadapter.NewSecretProtector(cipher)
	factory, err := oidcadapter.NewConnectionFactory(protector, callback.String())
	if err != nil {
		return err
	}
	protocol, err := identityenterprise.NewService(store, store, factory, protector, clock, ids)
	if err != nil {
		return err
	}
	connections, err := identityenterprise.NewConnections(store, protector, clock, ids, callback.String())
	if err != nil {
		return err
	}
	var mailer ports.UserContactMailer
	if cfg.NotificationSMTPHost != "" && cfg.NotificationSMTPFrom != "" {
		mailer = sender
	}
	admission, err := identityenterprise.NewAdmissionService(store, mailer, ids, clock)
	if err != nil {
		return err
	}
	recovery, err := identityrecovery.NewService(store, clock, ids)
	if err != nil {
		return err
	}
	if mailer != nil {
		recovery.SetAlertMailer(sender)
	}
	browser, err := identityenterprise.NewBrowser(store, protocol, admission, protector, clock, ids, identityenterprise.BrowserConfig{TenantID: tenant, ReadEnabled: cfg.IdentityCutoverReadForTenant, MutationEnabled: cfg.IdentityCutoverMutationForTenant, SessionTTL: 12 * time.Hour, LegacyBearerGrace: cfg.IdentityLegacyBearerGraceDuration})
	if err != nil {
		return err
	}
	auth.WrapBearerResolver(func(legacy httpapi.Resolver) httpapi.Resolver {
		return func(ctx context.Context, token string) (httpapi.Principal, error) {
			route, err := browser.Route(ctx, token)
			if err == nil {
				state, err := store.CutoverState(ctx, route.TenantID)
				if err != nil {
					return httpapi.Principal{}, authz.ErrAuthenticationUnavailable
				}
				if state.Declared {
					if route.Kind != ports.IdentityCredentialAPIKey {
						return httpapi.Principal{}, authz.ErrCredentialInvalid
					}
					p, err := browser.AuthenticateAPIKey(ctx, token)
					return httpapi.Principal{ID: p.ActorID, Role: string(p.Role), TenantID: p.TenantID, PersonID: p.PersonID, MembershipID: p.MembershipID, Epochs: p.Epochs, Credential: p.Credential.Kind, CredentialID: p.Credential.ID, Provenance: p.Provenance}, err
				}
			} else if !identityenterprise.IsRouteMiss(err) {
				return httpapi.Principal{}, authz.ErrAuthenticationUnavailable
			}
			return legacy(ctx, token)
		}
	})
	return router.SetEnterprise(browser, connections, recovery, admission, store, protector, clock, tenant, base.String())
}
