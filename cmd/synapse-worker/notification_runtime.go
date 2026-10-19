package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/adapter/notificationbuiltin"
	"github.com/KKloudTarus/synapse-ce/internal/adapter/observability"
	"github.com/KKloudTarus/synapse-ce/internal/domain/consolelink"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/messageformat"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/notificationsender"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/teamsbot"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/vault"
	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
	alertinguc "github.com/KKloudTarus/synapse-ce/internal/usecase/alerting"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/inbox"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/teamslink"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/usercontacts"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/worker"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type notificationWorkerRuntime struct {
	service         *notificationuc.Service
	handlers        map[string]worker.Handler
	maintenance     []func(context.Context)
	metricsRegistry *prometheus.Registry
	close           func()
}

type workerMetricsServer struct {
	address string
	close   func()
}

// notificationWorkerKinds is the complete and deliberately small claim set of the
// data-only notification worker. Unknown and scanner job kinds remain queued for
// workers that advertise their matching handlers.
func notificationWorkerKinds() []string {
	return []string{
		notificationuc.JobKind,
		usercontacts.JobKind,
		inbox.JobKind,
		inbox.SlackJobKind,
		inbox.TeamsJobKind,
	}
}

func notificationMaintenanceResource(cfg config.Config) string {
	return cfg.LeaderResource + "-worker-notification-maintenance"
}

// notificationWorkerVaultCipher validates the durable, API-shared key before a
// notification profile can construct handlers or enter a queue claim loop.
func notificationWorkerVaultCipher(cfg config.Config) (*vault.Cipher, error) {
	if strings.TrimSpace(cfg.VaultMasterKey) == "" {
		return nil, errors.New("notification worker requires SYNAPSE_VAULT_MASTER_KEY shared by API and worker")
	}
	key, err := vault.DecodeKey(cfg.VaultMasterKey)
	if err != nil {
		return nil, fmt.Errorf("decode notification worker vault master key: %w", err)
	}
	cipher, err := vault.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create notification worker vault cipher: %w", err)
	}
	return cipher, nil
}

// configureNotificationWorkerRuntime owns the notification-only composition shared
// by the all and notifications worker profiles. The caller keeps the returned close
// function alive for the root lifetime; this helper must not defer it because the
// registry is also used by optional SIEM metrics in the all profile.
func configureNotificationWorkerRuntime(
	ctx context.Context,
	stop context.CancelFunc,
	cfg config.Config,
	pool *pgxpool.Pool,
	vaultCipher *vault.Cipher,
	sender *notificationsender.Sender,
	disabledTypes []notification.ChannelType,
	auditLog ports.AuditLogger,
	clock ports.Clock,
	ids ports.IDGenerator,
	log *slog.Logger,
) (notificationWorkerRuntime, error) {
	if !cfg.NotificationEnabled {
		return notificationWorkerRuntime{}, errors.New("notification worker runtime requires SYNAPSE_NOTIFICATIONS_ENABLED=true")
	}
	if cfg.VaultMasterKey == "" {
		return notificationWorkerRuntime{}, errors.New("notification worker runtime requires SYNAPSE_VAULT_MASTER_KEY shared by API and worker")
	}
	if vaultCipher == nil || sender == nil || pool == nil || auditLog == nil || clock == nil || ids == nil || log == nil {
		return notificationWorkerRuntime{}, errors.New("notification worker runtime has an incomplete dependency")
	}

	notificationService, err := notificationuc.NewService(newNotificationRepository(pool), vaultCipher, sender, auditLog, clock, ids)
	if err != nil {
		return notificationWorkerRuntime{}, fmt.Errorf("create notification service: %w", err)
	}
	notificationService.SetDisabledChannelTypes(disabledTypes)
	if len(disabledTypes) > 0 {
		log.Warn("notification channel types disabled by the operator; their deliveries are cancelled with provider_disabled", "types", cfg.NotificationProvidersDisabled)
	}
	if err := notificationService.SetPauseThreshold(cfg.NotificationChannelPauseThreshold); err != nil {
		return notificationWorkerRuntime{}, fmt.Errorf("set notification channel pause threshold: %w", err)
	}
	notificationService.SetTransactionRunner(postgres.NewTenantTransactionRunner(pool))
	notificationService.SetSelfHostedChannelHosts(cfg.NotificationChatAllowedHosts)
	notificationService.SetSMTPAllowedHosts(cfg.NotificationSMTPAllowedHosts)
	notificationService.SetEmailSettingsStore(postgres.NewNotificationEmailSettingsStore(pool))
	notificationService.SetNotificationTXTResolver(net.DefaultResolver)
	notificationService.SetTemplateStore(postgres.NewNotificationTemplateStore(pool))
	notificationService.SetTenantSettings(postgres.NewTenantSettingsStore(pool))
	notificationService.SetFormatters(messageformat.Formatters())
	notificationService.SetSlackDirect(sender)
	notificationService.SetPublicBaseURL(cfg.EffectivePublicBaseURL())
	notificationService.SetBuiltinTemplates(notificationbuiltin.New())
	if base := cfg.EffectivePublicBaseURL(); base != "" {
		builder, err := consolelink.NewBuilder(base)
		if err != nil {
			return notificationWorkerRuntime{}, fmt.Errorf("build notification console links: %w", err)
		}
		notificationService.SetConsoleLinkBuilder(builder)
	}

	runtime := notificationWorkerRuntime{service: notificationService, handlers: make(map[string]worker.Handler, len(notificationWorkerKinds())), close: func() {}}
	if cfg.MetricsEnabled {
		metrics := observability.NewWorkerNotificationMetrics(postgres.NewNotificationRepository(pool))
		runtime.metricsRegistry = metrics.Registry()
		notificationService.SetDeliveryObserver(metrics)
		metricsServer, err := startWorkerMetrics(ctx, stop, cfg.MetricsAddr, runtime.metricsRegistry, log)
		if err != nil {
			return notificationWorkerRuntime{}, err
		}
		runtime.close = metricsServer.close
		log.Info("private worker notification metrics enabled", "addr", cfg.MetricsAddr)
	}

	runtime.handlers[notificationuc.JobKind] = notificationJobHandler{svc: notificationService}
	contactService, err := usercontacts.NewService(postgres.NewUserContactStore(pool), postgres.NewUserRepository(pool), vaultCipher, sender, ids, clock, usercontacts.DeriveVerifierKey(cfg.VaultMasterKey), cfg.NotificationSMTPHost != "" && cfg.NotificationSMTPFrom != "")
	if err != nil {
		runtime.close()
		return notificationWorkerRuntime{}, fmt.Errorf("create user contact service: %w", err)
	}
	contactService.SetSlack(notificationService)
	runtime.handlers[usercontacts.JobKind] = contactVerificationJobHandler{svc: contactService}

	inboxStore := postgres.NewInboxStore(pool)
	personalInbox, err := inbox.NewService(inboxStore, clock)
	if err != nil {
		runtime.close()
		return notificationWorkerRuntime{}, fmt.Errorf("create personal inbox service: %w", err)
	}
	personalInbox.SetMailer(sender)
	personalInbox.SetPersonalDelivery(inboxStore)
	personalInbox.SetPersonalSender(notification.PersonalSlack, notificationService.PersonalSlack())
	if err := cfg.ValidateTeamsBot(); err != nil {
		runtime.close()
		return notificationWorkerRuntime{}, fmt.Errorf("validate Microsoft Teams bot: %w", err)
	}
	if cfg.TeamsBotEnabled() {
		teamsService, err := teamslink.NewService(teamslink.Config{
			Bot:    teamsbot.New(teamsbot.Config{AppID: cfg.TeamsBotAppID, AppPassword: cfg.TeamsBotAppPassword, TenantID: cfg.TeamsBotTenantID}, safehttp.New(10*time.Second, false)),
			Offers: postgres.NewTeamsLinkOffers(pool), Contacts: postgres.NewUserContactStore(pool), Protector: vaultCipher, IDs: ids, Clock: clock,
			Key: teamslink.DeriveKey(cfg.VaultMasterKey), AcceptsServiceURL: teamsbot.ValidServiceURL,
			Formatter: messageformat.TeamsFormatter{}, PublicBaseURL: cfg.EffectivePublicBaseURL(),
		})
		if err != nil {
			runtime.close()
			return notificationWorkerRuntime{}, fmt.Errorf("create Microsoft Teams bot service: %w", err)
		}
		personalInbox.SetPersonalSender(notification.PersonalTeams, teamsService)
		personalInbox.SetTeamsAvailable(true)
	}
	for _, kind := range inbox.JobKinds() {
		runtime.handlers[kind] = personalMailJobHandler{svc: personalInbox}
	}
	if len(runtime.handlers) != len(notificationWorkerKinds()) {
		runtime.close()
		return notificationWorkerRuntime{}, fmt.Errorf("notification worker handler set has %d kinds, want %d", len(runtime.handlers), len(notificationWorkerKinds()))
	}

	alertinguc.WarnLegacyWebhookDeprecated(log, cfg.AlertWebhookURL != "")
	source := postgres.NewNotificationSource(pool, newNotificationRepository(pool), cfg.FleetAgentStaleAfter)
	if err := source.SetSLABreachMaxReminders(cfg.NotificationSLABreachMaxReminders); err != nil {
		runtime.close()
		return notificationWorkerRuntime{}, fmt.Errorf("set notification SLA reminders: %w", err)
	}
	source.SetVulnerabilityEnabled(cfg.VulnerabilityNotificationsEnabled && !cfg.VulnerabilityDryRunEnabled)
	runtime.maintenance = append(runtime.maintenance, func(taskCtx context.Context) {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if n, err := source.Poll(taskCtx, clock.Now().UTC(), 200); err != nil && taskCtx.Err() == nil {
				log.Warn("notification source poll failed", "err", err)
			} else if n > 0 {
				log.Info("notification source events projected", "count", n)
			}
			select {
			case <-taskCtx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	return runtime, nil
}

func startWorkerMetrics(ctx context.Context, stop context.CancelFunc, address string, registry *prometheus.Registry, log *slog.Logger) (workerMetricsServer, error) {
	if registry == nil {
		return workerMetricsServer{}, errors.New("worker metrics registry is required")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return workerMetricsServer{}, fmt.Errorf("listen for worker metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	var closeOnce sync.Once
	closeServer := func() {
		closeOnce.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("worker metrics shutdown failed", "err", err)
			}
		})
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			log.Error("worker metrics listener stopped", "err", err)
			stop()
		}
	}()
	return workerMetricsServer{address: listener.Addr().String(), close: closeServer}, nil
}
