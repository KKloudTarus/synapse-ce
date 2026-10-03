// Package notification provides tenant-scoped notification administration,
// durable publication, and worker delivery orchestration.
package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/tenancy"
	"github.com/KKloudTarus/synapse-ce/internal/platform/redact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const JobKind = "notification.deliver"

const (
	maxChannelsPerTenant = 50
	maxRulesPerTenant    = 200
)

type Service struct {
	tx        ports.TenantTransactionRunner
	repo      ports.NotificationRepository
	protector ports.NotificationSecretProtector
	sender    ports.NotificationSender
	audit     ports.AuditLogger
	clock     ports.Clock
	ids       ports.IDGenerator
	observer  ports.NotificationDeliveryObserver
	// disabled holds the channel types the operator switched off deployment-wide.
	disabled map[domain.ChannelType]bool
	// pauseThreshold is the number of consecutive permanent failures that pauses a channel (#1464).
	pauseThreshold int
	// templates stores tenant message templates (#1370); nil disables the template API.
	templates ports.NotificationTemplateStore
	// builtins is the built-in template catalog (#1366); NoBuiltinTemplates until it ships.
	builtins ports.BuiltinTemplates
	// events holds the per-type event builders; the worker asks them whether a delivery is still
	// relevant (#1344).
	events *EventBuilders
	// tenantSettings supplies the tenant default_locale to template resolution (#1371).
	tenantSettings ports.TenantSettingsStore
	// fixtures are the published event fixtures and eventReader the tenant's stored events, the
	// two samples a template preview renders against (#1372).
	fixtures    fs.FS
	eventReader ports.NotificationEventReader
}

// SetDisabledChannelTypes installs the operator kill switch (SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED),
// already checked against the driver registry by the composition root. A disabled type cannot be
// created, enabled, re-pointed or tested, and its queued deliveries are cancelled with
// provider_disabled. Existing channels are kept so turning the type back on restores them.
func (s *Service) SetDisabledChannelTypes(types []domain.ChannelType) {
	s.disabled = make(map[domain.ChannelType]bool, len(types))
	for _, channelType := range types {
		s.disabled[channelType] = true
	}
}

// refuseDisabled is the validation error an administrator sees for a disabled channel type.
func (s *Service) refuseDisabled(channelType domain.ChannelType) error {
	if s.disabled[channelType] {
		return fmt.Errorf("%w: channel type %q is disabled by the operator (SYNAPSE_NOTIFICATION_PROVIDERS_DISABLED)", shared.ErrValidation, channelType)
	}
	return nil
}

func NewService(repo ports.NotificationRepository, protector ports.NotificationSecretProtector, sender ports.NotificationSender, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || protector == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: notification dependencies are required", shared.ErrValidation)
	}
	return &Service{repo: repo, protector: protector, sender: sender, audit: audit, clock: clock, ids: ids, pauseThreshold: domain.DefaultPauseThreshold, builtins: ports.NoBuiltinTemplates{}, events: NewEventBuilders()}, nil
}

// SetPauseThreshold sets how many consecutive permanent failures pause a channel; zero keeps
// counting but never pauses. Values outside the documented bounds are refused.
func (s *Service) SetPauseThreshold(n int) error {
	if !domain.ValidPauseThreshold(n) {
		return fmt.Errorf("%w: channel pause threshold must be between 0 and %d", shared.ErrValidation, domain.MaxPauseThreshold)
	}
	s.pauseThreshold = n
	return nil
}

// SetDeliveryObserver installs optional worker-owned metrics instrumentation.
func (s *Service) SetDeliveryObserver(observer ports.NotificationDeliveryObserver) {
	s.observer = observer
}

func (s *Service) observeAttempt(channel domain.ChannelType, began, finished time.Time, delivered, fallback bool) {
	if s.observer != nil {
		s.observer.ObserveNotificationAttempt(channel, finished.Sub(began), delivered, fallback)
	}
}

func (s *Service) observeDeadLetter(channel domain.ChannelType) {
	if s.observer != nil {
		s.observer.ObserveNotificationDeadLetter(channel)
	}
}

type ChannelInput struct {
	Name       string             `json:"name"`
	Type       domain.ChannelType `json:"type"`
	Enabled    bool               `json:"enabled"`
	URL        string             `json:"url,omitempty"`
	Secret     string             `json:"secret,omitempty"`
	Recipients []string           `json:"recipients,omitempty"`
	// ChatID and ThreadID address a Telegram chat and, optionally, one of its forum topics; the bot
	// token travels in Secret. Like a URL they are part of the destination: changing either is a
	// destination change and needs the token re-entered.
	ChatID   string `json:"chat_id,omitempty"`
	ThreadID int64  `json:"thread_id,omitempty"`
	Revision int    `json:"revision,omitempty"`
	// AllowDestinationChange is set by the caller, never decoded from a request: true only when the
	// principal holds PermAdminister. Without it an update that changes the URL, the secret or the
	// email recipients is refused with shared.ErrForbidden (#1358), so an integration_admin can
	// rename, enable or disable a channel but cannot point it somewhere else.
	AllowDestinationChange bool `json:"-"`
	// TemplateID binds a template of the channel's family (#1371); "" unbinds and an absent field
	// keeps the current binding. Binding is not a destination change.
	TemplateID *shared.ID `json:"template_id,omitempty"`
	// Locale is the channel's locale, en or vi; "" uses the tenant default and an absent field keeps
	// the current value.
	Locale *tenancy.Locale `json:"locale,omitempty"`
	// CustomBody opts a webhook channel into sending its template's body as a custom JSON body
	// (#1376); it needs a bound template. An absent field keeps the current value.
	CustomBody *bool `json:"custom_body,omitempty"`
}

func (s *Service) createChannel(ctx context.Context, actor string, in ChannelInput) (domain.Channel, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Channel{}, err
	}
	if err = s.refuseDisabled(in.Type); err != nil {
		return domain.Channel{}, err
	}
	channels, err := s.repo.ListChannels(ctx, tenant)
	if err != nil {
		return domain.Channel{}, err
	}
	if len(channels) >= maxChannelsPerTenant {
		return domain.Channel{}, fmt.Errorf("notification channel limit reached: %w", shared.ErrSaturated)
	}
	id, now := s.ids.NewID(), s.clock.Now().UTC()
	config, destination, recipients, err := validateChannel(in, true)
	if err != nil {
		return domain.Channel{}, err
	}
	sealed, err := s.seal(tenant, id, 1, config)
	if err != nil {
		return domain.Channel{}, err
	}
	c := domain.Channel{TenantID: tenant, ID: id, Name: strings.TrimSpace(in.Name), Type: in.Type, Enabled: in.Enabled, Destination: destination, Recipients: recipients, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	c.TemplateBinding = applyBinding(domain.TemplateBinding{}, in)
	if err := s.validateBinding(ctx, tenant, c, nil); err != nil {
		return domain.Channel{}, err
	}
	created, err := s.repo.CreateChannel(domain.WithActor(ctx, actor), c, sealed)
	if err != nil {
		return domain.Channel{}, fmt.Errorf("create notification channel: %w", err)
	}
	if err := s.record(ctx, actor, "notification.channel.created", id.String(), channelAuditMetadata(created, bindingAuditMetadata(domain.TemplateBinding{}, created.TemplateBinding, nil))); err != nil {
		return domain.Channel{}, err
	}
	return created, nil
}

func (s *Service) updateChannel(ctx context.Context, actor string, id shared.ID, in ChannelInput) (domain.Channel, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Channel{}, err
	}
	current, err := s.repo.GetChannel(ctx, tenant, id)
	if err != nil {
		return domain.Channel{}, err
	}
	if in.Revision != current.Revision {
		return domain.Channel{}, fmt.Errorf("notification channel revision is stale: %w", shared.ErrConflict)
	}
	if in.Type == "" {
		in.Type = current.Type
	}
	if in.Type != current.Type {
		return domain.Channel{}, fmt.Errorf("%w: channel type is immutable", shared.ErrValidation)
	}
	replace := strings.TrimSpace(in.URL) != "" || strings.TrimSpace(in.Secret) != "" || strings.TrimSpace(in.ChatID) != "" || in.ThreadID != 0 || in.Type != current.Type
	if replace && !in.AllowDestinationChange {
		return domain.Channel{}, errDestinationChange
	}
	// A channel of a disabled type can still be renamed, switched off or deleted, but not switched
	// on or pointed at a new destination.
	if replace || (in.Enabled && !current.Enabled) {
		if err = s.refuseDisabled(current.Type); err != nil {
			return domain.Channel{}, err
		}
	}
	var sealed string
	destination := current.Destination
	recipients := current.Recipients
	if replace {
		config, dest, recips, e := validateChannel(in, true)
		if e != nil {
			return domain.Channel{}, e
		}
		sealed, e = s.seal(tenant, id, current.SecretVersion+1, config)
		if e != nil {
			return domain.Channel{}, e
		}
		destination, recipients = dest, recips
	} else {
		in.Type = current.Type
		if in.Type == domain.ChannelEmail && in.Recipients != nil {
			_, _, recips, e := validateChannel(ChannelInput{Name: in.Name, Type: domain.ChannelEmail, Recipients: in.Recipients, Enabled: in.Enabled}, false)
			if e != nil {
				return domain.Channel{}, e
			}
			// Recipients are an email channel's destination. Sending the same list back (the
			// console does on every save) is not a change.
			if !in.AllowDestinationChange && !sameRecipients(recips, current.Recipients) {
				return domain.Channel{}, errDestinationChange
			}
			recipients = recips
		}
		if in.Type == domain.ChannelEmail {
			destination = recipientSummary(recipients)
		}
	}
	now := s.clock.Now().UTC()
	updated := domain.Channel{TenantID: tenant, ID: id, Name: strings.TrimSpace(in.Name), Type: in.Type, Enabled: in.Enabled, Destination: destination, Recipients: recipients, Revision: current.Revision + 1, SecretVersion: current.SecretVersion, CreatedAt: current.CreatedAt, UpdatedAt: now}
	if updated.Name == "" {
		return domain.Channel{}, fmt.Errorf("%w: notification channel name is required", shared.ErrValidation)
	}
	updated.TemplateBinding = applyBinding(current.TemplateBinding, in)
	// An unchanged binding is not revalidated, so a channel whose template was archived can still
	// be renamed or switched off; resolution already skips that binding.
	if updated.TemplateBinding != current.TemplateBinding {
		rules, e := s.repo.ListRules(ctx, tenant)
		if e != nil {
			return domain.Channel{}, e
		}
		if e = s.validateBinding(ctx, tenant, updated, rules); e != nil {
			return domain.Channel{}, e
		}
	}
	updated, err = s.repo.UpdateChannel(domain.WithActor(ctx, actor), updated, sealed, replace)
	if err != nil {
		return domain.Channel{}, err
	}
	extra := bindingAuditMetadata(current.TemplateBinding, updated.TemplateBinding, map[string]string{"destination_changed": "false"})
	if previous := auditDestination(current); replace || !sameRecipients(current.Recipients, updated.Recipients) {
		extra["destination_changed"] = "true"
		extra["previous_destination"] = previous
	}
	if err := s.record(ctx, actor, "notification.channel.updated", id.String(), channelAuditMetadata(updated, extra)); err != nil {
		return domain.Channel{}, err
	}
	return updated, nil
}

func (s *Service) deleteChannel(ctx context.Context, actor string, id shared.ID, revision int) error {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return err
	}
	current, err := s.repo.GetChannel(ctx, tenant, id)
	if err != nil {
		return err
	}
	if err = s.repo.DeleteChannel(ctx, tenant, id, revision, s.clock.Now().UTC()); err != nil {
		return err
	}
	return s.record(ctx, actor, "notification.channel.deleted", id.String(), channelAuditMetadata(current, nil))
}
func (s *Service) GetChannel(ctx context.Context, id shared.ID) (domain.Channel, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Channel{}, err
	}
	return s.repo.GetChannel(ctx, tenant, id)
}
func (s *Service) ListChannels(ctx context.Context) ([]domain.Channel, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ListChannels(ctx, tenant)
}

type RuleInput struct {
	Name            string           `json:"name"`
	Enabled         bool             `json:"enabled"`
	EventType       domain.EventType `json:"event_type"`
	MinSeverity     shared.Severity  `json:"min_severity,omitempty"`
	ActionTypes     []string         `json:"action_types,omitempty"`
	EngagementIDs   []shared.ID      `json:"engagement_ids,omitempty"`
	TeamIDs         []shared.ID      `json:"team_ids,omitempty"`
	AllTeams        bool             `json:"all_teams,omitempty"`
	ChannelIDs      []shared.ID      `json:"channel_ids"`
	LeadTimeSeconds int64            `json:"lead_time_seconds,omitempty"`
	Revision        int              `json:"revision,omitempty"`
}

func (s *Service) createRule(ctx context.Context, actor string, in RuleInput) (domain.Rule, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Rule{}, err
	}
	rules, err := s.repo.ListRules(ctx, tenant)
	if err != nil {
		return domain.Rule{}, err
	}
	if len(rules) >= maxRulesPerTenant {
		return domain.Rule{}, fmt.Errorf("notification rule limit reached: %w", shared.ErrSaturated)
	}
	now := s.clock.Now().UTC()
	r := domain.Rule{TenantID: tenant, ID: s.ids.NewID(), Name: in.Name, Enabled: in.Enabled, EventType: in.EventType, MinSeverity: in.MinSeverity, ActionTypes: in.ActionTypes, EngagementIDs: in.EngagementIDs, TeamIDs: in.TeamIDs, AllTeams: in.AllTeams, ChannelIDs: in.ChannelIDs, LeadTimeSecs: in.LeadTimeSeconds, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err = r.Normalize(); err != nil {
		return domain.Rule{}, err
	}
	if err = s.checkRuleBindings(ctx, tenant, r); err != nil {
		return domain.Rule{}, err
	}
	r, err = s.repo.CreateRule(ctx, r)
	if err != nil {
		return domain.Rule{}, err
	}
	if err = s.record(ctx, actor, "notification.rule.created", r.ID.String(), map[string]string{"event_type": string(r.EventType)}); err != nil {
		return domain.Rule{}, err
	}
	return r, nil
}
func (s *Service) updateRule(ctx context.Context, actor string, id shared.ID, in RuleInput) (domain.Rule, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Rule{}, err
	}
	current, err := s.repo.GetRule(ctx, tenant, id)
	if err != nil {
		return domain.Rule{}, err
	}
	if current.Revision != in.Revision {
		return domain.Rule{}, fmt.Errorf("notification rule revision is stale: %w", shared.ErrConflict)
	}
	r := domain.Rule{TenantID: tenant, ID: id, Name: in.Name, Enabled: in.Enabled, EventType: in.EventType, MinSeverity: in.MinSeverity, ActionTypes: in.ActionTypes, EngagementIDs: in.EngagementIDs, TeamIDs: in.TeamIDs, AllTeams: in.AllTeams, ChannelIDs: in.ChannelIDs, LeadTimeSecs: in.LeadTimeSeconds, Revision: current.Revision + 1, CreatedAt: current.CreatedAt, UpdatedAt: s.clock.Now().UTC()}
	if err = r.Normalize(); err != nil {
		return domain.Rule{}, err
	}
	if err = s.checkRuleBindings(ctx, tenant, r); err != nil {
		return domain.Rule{}, err
	}
	r, err = s.repo.UpdateRule(ctx, r)
	if err != nil {
		return domain.Rule{}, err
	}
	if err = s.record(ctx, actor, "notification.rule.updated", id.String(), nil); err != nil {
		return domain.Rule{}, err
	}
	return r, nil
}
func (s *Service) deleteRule(ctx context.Context, actor string, id shared.ID, revision int) error {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return err
	}
	if err = s.repo.DeleteRule(ctx, tenant, id, revision); err != nil {
		return err
	}
	return s.record(ctx, actor, "notification.rule.deleted", id.String(), nil)
}
func (s *Service) GetRule(ctx context.Context, id shared.ID) (domain.Rule, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Rule{}, err
	}
	return s.repo.GetRule(ctx, tenant, id)
}
func (s *Service) ListRules(ctx context.Context) ([]domain.Rule, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ListRules(ctx, tenant)
}

func (s *Service) testChannel(ctx context.Context, actor string, cid shared.ID) (shared.ID, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return "", err
	}
	channel, err := s.repo.GetChannel(ctx, tenant, cid)
	if err != nil {
		return "", err
	}
	if err = s.refuseDisabled(channel.Type); err != nil {
		return "", err
	}
	now := s.clock.Now().UTC()
	data, _ := json.Marshal(map[string]any{"title": "Synapse notification test"})
	event := domain.Event{TenantID: tenant, ID: s.ids.NewID(), Type: domain.EventTest, SourceKind: "channel_test", SourceID: s.ids.NewID().String(), SchemaVersion: 1, OccurredAt: now, Data: data}
	id, err := s.repo.PublishToChannel(ctx, event, cid)
	if err != nil {
		return "", err
	}
	if err = s.record(ctx, actor, "notification.channel.test_queued", cid.String(), channelAuditMetadata(channel, map[string]string{"delivery_id": id.String()})); err != nil {
		return "", err
	}
	return id, nil
}
func (s *Service) GetDelivery(ctx context.Context, id shared.ID) (domain.Delivery, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Delivery{}, err
	}
	return s.repo.GetDelivery(ctx, tenant, id)
}
func (s *Service) ListDeliveries(ctx context.Context, f ports.NotificationDeliveryFilter) (domain.Page, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Page{}, err
	}
	f.TenantID = tenant
	return s.repo.ListDeliveries(ctx, f)
}
func (s *Service) ListSourceFailures(ctx context.Context, f ports.NotificationSourceFailureFilter) (domain.SourceFailurePage, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.SourceFailurePage{}, err
	}
	f.TenantID = tenant
	return s.repo.ListSourceFailures(ctx, f)
}
func (s *Service) ListAttempts(ctx context.Context, did shared.ID) ([]domain.Attempt, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ListAttempts(ctx, tenant, did)
}

// RedriveInput is the administrator's confirmation for one dead-lettered delivery.
type RedriveInput struct {
	Reason        string `json:"reason"`
	ExpectedFence int64  `json:"expected_fence"`
}

// RedriveDelivery schedules a new bounded retry cycle for the same delivery. It
// does not send inline, change the event or recipient, or update channel health.
func (s *Service) RedriveDelivery(ctx context.Context, actor string, id shared.ID, in RedriveInput) (domain.Delivery, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return domain.Delivery{}, fmt.Errorf("%w: redriving a delivery requires an actor", shared.ErrValidation)
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || len([]rune(reason)) > 500 {
		return domain.Delivery{}, fmt.Errorf("%w: redrive reason must contain 1 to 500 characters", shared.ErrValidation)
	}
	if in.ExpectedFence < 1 {
		return domain.Delivery{}, fmt.Errorf("%w: a positive expected queue fence is required", shared.ErrValidation)
	}
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return domain.Delivery{}, err
	}
	return mutation(ctx, s, func(ctx context.Context) (domain.Delivery, error) {
		current, err := s.repo.GetDelivery(ctx, tenant, id)
		if err != nil {
			return domain.Delivery{}, err
		}
		if err = s.refuseDisabled(current.ChannelType); err != nil {
			return domain.Delivery{}, err
		}
		if current.State != domain.DeliveryDead || current.RedriveFence != in.ExpectedFence {
			return domain.Delivery{}, fmt.Errorf("notification delivery state changed: %w", shared.ErrConflict)
		}
		safeReason, err := s.redriveAuditReason(ctx, tenant, id, reason)
		if err != nil {
			return domain.Delivery{}, err
		}
		redriven, channel, err := s.repo.RedriveDelivery(ctx, tenant, id, in.ExpectedFence)
		if err != nil {
			return domain.Delivery{}, err
		}
		scheme, host := "", ""
		if channel.Type.HTTPEndpoint() {
			scheme, host, _ = domain.MaskedEndpoint(channel.Destination)
		} else if channel.Type == domain.ChannelEmail {
			// The public channel summary may contain an email local-part when there is one
			// recipient. Audit only the validated domains, never full addresses.
			scheme, host = "mailto", emailDomainSummary([]string{redriven.Recipient})
		}
		if err := s.record(ctx, actor, "notification.delivery_redriven", id.String(), map[string]string{
			"channel_id":          channel.ID.String(),
			"channel_type":        string(channel.Type),
			"destination_scheme":  scheme,
			"destination_host":    host,
			"previous_fence":      strconv.FormatInt(in.ExpectedFence, 10),
			"queue_fence":         strconv.FormatInt(redriven.RedriveFence, 10),
			"previous_error_code": sanitizeCode(current.LastError),
			"reason":              safeReason,
		}); err != nil {
			return domain.Delivery{}, err
		}
		return redriven, nil
	})
}

func (s *Service) redriveAuditReason(ctx context.Context, tenant, id shared.ID, reason string) (string, error) {
	work, err := s.repo.LoadWork(ctx, tenant, id)
	if err != nil {
		return "", err
	}
	// Open only the delivery's immutable bound version, and keep its credentials
	// in the usecase. Never return plaintext or a protector error to the handler.
	raw, err := s.protector.Open(work.Sealed, channelAAD(tenant, work.Channel.ID, work.Channel.SecretVersion))
	if err != nil {
		return "", fmt.Errorf("notification channel configuration unavailable for audit: %w", shared.ErrConflict)
	}
	var cfg struct {
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if json.Unmarshal(raw, &cfg) != nil {
		return "", fmt.Errorf("notification channel configuration unavailable for audit: %w", shared.ErrConflict)
	}
	return privacy.ScrubSecretPatterns(redact.AuditText(reason, []string{cfg.URL, cfg.Secret, work.Delivery.Recipient})), nil
}

func emailDomainSummary(recipients []string) string {
	domains := make(map[string]struct{}, len(recipients))
	for _, recipient := range recipients {
		recipient = strings.TrimSpace(recipient)
		at := strings.LastIndex(recipient, "@")
		if at <= 0 || at == len(recipient)-1 {
			continue
		}
		address := recipient[at+1:]
		if strings.ContainsAny(address, " \t\r\n<>@") {
			continue
		}
		domains[strings.ToLower(address)] = struct{}{}
	}
	ordered := make([]string, 0, len(domains))
	for domain := range domains {
		ordered = append(ordered, domain)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func (s *Service) seal(tenant, id shared.ID, version int, cfg ports.NotificationChannelConfig) (string, error) {
	//nolint:gosec // The secret-bearing configuration is immediately sealed and is never persisted or logged as plaintext.
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	sealed, err := s.protector.Seal(raw, channelAAD(tenant, id, version))
	if err != nil {
		return "", fmt.Errorf("seal notification channel configuration: %w", err)
	}
	return sealed, nil
}
func channelAAD(tenant, id shared.ID, version int) []byte {
	return []byte("synapse:notification:" + tenant.String() + ":" + id.String() + ":" + strconv.Itoa(version))
}
func (s *Service) record(ctx context.Context, actor, action, target string, meta map[string]string) error {
	return s.audit.Record(ctx, ports.AuditEntry{Actor: actor, Action: action, Target: target, Metadata: meta, At: s.clock.Now().UTC()})
}
func tenantFrom(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return tenant, nil
}

// DeliveryError lets the generic worker schedule a channel-specific retry or
// stop immediately on a permanent transport response.
type DeliveryError struct {
	after    time.Duration
	terminal bool
	cause    error
}

func (e *DeliveryError) Error() string             { return e.cause.Error() }
func (e *DeliveryError) Unwrap() error             { return e.cause }
func (e *DeliveryError) RetryAfter() time.Duration { return e.after }
func (e *DeliveryError) Terminal() bool            { return e.terminal }
func (e *DeliveryError) MaxAttempts() int          { return 8 }

func (s *Service) HandleJob(ctx context.Context, job ports.QueuedJob) error {
	if s.sender == nil {
		return &DeliveryError{terminal: true, cause: errors.New("notification sender is not configured")}
	}
	var payload struct {
		DeliveryID shared.ID `json:"delivery_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.DeliveryID.IsZero() {
		return &DeliveryError{terminal: true, cause: errors.New("invalid notification delivery job")}
	}
	work, err := s.repo.LoadWork(ctx, job.TenantID, payload.DeliveryID)
	if err != nil {
		return err
	}
	if work.Delivery.State == domain.DeliverySucceeded || work.Delivery.State == domain.DeliveryCancelled {
		return nil
	}
	if work.Delivery.State == domain.DeliveryDead || job.Attempts > 8 {
		return &DeliveryError{terminal: true, cause: errors.New("notification_delivery_exhausted")}
	}
	// The operator switched this type off. Cancelling is not a channel failure, so the delivery is
	// not retried and the channel's own health is untouched.
	if s.disabled[work.Channel.Type] {
		return s.repo.CancelDelivery(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, domain.CodeProviderDisabled)
	}
	if !work.Channel.Enabled {
		return s.repo.CancelDelivery(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, "channel_disabled")
	}
	if work.Channel.Health.Paused() {
		// No new sends to a paused channel: its queued work is cancelled like a disabled channel's.
		return s.repo.CancelDelivery(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, "channel_paused")
	}
	relevant, err := s.events.StillRelevant(ctx, s.repo, work)
	if err != nil {
		return err
	}
	if !relevant {
		return s.repo.CancelDelivery(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, "source_no_longer_relevant")
	}
	now := s.clock.Now().UTC()
	aid := s.ids.NewID()
	if _, err = s.repo.BeginAttempt(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, aid, now); err != nil {
		return err
	}
	attempt := finishedAttempt{job: job, work: work, deliveryID: payload.DeliveryID, attemptID: aid}
	raw, err := s.protector.Open(work.Sealed, channelAAD(job.TenantID, work.Channel.ID, work.Channel.SecretVersion))
	if err != nil {
		finished := s.clock.Now().UTC()
		// The vault key is the operator's, not the channel's, so this never counts towards a pause.
		if finishErr := s.finishAttempt(ctx, attempt, finished, "failed", 0, "channel_secret_unavailable", nil, domain.AttemptIgnored); finishErr != nil {
			return finishErr
		}
		s.observeAttempt(work.Delivery.ChannelType, now, finished, false, false)
		s.observeDeadLetter(work.Delivery.ChannelType)
		return &DeliveryError{terminal: true, cause: errors.New("channel_secret_unavailable")}
	}
	cfg, configErr := decodeChannelConfig(work.Channel.Type, raw)
	if configErr != "" {
		finished := s.clock.Now().UTC()
		if finishErr := s.finishAttempt(ctx, attempt, finished, "failed", 0, configErr, nil, domain.ClassifyAttempt(false, configErr, false)); finishErr != nil {
			return finishErr
		}
		s.observeAttempt(work.Delivery.ChannelType, now, finished, false, false)
		s.observeDeadLetter(work.Delivery.ChannelType)
		return &DeliveryError{terminal: true, cause: errors.New(configErr)}
	}
	result := s.sender.Send(ctx, work, cfg)
	finished := s.clock.Now().UTC()
	if result.ErrorCode == "" && result.StatusCode >= 200 && result.StatusCode < 300 {
		if err = s.finishAttempt(ctx, attempt, finished, "delivered", result.StatusCode, "", nil, domain.AttemptDelivered); err != nil {
			return err
		}
		s.observeAttempt(work.Delivery.ChannelType, now, finished, true, result.TemplateFallback)
		return nil
	}
	terminal := !result.Retryable || job.Attempts >= 8
	outcome := "retrying"
	after := result.RetryAfter
	if after <= 0 {
		after = retryDelay(job.Attempts, payload.DeliveryID)
	}
	if after > time.Hour {
		after = time.Hour
	}
	next := finished.Add(after)
	nextPtr := &next
	if terminal {
		outcome = "failed"
		nextPtr = nil
	}
	code := sanitizeCode(result.ErrorCode)
	if code == "" {
		code = "delivery_failed"
	}
	// The health class reads the sender's own Retryable flag, so a retry that finally exhausts
	// its attempts (a 5xx eight times) still never counts towards a pause.
	if err = s.finishAttempt(ctx, attempt, finished, outcome, result.StatusCode, code, nextPtr, domain.ClassifyAttempt(false, code, result.Retryable)); err != nil {
		return err
	}
	s.observeAttempt(work.Delivery.ChannelType, now, finished, false, result.TemplateFallback)
	if terminal {
		s.observeDeadLetter(work.Delivery.ChannelType)
	}
	return &DeliveryError{after: after, terminal: terminal, cause: errors.New(code)}
}
func (s *Service) OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error {
	var p struct {
		DeliveryID shared.ID `json:"delivery_id"`
	}
	if json.Unmarshal(job.Payload, &p) != nil || p.DeliveryID.IsZero() {
		return nil
	}
	tenantCtx := shared.WithTenant(ctx, job.TenantID)
	d, err := s.repo.GetDelivery(tenantCtx, job.TenantID, p.DeliveryID)
	if err != nil {
		return err
	}
	if d.State != domain.DeliveryPending && d.State != domain.DeliveryRetrying {
		return nil // already terminal: do not count the same dead letter twice
	}
	transitioned, err := s.repo.DeadLetterDelivery(tenantCtx, job.TenantID, p.DeliveryID, job.Fence, "worker_dead_letter")
	if err != nil {
		return err
	}
	// Count only the transition committed by this callback. Re-reading a
	// dead row would double-count when two callbacks raced on the same job.
	if transitioned {
		s.observeDeadLetter(d.ChannelType)
	}
	return nil
}
func retryDelay(attempt int, id shared.ID) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := 10 * time.Second * time.Duration(1<<min(attempt-1, 8))
	h := int(id.String()[0])
	jitter := time.Duration((h%21)-10) * d / 100
	return d + jitter
}
func sanitizeCode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	if b.Len() > 64 {
		return b.String()[:64]
	}
	return b.String()
}
