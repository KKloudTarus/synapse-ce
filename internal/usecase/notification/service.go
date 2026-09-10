// Package notification provides tenant-scoped notification administration,
// durable publication, and worker delivery orchestration.
package notification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
}

func NewService(repo ports.NotificationRepository, protector ports.NotificationSecretProtector, sender ports.NotificationSender, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if repo == nil || protector == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: notification dependencies are required", shared.ErrValidation)
	}
	return &Service{repo: repo, protector: protector, sender: sender, audit: audit, clock: clock, ids: ids}, nil
}

type ChannelInput struct {
	Name       string             `json:"name"`
	Type       domain.ChannelType `json:"type"`
	Enabled    bool               `json:"enabled"`
	URL        string             `json:"url,omitempty"`
	Secret     string             `json:"secret,omitempty"`
	Recipients []string           `json:"recipients,omitempty"`
	Revision   int                `json:"revision,omitempty"`
}

func (s *Service) createChannel(ctx context.Context, actor string, in ChannelInput) (domain.Channel, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
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
	created, err := s.repo.CreateChannel(ctx, c, sealed)
	if err != nil {
		return domain.Channel{}, fmt.Errorf("create notification channel: %w", err)
	}
	if err := s.record(ctx, actor, "notification.channel.created", id.String(), map[string]string{"type": string(c.Type)}); err != nil {
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
	replace := strings.TrimSpace(in.URL) != "" || strings.TrimSpace(in.Secret) != "" || in.Type != current.Type
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
	updated, err = s.repo.UpdateChannel(ctx, updated, sealed, replace)
	if err != nil {
		return domain.Channel{}, err
	}
	if err := s.record(ctx, actor, "notification.channel.updated", id.String(), map[string]string{"type": string(updated.Type)}); err != nil {
		return domain.Channel{}, err
	}
	return updated, nil
}

func (s *Service) deleteChannel(ctx context.Context, actor string, id shared.ID, revision int) error {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return err
	}
	if err = s.repo.DeleteChannel(ctx, tenant, id, revision, s.clock.Now().UTC()); err != nil {
		return err
	}
	return s.record(ctx, actor, "notification.channel.deleted", id.String(), nil)
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
	r := domain.Rule{TenantID: tenant, ID: s.ids.NewID(), Name: in.Name, Enabled: in.Enabled, EventType: in.EventType, MinSeverity: in.MinSeverity, ActionTypes: in.ActionTypes, EngagementIDs: in.EngagementIDs, ChannelIDs: in.ChannelIDs, LeadTimeSecs: in.LeadTimeSeconds, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err = r.Normalize(); err != nil {
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
	r := domain.Rule{TenantID: tenant, ID: id, Name: in.Name, Enabled: in.Enabled, EventType: in.EventType, MinSeverity: in.MinSeverity, ActionTypes: in.ActionTypes, EngagementIDs: in.EngagementIDs, ChannelIDs: in.ChannelIDs, LeadTimeSecs: in.LeadTimeSeconds, Revision: current.Revision + 1, CreatedAt: current.CreatedAt, UpdatedAt: s.clock.Now().UTC()}
	if err = r.Normalize(); err != nil {
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
	now := s.clock.Now().UTC()
	data, _ := json.Marshal(map[string]any{"title": "Synapse notification test"})
	event := domain.Event{TenantID: tenant, ID: s.ids.NewID(), Type: domain.EventTest, SourceKind: "channel_test", SourceID: s.ids.NewID().String(), SchemaVersion: 1, OccurredAt: now, Data: data}
	id, err := s.repo.PublishToChannel(ctx, event, cid)
	if err != nil {
		return "", err
	}
	if err = s.record(ctx, actor, "notification.channel.test_queued", cid.String(), map[string]string{"delivery_id": id.String()}); err != nil {
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
func (s *Service) ListAttempts(ctx context.Context, did shared.ID) ([]domain.Attempt, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ListAttempts(ctx, tenant, did)
}
func (s *Service) Publish(ctx context.Context, e domain.Event) ([]shared.ID, error) {
	tenant, err := tenantFrom(ctx)
	if err != nil {
		return nil, err
	}
	e.TenantID = tenant
	if e.ID.IsZero() {
		e.ID = s.ids.NewID()
	}
	if e.SchemaVersion == 0 {
		e.SchemaVersion = 1
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = s.clock.Now().UTC()
	}
	return s.repo.Publish(ctx, e)
}

func (s *Service) seal(tenant, id shared.ID, version int, cfg ports.NotificationChannelConfig) (string, error) {
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

func validateChannel(in ChannelInput, requireSecret bool) (ports.NotificationChannelConfig, string, []string, error) {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 200 || !in.Type.Valid() {
		return ports.NotificationChannelConfig{}, "", nil, fmt.Errorf("%w: channel name and valid type are required", shared.ErrValidation)
	}
	cfg := ports.NotificationChannelConfig{}
	switch in.Type {
	case domain.ChannelWebhook:
		u, err := validateHTTPS(in.URL, false)
		if err != nil {
			return cfg, "", nil, err
		}
		if requireSecret && len(in.Secret) < 16 {
			return cfg, "", nil, fmt.Errorf("%w: webhook signing secret must be at least 16 bytes", shared.ErrValidation)
		}
		cfg.URL = u.String()
		cfg.Secret = in.Secret
		return cfg, u.Scheme + "://" + u.Host + "/…", nil, nil
	case domain.ChannelSlack:
		u, err := validateHTTPS(in.URL, true)
		if err != nil {
			return cfg, "", nil, err
		}
		cfg.URL = u.String()
		return cfg, "https://" + u.Host + "/services/…", nil, nil
	case domain.ChannelEmail:
		recipients := make([]string, 0, len(in.Recipients))
		seen := map[string]bool{}
		for _, v := range in.Recipients {
			a, err := mail.ParseAddress(strings.TrimSpace(v))
			if err != nil || strings.ContainsAny(a.Address, "\r\n") {
				return cfg, "", nil, fmt.Errorf("%w: invalid email recipient", shared.ErrValidation)
			}
			normalized := strings.ToLower(a.Address)
			if !seen[normalized] {
				seen[normalized] = true
				recipients = append(recipients, normalized)
			}
		}
		if len(recipients) == 0 || len(recipients) > 50 {
			return cfg, "", nil, fmt.Errorf("%w: email channel requires 1-50 recipients", shared.ErrValidation)
		}
		cfg.Recipients = recipients
		return cfg, recipientSummary(recipients), recipients, nil
	}
	return cfg, "", nil, fmt.Errorf("%w: unsupported channel type", shared.ErrValidation)
}
func validateHTTPS(raw string, slack bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%w: channel URL must be an HTTPS URL without credentials", shared.ErrValidation)
	}
	host := strings.ToLower(u.Hostname())
	if slack && !((host == "hooks.slack.com" || host == "hooks.slack-gov.com") && strings.HasPrefix(u.EscapedPath(), "/services/")) {
		return nil, fmt.Errorf("%w: Slack channel requires a supported incoming-webhook URL", shared.ErrValidation)
	}
	return u, nil
}
func recipientSummary(v []string) string {
	if len(v) == 1 {
		return v[0]
	}
	return strconv.Itoa(len(v)) + " recipients"
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
	if work.Delivery.State == domain.DeliverySucceeded || work.Delivery.State == domain.DeliveryCancelled || work.Delivery.State == domain.DeliveryDead {
		return nil
	}
	if !work.Channel.Enabled {
		return s.repo.CancelDelivery(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, "channel_disabled")
	}
	relevant, err := s.repo.DeliveryStillRelevant(ctx, work)
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
	raw, err := s.protector.Open(work.Sealed, channelAAD(job.TenantID, work.Channel.ID, work.Channel.SecretVersion))
	if err != nil {
		_ = s.repo.FinishAttempt(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, aid, s.clock.Now().UTC(), "failed", 0, "channel_secret_unavailable", nil)
		return &DeliveryError{terminal: true, cause: errors.New("channel_secret_unavailable")}
	}
	var cfg ports.NotificationChannelConfig
	if json.Unmarshal(raw, &cfg) != nil {
		_ = s.repo.FinishAttempt(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, aid, s.clock.Now().UTC(), "failed", 0, "channel_config_invalid", nil)
		return &DeliveryError{terminal: true, cause: errors.New("channel_config_invalid")}
	}
	result := s.sender.Send(ctx, work, cfg)
	finished := s.clock.Now().UTC()
	if result.ErrorCode == "" && result.StatusCode >= 200 && result.StatusCode < 300 {
		if err = s.repo.FinishAttempt(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, aid, finished, "delivered", result.StatusCode, "", nil); err != nil {
			return err
		}
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
	var nextPtr *time.Time = &next
	if terminal {
		outcome = "failed"
		nextPtr = nil
	}
	code := sanitizeCode(result.ErrorCode)
	if code == "" {
		code = "delivery_failed"
	}
	if err = s.repo.FinishAttempt(ctx, job.TenantID, payload.DeliveryID, job.ID, job.Fence, aid, finished, outcome, result.StatusCode, code, nextPtr); err != nil {
		return err
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
	d, err := s.repo.GetDelivery(shared.WithTenant(ctx, job.TenantID), job.TenantID, p.DeliveryID)
	if err == nil && (d.State == domain.DeliveryPending || d.State == domain.DeliveryRetrying) {
		return s.repo.DeadLetterDelivery(shared.WithTenant(ctx, job.TenantID), job.TenantID, p.DeliveryID, "worker_dead_letter")
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
