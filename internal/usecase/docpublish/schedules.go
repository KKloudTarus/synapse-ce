package docpublish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScheduleDependencies are the narrow boundaries used by durable scheduled
// releases. Composition supplies existing document, notification and SMTP
// components; this service never opens a second secret or transport path.
type ScheduleDependencies struct {
	Store        ports.DocumentScheduleStore
	Authority    ports.DocumentAuthorityReader
	ReportPolicy ports.DocumentReportReleaseReader
	Artifacts    ports.DocumentScheduledArtifactSource
	Channels     ports.DocumentScheduleChannelReader
	Integrations interface {
		GetIntegration(context.Context, shared.ID) (integration.Integration, error)
	}
	EmailConfig ports.DocumentScheduleEmailConfig
	EmailSender ports.DocumentPDFSender
	Publisher   interface {
		PublishArtifact(context.Context, shared.ID, ports.DocumentActor, PublishInput, ports.DocumentArtifact) (ReleaseResult, error)
	}
	Executor interface {
		Execute(context.Context, shared.ID, shared.ID) (domain.Intent, error)
	}
	Audit         ports.AuditLogger
	IDs           ports.IDGenerator
	Clock         ports.Clock
	PublicBaseURL string
	Projects      interface {
		GetByID(context.Context, shared.ID, shared.ID) (*project.Project, error)
	}
}

type ScheduleService struct{ deps ScheduleDependencies }

func NewScheduleService(deps ScheduleDependencies) (*ScheduleService, error) {
	if deps.Store == nil || deps.Authority == nil || deps.ReportPolicy == nil || deps.Artifacts == nil || deps.Channels == nil || deps.Integrations == nil || deps.EmailConfig == nil || deps.EmailSender == nil || deps.Publisher == nil || deps.Executor == nil || deps.Audit == nil || deps.IDs == nil || deps.Clock == nil {
		return nil, fmt.Errorf("%w: document schedule dependencies required", shared.ErrValidation)
	}
	return &ScheduleService{deps: deps}, nil
}

// ScheduleInput contains only configuration that an administrator may choose.
// Identity and source scope remain server-derived at the HTTP boundary.
type ScheduleInput struct {
	ID              shared.ID                  `json:"id,omitempty"`
	Source          domain.Source              `json:"source"`
	Destination     domain.ScheduleDestination `json:"destination"`
	IntegrationID   shared.ID                  `json:"integration_id,omitempty"`
	EmailChannelID  shared.ID                  `json:"email_channel_id,omitempty"`
	Timezone        string                     `json:"timezone"`
	Frequency       domain.ScheduleFrequency   `json:"frequency"`
	Weekday         int                        `json:"weekday,omitempty"`
	Day             int                        `json:"day,omitempty"`
	Hour            int                        `json:"hour"`
	Minute          int                        `json:"minute"`
	Enabled         bool                       `json:"enabled"`
	ExpectedVersion int                        `json:"expected_version,omitempty"`
}
type ScheduleEmailDestination struct {
	ID             shared.ID `json:"id"`
	Name           string    `json:"name"`
	RecipientCount int       `json:"recipient_count"`
}

// EmailDestinations returns only safe selectable metadata. Recipient addresses,
// relay data and sealed channel configuration never leave the schedule service.
func (s *ScheduleService) EmailDestinations(ctx context.Context, tenant shared.ID, actor ports.DocumentActor) ([]ScheduleEmailDestination, error) {
	ctx = shared.WithTenant(ctx, tenant)
	if ok, err := s.deps.Authority.CanReleaseDocument(ctx, tenant, actor); err != nil {
		return nil, err
	} else if !ok {
		return nil, shared.ErrForbidden
	}
	channels, err := s.deps.Channels.ListChannels(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := make([]ScheduleEmailDestination, 0)
	for _, ch := range channels {
		if ch.Type != notification.ChannelEmail || !ch.Enabled || ch.DeletedAt != nil || ch.Health.State == notification.ChannelPaused || ch.Class() != notification.DataClassDetail || len(ch.Recipients) == 0 || len(ch.Recipients) > 20 {
			continue
		}
		verified := true
		for _, recipient := range ch.Recipients {
			cfg, code := s.deps.EmailConfig.EmailChannelConfig(ctx, ports.NotificationWork{Channel: ch, Delivery: notification.Delivery{Recipient: recipient}}, ports.EmailChannelConfig{Recipients: ch.Recipients})
			if code != "" {
				verified = false
				break
			}
			_, ok := cfg.(ports.EmailChannelConfig)
			if !ok {
				verified = false
				break
			}
		}
		if verified {
			out = append(out, ScheduleEmailDestination{ID: ch.ID, Name: ch.Name, RecipientCount: len(ch.Recipients)})
		}
	}
	return out, nil
}

func (s *ScheduleService) SaveSchedule(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, in ScheduleInput) (domain.Schedule, error) {
	if tenant.IsZero() || in.ID.IsZero() {
		return domain.Schedule{}, shared.ErrValidation
	}
	ctx = shared.WithTenant(ctx, tenant)
	if ok, err := s.deps.Authority.CanReleaseDocument(ctx, tenant, actor); err != nil {
		return domain.Schedule{}, err
	} else if !ok {
		return domain.Schedule{}, shared.ErrForbidden
	}
	if err := validateScheduleSource(in.Source); err != nil {
		return domain.Schedule{}, err
	}
	now := s.deps.Clock.Now().UTC()
	next, err := scheduleNext(in, now)
	if err != nil {
		return domain.Schedule{}, err
	}
	schedule := domain.Schedule{ID: in.ID, TenantID: tenant, Source: in.Source, Destination: in.Destination, IntegrationID: in.IntegrationID, EmailChannelID: in.EmailChannelID, OwnerUserID: actor.UserID, OwnerMembershipID: actor.MembershipID, OwnerPersonID: actor.PersonID, Timezone: in.Timezone, Frequency: in.Frequency, Weekday: in.Weekday, Day: in.Day, Hour: in.Hour, Minute: in.Minute, Enabled: in.Enabled, Version: 1, NextDueAt: next, CreatedAt: now, UpdatedAt: now}
	if old, err := s.deps.Store.GetDocumentSchedule(ctx, tenant, in.ID); err == nil {
		if old.Source != schedule.Source || old.Destination != schedule.Destination || old.IntegrationID != schedule.IntegrationID || old.EmailChannelID != schedule.EmailChannelID {
			return domain.Schedule{}, shared.ErrConflict
		}
		schedule.Version = old.Version
		schedule.CreatedAt = old.CreatedAt
		if schedule.NextDueAt.Before(now) || !in.Enabled {
			schedule.NextDueAt = old.NextDueAt
		}
		if in.ExpectedVersion != old.Version {
			return domain.Schedule{}, shared.ErrConflict
		}
	} else if !errorsIsNotFound(err) {
		return domain.Schedule{}, err
	} else if in.ExpectedVersion != 0 {
		return domain.Schedule{}, shared.ErrConflict
	}
	if err := s.scheduleAdmission(ctx, tenant, schedule, actor); err != nil {
		return domain.Schedule{}, err
	}
	// Record admission before making the schedule executable. A later CAS refusal
	// leaves an audited request, without claiming that the change committed.
	if err := s.audit(ctx, tenant, actor, "document.schedule_save_requested", schedule.ID.String(), map[string]string{"destination": string(schedule.Destination), "source_kind": string(schedule.Source.SourceKind)}); err != nil {
		return domain.Schedule{}, err
	}
	return s.deps.Store.SaveDocumentSchedule(ctx, tenant, schedule, in.ExpectedVersion)
}

func (s *ScheduleService) ListSchedules(ctx context.Context, tenant shared.ID, scope domain.Scope, scopeID shared.ID) ([]domain.Schedule, error) {
	return s.deps.Store.ListDocumentSchedules(shared.WithTenant(ctx, tenant), tenant, scope, scopeID, domain.MaxListLimit)
}
func (s *ScheduleService) DeleteSchedule(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, id shared.ID, expected int) error {
	ctx = shared.WithTenant(ctx, tenant)
	if ok, err := s.deps.Authority.CanReleaseDocument(ctx, tenant, actor); err != nil {
		return err
	} else if !ok {
		return shared.ErrForbidden
	}
	current, err := s.deps.Store.GetDocumentSchedule(ctx, tenant, id)
	if err != nil {
		return err
	}
	if current.Version != expected {
		return shared.ErrConflict
	}
	if err := s.audit(ctx, tenant, actor, "document.schedule_disable_requested", current.ID.String(), nil); err != nil {
		return err
	}
	return s.deps.Store.DeleteDocumentSchedule(ctx, tenant, id, expected, s.deps.Clock.Now().UTC())
}

// Tick admits at most limit (and never more than twenty) due occurrences. Each
// occurrence is independently durable, so duplicate workers cannot create two
// emails or document commands for the same scheduled instant.
func (s *ScheduleService) Tick(ctx context.Context, tenant shared.ID, limit int) error {
	if tenant.IsZero() || limit < 1 {
		return shared.ErrValidation
	}
	if limit > 20 {
		limit = 20
	}
	ctx = shared.WithTenant(ctx, tenant)
	now := s.deps.Clock.Now().UTC()
	work, err := s.deps.Store.ClaimDueDocumentScheduleOccurrences(ctx, tenant, limit, now)
	if err != nil {
		return err
	}
	var failures []error
	for _, item := range work {
		if err := s.executeOccurrence(ctx, tenant, item, now); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func scheduleNext(in ScheduleInput, now time.Time) (time.Time, error) {
	probe := domain.Schedule{ID: "schedule", TenantID: "tenant", Source: in.Source, Destination: in.Destination, IntegrationID: in.IntegrationID, EmailChannelID: in.EmailChannelID, OwnerUserID: "owner", Timezone: in.Timezone, Frequency: in.Frequency, Weekday: in.Weekday, Day: in.Day, Hour: in.Hour, Minute: in.Minute, Enabled: in.Enabled, Version: 1, NextDueAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now}
	return probe.NextDueAfter(now)
}
func validateScheduleSource(source domain.Source) error {
	if err := source.Validate(); err != nil {
		return err
	}
	prefix := map[domain.SourceKind]string{domain.EngagementReport: "engagement:", domain.ProjectQualitySummary: "project:", domain.AssessmentClosureReport: "assessment-cycle:"}[source.SourceKind]
	if !strings.HasPrefix(source.SourceRef, prefix) || strings.TrimPrefix(source.SourceRef, prefix) == "" {
		return shared.ErrValidation
	}
	return nil
}
func (s *ScheduleService) scheduleAdmission(ctx context.Context, tenant shared.ID, schedule domain.Schedule, actor ports.DocumentActor) error {
	if ok, err := s.deps.Authority.CanReleaseDocument(ctx, tenant, actor); err != nil {
		return err
	} else if !ok {
		return shared.ErrForbidden
	}
	if err := s.deps.ReportPolicy.CheckReportSource(ctx, tenant, schedule.Source); err != nil {
		return err
	}
	if schedule.Destination == domain.ScheduleConfluence {
		item, err := s.deps.Integrations.GetIntegration(ctx, schedule.IntegrationID)
		if err != nil {
			return err
		}
		if item.TenantID != tenant || !item.Enabled || item.Archived || (item.Provider != "confluence-cloud" && item.Provider != "confluence-dc") {
			return shared.ErrForbidden
		}
		if _, _, err := destination(item); err != nil {
			return err
		}
	} else {
		ch, err := s.deps.Channels.GetChannel(ctx, tenant, schedule.EmailChannelID)
		if err != nil {
			return err
		}
		if ch.Type != notification.ChannelEmail || !ch.Enabled || ch.DeletedAt != nil || ch.Health.State == notification.ChannelPaused || ch.Class() != notification.DataClassDetail || len(ch.Recipients) == 0 || len(ch.Recipients) > 20 {
			return shared.ErrForbidden
		}
		for _, recipient := range ch.Recipients {
			if _, code := s.deps.EmailConfig.EmailChannelConfig(ctx, ports.NotificationWork{Channel: ch, Delivery: notification.Delivery{Recipient: recipient}}, ports.EmailChannelConfig{Recipients: ch.Recipients}); code != "" {
				return shared.ErrForbidden
			}
		}
	}
	return nil
}
func (s *ScheduleService) audit(ctx context.Context, tenant shared.ID, actor ports.DocumentActor, action, target string, meta map[string]string) error {
	return s.deps.Audit.Record(ctx, ports.AuditEntry{Actor: actor.UserID.String(), Action: action, Target: target, Metadata: meta, At: s.deps.Clock.Now().UTC()})
}
func errorsIsNotFound(err error) bool { return errors.Is(err, shared.ErrNotFound) }
func scheduleKey(id shared.ID, due time.Time) string {
	h := sha256.Sum256([]byte(id.String() + "\x00" + due.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h[:])
}

func (s *ScheduleService) executeOccurrence(ctx context.Context, tenant shared.ID, work ports.DocumentScheduleWork, now time.Time) error {
	// A change or disable committed after admission wins over the claimed copy.
	current, err := s.deps.Store.GetDocumentSchedule(ctx, tenant, work.Schedule.ID)
	if err != nil {
		return err
	}
	if !current.Enabled || current.Version != work.Schedule.Version || current.Version != work.Occurrence.Occurrence.ScheduleVersion {
		stopped := work.Occurrence
		stopped.Occurrence.State, stopped.Occurrence.LeaseUntil = domain.OccurrenceFailed, nil
		_, err := s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, stopped, stopped.Occurrence.Version, now)
		return err
	}
	actor := ports.DocumentActor{UserID: current.OwnerUserID, MembershipID: current.OwnerMembershipID, PersonID: current.OwnerPersonID}
	if err := s.scheduleAdmission(ctx, tenant, current, actor); err != nil {
		stopped := work.Occurrence
		stopped.Occurrence.State, stopped.Occurrence.LeaseUntil = domain.OccurrenceFailed, nil
		_, saveErr := s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, stopped, stopped.Occurrence.Version, now)
		return errors.Join(err, saveErr)
	}
	occurrence := work.Occurrence
	if occurrence.Occurrence.State == domain.OccurrenceDone || occurrence.Occurrence.State == domain.OccurrenceUncertain {
		return nil
	}
	lease := now.Add(5 * time.Minute)
	occurrence.Occurrence.State, occurrence.Occurrence.LeaseUntil = domain.OccurrenceInFlight, &lease
	claimed, err := s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, now)
	if err != nil {
		return err
	}
	occurrence = claimed
	if !occurrence.ArtifactStored {
		artifact, err := s.deps.Artifacts.BuildSourceArtifact(ctx, tenant, current.Source)
		if err != nil {
			return err
		}
		digest, err := artifactDigest(artifact)
		if err != nil {
			return err
		}
		occurrence.Artifact, occurrence.ArtifactStored, occurrence.Occurrence.ArtifactDigest = artifact, true, digest
		saved, err := s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, now)
		if err != nil {
			return err
		}
		occurrence = saved
	}
	if current.Destination == domain.ScheduleConfluence {
		return s.executeConfluenceOccurrence(ctx, tenant, current, actor, occurrence, now)
	}
	return s.executeEmailOccurrence(ctx, tenant, current, actor, occurrence, now)
}

func (s *ScheduleService) executeConfluenceOccurrence(ctx context.Context, tenant shared.ID, schedule domain.Schedule, actor ports.DocumentActor, occurrence ports.DocumentScheduleOccurrence, now time.Time) error {
	key := scheduleKey(schedule.ID, occurrence.Occurrence.DueAt)
	result, err := s.deps.Publisher.PublishArtifact(ctx, tenant, actor, PublishInput{IntegrationID: schedule.IntegrationID, SourceKind: schedule.Source.SourceKind, ScopeID: schedule.Source.ScopeID, SourceRef: schedule.Source.SourceRef, RequestKey: key}, occurrence.Artifact)
	if err != nil {
		return err
	}
	if result.Intent == nil {
		occurrence.Occurrence.State, occurrence.Occurrence.LeaseUntil = domain.OccurrenceDone, nil
		_, err = s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, now)
		return err
	}
	occurrence.Occurrence.DocumentIntentID = result.Intent.ID
	updated, err := s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, now)
	if err != nil {
		return err
	}
	intent, err := s.deps.Executor.Execute(ctx, tenant, result.Intent.ID)
	if err != nil {
		return err
	}
	if intent.State == writeintent.Done {
		updated.Occurrence.State, updated.Occurrence.LeaseUntil = domain.OccurrenceDone, nil
		updated.Occurrence.RemotePageID = intent.RemoteID
		updated.Occurrence.RemoteVersion = intent.RemoteVersion
	} else if intent.State == writeintent.Uncertain {
		updated.Occurrence.State, updated.Occurrence.LeaseUntil = domain.OccurrenceUncertain, nil
	} else {
		return nil
	}
	_, err = s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, updated, updated.Occurrence.Version, s.deps.Clock.Now().UTC())
	return err
}

func (s *ScheduleService) executeEmailOccurrence(ctx context.Context, tenant shared.ID, schedule domain.Schedule, actor ports.DocumentActor, occurrence ports.DocumentScheduleOccurrence, now time.Time) error {
	channel, err := s.deps.Channels.GetChannel(ctx, tenant, schedule.EmailChannelID)
	if err != nil {
		return err
	}
	if channel.Type != notification.ChannelEmail || !channel.Enabled || channel.DeletedAt != nil || channel.Health.State == notification.ChannelPaused || channel.Class() != notification.DataClassDetail || len(channel.Recipients) == 0 || len(channel.Recipients) > 20 {
		return shared.ErrForbidden
	}
	link, err := s.sourceLink(ctx, tenant, schedule.Source)
	if err != nil {
		return err
	}
	allDone, anyUncertain, hasRetryable := true, false, false
	for _, recipient := range channel.Recipients {
		if err := s.scheduleAdmission(ctx, tenant, schedule, actor); err != nil {
			return err
		}
		hash := recipientDigest(recipient)
		delivery, err := s.deps.Store.GetDocumentScheduleDelivery(ctx, tenant, occurrence.Occurrence.ID, hash)
		if err == shared.ErrNotFound {
			identity := deliveryDigest(occurrence.Occurrence.ID, hash)
			delivery = ports.DocumentScheduleDelivery{ID: shared.ID("schedule-mail:" + identity[:32]), TenantID: tenant, OccurrenceID: occurrence.Occurrence.ID, Recipient: recipient, RecipientHash: hash, MessageID: shared.ID("schedule-msg-" + identity[:32]), State: ports.DocumentScheduleDeliveryPending, Version: 1, CreatedAt: now, UpdatedAt: now}
			delivery, err = s.deps.Store.SaveDocumentScheduleDelivery(ctx, tenant, delivery, 0, now)
		}
		if err != nil {
			return err
		}
		if delivery.State == ports.DocumentScheduleDeliveryDone {
			continue
		}
		if delivery.State == ports.DocumentScheduleDeliveryUncertain {
			allDone = false
			anyUncertain = true
			continue
		}
		if delivery.State == ports.DocumentScheduleDeliveryRejected {
			allDone = false
			continue
		}
		if delivery.State == ports.DocumentScheduleDeliveryInFlight {
			// The sender may have reached DATA before this process crashed. An
			// expired lease is evidence of a lost acknowledgement, never a retry.
			if delivery.LeaseUntil == nil || !delivery.LeaseUntil.After(now) {
				delivery.State = ports.DocumentScheduleDeliveryUncertain
				delivery.LeaseUntil = nil
				delivery.ErrorCode = "delivery_ack_unknown"
				delivery, err = s.deps.Store.SaveDocumentScheduleDelivery(ctx, tenant, delivery, delivery.Version, now)
				if err != nil {
					return err
				}
				anyUncertain = true
			}
			allDone = false
			continue
		}
		cfg, code := s.deps.EmailConfig.EmailChannelConfig(ctx, ports.NotificationWork{Channel: channel, Delivery: notification.Delivery{Recipient: recipient}}, ports.EmailChannelConfig{Recipients: channel.Recipients})
		if code != "" {
			return fmt.Errorf("%w: %s", shared.ErrForbidden, code)
		}
		email, ok := cfg.(ports.EmailChannelConfig)
		if !ok {
			return shared.ErrForbidden
		}
		lease := now.Add(5 * time.Minute)
		delivery.State = ports.DocumentScheduleDeliveryInFlight
		delivery.LeaseUntil = &lease
		delivery, err = s.deps.Store.SaveDocumentScheduleDelivery(ctx, tenant, delivery, delivery.Version, now)
		if err != nil {
			return err
		}
		relayKey := ""
		if email.Relay != nil {
			relayKey = email.Relay.CacheKey
		}
		result := s.deps.EmailSender.SendDocumentPDF(ctx, ports.DocumentPDFMail{Recipient: recipient, Subject: occurrence.Artifact.Title, Text: s.mailText(link, occurrence.Artifact), HTML: s.mailHTML(link, occurrence.Artifact), Filename: "synapse-report-" + occurrence.Occurrence.ArtifactDigest[:16] + ".pdf", PDF: occurrence.Artifact.PDF, MessageID: delivery.MessageID, Relay: email.Relay, BeforeData: func(callCtx context.Context) error {
			return s.beforeMailData(callCtx, tenant, schedule, actor, recipient, relayKey)
		}})
		delivery.LeaseUntil = nil
		if result.Accepted {
			delivery.State = ports.DocumentScheduleDeliveryDone
			delivery.ErrorCode = ""
		} else if result.Ambiguous {
			delivery.State = ports.DocumentScheduleDeliveryUncertain
			delivery.ErrorCode = safeScheduleCode(result.ErrorCode)
			allDone, anyUncertain = false, true
		} else if result.Retryable {
			delivery.State = ports.DocumentScheduleDeliveryFailed
			delivery.ErrorCode = safeScheduleCode(result.ErrorCode)
			allDone, hasRetryable = false, true
		} else {
			delivery.State = ports.DocumentScheduleDeliveryRejected
			delivery.ErrorCode = safeScheduleCode(result.ErrorCode)
			allDone = false
		}
		if _, err = s.deps.Store.SaveDocumentScheduleDelivery(ctx, tenant, delivery, delivery.Version, s.deps.Clock.Now().UTC()); err != nil {
			return err
		}
		if delivery.State != ports.DocumentScheduleDeliveryDone {
			allDone = false
		}
	}
	if allDone {
		occurrence.Occurrence.State = domain.OccurrenceDone
		occurrence.Occurrence.LeaseUntil = nil
		_, err = s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, s.deps.Clock.Now().UTC())
	} else if anyUncertain {
		occurrence.Occurrence.State, occurrence.Occurrence.LeaseUntil = domain.OccurrenceUncertain, nil
		_, err = s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, s.deps.Clock.Now().UTC())
	} else if hasRetryable {
		occurrence.Occurrence.State, occurrence.Occurrence.LeaseUntil = domain.OccurrenceFailed, nil
		_, err = s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, s.deps.Clock.Now().UTC())
	} else {
		// A definite recipient refusal is retained in delivery history but does
		// not manufacture another recipient send attempt.
		occurrence.Occurrence.State, occurrence.Occurrence.LeaseUntil = domain.OccurrenceDone, nil
		_, err = s.deps.Store.SaveDocumentScheduleOccurrence(ctx, tenant, occurrence, occurrence.Occurrence.Version, s.deps.Clock.Now().UTC())
	}
	return err
}
func (s *ScheduleService) beforeMailData(ctx context.Context, tenant shared.ID, schedule domain.Schedule, actor ports.DocumentActor, recipient, relayKey string) error {
	current, err := s.deps.Store.GetDocumentSchedule(ctx, tenant, schedule.ID)
	if err != nil {
		return err
	}
	if !current.Enabled || current.Version != schedule.Version {
		return shared.ErrForbidden
	}
	if err := s.scheduleAdmission(ctx, tenant, current, actor); err != nil {
		return err
	}
	channel, err := s.deps.Channels.GetChannel(ctx, tenant, current.EmailChannelID)
	if err != nil {
		return err
	}
	if !containsRecipient(channel.Recipients, recipient) {
		return shared.ErrForbidden
	}
	cfg, code := s.deps.EmailConfig.EmailChannelConfig(ctx, ports.NotificationWork{Channel: channel, Delivery: notification.Delivery{Recipient: recipient}}, ports.EmailChannelConfig{Recipients: channel.Recipients})
	if code != "" {
		return shared.ErrForbidden
	}
	email, ok := cfg.(ports.EmailChannelConfig)
	if !ok {
		return shared.ErrForbidden
	}
	got := ""
	if email.Relay != nil {
		got = email.Relay.CacheKey
	}
	if got != relayKey {
		return shared.ErrConflict
	}
	return nil
}
func containsRecipient(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
func recipientDigest(v string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(v))))
	return hex.EncodeToString(h[:])
}
func deliveryDigest(occurrenceID shared.ID, recipientHash string) string {
	h := sha256.Sum256([]byte(occurrenceID.String() + "\x00" + recipientHash))
	return hex.EncodeToString(h[:])
}
func artifactDigest(a ports.DocumentArtifact) (string, error) {
	if len(a.PDF) == 0 || len(a.PDF) > 10<<20 || strings.TrimSpace(a.Title) == "" || a.GeneratedAt.IsZero() {
		return "", shared.ErrValidation
	}
	raw, err := json.Marshal(a)
	if err != nil || len(raw) > 32<<20 {
		return "", shared.ErrValidation
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
func (s *ScheduleService) mailText(link string, a ports.DocumentArtifact) string {
	text := a.Title
	if a.Severity.Valid() {
		text += "\nSeverity: " + string(a.Severity)
	}
	text += "\n\n" + strings.Join(a.Paragraphs, "\n\n")
	if link != "" {
		text += "\n\nView in Synapse: " + link
	}
	return text
}
func (s *ScheduleService) mailHTML(link string, a ports.DocumentArtifact) string {
	parts := make([]string, 0, len(a.Paragraphs)+3)
	parts = append(parts, "<h1>"+html.EscapeString(a.Title)+"</h1>")
	if a.Severity.Valid() {
		parts = append(parts, "<p><span style=\"display:inline-block;padding:2px 8px;color:#fff;background:"+severityColor(a.Severity)+"\">"+html.EscapeString(string(a.Severity))+"</span></p>")
	}
	for _, p := range a.Paragraphs {
		parts = append(parts, "<p>"+html.EscapeString(p)+"</p>")
	}
	if link != "" {
		parts = append(parts, "<p><a href=\""+html.EscapeString(link)+"\">View in Synapse</a></p>")
	}
	return strings.Join(parts, "")
}
func (s *ScheduleService) sourceLink(ctx context.Context, tenant shared.ID, source domain.Source) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(s.deps.PublicBaseURL), "/")
	if base == "" {
		return "", nil
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", shared.ErrValidation
	}
	if source.Scope == domain.Engagement {
		return base + "/engagements/" + url.PathEscape(source.ScopeID.String()), nil
	}
	if s.deps.Projects == nil {
		return "", shared.ErrForbidden
	}
	p, err := s.deps.Projects.GetByID(shared.WithTenant(ctx, tenant), tenant, source.ScopeID)
	if err != nil {
		return "", err
	}
	if p == nil || p.ID != source.ScopeID || p.TenantID != tenant || strings.TrimSpace(p.Key) == "" {
		return "", shared.ErrForbidden
	}
	return base + "/code-quality/projects/" + url.PathEscape(p.Key), nil
}

func severityColor(v shared.Severity) string {
	switch v {
	case shared.SeverityCritical:
		return "#8b0000"
	case shared.SeverityHigh:
		return "#b91c1c"
	case shared.SeverityMedium:
		return "#b45309"
	case shared.SeverityLow:
		return "#1d4ed8"
	case shared.SeverityInfo:
		return "#475569"
	}
	return "#475569"
}
func safeScheduleCode(code string) string {
	if len(code) > 64 {
		return "delivery_failed"
	}
	for i, r := range code {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') || (i == 0 && (r < 'a' || r > 'z')) {
			return "delivery_failed"
		}
	}
	if code == "" {
		return "delivery_failed"
	}
	return code
}
