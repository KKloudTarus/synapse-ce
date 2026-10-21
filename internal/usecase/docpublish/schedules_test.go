package docpublish

import (
	"context"
	"errors"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scheduleReportPolicy struct{ err error }

func (p scheduleReportPolicy) CheckReportSource(context.Context, shared.ID, domain.Source) error {
	return p.err
}

type scheduleArtifacts struct{ artifact ports.DocumentArtifact }

func (a scheduleArtifacts) BuildSourceArtifact(context.Context, shared.ID, domain.Source) (ports.DocumentArtifact, error) {
	return a.artifact, nil
}

type scheduleChannels struct{}

func (scheduleChannels) GetChannel(context.Context, shared.ID, shared.ID) (notification.Channel, error) {
	return notification.Channel{}, shared.ErrNotFound
}
func (scheduleChannels) ListChannels(context.Context, shared.ID) ([]notification.Channel, error) {
	return nil, nil
}

type scheduleEmailConfig struct{}

func (scheduleEmailConfig) EmailChannelConfig(context.Context, ports.NotificationWork, ports.NotificationChannelConfig) (ports.NotificationChannelConfig, string) {
	return nil, "unavailable"
}

type scheduleSender struct{}

func (scheduleSender) SendDocumentPDF(context.Context, ports.DocumentPDFMail) ports.DocumentEmailResult {
	return ports.DocumentEmailResult{}
}

type scheduleReadyChannels struct{ channel notification.Channel }

func (s scheduleReadyChannels) GetChannel(context.Context, shared.ID, shared.ID) (notification.Channel, error) {
	return s.channel, nil
}
func (s scheduleReadyChannels) ListChannels(context.Context, shared.ID) ([]notification.Channel, error) {
	return []notification.Channel{s.channel}, nil
}

type scheduleReadyConfig struct{}

func (scheduleReadyConfig) EmailChannelConfig(_ context.Context, _ ports.NotificationWork, c ports.NotificationChannelConfig) (ports.NotificationChannelConfig, string) {
	return ports.EmailChannelConfig{Recipients: c.(ports.EmailChannelConfig).Recipients, Relay: &ports.SMTPRelayConfig{CacheKey: "relay-1"}}, ""
}

type countingScheduleSender struct{ calls int }

func (s *countingScheduleSender) SendDocumentPDF(context.Context, ports.DocumentPDFMail) ports.DocumentEmailResult {
	s.calls++
	return ports.DocumentEmailResult{Accepted: true}
}

type schedulePublisher struct{}

func (schedulePublisher) ValidateDocumentDestination(context.Context, shared.ID, shared.ID) error {
	return nil
}

func (schedulePublisher) PublishArtifact(context.Context, shared.ID, ports.DocumentActor, PublishInput, ports.DocumentArtifact) (ReleaseResult, error) {
	return ReleaseResult{}, nil
}

type scheduleValidationPublisher struct {
	schedulePublisher
	err   error
	calls int
}

func (p *scheduleValidationPublisher) ValidateDocumentDestination(context.Context, shared.ID, shared.ID) error {
	p.calls++
	return p.err
}

type scheduleExecutor struct{}

func (scheduleExecutor) Execute(context.Context, shared.ID, shared.ID) (domain.Intent, error) {
	return domain.Intent{}, nil
}

type scheduleIntegration struct{}

func (scheduleIntegration) GetIntegration(context.Context, shared.ID) (integration.Integration, error) {
	return integration.Integration{TenantID: "tenant", Provider: "confluence-cloud", Enabled: true, Config: []byte(`{"space":"LAB","read_group":"readers","data_class":"detail"}`)}, nil
}

type confluenceOccurrenceStore struct {
	ports.DocumentScheduleStore
	saves []ports.DocumentScheduleOccurrence
}

func (s *confluenceOccurrenceStore) SaveDocumentScheduleOccurrence(_ context.Context, _ shared.ID, v ports.DocumentScheduleOccurrence, _ int, _ time.Time) (ports.DocumentScheduleOccurrence, error) {
	v.Occurrence.Version++
	s.saves = append(s.saves, v)
	return v, nil
}

type confluencePublisher struct{ result ReleaseResult }

type scheduleVersionRaceStore struct {
	confluenceOccurrenceStore
	current domain.Schedule
}

func (s *scheduleVersionRaceStore) GetDocumentSchedule(context.Context, shared.ID, shared.ID) (domain.Schedule, error) {
	return s.current, nil
}

func TestScheduleOccurrenceRejectsNewerScheduleReloadedDuringClaim(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	current := domain.Schedule{ID: "schedule", TenantID: "tenant", Enabled: true, Version: 2}
	store := &scheduleVersionRaceStore{current: current}
	svc := &ScheduleService{deps: ScheduleDependencies{Store: store}}
	work := ports.DocumentScheduleWork{Schedule: current, Occurrence: ports.DocumentScheduleOccurrence{Occurrence: domain.ScheduleOccurrence{ID: "occurrence", TenantID: "tenant", ScheduleID: current.ID, ScheduleVersion: 1, State: domain.OccurrenceInFlight, Version: 2}}}
	// No artifact or provider dependency is installed: the stale occurrence must
	// stop before either can run, even when the claimed schedule was reloaded.
	if err := svc.executeOccurrence(context.Background(), "tenant", work, now); err != nil {
		t.Fatal(err)
	}
	if len(store.saves) != 1 || store.saves[0].Occurrence.State != domain.OccurrenceFailed || store.saves[0].Occurrence.LeaseUntil != nil {
		t.Fatalf("stale occurrence was not stopped: %+v", store.saves)
	}
}

func (p confluencePublisher) PublishArtifact(context.Context, shared.ID, ports.DocumentActor, PublishInput, ports.DocumentArtifact) (ReleaseResult, error) {
	return p.result, nil
}

func (confluencePublisher) ValidateDocumentDestination(context.Context, shared.ID, shared.ID) error {
	return nil
}

type confluenceExecutor struct{ intent domain.Intent }

func (e confluenceExecutor) Execute(context.Context, shared.ID, shared.ID) (domain.Intent, error) {
	return e.intent, nil
}

func TestScheduleServiceSavePolicyAndCAS(t *testing.T) {
	ctx := context.Background()
	engs := memory.NewEngagementRepository()
	projects := memory.NewProjectRepository()
	store, err := memory.NewDocumentStore(engs, projects)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	e, err := engagement.New("eng", "tenant", "name", "client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = engs.Create(shared.WithTenant(ctx, "tenant"), e); err != nil {
		t.Fatal(err)
	}
	p, err := project.New("project", "tenant", "project", "key", project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = projects.Create(shared.WithTenant(ctx, "tenant"), p); err != nil {
		t.Fatal(err)
	}
	audit := &releaseAudit{}
	svc, err := NewScheduleService(ScheduleDependencies{Store: store, Authority: &releaseAuthority{allowed: true}, ReportPolicy: scheduleReportPolicy{}, Artifacts: scheduleArtifacts{}, Channels: scheduleChannels{}, Integrations: scheduleIntegration{}, EmailConfig: scheduleEmailConfig{}, EmailSender: scheduleSender{}, Publisher: schedulePublisher{}, Executor: scheduleExecutor{}, Audit: audit, IDs: &releaseIDs{}, Clock: &releaseClock{at: now}})
	if err != nil {
		t.Fatal(err)
	}
	actor := ports.DocumentActor{UserID: "admin"}
	in := ScheduleInput{ID: "sched", Source: domain.Source{SourceKind: domain.EngagementReport, SourceRef: "engagement:eng", Scope: domain.Engagement, ScopeID: "eng"}, Destination: domain.ScheduleConfluence, IntegrationID: "integration", Timezone: "UTC", Frequency: domain.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 13, Enabled: true}
	saved, err := svc.SaveSchedule(ctx, "tenant", actor, in)
	if err != nil || saved.Version != 1 {
		t.Fatalf("save=%+v err=%v", saved, err)
	}
	in.ExpectedVersion = saved.Version
	in.Hour = 14
	saved, err = svc.SaveSchedule(ctx, "tenant", actor, in)
	if err != nil || saved.Version != 2 {
		t.Fatalf("update=%+v err=%v", saved, err)
	}
	if err = svc.DeleteSchedule(ctx, "tenant", actor, saved.ID, 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale delete=%v", err)
	}
	if len(audit.entries) != 2 {
		t.Fatalf("audit entries=%d", len(audit.entries))
	}
}

func TestScheduleServiceExpiredSMTPLeaseBecomesUncertainWithoutResend(t *testing.T) {
	ctx := context.Background()
	engs := memory.NewEngagementRepository()
	projects := memory.NewProjectRepository()
	store, _ := memory.NewDocumentStore(engs, projects)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	e, _ := engagement.New("eng", "tenant", "name", "client", now)
	if err := engs.Create(shared.WithTenant(ctx, "tenant"), e); err != nil {
		t.Fatal(err)
	}
	channel := notification.Channel{TenantID: "tenant", ID: "mail", Name: "mail", Type: notification.ChannelEmail, Enabled: true, Recipients: []string{"reviewer@example.test"}, Revision: 1, SecretVersion: 1, DataClass: notification.DataClassDetail, CreatedAt: now, UpdatedAt: now}
	sender := &countingScheduleSender{}
	svc, err := NewScheduleService(ScheduleDependencies{Store: store, Authority: &releaseAuthority{allowed: true}, ReportPolicy: scheduleReportPolicy{}, Artifacts: scheduleArtifacts{artifact: ports.DocumentArtifact{Title: "Report", Paragraphs: []string{"fact"}, PDF: []byte("pdf"), SourceRevision: "v1", GeneratedAt: now}}, Channels: scheduleReadyChannels{channel}, Integrations: scheduleIntegration{}, EmailConfig: scheduleReadyConfig{}, EmailSender: sender, Publisher: schedulePublisher{}, Executor: scheduleExecutor{}, Audit: &releaseAudit{}, IDs: &releaseIDs{}, Clock: &releaseClock{at: now}})
	if err != nil {
		t.Fatal(err)
	}
	actor := ports.DocumentActor{UserID: "admin"}
	input := ScheduleInput{ID: "mail-schedule", Source: domain.Source{SourceKind: domain.EngagementReport, SourceRef: "engagement:eng", Scope: domain.Engagement, ScopeID: "eng"}, Destination: domain.ScheduleEmail, EmailChannelID: "mail", Timezone: "UTC", Frequency: domain.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true}
	saved, err := svc.SaveSchedule(ctx, "tenant", actor, input)
	if err != nil {
		t.Fatal(err)
	}
	// Force one due instant without changing the public configuration contract.
	saved.NextDueAt = now.Add(-time.Minute)
	saved.UpdatedAt = now
	if _, err = store.SaveDocumentSchedule(ctx, "tenant", saved, saved.Version); err != nil {
		t.Fatal(err)
	}
	work, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "tenant", 20, now)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim=%d err=%v", len(work), err)
	}
	hash := recipientDigest(channel.Recipients[0])
	past := now.Add(-time.Second)
	delivery := ports.DocumentScheduleDelivery{ID: "delivery", TenantID: "tenant", OccurrenceID: work[0].Occurrence.Occurrence.ID, Recipient: channel.Recipients[0], RecipientHash: hash, MessageID: "message", State: ports.DocumentScheduleDeliveryInFlight, Version: 1, LeaseUntil: &past, CreatedAt: now, UpdatedAt: now}
	if _, err = store.SaveDocumentScheduleDelivery(ctx, "tenant", delivery, 0, now); err != nil {
		t.Fatal(err)
	}
	if err = svc.executeOccurrence(ctx, "tenant", work[0], now); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 0 {
		t.Fatalf("resent after lost ACK: %d", sender.calls)
	}
	got, err := store.GetDocumentScheduleDelivery(ctx, "tenant", work[0].Occurrence.Occurrence.ID, hash)
	if err != nil || got.State != ports.DocumentScheduleDeliveryUncertain {
		t.Fatalf("delivery=%+v err=%v", got, err)
	}
}

func TestDocumentOccurrenceTerminalTransitionsClearLease(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	lease := now.Add(time.Minute)
	schedule := domain.Schedule{ID: "schedule", IntegrationID: "integration", Source: domain.Source{SourceKind: domain.EngagementReport, SourceRef: "engagement:eng", Scope: domain.Engagement, ScopeID: "eng"}}
	base := ports.DocumentScheduleOccurrence{Occurrence: domain.ScheduleOccurrence{ID: "occurrence", TenantID: "tenant", ScheduleID: "schedule", DueAt: now, State: domain.OccurrenceInFlight, Version: 1, LeaseUntil: &lease}}
	for _, tc := range []struct {
		name   string
		result ReleaseResult
		intent domain.Intent
		want   domain.ScheduleOccurrenceState
	}{
		{"skip", ReleaseResult{}, domain.Intent{}, domain.OccurrenceDone},
		{"done", ReleaseResult{Intent: &domain.Intent{ID: "intent"}}, domain.Intent{State: writeintent.Done, RemoteID: "page", RemoteVersion: 1}, domain.OccurrenceDone},
		{"uncertain", ReleaseResult{Intent: &domain.Intent{ID: "intent"}}, domain.Intent{State: writeintent.Uncertain}, domain.OccurrenceUncertain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &confluenceOccurrenceStore{}
			svc := &ScheduleService{deps: ScheduleDependencies{Store: store, Publisher: confluencePublisher{tc.result}, Executor: confluenceExecutor{tc.intent}, Clock: &releaseClock{at: now}}}
			if err := svc.executeDocumentOccurrence(context.Background(), "tenant", schedule, ports.DocumentActor{UserID: "admin"}, base, now); err != nil {
				t.Fatal(err)
			}
			got := store.saves[len(store.saves)-1].Occurrence
			if got.State != tc.want || got.LeaseUntil != nil {
				t.Fatalf("state=%s lease=%v", got.State, got.LeaseUntil)
			}
		})
	}
}
