package docpublish

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type transactionAwareScheduleSender struct {
	active              *bool
	calledInTransaction bool
}

func (s *transactionAwareScheduleSender) SendDocumentPDF(context.Context, ports.DocumentPDFMail) ports.DocumentEmailResult {
	if *s.active {
		s.calledInTransaction = true
	}
	return ports.DocumentEmailResult{Retryable: true, ErrorCode: "relay_unavailable"}
}

func TestScheduledArtifactCaptureSurvivesLaterSMTPFailure(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	engagements := memory.NewEngagementRepository()
	projects := memory.NewProjectRepository()
	projectRecord, err := project.New("project-a", "tenant", "Project A", "project-a", project.SourceBinding{Kind: project.SourceLocal, Value: "/tmp/project-a"}, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = projects.Create(shared.WithTenant(ctx, "tenant"), projectRecord); err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewDocumentStore(engagements, projects)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engagement.New("eng", "tenant", "name", "client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = engagements.Create(shared.WithTenant(ctx, "tenant"), eng); err != nil {
		t.Fatal(err)
	}
	channel := notification.Channel{TenantID: "tenant", ID: "mail", Name: "mail", Type: notification.ChannelEmail, Enabled: true, Recipients: []string{"reviewer@example.test"}, Revision: 1, SecretVersion: 1, DataClass: notification.DataClassDetail, CreatedAt: now, UpdatedAt: now}
	runner := &reportNotificationRunner{next: memory.NewTenantTransactionRunner()}
	sender := &transactionAwareScheduleSender{active: &runner.active}
	svc, err := NewScheduleService(ScheduleDependencies{
		Store: store, Authority: &releaseAuthority{allowed: true}, ReportPolicy: scheduleReportPolicy{},
		Artifacts: scheduleArtifacts{artifact: ports.DocumentArtifact{Title: "Report", Paragraphs: []string{"fact"}, PDF: []byte("pdf"), SourceRevision: "v1", GeneratedAt: now, CycleID: "cycle-a"}},
		Channels:  scheduleReadyChannels{channel}, Integrations: scheduleIntegration{}, EmailConfig: scheduleReadyConfig{}, EmailSender: sender,
		Publisher: schedulePublisher{}, Executor: scheduleExecutor{}, Audit: &releaseAudit{}, IDs: &releaseIDs{}, Clock: &releaseClock{at: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate("tenant", now.Add(-time.Second))
	if err = svc.SetNotifications(runner, outbox); err != nil {
		t.Fatalf("enable notifications: %v", err)
	}
	input := ScheduleInput{ID: "mail-schedule", Source: domain.Source{SourceKind: domain.AssessmentClosureReport, SourceRef: AssessmentClosureSourceRef("cycle-a"), Scope: domain.Project, ScopeID: "project-a"}, Destination: domain.ScheduleEmail, EmailChannelID: "mail", Timezone: "UTC", Frequency: domain.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true}
	schedule, err := svc.SaveSchedule(ctx, "tenant", ports.DocumentActor{UserID: "admin"}, input)
	if err != nil {
		t.Fatalf("save schedule: %v", err)
	}
	schedule.NextDueAt = now.Add(-time.Minute)
	schedule.UpdatedAt = now
	if _, err = store.SaveDocumentSchedule(ctx, "tenant", schedule, schedule.Version); err != nil {
		t.Fatalf("make due: %v", err)
	}
	work, err := store.ClaimDueDocumentScheduleOccurrences(ctx, "tenant", 1, now)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim=%d err=%v", len(work), err)
	}
	if err = svc.executeOccurrence(ctx, "tenant", work[0], now); err != nil {
		t.Fatalf("execute: %v", err)
	}
	records := outbox.Records("tenant")
	if len(records) != 1 || records[0].EventType != notification.EventReportGenerated {
		t.Fatalf("records=%+v", records)
	}
	var data map[string]any
	if err := json.Unmarshal(records[0].Data, &data); err != nil {
		t.Fatalf("decode record data: %v", err)
	}
	if data["cycle_id"] != "cycle-a" {
		t.Fatalf("closure navigation used project scope instead of stored cycle: %v", data)
	}
	if sender.calledInTransaction {
		t.Fatal("SMTP delivery ran inside the artifact persistence transaction")
	}
}

func TestScheduleNotificationConfigurationRejectsPartialDependencies(t *testing.T) {
	svc := &ScheduleService{}
	if err := svc.SetNotifications(nil, memory.NewNotificationOutbox()); err == nil {
		t.Fatal("nil transaction was accepted")
	}
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), nil); err == nil {
		t.Fatal("nil outbox was accepted")
	}
}
