package docpublish

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/notificationsender"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	notificationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type operatorScheduleConfig struct{}

type scheduleSecretProtector struct{}

func (scheduleSecretProtector) Seal(raw, _ []byte) (string, error) { return string(raw), nil }
func (scheduleSecretProtector) Open(raw string, _ []byte) ([]byte, error) {
	return []byte(raw), nil
}

func (operatorScheduleConfig) EmailChannelConfig(_ context.Context, _ ports.NotificationWork, c ports.NotificationChannelConfig) (ports.NotificationChannelConfig, string) {
	return c, ""
}

type tenantScheduleArtifacts struct {
	calls    int
	artifact ports.DocumentArtifact
}

func (a *tenantScheduleArtifacts) BuildSourceArtifact(ctx context.Context, tenant shared.ID, _ domain.Source) (ports.DocumentArtifact, error) {
	if got, ok := shared.TenantFrom(ctx); !ok || got != tenant {
		return ports.DocumentArtifact{}, shared.ErrForbidden
	}
	a.calls++
	return a.artifact, nil
}

type tenantScheduleIntegration struct{}

func (tenantScheduleIntegration) GetIntegration(ctx context.Context, id shared.ID) (integration.Integration, error) {
	if got, ok := shared.TenantFrom(ctx); !ok || got != "tenant" {
		return integration.Integration{}, shared.ErrForbidden
	}
	return integration.Integration{ID: id, TenantID: "tenant", Enabled: true, Provider: "confluence-cloud", Config: []byte(`{"space":"LAB","read_group":"readers","data_class":"detail"}`)}, nil
}

type tenantScheduleAuthority struct{}

func (tenantScheduleAuthority) CanReleaseDocument(ctx context.Context, tenant shared.ID, a ports.DocumentActor) (bool, error) {
	got, ok := shared.TenantFrom(ctx)
	return ok && got == tenant && a.UserID != "denied", nil
}

func newDeliveryContractFixture(t *testing.T) (*ScheduleService, *memory.DocumentStore, domain.Schedule, *tenantScheduleArtifacts) {
	t.Helper()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	engs := memory.NewEngagementRepository()
	projects := memory.NewProjectRepository()
	eng, _ := engagement.New("eng", "tenant", "Assessment", "Personal lab", now)
	if err := engs.Create(shared.WithTenant(context.Background(), "tenant"), eng); err != nil {
		t.Fatal(err)
	}
	store, err := memory.NewDocumentStore(engs, projects)
	if err != nil {
		t.Fatal(err)
	}
	source := &tenantScheduleArtifacts{artifact: ports.DocumentArtifact{Title: "Báo cáo bảo mật", Severity: shared.SeverityHigh, Paragraphs: []string{"Kết quả đã kiểm chứng"}, PDF: []byte("%PDF-1.7\nfrozen stored report"), GeneratedAt: now, SourceRevision: "stored-v1"}}
	channel := notification.Channel{TenantID: "tenant", ID: "mail", Name: "Verified operator email", Type: notification.ChannelEmail, Enabled: true, Recipients: []string{"reviewer@example.test"}, Revision: 1, SecretVersion: 1, DataClass: notification.DataClassDetail, CreatedAt: now, UpdatedAt: now}
	svc, err := NewScheduleService(ScheduleDependencies{Store: store, Authority: tenantScheduleAuthority{}, ReportPolicy: scheduleReportPolicy{}, Artifacts: source, Channels: scheduleReadyChannels{channel}, Integrations: tenantScheduleIntegration{}, EmailConfig: operatorScheduleConfig{}, EmailSender: &countingScheduleSender{}, Publisher: schedulePublisher{}, Executor: scheduleExecutor{}, Audit: &releaseAudit{}, IDs: &releaseIDs{}, Clock: &releaseClock{at: now}, PublicBaseURL: "https://console.example"})
	if err != nil {
		t.Fatal(err)
	}
	schedule := domain.Schedule{ID: "scheduled-report", TenantID: "tenant", Source: domain.Source{SourceKind: domain.EngagementReport, SourceRef: "engagement:eng", Scope: domain.Engagement, ScopeID: "eng"}, Destination: domain.ScheduleEmail, EmailChannelID: "mail", OwnerUserID: "reviewer", Timezone: "UTC", Frequency: domain.ScheduleWeekly, Weekday: int(now.Weekday()), Hour: 11, Enabled: true, Version: 1, NextDueAt: now.Add(-time.Minute), CreatedAt: now, UpdatedAt: now}
	return svc, store, schedule, source
}

func TestScheduleEmailOptionsIncludeVerifiedOperatorRelay(t *testing.T) {
	svc, _, _, _ := newDeliveryContractFixture(t)
	got, err := svc.EmailDestinations(context.Background(), "tenant", ports.DocumentActor{UserID: "reviewer"})
	if err != nil || len(got) != 1 || got[0].RecipientCount != 1 {
		t.Fatalf("options=%+v err=%v", got, err)
	}
}

func TestScheduledPDFRefusesOperatorDisabledEmailBeforeSMTP(t *testing.T) {
	svc, store, schedule, _ := newDeliveryContractFixture(t)
	config, err := notificationuc.NewService(memory.NewNotificationRepository(nil, nil), scheduleSecretProtector{}, nil, svc.deps.Audit, svc.deps.Clock, svc.deps.IDs)
	if err != nil {
		t.Fatal(err)
	}
	config.SetDisabledChannelTypes([]notification.ChannelType{notification.ChannelEmail})
	svc.deps.EmailConfig = config
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	svc.deps.EmailSender = notificationsender.New(notificationsender.SMTPConfig{Host: host, Port: number, From: "sender@example.test"}, time.Second)
	if options, err := svc.EmailDestinations(context.Background(), "tenant", ports.DocumentActor{UserID: "reviewer"}); err != nil || len(options) != 0 {
		t.Fatalf("disabled email options=%v err=%v", options, err)
	}
	if _, err = store.SaveDocumentSchedule(context.Background(), "tenant", schedule, 0); err != nil {
		t.Fatal(err)
	}
	if err = svc.Tick(context.Background(), "tenant", 20); err == nil {
		t.Fatal("operator-disabled email schedule was admitted")
	}
	if err = listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("disabled email reached SMTP")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
}

func TestScheduleTickBindsTenantAndContinuesIndependentOccurrences(t *testing.T) {
	svc, store, schedule, source := newDeliveryContractFixture(t)
	schedule.Destination = domain.ScheduleConfluence
	schedule.IntegrationID = "confluence"
	schedule.EmailChannelID = ""
	denied := schedule
	denied.ID = "a-denied"
	denied.OwnerUserID = "denied"
	for _, item := range []domain.Schedule{denied, schedule} {
		if _, err := store.SaveDocumentSchedule(context.Background(), "tenant", item, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Tick(context.Background(), "tenant", 20); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("denial=%v", err)
	}
	runs, err := store.ListDocumentScheduleRuns(context.Background(), "tenant", schedule.ID, 20)
	if err != nil || len(runs) != 1 || runs[0].State != domain.OccurrenceDone || source.calls != 1 {
		t.Fatalf("runs=%+v calls=%d err=%v", runs, source.calls, err)
	}
	stopped, _ := store.ListDocumentScheduleRuns(context.Background(), "tenant", denied.ID, 20)
	if len(stopped) != 1 || stopped[0].State != domain.OccurrenceFailed {
		t.Fatalf("denied=%+v", stopped)
	}
}

func TestScheduledProjectLinksUseCurrentTenantProjectKey(t *testing.T) {
	svc, _, _, _ := newDeliveryContractFixture(t)
	projects := memory.NewProjectRepository()
	now := svc.deps.Clock.Now()
	p, err := project.New("opaque-project-id", "tenant", "Security platform", "security-platform", project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}, nil, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = projects.Create(shared.WithTenant(context.Background(), "tenant"), p); err != nil {
		t.Fatal(err)
	}
	svc.deps.Projects = projects
	for _, kind := range []domain.SourceKind{domain.ProjectQualitySummary, domain.AssessmentClosureReport} {
		link, err := svc.sourceLink(context.Background(), "tenant", domain.Source{SourceKind: kind, Scope: domain.Project, ScopeID: p.ID})
		if err != nil || link != "https://console.example/code-quality/projects/security-platform" {
			t.Fatalf("kind=%s link=%s err=%v", kind, link, err)
		}
	}
	if _, err = svc.sourceLink(context.Background(), "foreign", domain.Source{Scope: domain.Project, ScopeID: p.ID}); err == nil {
		t.Fatal("resolved foreign project key")
	}
	link, err := svc.sourceLink(context.Background(), "tenant", domain.Source{Scope: domain.Engagement, ScopeID: "part/segment"})
	if err != nil || !strings.HasSuffix(link, "/engagements/part%2Fsegment") {
		t.Fatalf("unsafe segment %s %v", link, err)
	}
}

func TestScheduledPDFUsesActualSenderAndRetainsLostAcknowledgement(t *testing.T) {
	for _, ack := range []bool{true, false} {
		t.Run(fmt.Sprintf("ack=%v", ack), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			messages := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprint(conn, "220 relay\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if strings.HasPrefix(line, "DATA") {
						_, _ = fmt.Fprint(conn, "354 send\r\n")
						var body strings.Builder
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							body.WriteString(line)
						}
						messages <- body.String()
						if ack {
							_, _ = fmt.Fprint(conn, "250 accepted\r\n")
						}
						return
					}
					_, _ = fmt.Fprint(conn, "250 accepted\r\n")
				}
			}()
			svc, store, schedule, source := newDeliveryContractFixture(t)
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			number, _ := strconv.Atoi(port)
			svc.deps.EmailSender = notificationsender.New(notificationsender.SMTPConfig{Host: host, Port: number, From: "sender@example.test"}, time.Second)
			if _, err = store.SaveDocumentSchedule(context.Background(), "tenant", schedule, 0); err != nil {
				t.Fatal(err)
			}
			if err = svc.Tick(context.Background(), "tenant", 20); err != nil {
				t.Fatal(err)
			}
			select {
			case body := <-messages:
				if !strings.Contains(body, "Message-ID: <schedule-msg-") || !strings.Contains(body, base64.StdEncoding.EncodeToString(source.artifact.PDF)) {
					t.Fatal("scheduled sender contract or frozen PDF missing")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("real sender never received scheduled PDF")
			}
			runs, err := store.ListDocumentScheduleRuns(context.Background(), "tenant", schedule.ID, 20)
			want := domain.OccurrenceDone
			if !ack {
				want = domain.OccurrenceUncertain
			}
			if err != nil || len(runs) != 1 || runs[0].State != want {
				t.Fatalf("runs=%+v err=%v", runs, err)
			}
			if err = svc.Tick(context.Background(), "tenant", 20); err != nil {
				t.Fatal(err)
			}
			if source.calls != 1 {
				t.Fatalf("regenerated or retransmitted occurrence %d", source.calls)
			}
		})
	}
}

func TestScheduleSaveValidatesDocumentDestinationBeforeArtifactBuild(t *testing.T) {
	for _, scenario := range []string{"unsupported_release_contract", "invalid_destination", "working_profile"} {
		t.Run(scenario, func(t *testing.T) {
			svc, _, schedule, source := newDeliveryContractFixture(t)
			publisher := &scheduleValidationPublisher{}
			switch scenario {
			case "unsupported_release_contract":
				publisher.err = &ports.DocumentProviderError{Code: "notion_release_contract_unavailable"}
			case "invalid_destination":
				publisher.err = shared.ErrForbidden
			}
			svc.deps.Publisher = publisher
			_, err := svc.SaveSchedule(context.Background(), "tenant", ports.DocumentActor{UserID: "reviewer"}, ScheduleInput{ID: "scheduled-document", Source: schedule.Source, Destination: domain.ScheduleConfluence, IntegrationID: "google-drive", Timezone: "UTC", Frequency: domain.ScheduleWeekly, Weekday: 6, Hour: 13, Enabled: true})
			if publisher.calls != 1 {
				t.Fatalf("destination validation calls=%d", publisher.calls)
			}
			if scenario == "working_profile" && err != nil {
				t.Fatal(err)
			}
			if scenario != "working_profile" && err == nil {
				t.Fatal("admitted unavailable document destination")
			}
			if source.calls != 0 {
				t.Fatalf("artifact built during schedule admission: %d", source.calls)
			}
		})
	}
}

func TestScheduledNotionDestinationRefusesBeforeArtifactBuild(t *testing.T) {
	svc, store, schedule, source := newDeliveryContractFixture(t)
	schedule.Destination = domain.ScheduleConfluence // persisted value denotes document publishing.
	schedule.IntegrationID = "notion"
	schedule.EmailChannelID = ""
	svc.deps.Publisher = &scheduleValidationPublisher{err: &ports.DocumentProviderError{Code: "notion_release_contract_unavailable"}}
	if _, err := store.SaveDocumentSchedule(context.Background(), "tenant", schedule, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.Tick(context.Background(), "tenant", 20); err == nil {
		t.Fatal("scheduled Notion publication was admitted")
	}
	if source.calls != 0 {
		t.Fatalf("artifact built after Notion refusal: %d", source.calls)
	}
	runs, err := store.ListDocumentScheduleRuns(context.Background(), "tenant", schedule.ID, 20)
	if err != nil || len(runs) != 1 || runs[0].State != domain.OccurrenceFailed {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
}

type unavailableScheduleAudit struct{}

func (unavailableScheduleAudit) Record(context.Context, ports.AuditEntry) error {
	return errors.New("audit unavailable")
}

func TestScheduleMutationRefusesBeforePersistenceWhenAuditUnavailable(t *testing.T) {
	svc, store, schedule, _ := newDeliveryContractFixture(t)
	svc.deps.Audit = unavailableScheduleAudit{}
	input := ScheduleInput{ID: schedule.ID, Source: schedule.Source, Destination: schedule.Destination, EmailChannelID: schedule.EmailChannelID, Timezone: schedule.Timezone, Frequency: schedule.Frequency, Weekday: schedule.Weekday, Hour: schedule.Hour, Enabled: true}
	if _, err := svc.SaveSchedule(context.Background(), "tenant", ports.DocumentActor{UserID: "reviewer"}, input); err == nil {
		t.Fatal("saved without admission audit")
	}
	if _, err := store.GetDocumentSchedule(context.Background(), "tenant", schedule.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("schedule persisted after failed audit: %v", err)
	}
	if _, err := store.SaveDocumentSchedule(context.Background(), "tenant", schedule, 0); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteSchedule(context.Background(), "tenant", ports.DocumentActor{UserID: "reviewer"}, schedule.ID, 1); err == nil {
		t.Fatal("disabled without admission audit")
	}
	current, err := store.GetDocumentSchedule(context.Background(), "tenant", schedule.ID)
	if err != nil || !current.Enabled || current.Version != 1 {
		t.Fatalf("mutated after failed audit: %+v %v", current, err)
	}
}
