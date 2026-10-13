package findings

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

type notificationEngagementResolver struct{ value engagement.Engagement }

func (r notificationEngagementResolver) GetByID(_ context.Context, id shared.ID) (*engagement.Engagement, error) {
	if id != r.value.ID {
		return nil, shared.ErrNotFound
	}
	copy := r.value
	return &copy, nil
}

type appendThenFailOutbox struct {
	next *memory.NotificationOutbox
	err  error
}

func (o appendThenFailOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

func notificationFindingService(t *testing.T, repo *memory.FindingRepository, retests *memory.RetestRepository, audit *fakeAudit, outbox notificationOutbox) (*Service, shared.ID, shared.ID) {
	t.Helper()
	tenantID, engagementID := shared.ID("tenant-notifications"), shared.ID("engagement-notifications")
	service := NewService(repo, nil, retests, audit, fixedClock{t: testNow}, &fakeIDs{})
	service.SetEngagementTenantResolver(notificationEngagementResolver{value: engagement.Engagement{ID: engagementID, TenantID: tenantID, Name: "Northstar assessment"}})
	if err := service.SetNotifications(memory.NewTenantTransactionRunner(), outbox, memory.NewNotificationFindingFactsReader(memory.NewUserRepository())); err != nil {
		t.Fatalf("configure notifications: %v", err)
	}
	return service, tenantID, engagementID
}

// notificationOutbox is the public producer dependency used by the test helper.
// It keeps the failure test focused on a real memory outbox plus the producer's
// transaction boundary.
type notificationOutbox interface {
	Append(context.Context, notification.SourceRecord) error
}

func TestFindingCreatedNotificationCapturesImmutableFacts(t *testing.T) {
	repo := memory.NewFindingRepository()
	outbox := memory.NewNotificationOutbox()
	service, tenantID, engagementID := notificationFindingService(t, repo, memory.NewRetestRepository(), &fakeAudit{}, outbox)
	outbox.Activate(tenantID, testNow.Add(-time.Second))

	created, err := service.Create(context.Background(), "untrusted-display-name", engagementID, finding.ManualInput{Title: "SQL injection", Severity: shared.SeverityHigh})
	if err != nil {
		t.Fatalf("create finding: %v", err)
	}
	records := outbox.Records(tenantID)
	if len(records) != 1 {
		t.Fatalf("records=%d, want 1", len(records))
	}
	record := records[0]
	if record.EventType != notification.EventFindingCreated || record.SourceKind != "finding_created" || record.SourceID != created.ID.String() || record.CaptureVersion != 3 {
		t.Fatalf("unexpected source record: %+v", record)
	}
	var data map[string]any
	if err := json.Unmarshal(record.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["finding_id"] != created.ID.String() || data["engagement_id"] != engagementID.String() || data["finding_version"] != float64(created.Version) {
		t.Fatalf("source data was not captured from the committed finding: %#v", data)
	}
	templateContext, err := notification.DecodeTemplateContext(record.Context)
	if err != nil {
		t.Fatal(err)
	}
	if templateContext.Vars["finding_title"] != "SQL injection" || templateContext.Vars["engagement_name"] != "Northstar assessment" {
		t.Fatalf("frozen context=%+v", templateContext.Vars)
	}
	if _, leaked := data["actor_user_id"]; leaked {
		t.Fatalf("opaque actor became a user identity: %#v", data)
	}
}

func TestRetestNotificationFailureRollsBackFindingRetestAndOutbox(t *testing.T) {
	repo := memory.NewFindingRepository()
	retests := memory.NewRetestRepository()
	plain := NewService(repo, nil, retests, &fakeAudit{}, fixedClock{t: testNow}, &fakeIDs{})
	engagementID := shared.ID("engagement-notifications")
	created, err := plain.Create(context.Background(), "creator", engagementID, finding.ManualInput{Title: "XSS", Severity: shared.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	outbox := memory.NewNotificationOutbox()
	service, tenantID, _ := notificationFindingService(t, repo, retests, &fakeAudit{}, appendThenFailOutbox{next: outbox, err: errors.New("outbox unavailable")})
	outbox.Activate(tenantID, testNow.Add(-time.Second))

	_, _, err = service.RecordRetest(context.Background(), engagementID, created.ID, finding.RetestRemediated, "fixed", "tester", created.Version)
	if err == nil {
		t.Fatal("want outbox failure")
	}
	stored, err := repo.GetByEngagementAndID(context.Background(), engagementID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != finding.StatusOpen || stored.Version != created.Version {
		t.Fatalf("finding escaped rollback: %+v", stored)
	}
	ctx := shared.WithTenant(context.Background(), tenantID)
	gotRetests, err := retests.ListByEngagementFinding(ctx, engagementID, created.ID)
	if err != nil || len(gotRetests) != 0 {
		t.Fatalf("retests escaped rollback: %v, %+v", err, gotRetests)
	}
	if records := outbox.Records(tenantID); len(records) != 0 {
		t.Fatalf("outbox escaped rollback: %+v", records)
	}
}

func TestFindingNotificationRejectsMismatchedTenantContext(t *testing.T) {
	repo := memory.NewFindingRepository()
	outbox := memory.NewNotificationOutbox()
	service, tenantID, engagementID := notificationFindingService(t, repo, memory.NewRetestRepository(), &fakeAudit{}, outbox)
	outbox.Activate(tenantID, testNow.Add(-time.Second))

	wrongTenant := shared.WithTenant(context.Background(), "tenant-other")
	if _, err := service.Create(wrongTenant, "creator", engagementID, finding.ManualInput{Title: "Cross tenant", Severity: shared.SeverityLow}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched context error=%v, want validation", err)
	}
	if findings, err := repo.ListByEngagement(context.Background(), engagementID); err != nil || len(findings) != 0 {
		t.Fatalf("mismatched context wrote finding: %v, %+v", err, findings)
	}
}

func TestFindingNotificationCapturesOnlyVerifiedActorIdentity(t *testing.T) {
	tenantID, engagementID := shared.ID("tenant-identity"), shared.ID("engagement-identity")
	users := memory.NewUserRepository()
	actor, err := user.New("actor-identity", tenantID.String(), "Verified operator", user.RoleAdmin, "test-api-key-hash", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	repo, outbox := memory.NewFindingRepository(), memory.NewNotificationOutbox()
	service := NewService(repo, nil, memory.NewRetestRepository(), &fakeAudit{}, fixedClock{t: testNow}, &fakeIDs{})
	service.SetEngagementTenantResolver(notificationEngagementResolver{value: engagement.Engagement{ID: engagementID, TenantID: tenantID, Name: "Identity assessment"}})
	if err := service.SetNotifications(memory.NewTenantTransactionRunner(), outbox, memory.NewNotificationFindingFactsReader(users)); err != nil {
		t.Fatal(err)
	}
	outbox.Activate(tenantID, testNow.Add(-time.Second))
	if _, err := service.Create(context.Background(), actor.ID.String(), engagementID, finding.ManualInput{Title: "Verified", Severity: shared.SeverityMedium}); err != nil {
		t.Fatal(err)
	}
	records := outbox.Records(tenantID)
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	var data map[string]any
	if err := json.Unmarshal(records[0].Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["actor_user_id"] != actor.ID.String() {
		t.Fatalf("actor identity=%#v", data["actor_user_id"])
	}
	templateContext, err := notification.DecodeTemplateContext(records[0].Context)
	if err != nil || templateContext.Vars["actor"] != actor.Name {
		t.Fatalf("actor snapshot=%+v err=%v", templateContext.Vars, err)
	}
	actor.SetDisabled(true, testNow.Add(time.Second))
	if err := users.Update(context.Background(), tenantID, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(context.Background(), actor.ID.String(), engagementID, finding.ManualInput{Title: "Disabled actor", Severity: shared.SeverityMedium}); err != nil {
		t.Fatal(err)
	}
	records = outbox.Records(tenantID)
	var disabledData map[string]any
	if err := json.Unmarshal(records[1].Data, &disabledData); err != nil {
		t.Fatal(err)
	}
	if _, present := disabledData["actor_user_id"]; present {
		t.Fatalf("disabled actor leaked into identity snapshot: %#v", disabledData)
	}
}
