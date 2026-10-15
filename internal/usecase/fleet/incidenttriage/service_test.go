package incidenttriage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/incidentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	tenant = shared.ID("tenant-t")
	asset  = shared.ID("asset-t")
	incID  = shared.ID("inc-t")
)

var base = time.Unix(1_800_000_000, 0).UTC()

// captureAudit records entries; if fail is set, Record errors.
type captureAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
	fail    bool
}

type lifecycleFacts struct {
	ports.NotificationLifecycleFacts
}

func (f lifecycleFacts) SnapshotNotificationLifecycleFacts(context.Context, shared.ID, shared.ID, string) (ports.NotificationLifecycleFacts, error) {
	return f.NotificationLifecycleFacts, nil
}

type appendThenFailOutbox struct {
	next ports.NotificationOutbox
	err  error
}

func (o appendThenFailOutbox) Append(ctx context.Context, record notification.SourceRecord) error {
	if err := o.next.Append(ctx, record); err != nil {
		return err
	}
	return o.err
}

func (c *captureAudit) Record(_ context.Context, e ports.AuditEntry) error {
	if c.fail {
		return errors.New("audit down")
	}
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
	return nil
}

func setup(t *testing.T) (*Service, *captureAudit, context.Context, *incidentuc.Service) {
	t.Helper()
	store := memory.NewIncidentEventStore()
	inc, err := incidentuc.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	audit := &captureAudit{}
	var n int
	clock := func() time.Time { n++; return base.Add(time.Duration(n) * time.Minute) }
	svc, err := NewService(inc, audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := shared.WithTenant(context.Background(), tenant)
	// Seed a fresh incident (StateNew).
	created := incident.IncidentEvent{IncidentID: incID, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, Severity: shared.SeverityHigh, DetectionID: "d1"}
	if _, err := inc.Append(ctx, incID, 0, []incident.IncidentEvent{created}); err != nil {
		t.Fatal(err)
	}
	return svc, audit, ctx, inc
}

func TestTriageFullLoopAuditsEveryMutation(t *testing.T) {
	svc, audit, ctx, _ := setup(t)
	if _, err := svc.AssignOwner(ctx, "alice", incID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Comment(ctx, "alice", incID, "investigating this"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeStatus(ctx, "alice", incID, incident.StateInvestigating); err != nil {
		t.Fatal(err)
	}
	inc, err := svc.SetDisposition(ctx, "alice", incID, incident.DispositionTruePositive)
	if err != nil {
		t.Fatal(err)
	}
	if inc.OwnerID != "alice" || inc.State != incident.StateInvestigating || inc.Disposition != incident.DispositionTruePositive || len(inc.Comments) != 1 {
		t.Fatalf("triage projection wrong: %+v", inc)
	}
	if len(audit.entries) != 4 {
		t.Fatalf("every mutation must be audited, got %d", len(audit.entries))
	}
	wantActions := map[string]bool{"incident.owner_changed": false, "incident.commented": false, "incident.status_changed": false, "incident.disposition_set": false}
	for _, e := range audit.entries {
		if _, ok := wantActions[e.Action]; !ok {
			t.Fatalf("unexpected audit action %q", e.Action)
		}
		wantActions[e.Action] = true
		if e.Target != incID.String() || e.Actor != "alice" {
			t.Fatalf("audit entry not attributed: %+v", e)
		}
	}
	for a, seen := range wantActions {
		if !seen {
			t.Fatalf("missing audit for %s", a)
		}
	}
}

func TestTriageDispositionDoesNotChangeRisk(t *testing.T) {
	svc, _, ctx, inc := setup(t)
	// Attach a risk assessment first (via the incident store directly).
	risk := &riskassessment.RiskAssessment{AssessmentID: "ra-1", ScorerVersion: "v1", PolicyVersion: "p1", Risk: 88, Confidence: 61, Coverage: 43}
	cur, _ := inc.Get(ctx, incID)
	if _, err := inc.Append(ctx, incID, cur.Revision, []incident.IncidentEvent{{IncidentID: incID, Kind: incident.EventRiskReassessed, At: base.Add(30 * time.Second), Actor: "scorer", Risk: risk}}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.SetDisposition(ctx, "alice", incID, incident.DispositionFalsePositive)
	if err != nil {
		t.Fatal(err)
	}
	if got.Risk == nil || got.Risk.Risk != 88 {
		t.Fatalf("disposition must not change risk: %+v", got.Risk)
	}
}

func TestTriageIllegalTransitionRejectedNotAudited(t *testing.T) {
	svc, audit, ctx, _ := setup(t)
	// new -> resolved is illegal; the append's project-validation rejects it.
	if _, err := svc.ChangeStatus(ctx, "alice", incID, incident.StateResolved); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("illegal transition must be rejected, got %v", err)
	}
	if len(audit.entries) != 0 {
		t.Fatal("a rejected mutation must NOT be audited")
	}
}

func TestTriageAuditFailurePropagates(t *testing.T) {
	svc, audit, ctx, inc := setup(t)
	audit.fail = true
	if _, err := svc.Comment(ctx, "alice", incID, "note"); err == nil {
		t.Fatal("an audit failure must propagate")
	}
	// The event WAS appended (audit is after append); the projection reflects it, but the mutation is
	// reported failed so the caller knows the audit gap.
	got, _ := inc.Get(ctx, incID)
	if len(got.Comments) != 1 {
		t.Fatalf("append happens before audit; comment present, got %d", len(got.Comments))
	}
}

func TestTriageFailsClosed(t *testing.T) {
	svc, _, ctx, _ := setup(t)
	bad := []func() error{
		func() error { _, e := svc.AssignOwner(ctx, "alice", incID, ""); return e },
		func() error { _, e := svc.Comment(ctx, "alice", incID, ""); return e },
		func() error { _, e := svc.ChangeStatus(ctx, "alice", incID, "bogus"); return e },
		func() error { _, e := svc.SetDisposition(ctx, "alice", incID, "bogus"); return e },
		func() error { _, e := svc.Comment(ctx, "", incID, "x"); return e },   // no actor
		func() error { _, e := svc.Comment(ctx, "alice", "", "x"); return e }, // no incident id
	}
	for i, f := range bad {
		if err := f(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("case %d must fail closed, got %v", i, err)
		}
	}
	// Unknown incident -> ErrNotFound from Get.
	if _, err := svc.Comment(ctx, "alice", "missing", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown incident must be ErrNotFound, got %v", err)
	}
	if _, err := NewService(nil, &captureAudit{}, time.Now); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil store must be rejected")
	}
}

func TestTriageNotificationCapturesCanonicalRevisionAndSafeImmutableFacts(t *testing.T) {
	_, _, ctx, _ := setup(t)
	engagementID := shared.ID("eng-notify")
	// Re-seed with an engagement-bound incident because legacy incidents without an engagement
	// intentionally cannot emit this engagement-scoped event.
	store := memory.NewIncidentEventStore()
	canonical, err := incidentuc.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	created := incident.IncidentEvent{IncidentID: incID, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, EngagementID: engagementID, Severity: shared.SeverityHigh, Title: "Target https://alice:secret@example.test"}
	if _, err := canonical.Append(ctx, incID, 0, []incident.IncidentEvent{created}); err != nil {
		t.Fatal(err)
	}
	audit := &captureAudit{}
	svc, err := NewService(canonical, audit, func() time.Time { return base.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, base.Add(-time.Second))
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, lifecycleFacts{NotificationLifecycleFacts: ports.NotificationLifecycleFacts{
		EngagementName: "Assessment", ActorName: "Alice", ActorUserID: "user-alice", LeadUserID: "user-lead",
	}}); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.ChangeStatus(ctx, "alice", incID, incident.StateInvestigating)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != incID || updated.Revision != 2 || updated.State != incident.StateInvestigating {
		t.Fatalf("canonical update = %+v", updated)
	}
	records := outbox.Records(tenant)
	if len(records) != 1 {
		t.Fatalf("notification records = %d, want 1", len(records))
	}
	record := records[0]
	if record.SourceKind != "incident_update" || record.SourceID != "inc-t:2" || record.CaptureVersion != 3 {
		t.Fatalf("source record = %+v", record)
	}
	var data map[string]any
	if err := json.Unmarshal(record.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data["update_kind"] != "status" || data["status"] != string(incident.StateInvestigating) || data["actor"] != "Alice" {
		t.Fatalf("notification data = %#v", data)
	}
	if title, _ := data["incident_title"].(string); title == "" || title == "Target https://alice:secret@example.test" || strings.Contains(title, "secret") {
		t.Fatalf("incident title leaks a credential: %q", title)
	}
	if len(audit.entries) != 1 || audit.entries[0].Target != incID.String() {
		t.Fatalf("audit = %+v", audit.entries)
	}
}

func TestTriageNotificationOutboxFailureRollsBackIncidentRevision(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), tenant)
	store := memory.NewIncidentEventStore()
	inc, err := incidentuc.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	created := incident.IncidentEvent{IncidentID: incID, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, EngagementID: "eng-notify", Severity: shared.SeverityHigh}
	if _, err := inc.Append(ctx, incID, 0, []incident.IncidentEvent{created}); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(inc, &captureAudit{}, func() time.Time { return base.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, base.Add(-time.Second))
	injected := errors.New("outbox unavailable after append")
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), appendThenFailOutbox{next: outbox, err: injected}, lifecycleFacts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeStatus(ctx, "alice", incID, incident.StateInvestigating); !errors.Is(err, injected) {
		t.Fatalf("change status error = %v, want injected outbox error", err)
	}
	stored, err := inc.Get(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != 1 || stored.State != incident.StateNew {
		t.Fatalf("incident must roll back after append failure: %+v", stored)
	}
	if records := outbox.Records(tenant); len(records) != 0 {
		t.Fatalf("outbox must roll back after appended failure: %+v", records)
	}
}

func TestTriageUnboundIncidentRemainsMutableWithNotifications(t *testing.T) {
	svc, audit, ctx, _ := setup(t)
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, base.Add(-time.Second))
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), outbox, lifecycleFacts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AssignOwner(ctx, "alice", incID, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Comment(ctx, "alice", incID, "investigating"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeStatus(ctx, "alice", incID, incident.StateInvestigating); err != nil {
		t.Fatal(err)
	}
	got, err := svc.SetDisposition(ctx, "alice", incID, incident.DispositionTruePositive)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 5 || got.OwnerID != "alice" || got.State != incident.StateInvestigating || len(got.Comments) != 1 || got.Disposition != incident.DispositionTruePositive {
		t.Fatalf("legacy triage projection = %+v", got)
	}
	if len(audit.entries) != 4 {
		t.Fatalf("audit count = %d, want 4", len(audit.entries))
	}
	if len(outbox.Records(tenant)) != 0 {
		t.Fatal("unbound incident cannot emit engagement-scoped facts")
	}
}

func TestTriageBoundCommentDoesNotEmitLifecycleNotification(t *testing.T) {
	svc, audit, ctx, canonical := setup(t)
	boundID := shared.ID("bound-comment-incident")
	if _, err := canonical.Append(ctx, boundID, 0, []incident.IncidentEvent{{IncidentID: boundID, Kind: incident.EventCreated, At: base, Actor: "correlator", AssetID: asset, EngagementID: "eng-notify", Severity: shared.SeverityHigh}}); err != nil {
		t.Fatal(err)
	}
	outbox := memory.NewNotificationOutbox()
	outbox.Activate(tenant, base.Add(-time.Second))
	injected := errors.New("capture must not run for a comment")
	if err := svc.SetNotifications(memory.NewTenantTransactionRunner(), appendThenFailOutbox{next: outbox, err: injected}, lifecycleFacts{}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Comment(ctx, "alice", boundID, "analyst note")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Comments) != 1 || len(audit.entries) != 1 || len(outbox.Records(tenant)) != 0 {
		t.Fatalf("comment/audit/capture = %d/%d/%d", len(got.Comments), len(audit.entries), len(outbox.Records(tenant)))
	}
}
