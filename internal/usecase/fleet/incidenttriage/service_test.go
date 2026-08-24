package incidenttriage

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
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
		func() error { _, e := svc.AssignOwner(ctx, "alice", incID, "   "); return e },
		func() error {
			_, e := svc.AssignOwner(ctx, "alice", incID, strings.Repeat("x", maxOwnerRunes+1))
			return e
		},
		func() error { _, e := svc.Comment(ctx, "alice", incID, ""); return e },
		func() error {
			_, e := svc.Comment(ctx, "alice", incID, strings.Repeat("x", maxCommentRunes+1))
			return e
		},
		func() error { _, e := svc.ChangeStatus(ctx, "alice", incID, "bogus"); return e },
		func() error { _, e := svc.SetDisposition(ctx, "alice", incID, "bogus"); return e },
		func() error { _, e := svc.Comment(ctx, "", incID, "x"); return e }, // no actor
		func() error { _, e := svc.Comment(ctx, strings.Repeat("x", maxActorRunes+1), incID, "x"); return e },
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

func TestTriageCanonicalizesAttributionAndText(t *testing.T) {
	svc, audit, ctx, inc := setup(t)
	if _, err := svc.AssignOwner(ctx, "  alice  ", incID, "  bob  "); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Comment(ctx, "  alice  ", incID, "  note  "); err != nil {
		t.Fatal(err)
	}
	got, err := inc.Get(ctx, incID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnerID != "bob" || len(got.Comments) != 1 || got.Comments[0].Actor != "alice" || got.Comments[0].Text != "note" {
		t.Fatalf("canonicalized incident = %+v", got)
	}
	for _, entry := range audit.entries {
		if entry.Actor != "alice" {
			t.Fatalf("audit actor = %q, want alice", entry.Actor)
		}
	}
}
