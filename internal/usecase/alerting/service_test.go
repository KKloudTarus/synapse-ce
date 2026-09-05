package alerting

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/alerting"
	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The fakes are mutex-guarded: deliveries run on the service's workers.
type fakeSink struct {
	mu    sync.Mutex
	name  string
	err   error
	got   []alerting.Alert
	ctxOK bool
}

func (f *fakeSink) Name() string { return f.name }
func (f *fakeSink) Deliver(ctx context.Context, a alerting.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, f.ctxOK = shared.TenantFrom(ctx)
	f.got = append(f.got, a)
	return f.err
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
	err     error
}

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return a.err
}

func (a *fakeAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.entries))
	for _, e := range a.entries {
		out = append(out, e.Action)
	}
	return out
}

type clock struct{}

func (clock) Now() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) }

type ids struct{ n int }

func (i *ids) NewID() shared.ID { i.n++; return shared.ID("alert-" + string(rune('0'+i.n))) }

func ctxT() context.Context { return shared.WithTenant(context.Background(), "tenant-a") }

func newSvc(t *testing.T, rule alerting.Rule, sinks ...ports.AlertSink) (*Service, *fakeAudit) {
	t.Helper()
	audit := &fakeAudit{}
	svc, err := NewService(sinks, rule, audit, clock{}, &ids{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, audit
}

func incidents() []incident.Incident {
	return []incident.Incident{
		{ID: "inc-1", AssetID: "host-1", Title: "process: det.process_enumeration", Severity: shared.SeverityHigh, DetectionIDs: []shared.ID{"d1", "d2"}, CreatedAt: time.Unix(1_700_000_000, 0).UTC()},
		{ID: "inc-2", AssetID: "host-2", Title: "network: det.suspicious_dns_beacon", Severity: shared.SeverityLow, DetectionIDs: []shared.ID{"d3"}},
	}
}

func TestIncidentsCreatedDeliversMatchingAlertsAndAudits(t *testing.T) {
	sink := &fakeSink{name: "webhook"}
	svc, audit := newSvc(t, alerting.Rule{MinSeverity: shared.SeverityMedium}, sink)

	svc.IncidentsCreated(ctxT(), "agent-1", "eng-1", incidents())
	svc.Flush()

	if len(sink.got) != 1 {
		t.Fatalf("the low incident must be filtered; delivered %d", len(sink.got))
	}
	a := sink.got[0]
	if a.Kind != alerting.KindIncidentCreated || a.IncidentID != "inc-1" || a.AssetID != "host-1" || a.EngagementID != "eng-1" || a.TenantID != "tenant-a" {
		t.Fatalf("alert = %+v", a)
	}
	if a.Link != "/fleet/incidents/inc-1" || a.Severity != shared.SeverityHigh || a.OccurredAt != time.Unix(1_700_000_000, 0).UTC() || a.Summary != "2 detection(s) correlated on asset host-1" {
		t.Fatalf("alert content = %+v", a)
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "alert.delivered" {
		t.Fatalf("audit = %v", got)
	}
	e := audit.entries[0]
	if e.Actor != "agent-1" || e.Target != "inc-1" || e.Metadata["sink"] != "webhook" || e.Metadata["severity"] != "high" || e.Metadata["engagement"] != "eng-1" {
		t.Fatalf("audit entry = %+v", e)
	}
}

func TestSinkFailureIsAuditedNotReturned(t *testing.T) {
	ok := &fakeSink{name: "webhook"}
	bad := &fakeSink{name: "pager", err: errors.New("502 from receiver")}
	svc, audit := newSvc(t, alerting.DefaultRule(), ok, bad)

	svc.IncidentsCreated(ctxT(), "agent-1", "eng-1", incidents()[:1])
	svc.Flush()

	got := audit.actions()
	if len(got) != 2 || got[0] != "alert.delivered" || got[1] != "alert.failed" {
		t.Fatalf("audit = %v", got)
	}
	if audit.entries[1].Metadata["error"] != "502 from receiver" || audit.entries[1].Metadata["sink"] != "pager" {
		t.Fatalf("failure audit = %+v", audit.entries[1])
	}
}

func TestIncidentWithoutTimestampUsesClock(t *testing.T) {
	sink := &fakeSink{name: "webhook"}
	svc, _ := newSvc(t, alerting.Rule{MinSeverity: shared.SeverityLow}, sink)
	svc.IncidentsCreated(ctxT(), "agent-1", "eng-1", incidents()[1:])
	svc.Flush()
	if len(sink.got) != 1 || sink.got[0].OccurredAt != (clock{}).Now() {
		t.Fatalf("alert = %+v", sink.got)
	}
}

func TestTestAlertBypassesRuleAndReportsOutcome(t *testing.T) {
	sink := &fakeSink{name: "webhook"}
	svc, audit := newSvc(t, alerting.Rule{MinSeverity: shared.SeverityCritical}, sink)
	out, err := svc.Test(ctxT(), "admin")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !out.Matched || out.Delivered != 1 || out.Failed != 0 {
		t.Fatalf("outcome = %+v", out)
	}
	if len(sink.got) != 1 || sink.got[0].Kind != alerting.KindTest || sink.got[0].Severity != shared.SeverityInfo {
		t.Fatalf("test alert = %+v", sink.got)
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "alert.delivered" {
		t.Fatalf("audit = %v", got)
	}

	bad := &fakeSink{name: "webhook", err: errors.New("connection refused")}
	svc, _ = newSvc(t, alerting.DefaultRule(), bad)
	out, err = svc.Test(ctxT(), "admin")
	if !errors.Is(err, ErrNoSinkAcknowledged) || out.Failed != 1 || out.Delivered != 0 {
		t.Fatalf("failed test = %+v, %v", out, err)
	}
}

func TestAuditFailureIsCounted(t *testing.T) {
	sink := &fakeSink{name: "webhook"}
	svc, audit := newSvc(t, alerting.DefaultRule(), sink)
	audit.err = errors.New("audit down")
	out := svc.Notify(ctxT(), "admin", alerting.Alert{ID: "a", TenantID: "t", Kind: alerting.KindIncidentCreated, Severity: shared.SeverityHigh, Title: "x", OccurredAt: time.Unix(1, 0)})
	if out.Delivered != 1 || out.AuditFailed != 1 {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestInvalidAlertIsAuditedNotDelivered(t *testing.T) {
	sink := &fakeSink{name: "webhook"}
	svc, audit := newSvc(t, alerting.DefaultRule(), sink)
	out := svc.Notify(ctxT(), "admin", alerting.Alert{ID: "a"})
	if out.Matched || out.Failed != 1 || len(sink.got) != 0 {
		t.Fatalf("outcome = %+v delivered=%d", out, len(sink.got))
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "alert.invalid" {
		t.Fatalf("audit = %v", got)
	}
}

func TestNewServiceValidation(t *testing.T) {
	audit := &fakeAudit{}
	if _, err := NewService(nil, alerting.DefaultRule(), audit, clock{}, &ids{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no sinks: %v", err)
	}
	if _, err := NewService([]ports.AlertSink{nil}, alerting.DefaultRule(), audit, clock{}, &ids{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil sink: %v", err)
	}
	if _, err := NewService([]ports.AlertSink{&fakeSink{}}, alerting.Rule{MinSeverity: "loud"}, audit, clock{}, &ids{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad rule: %v", err)
	}
	if _, err := NewService([]ports.AlertSink{&fakeSink{}}, alerting.DefaultRule(), nil, clock{}, &ids{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil audit: %v", err)
	}
}

// A slow sink never holds the caller: IncidentsCreated returns before delivery, and delivery still
// completes on the workers with a context that outlives the request.
func TestIncidentsCreatedDoesNotBlockOnASlowSink(t *testing.T) {
	release := make(chan struct{})
	slow := &blockingSink{release: release}
	svc, audit := newSvc(t, alerting.DefaultRule(), slow)
	ctx, cancel := context.WithCancel(ctxT())
	done := make(chan struct{})
	go func() {
		svc.IncidentsCreated(ctx, "agent-1", "eng-1", incidents()[:1])
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("IncidentsCreated blocked on the sink")
	}
	cancel() // the request is over; delivery must still run
	close(release)
	svc.Flush()
	slow.mu.Lock()
	calls, cancelled := slow.calls, slow.cancelled
	slow.mu.Unlock()
	if calls != 1 || cancelled {
		t.Fatalf("delivery calls=%d cancelled=%v", calls, cancelled)
	}
	if got := audit.actions(); len(got) != 1 || got[0] != "alert.delivered" {
		t.Fatalf("audit = %v", got)
	}
}

type blockingSink struct {
	mu        sync.Mutex
	release   chan struct{}
	calls     int
	cancelled bool
}

func (b *blockingSink) Name() string { return "slow" }
func (b *blockingSink) Deliver(ctx context.Context, _ alerting.Alert) error {
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	b.cancelled = ctx.Err() != nil
	return nil
}

// Beyond the per-tenant bucket, alerts are audited as suppressed instead of delivered, and another
// tenant's bucket is untouched.
func TestIncidentsCreatedIsRateLimitedPerTenant(t *testing.T) {
	sink := &fakeSink{name: "webhook"}
	svc, audit := newSvc(t, alerting.Rule{MinSeverity: shared.SeverityLow}, sink)
	flood := make([]incident.Incident, 0, tenantAlertsPerMinute+5)
	for i := 0; i < tenantAlertsPerMinute+5; i++ {
		flood = append(flood, incident.Incident{ID: shared.ID("inc-" + strconv.Itoa(i)), AssetID: "host-1", Title: "burst", Severity: shared.SeverityHigh, CreatedAt: time.Unix(1, 0)})
	}
	svc.IncidentsCreated(ctxT(), "agent-1", "eng-1", flood)
	svc.IncidentsCreated(shared.WithTenant(context.Background(), "tenant-b"), "agent-2", "eng-2", flood[:1])
	svc.Flush()
	if len(sink.got) != tenantAlertsPerMinute+1 {
		t.Fatalf("delivered %d, want %d for tenant-a plus 1 for tenant-b", len(sink.got), tenantAlertsPerMinute+1)
	}
	suppressed := 0
	for _, action := range audit.actions() {
		if action == "alert.suppressed" {
			suppressed++
		}
	}
	if suppressed != 5 {
		t.Fatalf("suppressed = %d, want 5", suppressed)
	}
}
