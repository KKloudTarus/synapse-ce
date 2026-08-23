package egressgrant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/egress"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/egressgrant"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type auditRecorder struct{ entries []ports.AuditEntry }

func (a *auditRecorder) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

type reconTool struct{ name string }

func (t reconTool) Name() string                         { return t.name }
func (t reconTool) Binary() string                       { return t.name }
func (t reconTool) Action() string                       { return "recon." + t.name }
func (t reconTool) Accepts(k engagement.TargetKind) bool { return k == engagement.TargetDomain }
func (t reconTool) CapabilitySensitive() bool            { return false }
func (t reconTool) Parse([]byte) ([]recon.Result, error) { return nil, nil }
func (t reconTool) BuildArgs(target engagement.Target) (ports.ToolSpec, error) {
	return ports.ToolSpec{Name: t.name, Args: []string{"-d", target.Value}}, nil
}

type canonicalizer struct {
	rules []ports.CanonicalEgressRule
	calls int
}

func (c *canonicalizer) Canonicalize(context.Context, ports.EgressPolicy) ([]ports.CanonicalEgressRule, error) {
	c.calls++
	return append([]ports.CanonicalEgressRule(nil), c.rules...), nil
}

type signer struct {
	calls int
	req   ports.EgressGrantRequest
}

func (s *signer) Sign(req ports.EgressGrantRequest, _ time.Time, lifetime time.Duration) (string, error) {
	if lifetime != egressgrant.GrantLifetime {
		return "", errors.New("unexpected grant lifetime")
	}
	s.calls++
	s.req = req
	return "signed-grant", nil
}

type fixture struct {
	ctx           context.Context
	request       ports.EgressGrantRequest
	service       *egressgrant.Service
	engagement    *engagement.Engagement
	runStore      *memory.ReconRunRepository
	engagements   *memory.EngagementRepository
	canonicalizer *canonicalizer
	signer        *signer
	audit         *auditRecorder
	now           time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	tenantID := shared.ID("tenant-test")
	eng, err := engagement.New("eng-1", tenantID, "Engagement", "Client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.SetScope([]engagement.Target{{Kind: engagement.TargetDomain, Value: "app.example.com"}}, nil, now); err != nil {
		t.Fatal(err)
	}
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	if err := eng.SetAuthorizationWindow(&from, &to, "UTC", now); err != nil {
		t.Fatal(err)
	}
	if err := eng.Transition(engagement.StatusActive, now); err != nil {
		t.Fatal(err)
	}
	eng.SetLiveRecon(true, now)

	engagements := memory.NewEngagementRepository()
	if err := engagements.Create(context.Background(), eng); err != nil {
		t.Fatal(err)
	}
	runs := memory.NewReconRunRepository()
	run := recon.Run{
		ID:           "run-1",
		EngagementID: eng.ID,
		Tool:         "subfinder",
		Target:       "app.example.com",
		Status:       recon.StatusRunning,
		StartedAt:    now,
	}
	if err := runs.Save(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	audit := &auditRecorder{}
	clock := fixedClock{now: now}
	guard, err := execution.NewGuard(engagements, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	rules := []ports.CanonicalEgressRule{{Allow: true, CIDR: "203.0.113.0/24", Ports: []uint16{443}}}
	canonical := &canonicalizer{rules: rules}
	sign := &signer{}
	service, err := egressgrant.NewService(
		runs,
		engagements,
		guard,
		clock,
		map[string]ports.ReconTool{"subfinder": reconTool{name: "subfinder"}},
		egress.Compiler{},
		canonical,
		sign,
	)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		ctx:           shared.WithTenant(context.Background(), tenantID),
		request:       ports.EgressGrantRequest{TenantID: tenantID.String(), ExecutionKind: egressgrant.ExecutionKindRecon, ExecutionID: run.ID.String(), RunID: "syn1", Slot: 1, PID: 1234, Rules: rules},
		service:       service,
		engagement:    eng,
		runStore:      runs,
		engagements:   engagements,
		canonicalizer: canonical,
		signer:        sign,
		audit:         audit,
		now:           now,
	}
}

func TestAuthorizeSignsAuthoritativeRunningRecon(t *testing.T) {
	f := newFixture(t)
	grant, err := f.service.Authorize(f.ctx, f.request)
	if err != nil {
		t.Fatal(err)
	}
	if grant != "signed-grant" || f.signer.calls != 1 || f.canonicalizer.calls != 1 {
		t.Fatalf("grant=%q signer_calls=%d canonicalizer_calls=%d", grant, f.signer.calls, f.canonicalizer.calls)
	}
	if f.signer.req.TenantID != f.request.TenantID || f.signer.req.ExecutionKind != f.request.ExecutionKind || f.signer.req.ExecutionID != f.request.ExecutionID {
		t.Fatalf("signed request = %+v", f.signer.req)
	}
	if len(f.audit.entries) != 1 || f.audit.entries[0].Actor != "synapse-egress-authority" {
		t.Fatalf("audit entries = %+v", f.audit.entries)
	}
}

func TestAuthorizeFailsClosedBeforeSigning(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *fixture)
	}{
		{
			name: "tenant mismatch",
			mutate: func(_ *testing.T, f *fixture) {
				f.request.TenantID = "other-tenant"
			},
		},
		{
			name: "unsupported execution kind",
			mutate: func(_ *testing.T, f *fixture) {
				f.request.ExecutionKind = "acquisition"
			},
		},
		{
			name: "execution not running",
			mutate: func(t *testing.T, f *fixture) {
				run, err := f.runStore.Get(f.ctx, "run-1")
				if err != nil {
					t.Fatal(err)
				}
				run.Status = recon.StatusSucceeded
				if err := f.runStore.Save(f.ctx, run); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "live recon disabled",
			mutate: func(_ *testing.T, f *fixture) {
				f.engagement.SetLiveRecon(false, f.now)
			},
		},
		{
			name: "unknown tool",
			mutate: func(t *testing.T, f *fixture) {
				run, err := f.runStore.Get(f.ctx, "run-1")
				if err != nil {
					t.Fatal(err)
				}
				run.Tool = "unknown"
				if err := f.runStore.Save(f.ctx, run); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "authorization window expired",
			mutate: func(t *testing.T, f *fixture) {
				from, to := f.now.Add(-2*time.Hour), f.now.Add(-time.Hour)
				if err := f.engagement.SetAuthorizationWindow(&from, &to, "UTC", f.now); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "canonical rules mismatch",
			mutate: func(_ *testing.T, f *fixture) {
				f.request.Rules = []ports.CanonicalEgressRule{{Allow: true, CIDR: "198.51.100.0/24", Ports: []uint16{443}}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			test.mutate(t, f)
			if _, err := f.service.Authorize(f.ctx, f.request); err == nil {
				t.Fatal("expected authorization failure")
			}
			if f.signer.calls != 0 {
				t.Fatalf("signer called %d times", f.signer.calls)
			}
		})
	}
}
