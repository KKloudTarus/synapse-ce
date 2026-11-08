package egressgrant_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastconfig"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/egressgrant"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type scanAuthority struct {
	mu          sync.Mutex
	auth        ports.DASTScanAuthorization
	beforeClaim func()
	lost        bool
}

func (a *scanAuthority) GetDASTScanAuthorization(_ context.Context, e ports.DASTScanExecution) (ports.DASTScanAuthorization, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.auth.Execution != e {
		return ports.DASTScanAuthorization{}, shared.ErrNotFound
	}
	return a.auth, nil
}
func (a *scanAuthority) ClaimDASTScanGrant(ctx context.Context, expected ports.DASTScanAuthorization, _ time.Time, guard func(context.Context) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !reflect.DeepEqual(expected, a.auth) || a.auth.GrantIssued {
		return shared.ErrConflict
	}
	if a.beforeClaim != nil {
		a.beforeClaim()
	}
	if err := guard(ctx); err != nil {
		return err
	}
	a.auth.GrantIssued = true
	if a.lost {
		return errors.New("uncertain commit")
	}
	return nil
}

func newScanFixture(t *testing.T) (*fixture, *scanAuthority) {
	t.Helper()
	f := newFixture(t)
	ceilings := dastconfig.DefaultScanCeilings()
	config := dastconfig.ScanConfig{Target: "https://app.example.com/", Crawler: dastcrawl.Input{Target: "https://app.example.com/"}, Session: dastsession.Config{Scheme: dastsession.SchemeBearer, Credentials: []dastsession.CredentialBinding{{Name: "token", Reference: "token"}}, LoginRequest: dastsession.Request{Method: "GET", Path: "/"}, CheckRequest: dastsession.Request{Method: "GET", Path: "/"}, Success: dastsession.SuccessSignal{StatusCode: 200}}}
	_, raw, digest, err := dastconfig.Canonical(config, ceilings)
	if err != nil {
		t.Fatal(err)
	}
	r := dastrun.Run{ID: "scan-1", Kind: dastrun.KindAuthenticatedScan, TenantID: "tenant-test", EngagementID: "eng-1", ActionID: "action-1", Actor: "operator", Status: dastrun.RunRunning, StartedAt: f.now}
	helper, pin := "/usr/bin/dast-helper", strings.Repeat("a", 64)
	p := agent.ProposedAction{ID: r.ActionID, SessionID: shared.ID("dast-scan:" + digest), EngagementID: r.EngagementID, Tool: "run_authenticated_dast", Action: "dast.authenticated_scan", Target: engagement.Target{Kind: engagement.TargetURL, Value: config.Target}, Argv: []string{helper, "run", "--config-sha256=" + digest, "--helper-sha256=" + pin}, Risk: agent.RiskIntrusive, ProposedAt: f.now}
	d := agent.ApprovalDecision{ActionID: p.ID, State: agent.ApprovalConsumed, DecidedBy: r.Actor}
	ab, _ := json.Marshal(map[string]any{"action_id": p.ID, "session_id": p.SessionID, "tool": p.Tool, "action": p.Action, "target": p.Target.Value, "argv": p.Argv, "risk": p.Risk, "decided_by": d.DecidedBy})
	adm := evidence.Evidence{ID: "admission-1", EngagementID: r.EngagementID, Kind: "agent_admission", Content: ab, CreatedBy: r.Actor, CreatedAt: f.now}.Seal()
	cb, _ := json.Marshal(ports.DASTApprovalConsumption{TenantID: r.TenantID, EngagementID: r.EngagementID, RunID: r.ID, ActionID: p.ID, Actor: r.Actor, AdmissionID: adm.ID})
	cons := evidence.Evidence{ID: ports.DASTConsumptionEvidenceID(r.ID), EngagementID: r.EngagementID, Kind: "agent_approval_consumed", Content: cb, CreatedBy: r.Actor, CreatedAt: f.now}.Seal()
	ex := ports.DASTScanExecution{TenantID: r.TenantID, RunID: r.ID, JobID: "job-1", Fence: 1}
	a := &scanAuthority{auth: ports.DASTScanAuthorization{Run: r, Job: ports.DASTScanJob{TenantID: r.TenantID, RunID: r.ID, Config: raw, ConfigSHA256: digest, HelperPath: helper, HelperSHA256: pin}, Execution: ex, Action: p, Decision: d, ConsumedBy: r.ID, Admission: adm, Consumption: cons}}
	if err := f.service.SetDASTScan(a, helper, pin, ceilings); err != nil {
		t.Fatal(err)
	}
	f.request.ExecutionKind = egressgrant.ExecutionKindDASTSession
	f.request.ExecutionID, err = ex.ExecutionID()
	if err != nil {
		t.Fatal(err)
	}
	f.canonicalizer.rules = []ports.CanonicalEgressRule{{Allow: true, CIDR: "93.184.216.34/32", Ports: []uint16{443}}, {Allow: true, CIDR: "93.184.216.35/32", Ports: []uint16{443}}}
	f.request.Rules = append([]ports.CanonicalEgressRule(nil), f.canonicalizer.rules...)
	return f, a
}

func TestScanGrantRequiresExactAuthorityAndIsSingleUse(t *testing.T) {
	f, a := newScanFixture(t)
	token, err := f.service.Authorize(f.ctx, f.request)
	if err != nil || token == "" || !a.auth.GrantIssued {
		t.Fatalf("grant=%q err=%v", token, err)
	}
	if token, err = f.service.Authorize(f.ctx, f.request); err == nil || token != "" {
		t.Fatalf("second grant=%q err=%v", token, err)
	}
}

func TestScanGrantRejectsAuthoritySubstitution(t *testing.T) {
	cases := map[string]func(*fixture, *scanAuthority){
		"wrong kind":       func(_ *fixture, a *scanAuthority) { a.auth.Run.Kind = dastrun.KindVerifier },
		"wrong owner":      func(_ *fixture, a *scanAuthority) { a.auth.ConsumedBy = "other" },
		"approval":         func(_ *fixture, a *scanAuthority) { a.auth.Decision.DecidedBy = "auto" },
		"machine approval": func(_ *fixture, a *scanAuthority) { a.auth.Decision.DecidedBy = "agent:approver" },
		"helper":           func(_ *fixture, a *scanAuthority) { a.auth.Job.HelperPath = "/tmp/helper" },
		"pin":              func(_ *fixture, a *scanAuthority) { a.auth.Job.HelperSHA256 = strings.Repeat("b", 64) },
		"config":           func(_ *fixture, a *scanAuthority) { a.auth.Job.ConfigSHA256 = strings.Repeat("c", 64) },
		"foreign tenant":   func(f *fixture, _ *scanAuthority) { f.request.TenantID = "other" },
		"session":          func(_ *fixture, a *scanAuthority) { a.auth.Action.SessionID = "other" },
		"custody":          func(_ *fixture, a *scanAuthority) { a.auth.Consumption.Content = []byte(`{}`) },
		"fence": func(f *fixture, a *scanAuthority) {
			ex := a.auth.Execution
			ex.Fence++
			f.request.ExecutionID, _ = ex.ExecutionID()
		},
		"missing rule": func(f *fixture, _ *scanAuthority) { f.request.Rules = f.request.Rules[:1] },
		"extra rule": func(f *fixture, _ *scanAuthority) {
			f.request.Rules = append(f.request.Rules, ports.CanonicalEgressRule{Allow: true, CIDR: "8.8.8.8/32", Ports: []uint16{443}})
		},
		"unsafe DNS": func(f *fixture, _ *scanAuthority) {
			f.canonicalizer.rules[0].CIDR = "10.0.0.1/32"
			f.request.Rules[0].CIDR = "10.0.0.1/32"
		},
		"wide DNS": func(f *fixture, _ *scanAuthority) {
			f.canonicalizer.rules[0].CIDR = "93.184.216.0/24"
			f.request.Rules[0].CIDR = "93.184.216.0/24"
		},
		"changed after DNS": func(f *fixture, a *scanAuthority) { f.canonicalizer.after = func() { a.auth.ConsumedBy = "other" } },
		"scope revoked after DNS": func(f *fixture, _ *scanAuthority) {
			f.canonicalizer.after = func() {
				if err := f.engagement.SetScope([]engagement.Target{{Kind: engagement.TargetDomain, Value: "other.example.com"}}, nil, f.now); err != nil {
					t.Fatal(err)
				}
				if err := f.engagements.Update(f.ctx, f.engagement); err != nil {
					t.Fatal(err)
				}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, a := newScanFixture(t)
			mutate(f, a)
			token, err := f.service.Authorize(f.ctx, f.request)
			if err == nil || token != "" || a.auth.GrantIssued {
				t.Fatalf("token=%q issued=%v err=%v", token, a.auth.GrantIssued, err)
			}
		})
	}
}

func TestScanGrantClaimFailureAndFreshWindowNeverExposeToken(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "window revoked in claim", true: "lost claim response"}[lost], func(t *testing.T) {
			f, a := newScanFixture(t)
			if lost {
				a.lost = true
			} else {
				a.beforeClaim = func() {
					start, end := f.now.Add(-time.Hour), f.now.Add(-10*time.Minute)
					if err := f.engagement.SetAuthorizationWindow(&start, &end, "UTC", f.now); err != nil {
						t.Fatal(err)
					}
					if err := f.engagements.Update(f.ctx, f.engagement); err != nil {
						t.Fatal(err)
					}
				}
			}
			token, err := f.service.Authorize(f.ctx, f.request)
			if err == nil || token != "" {
				t.Fatalf("token=%q err=%v", token, err)
			}
			if lost {
				token, err = f.service.Authorize(f.ctx, f.request)
				if err == nil || token != "" {
					t.Fatalf("retry token=%q err=%v", token, err)
				}
			}
		})
	}
}

func TestScanGrantConcurrentClaimsOnlyOneWins(t *testing.T) {
	f1, a := newScanFixture(t)
	f2, _ := newScanFixture(t)
	if err := f2.service.SetDASTScan(a, "/usr/bin/dast-helper", strings.Repeat("a", 64), dastconfig.DefaultScanCeilings()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan string, 2)
	for _, f := range []*fixture{f1, f2} {
		wg.Add(1)
		go func(f *fixture) { defer wg.Done(); token, _ := f.service.Authorize(f.ctx, f.request); results <- token }(f)
	}
	wg.Wait()
	close(results)
	wins := 0
	for token := range results {
		if token != "" {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("got %d grants", wins)
	}
}
