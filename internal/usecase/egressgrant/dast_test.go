package egressgrant_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastprobe"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/egressgrant"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type dastAuthority struct {
	auth     ports.DASTRunAuthorization
	claimErr error
}

func (a *dastAuthority) GetDASTRunAuthorization(_ context.Context, tenant, id shared.ID) (ports.DASTRunAuthorization, error) {
	if a.auth.Run.ID != id || a.auth.Run.TenantID != tenant {
		return ports.DASTRunAuthorization{}, shared.ErrNotFound
	}
	return a.auth, nil
}
func (a *dastAuthority) ClaimDASTRunGrant(_ context.Context, expected ports.DASTRunAuthorization, _ time.Time) error {
	if a.claimErr != nil {
		return a.claimErr
	}
	if !reflect.DeepEqual(expected, a.auth) || a.auth.GrantIssued {
		return shared.ErrConflict
	}
	a.auth.GrantIssued = true
	return nil
}

func newDASTFixture(t *testing.T) (*fixture, *dastAuthority) {
	t.Helper()
	f := newFixture(t)
	p := dastprobe.Probe{JudgmentID: "judgment-1", URL: "https://app.example.com/fixture.json", ExpectedStatus: 200, ExpectedBodyContains: "synthetic fixture", ScoreIfConfirmed: 90, ScoreIfRefuted: 10, ExpectedVersion: 1, Rationale: "Confirm public static fixture response only"}
	r := dastrun.Run{ID: "dast-run-1", TenantID: "tenant-test", EngagementID: "eng-1", ActionID: "action-1", Actor: "operator", Status: dastrun.RunRunning, StartedAt: f.now}
	action := agent.ProposedAction{ID: r.ActionID, SessionID: "dast:judgment-1", EngagementID: r.EngagementID, Tool: dastprobe.ToolRunDASTVerifier, Action: dastprobe.ActionSafeHTTPProbe, Target: engagement.Target{Kind: engagement.TargetURL, Value: p.URL}, Argv: []string{"synapse-dast-probe", "--config-sha256=" + p.ApprovalDigest()}, Risk: agent.RiskIntrusive, ProposedAt: f.now}
	decision := agent.ApprovalDecision{ActionID: r.ActionID, State: agent.ApprovalConsumed, DecidedBy: "reviewer"}
	admBytes, _ := json.Marshal(map[string]any{"action_id": action.ID, "session_id": action.SessionID, "tool": action.Tool, "action": action.Action, "target": action.Target.Value, "argv": action.Argv, "risk": action.Risk, "decided_by": decision.DecidedBy})
	adm := evidence.Evidence{ID: "admission-1", EngagementID: r.EngagementID, Kind: "agent_admission", Content: admBytes, CreatedBy: r.Actor, CreatedAt: f.now}.Seal()
	consumedBytes, _ := json.Marshal(ports.DASTApprovalConsumption{TenantID: r.TenantID, EngagementID: r.EngagementID, RunID: r.ID, ActionID: r.ActionID, Actor: r.Actor, AdmissionID: adm.ID})
	consumed := evidence.Evidence{ID: ports.DASTConsumptionEvidenceID(r.ID), EngagementID: r.EngagementID, Kind: "agent_approval_consumed", Content: consumedBytes, PreviousHash: adm.Hash, CreatedBy: r.Actor, CreatedAt: f.now}.Seal()
	a := &dastAuthority{auth: ports.DASTRunAuthorization{Run: r, Job: ports.DASTRunJob{TenantID: r.TenantID, RunID: r.ID, Probe: p}, Action: action, Decision: decision, ConsumedBy: r.ID, Admission: adm, Consumption: consumed}}
	if err := f.service.SetDAST(a); err != nil {
		t.Fatal(err)
	}
	f.canonicalizer.rules = []ports.CanonicalEgressRule{{Allow: true, CIDR: "93.184.216.34/32", Ports: []uint16{443}}}
	f.request.ExecutionKind, f.request.ExecutionID = egressgrant.ExecutionKindDASTVerifier, r.ID.String()
	f.request.Rules = append([]ports.CanonicalEgressRule(nil), f.canonicalizer.rules...)
	return f, a
}

func TestDASTGrantRequiresCommittedAuthorityAndIsSingleUse(t *testing.T) {
	f, a := newDASTFixture(t)
	token, err := f.service.Authorize(f.ctx, f.request)
	if err != nil || token == "" || !a.auth.GrantIssued {
		t.Fatalf("first authorization: token=%t issued=%t err=%v", token != "", a.auth.GrantIssued, err)
	}
	if f.canonicalizer.policy.AllowDomainRules[0].Host != "app.example.com" {
		t.Fatal("policy did not derive original approved hostname")
	}
	token, err = f.service.Authorize(f.ctx, f.request)
	if err == nil || token != "" {
		t.Fatal("second token escaped for consumed issuance")
	}
}

func TestDASTGrantRejectsSubstitutionAndMissingCustody(t *testing.T) {
	cases := map[string]func(*fixture, *dastAuthority){
		"legacy owner":             func(_ *fixture, a *dastAuthority) { a.auth.ConsumedBy = "" },
		"losing run":               func(_ *fixture, a *dastAuthority) { a.auth.ConsumedBy = "other-run" },
		"job identity":             func(_ *fixture, a *dastAuthority) { a.auth.Job.RunID = "other-run" },
		"different approved probe": func(_ *fixture, a *dastAuthority) { a.auth.Job.Probe.ExpectedBodyContains = "different" },
		"no human":                 func(_ *fixture, a *dastAuthority) { a.auth.Decision.DecidedBy = "auto" },
		"wrong action":             func(_ *fixture, a *dastAuthority) { a.auth.Action.Action = "dast.authenticated_scan" },
		"missing consumption":      func(_ *fixture, a *dastAuthority) { a.auth.Consumption = evidence.Evidence{} },
		"tampered admission":       func(_ *fixture, a *dastAuthority) { a.auth.Admission.Content = []byte(`{}`) },
		"wrong consumption": func(_ *fixture, a *dastAuthority) {
			var c ports.DASTApprovalConsumption
			_ = json.Unmarshal(a.auth.Consumption.Content, &c)
			c.RunID = "other-run"
			a.auth.Consumption.Content, _ = json.Marshal(c)
			a.auth.Consumption = a.auth.Consumption.Seal()
		},
		"foreign tenant": func(f *fixture, _ *dastAuthority) { f.request.TenantID = "other-tenant" },
		"broader pin":    func(f *fixture, _ *dastAuthority) { f.request.Rules[0].CIDR = "93.184.216.0/24" },
		"wrong port": func(f *fixture, _ *dastAuthority) {
			f.request.Rules = []ports.CanonicalEgressRule{{Allow: true, CIDR: "93.184.216.34/32", Ports: []uint16{80}}}
		},
		"mixed private DNS": func(f *fixture, _ *dastAuthority) {
			f.canonicalizer.rules = append(f.canonicalizer.rules, ports.CanonicalEgressRule{Allow: true, CIDR: "10.0.0.1/32", Ports: []uint16{443}})
		},
		"shared DNS": func(f *fixture, _ *dastAuthority) {
			f.canonicalizer.rules = []ports.CanonicalEgressRule{{Allow: true, CIDR: "100.100.100.200/32", Ports: []uint16{443}}}
			f.request.Rules = f.canonicalizer.rules
		},
		"mixed shared DNS": func(f *fixture, _ *dastAuthority) {
			f.canonicalizer.rules = append(f.canonicalizer.rules, ports.CanonicalEgressRule{Allow: true, CIDR: "100.64.0.1/32", Ports: []uint16{443}})
		},
		"terminal after DNS": func(f *fixture, a *dastAuthority) {
			f.canonicalizer.after = func() { a.auth.Run.Fail("interrupted", f.now) }
		},
		"authority changed after DNS": func(f *fixture, a *dastAuthority) {
			f.canonicalizer.after = func() { a.auth.Job.Probe.Rationale = "changed" }
		},
		"window revoked after DNS": func(f *fixture, _ *dastAuthority) {
			f.canonicalizer.after = func() {
				start, end := f.now.Add(-time.Hour), f.now.Add(-3*time.Minute)
				if err := f.engagement.SetAuthorizationWindow(&start, &end, "UTC", f.now); err != nil {
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
			f, a := newDASTFixture(t)
			mutate(f, a)
			token, err := f.service.Authorize(f.ctx, f.request)
			if err == nil || token != "" || a.auth.GrantIssued {
				t.Fatalf("invalid authority returned token=%t issued=%t err=%v", token != "", a.auth.GrantIssued, err)
			}
		})
	}
}

func TestDASTGrantDoesNotExposeSignedTokenOnClaimFailure(t *testing.T) {
	f, a := newDASTFixture(t)
	a.claimErr = errors.New("uncertain commit")
	token, err := f.service.Authorize(f.ctx, f.request)
	if err == nil || token != "" || f.signer.calls != 1 {
		t.Fatalf("claim failure token=%t signed=%d err=%v", token != "", f.signer.calls, err)
	}
}
