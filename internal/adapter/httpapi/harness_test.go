package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeupdraft"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	dastverifieruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
	dastworkflowuc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastworkflow"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	usersuc "github.com/KKloudTarus/synapse-ce/internal/usecase/users"
)

// fakeJudgments is a no-op judgmentService for the harness – every judgment assertion below is a
// DENY (403/404) rejected by authz/withEngTenant before any method runs, except the readonly LIST
// allow which returns an empty set.
type fakeJudgments struct{}

func (fakeJudgments) List(context.Context, shared.ID) ([]judgment.Judgment, error) { return nil, nil }
func (fakeJudgments) Verify(context.Context, string, shared.ID, shared.ID, int, string, int) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}
func (fakeJudgments) Accept(context.Context, string, shared.ID, shared.ID, int) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}

type fakeRuntimeVerifier struct{}

func (fakeRuntimeVerifier) Apply(context.Context, shared.ID, dastverifieruc.Result) (judgment.Judgment, error) {
	return judgment.Judgment{}, nil
}

// fakeThreatModel is a no-op threatModelService for the harness – every threat-model assertion below is a
// DENY (403/404) rejected by authz/withEngTenant before either method runs.
type fakeDASTWorkflow struct{}

func (fakeDASTWorkflow) Propose(context.Context, string, shared.ID, dastrunner.Probe) (dastworkflowuc.Proposal, error) {
	return dastworkflowuc.Proposal{}, nil
}
func (fakeDASTWorkflow) Decide(context.Context, string, shared.ID, shared.ID, bool, string) (agent.ApprovalDecision, error) {
	return agent.ApprovalDecision{}, nil
}
func (fakeDASTWorkflow) Run(context.Context, string, shared.ID, shared.ID, dastrunner.Probe) (dastrunner.Result, error) {
	return dastrunner.Result{}, nil
}

type fakeThreatModel struct{}

func (fakeThreatModel) Ingest(context.Context, string, shared.ID, shared.ID, threatmodel.Model) (threatmodel.ModelDelta, error) {
	return threatmodel.ModelDelta{}, nil
}
func (fakeThreatModel) Get(context.Context, shared.ID) (threatmodel.Model, bool, error) {
	return threatmodel.Model{}, false, nil
}

// fakeWriteupDrafts is a no-op writeupDraftService for the harness – every sign-off assertion below is a
// DENY (403/404) rejected by authz/withEngTenant before any method runs, except the readonly LIST allow.
type fakeWriteupDrafts struct{}

func (fakeWriteupDrafts) ListByEngagement(context.Context, shared.ID) ([]writeupdraft.Draft, error) {
	return nil, nil
}
func (fakeWriteupDrafts) Edit(context.Context, string, shared.ID, shared.ID, string, string) (writeupdraft.Draft, error) {
	return writeupdraft.Draft{}, nil
}
func (fakeWriteupDrafts) Accept(context.Context, string, shared.ID, shared.ID) (writeupdraft.Draft, error) {
	return writeupdraft.Draft{}, nil
}
func (fakeWriteupDrafts) Reject(context.Context, string, shared.ID, shared.ID) (writeupdraft.Draft, error) {
	return writeupdraft.Draft{}, nil
}

// TestHostileHarness drives the REAL route table (rt.routes()) through the production
// authz → withEngTenant → handler chain with a context-injected principal, asserting the program's
// cross-cutting authorization invariants END-TO-END through the actual wiring (not a stand-in):
// RBAC allow/deny per role (the matrix, as wired per route),
// tenant isolation (cross-tenant → 404, never a 200 nor an existence-revealing 403),
// machine-role denial (separation of duties), and
// fail-closed on a missing principal.
//
// A future route registered WITHOUT the right authz/withEngTenant wrapper, or with the wrong
// permission, fails here – that is the regression this harness exists to catch. The auth + AUP
// middleware are intentionally bypassed (driven via routes(), not Handler()) to isolate the
// authorization layer; they are validated by their own tests.
//
// Allow (200) cases are asserted only on routes whose downstream service is wired here (the
// engagement + users services); deny cases (403/404) are rejected by authz/withEngTenant before any
// handler runs, so they need no downstream service. This is deliberate – the security-critical
// assertions are the denials.
func TestHostileHarness(t *testing.T) {
	engRepo := memory.NewEngagementRepository()
	if err := engRepo.Create(context.Background(), &engdom.Engagement{
		ID: "engA", TenantID: "tenantA", Name: "A", Client: "A", Status: engdom.StatusActive,
	}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	usersSvc, err := usersuc.NewService(memory.NewUserRepository(), &fakeAudit{}, fixedClock{}, engIDs{})
	if err != nil {
		t.Fatalf("users svc: %v", err)
	}
	rt := &Router{
		log:   discardLog(),
		eng:   enguc.NewService(engRepo, fixedClock{}, engIDs{}, &fakeAudit{}),
		users: usersSvc,
	}
	// Register the two CONDITIONAL sign-off routes so the harness guards their gates too: the
	// PermReview /verify route (needs a non-nil exploitation verifier) and the agent routes incl.
	// PermReview approval-decide (needs a non-nil agent – nil deps are fine because every assertion
	// below on these routes is a DENY that authz/withEngTenant reject before any handler runs).
	rt.SetExploitation(&fakeVerifier{})
	rt.SetJudgments(&fakeJudgments{}) // register the judgment sign-off routes so the harness guards their SoD gates
	rt.SetRuntimeVerifier(&fakeRuntimeVerifier{})
	rt.SetDASTWorkflow(&fakeDASTWorkflow{})
	rt.SetThreatModel(&fakeThreatModel{})     // register the threat-model ingest/read routes so the harness guards their gates
	rt.SetWriteupDrafts(&fakeWriteupDrafts{}) // register the writeup-draft sign-off routes so the harness guards their SoD gates
	rt.EnableAgent(nil, nil, nil, nil, nil, 1, 8)
	mux := rt.routes()

	send := func(role, tenant, method, path string, authed bool) int {
		req := httptest.NewRequest(method, path, nil)
		if authed {
			req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "p", Role: role, TenantID: tenant}))
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	cases := []struct {
		name         string
		role, tenant string
		authed       bool
		method, path string
		want         int
	}{
		// Fail-closed: no principal → 403 at the authz chokepoint (the 401-producing auth middleware
		// is bypassed here on purpose to isolate the authorization layer).
		{"no principal is denied", "", "", false, http.MethodGet, "/api/v1/engagements", http.StatusForbidden},
		// A machine role is granted NOTHING – not even view (separation of duties).
		{"machine role denied even view", "agent", "tenantA", true, http.MethodGet, "/api/v1/engagements", http.StatusForbidden},
		// RBAC allow (view): every human role reads.
		{"readonly may list", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements", http.StatusOK},
		{"readonly may get own-tenant engagement", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA", http.StatusOK},
		// RBAC deny: readonly holds only view.
		{"readonly may not create (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements", http.StatusForbidden},
		{"readonly may not author finding (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/findings", http.StatusForbidden},
		{"readonly may not triage (triage)", "readonly", "tenantA", true, http.MethodPatch, "/api/v1/engagements/engA/findings/f1", http.StatusForbidden},
		{"readonly may not run scan (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/sca/scans", http.StatusForbidden},
		{"readonly may not read audit (review)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/audit", http.StatusForbidden},
		{"readonly may not manage users (administer)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/users", http.StatusForbidden},
		// Consultant: operate yes (covered elsewhere), but NOT review or administer.
		{"consultant may not read audit (review)", "consultant", "tenantA", true, http.MethodGet, "/api/v1/audit", http.StatusForbidden},
		{"consultant may not manage users (administer)", "consultant", "tenantA", true, http.MethodGet, "/api/v1/users", http.StatusForbidden},
		// Admin: administer yes.
		{"admin may manage users", "admin", "tenantA", true, http.MethodGet, "/api/v1/users", http.StatusOK},
		// Tenant isolation: tenant B cannot READ tenant A's engagement row (service-scoped), nor
		// reach its child resource (withEngTenant chokepoint) – both 404, never 200, never a
		// 403 that would reveal the engagement exists.
		{"cross-tenant engagement read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA", http.StatusNotFound},
		{"cross-tenant child resource → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/findings", http.StatusNotFound},
		// Same-tenant read still works (isolation does not over-block).
		{"same-tenant engagement read → 200", "consultant", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA", http.StatusOK},
		// Sign-off routes (PermReview) – the crown-jewel separation-of-duties gates. A machine role
		// can never verify a finding nor decide an agent approval; a consultant lacks review; a
		// reviewer in another tenant is tenant-blocked (404) before the sign-off runs.
		{"machine may not verify (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/findings/f1/verify", http.StatusForbidden},
		{"consultant may not verify (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/findings/f1/verify", http.StatusForbidden},
		{"cross-tenant verify → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/findings/f1/verify", http.StatusNotFound},
		{"machine may not decide approvals (SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/agent/approvals/a1/decide", http.StatusForbidden},
		{"consultant may not decide (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/agent/approvals/a1/decide", http.StatusForbidden},
		{"cross-tenant decide → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/agent/approvals/a1/decide", http.StatusNotFound},
		{"readonly may not start agent (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/agent/sessions", http.StatusForbidden},
		// Judgment sign-off (PermReview SoD): a machine role can NEVER verify/accept an AI
		// judgment (the runtime twin of the AST tripwire) – no agent self-confirm; a consultant lacks
		// review; cross-tenant is 404 before the sign-off; readonly may read.
		{"machine may not verify judgment (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/verify", http.StatusForbidden},
		{"consultant may not verify judgment (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/verify", http.StatusForbidden},
		{"machine may not accept judgment (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/accept", http.StatusForbidden},
		{"cross-tenant judgment verify → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/verify", http.StatusNotFound},
		{"machine may not apply runtime verification (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification", http.StatusForbidden},
		{"consultant may not apply runtime verification (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification", http.StatusForbidden},
		{"cross-tenant runtime verification -> 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification", http.StatusNotFound},
		{"readonly may not propose runtime verifier (operate)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification/proposals", http.StatusForbidden},
		{"machine may not decide runtime verifier (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/dast/approvals/a1/decide", http.StatusForbidden},
		{"consultant may not decide runtime verifier (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/dast/approvals/a1/decide", http.StatusForbidden},
		{"cross-tenant runtime verifier run -> 404", "consultant", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/judgments/j1/runtime-verification/proposals/a1/run", http.StatusNotFound},
		{"readonly may list judgments (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/judgments", http.StatusOK},
		// threat-model ingest (PermOperate) + read (PermView), tenant-gated like every child route.
		{"machine may not ingest threat model (operate)", "agent", "tenantA", true, http.MethodPut, "/api/v1/engagements/engA/threat-model", http.StatusForbidden},
		{"readonly may not ingest threat model (operate)", "readonly", "tenantA", true, http.MethodPut, "/api/v1/engagements/engA/threat-model", http.StatusForbidden},
		{"cross-tenant threat-model ingest → 404", "consultant", "tenantB", true, http.MethodPut, "/api/v1/engagements/engA/threat-model", http.StatusNotFound},
		{"cross-tenant threat-model read → 404", "consultant", "tenantB", true, http.MethodGet, "/api/v1/engagements/engA/threat-model", http.StatusNotFound},
		// writeup-draft sign-off (PermReview SoD) + read (PermView): the agent PROPOSES (via the tool,
		// not HTTP); a machine/consultant/readonly can NEVER edit/accept/reject here; cross-tenant is 404.
		{"machine may not accept writeup draft (review/SoD)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/accept", http.StatusForbidden},
		{"consultant may not accept writeup draft (review)", "consultant", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/accept", http.StatusForbidden},
		{"readonly may not reject writeup draft (review)", "readonly", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/reject", http.StatusForbidden},
		{"machine may not edit writeup draft (review)", "agent", "tenantA", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/edit", http.StatusForbidden},
		{"cross-tenant writeup-draft accept → 404", "reviewer", "tenantB", true, http.MethodPost, "/api/v1/engagements/engA/writeup-drafts/d1/accept", http.StatusNotFound},
		{"readonly may list writeup drafts (view)", "readonly", "tenantA", true, http.MethodGet, "/api/v1/engagements/engA/writeup-drafts", http.StatusOK},
	}
	for _, c := range cases {
		if got := send(c.role, c.tenant, c.method, c.path, c.authed); got != c.want {
			t.Errorf("%s: %s %s (role=%q tenant=%q) → %d, want %d", c.name, c.method, c.path, c.role, c.tenant, got, c.want)
		}
	}
}
