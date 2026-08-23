package dastsession

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsurface"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/approval"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/execution"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/safety"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

type testAudit struct{ entries []ports.AuditEntry }

func (a *testAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	a.entries = append(a.entries, entry)
	return nil
}

type testIDs struct{ next int }

func (i *testIDs) NewID() shared.ID {
	i.next++
	return shared.ID("evidence-" + string(rune('0'+i.next)))
}

const (
	// The helper name the engine is configured with, and a 64-hex digest standing in for the hash of an
	// approved configuration (dastworkflow/scan.go derives the real one and binds it into the approval).
	testHelperBin    = "synapse-dast-helper"
	testConfigDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type authorizingEngine struct {
	requests []ports.DASTRequest
	before   func(int)
}

// Run mirrors the REAL engine's plan validation before doing anything else. A fake that accepts any
// plan cannot disagree with dastengine.Engine about what a valid plan is -- which is exactly how a
// service building a plan with no ConfigDigest passed its tests while being unable to execute.
func (e *authorizingEngine) Run(ctx context.Context, plan ports.DASTPlan, _ []string, authorize func(context.Context, ports.DASTRequest) error) (ports.DASTOutcome, error) {
	if err := plan.Session.Validate(); err != nil {
		return ports.DASTOutcome{}, err
	}
	if strings.TrimSpace(plan.Target) == "" {
		return ports.DASTOutcome{}, fmt.Errorf("%w: DAST target is required", shared.ErrValidation)
	}
	if len(plan.ConfigDigest) != 64 {
		return ports.DASTOutcome{}, fmt.Errorf("%w: approved DAST configuration digest is required", shared.ErrValidation)
	}
	if plan.EgressPolicy == nil || plan.EgressExecutionKind != "dast-session" || plan.EgressExecutionID == "" {
		return ports.DASTOutcome{}, fmt.Errorf("%w: authoritative DAST execution identity is required", shared.ErrValidation)
	}
	for i, request := range e.requests {
		if e.before != nil {
			e.before(i)
		}
		if err := authorize(ctx, request); err != nil {
			return ports.DASTOutcome{}, err
		}
	}
	return ports.DASTOutcome{}, nil
}

func sessionFixture(t *testing.T, engine ports.DASTEngine) (*Service, safety.AdmittedAction, *testClock, *testAudit) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1_700_100_000, 0).UTC()
	clock := &testClock{now: now}
	audit := &testAudit{}
	eng, err := engagement.New("eng-1", "", "Acme", "Acme", now)
	if err != nil {
		t.Fatal(err)
	}
	eng.Status = engagement.StatusActive
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	if err := eng.SetAuthorizationWindow(&from, &to, "UTC", now); err != nil {
		t.Fatal(err)
	}
	eng.Scope = engagement.Scope{InScope: []engagement.Target{{Kind: engagement.TargetURL, Value: "https://203.0.113.10/"}}}
	repo := memory.NewEngagementRepository()
	if err := repo.Create(ctx, eng); err != nil {
		t.Fatal(err)
	}
	guard, err := execution.NewGuard(repo, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	store := memory.NewApprovalStore()
	approvals, err := approval.NewService(store, audit, clock, agent.ModeManual, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := evidence.NewService(memory.NewEvidenceStore(), nil, audit, clock, &testIDs{})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := safety.NewGate(guard, approvals, ev)
	if err != nil {
		t.Fatal(err)
	}
	action := agent.ProposedAction{
		ID: "action-1", SessionID: "session-1", EngagementID: "eng-1",
		Tool: ToolAuthenticatedDAST, Action: ActionAuthenticatedDAST,
		Target: engagement.Target{Kind: engagement.TargetURL, Value: "https://203.0.113.10/"}, Risk: agent.RiskIntrusive,
	}
	if _, err := gate.Admit(ctx, action, "alice"); !errors.Is(err, safety.ErrPendingApproval) {
		t.Fatalf("initial admission err=%v", err)
	}
	if _, err := approvals.Decide(ctx, "bob", action.ID, true, "approved test scan"); err != nil {
		t.Fatal(err)
	}
	admitted, err := gate.Admit(ctx, action, "alice")
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(engine, guard, ev)
	if err != nil {
		t.Fatal(err)
	}
	return service, admitted, clock, audit
}

func validSession() domain.Config {
	return domain.Config{
		Scheme:       domain.SchemeBearer,
		Credentials:  []domain.CredentialBinding{{Name: "token", Reference: "vault-token"}},
		LoginRequest: domain.Request{Method: "GET", Path: "/login"},
		CheckRequest: domain.Request{Method: "GET", Path: "/live"},
		Success:      domain.SuccessSignal{StatusCode: 200},
	}
}

func TestExecuteAuthorizesEveryRequest(t *testing.T) {
	engine := &authorizingEngine{requests: []ports.DASTRequest{
		{Method: "GET", URL: "https://203.0.113.10/login"},
		{Method: "GET", URL: "https://203.0.113.10/live"},
		{Method: "GET", URL: "https://203.0.113.10/one"},
	}}
	service, admitted, _, audit := sessionFixture(t, engine)
	if _, err := service.ExecuteWithBinding(context.Background(), admitted, testHelperBin, testConfigDigest, validSession(), []dastsurface.Request{{Method: "GET", URL: "https://203.0.113.10/one"}}); err != nil {
		t.Fatal(err)
	}
	authorized := 0
	for _, entry := range audit.entries {
		if entry.Metadata["method"] != "" {
			authorized++
		}
	}
	if authorized != len(engine.requests) {
		t.Fatalf("per-request authorizations=%d want=%d audit=%+v", authorized, len(engine.requests), audit.entries)
	}
}

func TestExecuteRejectsOriginAndWindowChanges(t *testing.T) {
	for name, configure := range map[string]func(*authorizingEngine, *testClock){
		"origin": func(engine *authorizingEngine, _ *testClock) {
			engine.requests = []ports.DASTRequest{{Method: "GET", URL: "https://outside.example/"}}
		},
		"window": func(engine *authorizingEngine, clock *testClock) {
			engine.requests = []ports.DASTRequest{{Method: "GET", URL: "https://203.0.113.10/one"}, {Method: "GET", URL: "https://203.0.113.10/two"}}
			engine.before = func(i int) {
				if i == 1 {
					clock.now = clock.now.Add(2 * time.Hour)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			engine := &authorizingEngine{}
			service, admitted, clock, _ := sessionFixture(t, engine)
			configure(engine, clock)
			if _, err := service.ExecuteWithBinding(context.Background(), admitted, testHelperBin, testConfigDigest, validSession(), nil); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("Execute err=%v", err)
			}
		})
	}
}
