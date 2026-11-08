package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/issue"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualityprofile"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	rls817Role    = "synapse_rls817_runtime"
	rls817TenantA = shared.ID("rls817-tenant-a")
	rls817TenantB = shared.ID("rls817-tenant-b")
	rls817EngA    = shared.ID("rls817-eng-a")
	rls817EngB    = shared.ID("rls817-eng-b")
)

// rls817Password is generated per run rather than written into the source. The role exists only for
// the length of one test, so a literal buys nothing, and a checked-in password string is a finding
// for any credential scanner pointed at this repository whatever the value actually protects.
var rls817Password = func() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("generate rls test role password: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}()

// rls817Fixture holds an owner pool (the dev superuser, which bypasses RLS and is therefore only
// used for setup and teardown) and a runtime pool that connects as a NOSUPERUSER NOBYPASSRLS role
// holding exactly the privileges GrantRuntimePrivileges grants in production. Every assertion
// about isolation or about the converted stores runs on the runtime pool, or it proves nothing:
// RLS is bypassed entirely by SUPERUSER and BYPASSRLS regardless of FORCE ROW LEVEL SECURITY.
type rls817Fixture struct {
	owner   *pgxpool.Pool
	runtime *pgxpool.Pool
}

func newRLS817Fixture(t *testing.T) *rls817Fixture {
	t.Helper()
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	owner, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect owner: %v", err)
	}

	runtimeDSN := rls817RuntimeDSN(t, dsn)
	// Roles are cluster-wide, not per-database, so a role left behind by an interrupted run (or by
	// a run against a sibling database on the same server) must not fail this one. Create it only
	// when absent, then assert the attributes either way.
	if _, err := owner.Exec(ctx, fmt.Sprintf(`DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
        CREATE ROLE %[1]s;
    END IF;
    ALTER ROLE %[1]s NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE LOGIN PASSWORD '%[2]s';
END $$;`, rls817Role, rls817Password)); err != nil {
		owner.Close()
		t.Fatalf("create runtime role: %v", err)
	}
	if err := GrantRuntimePrivileges(ctx, dsn, runtimeDSN); err != nil {
		owner.Close()
		t.Fatalf("grant runtime privileges: %v", err)
	}
	runtime, err := Connect(ctx, runtimeDSN)
	if err != nil {
		owner.Close()
		t.Fatalf("connect runtime: %v", err)
	}
	// Without this the whole suite is vacuous: a role that bypasses RLS satisfies every assertion.
	if err := CheckRLSRuntimeRole(ctx, runtime); err != nil {
		runtime.Close()
		owner.Close()
		t.Fatalf("runtime role cannot enforce RLS: %v", err)
	}

	fixture := &rls817Fixture{owner: owner, runtime: runtime}
	fixture.reset(t)
	t.Cleanup(func() {
		fixture.reset(t)
		runtime.Close()
		bg := context.Background()
		// Best effort: DROP ROLE fails while the role holds grants in another database of the same
		// cluster, and the create path above is written to tolerate finding it still there.
		_, _ = owner.Exec(bg, fmt.Sprintf(`DROP OWNED BY %s`, rls817Role))
		_, _ = owner.Exec(bg, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, rls817Role))
		owner.Close()
	})
	fixture.seedTenants(t)
	return fixture
}

// rls817RuntimeDSN rewrites the owner DSN to connect as the restricted runtime role.
func rls817RuntimeDSN(t *testing.T, dsn string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	parsed.User = url.UserPassword(rls817Role, rls817Password)
	return parsed.String()
}

// reset removes everything this fixture seeds, in dependency order, as the owner.
func (f *rls817Fixture) reset(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	tenants := []string{rls817TenantA.String(), rls817TenantB.String()}
	_, _ = f.owner.Exec(ctx, `DELETE FROM agent_messages WHERE session_id IN (SELECT id FROM agent_sessions WHERE tenant_id = ANY($1))`, tenants)
	for _, table := range []string{
		"project_issue_review_events", "project_hotspot_review_events", "project_analysis_hotspots",
		"project_issues", "project_hotspots", "project_analyses", "projects",
		"quality_gates", "quality_profiles", "threat_models",
		"agent_plans", "agent_approvals", "agent_sessions",
	} {
		_, _ = f.owner.Exec(ctx, fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = ANY($1)`, table), tenants)
	}
	// The quality-gate mutator commits an audit record with each write, and audit_log is
	// append-only by trigger. Leaving those rows behind would block migration 0085's Down
	// direction for every other migration test in this package, so lift the guard exactly the way
	// migration 0066 does and restore it immediately.
	if _, err := f.owner.Exec(ctx, `ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only`); err == nil {
		_, _ = f.owner.Exec(ctx, `DELETE FROM audit_log WHERE tenant_id = ANY($1)`, tenants)
		if _, err := f.owner.Exec(ctx, `ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only`); err != nil {
			t.Fatalf("restore audit_log append-only trigger: %v", err)
		}
	}
	_, _ = f.owner.Exec(ctx, `DELETE FROM engagements WHERE tenant_id = ANY($1)`, tenants)
	_, _ = f.owner.Exec(ctx, `DELETE FROM tenants WHERE id = ANY($1)`, tenants)
}

func (f *rls817Fixture) seedTenants(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, pair := range []struct{ tenant, eng shared.ID }{{rls817TenantA, rls817EngA}, {rls817TenantB, rls817EngB}} {
		if _, err := f.owner.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT DO NOTHING`, pair.tenant.String()); err != nil {
			t.Fatalf("seed tenant %s: %v", pair.tenant, err)
		}
		if _, err := f.owner.Exec(ctx, `INSERT INTO engagements (id, tenant_id, name) VALUES ($1,$2,$1) ON CONFLICT (id) DO NOTHING`, pair.eng.String(), pair.tenant.String()); err != nil {
			t.Fatalf("seed engagement %s: %v", pair.eng, err)
		}
	}
}

// TestTenantRLSIsolatesProjectAndAgentTables proves the database, not the Go code, is what stops a
// cross-tenant read or write on the tables migration 0129 protects. Every statement runs on the
// restricted runtime pool. For each table it asserts three things: an intentionally UNSCOPED
// select bound to tenant A returns only A's rows, an update aimed at B's primary key from tenant A
// touches nothing, and a query with no tenant bound sees nothing at all (the empty tenant is DENY,
// not a default partition).
func TestTenantRLSIsolatesProjectAndAgentTables(t *testing.T) {
	f := newRLS817Fixture(t)
	ctx := context.Background()

	// Seed one row per tenant through the runtime pool, which also proves WITH CHECK admits a
	// write that matches the bound tenant.
	seed := []struct {
		tenant shared.ID
		eng    shared.ID
		suffix string
	}{{rls817TenantA, rls817EngA, "a"}, {rls817TenantB, rls817EngB, "b"}}
	for _, s := range seed {
		if err := WithTenant(ctx, f.runtime, s.tenant.String(), func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding, default_profile_by_lang, gate_id, created_at, updated_at, created_by, updated_by)
				VALUES ($1,$2,$3,$4,'{}'::jsonb,'{}'::jsonb,'',now(),now(),'','')`,
				"rls817-project-"+s.suffix, s.tenant.String(), "p"+s.suffix, "rls817-key-"+s.suffix); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO quality_gates (tenant_id, key, name, conditions) VALUES ($1,$2,$3,'[]'::jsonb)`,
				s.tenant.String(), "rls817-gate-"+s.suffix, "g"+s.suffix); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO agent_approvals (action_id, tenant_id, session_id, engagement_id, tool, action, risk, proposed_at, decision_state)
				VALUES ($1,$2,'sess','`+s.eng.String()+`','t','a','read',now(),'pending')`,
				"rls817-action-"+s.suffix, s.tenant.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO threat_models (engagement_id, tenant_id, data) VALUES ($1,$2,'{}'::jsonb)`,
				s.eng.String(), s.tenant.String())
			return err
		}); err != nil {
			t.Fatalf("seed tenant %s: %v", s.tenant, err)
		}
	}

	cases := []struct {
		table       string
		countSQL    string
		updateBSQL  string
		updateBArgs []any
	}{
		{
			table:       "projects",
			countSQL:    `SELECT count(*) FROM projects`,
			updateBSQL:  `UPDATE projects SET name='stolen' WHERE id=$1`,
			updateBArgs: []any{"rls817-project-b"},
		},
		{
			table:       "quality_gates",
			countSQL:    `SELECT count(*) FROM quality_gates`,
			updateBSQL:  `UPDATE quality_gates SET name='stolen' WHERE key=$1`,
			updateBArgs: []any{"rls817-gate-b"},
		},
		{
			table:       "agent_approvals",
			countSQL:    `SELECT count(*) FROM agent_approvals`,
			updateBSQL:  `UPDATE agent_approvals SET decision_state='approved', decided_by='attacker' WHERE action_id=$1`,
			updateBArgs: []any{"rls817-action-b"},
		},
		{
			table:       "threat_models",
			countSQL:    `SELECT count(*) FROM threat_models`,
			updateBSQL:  `UPDATE threat_models SET data='{"stolen":true}'::jsonb WHERE engagement_id=$1`,
			updateBArgs: []any{rls817EngB.String()},
		},
	}

	for _, tc := range cases {
		t.Run(tc.table, func(t *testing.T) {
			var seen int
			if err := WithTenant(ctx, f.runtime, rls817TenantA.String(), func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, tc.countSQL).Scan(&seen)
			}); err != nil {
				t.Fatalf("scoped count: %v", err)
			}
			if seen != 1 {
				t.Fatalf("tenant A saw %d rows via an unscoped query, want only its own 1", seen)
			}

			var affected int64
			if err := WithTenant(ctx, f.runtime, rls817TenantA.String(), func(tx pgx.Tx) error {
				tag, err := tx.Exec(ctx, tc.updateBSQL, tc.updateBArgs...)
				affected = tag.RowsAffected()
				return err
			}); err != nil {
				t.Fatalf("cross-tenant update: %v", err)
			}
			if affected != 0 {
				t.Fatalf("tenant A updated %d of tenant B's rows", affected)
			}

			var unbound int
			if err := WithTenant(ctx, f.runtime, "", func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, tc.countSQL).Scan(&unbound)
			}); err != nil {
				t.Fatalf("unbound count: %v", err)
			}
			if unbound != 0 {
				t.Fatalf("a query with no tenant bound saw %d rows, want 0 (empty tenant is DENY)", unbound)
			}
		})
	}

	// Tenant B's rows survived the attempted writes untouched.
	var stolen int
	if err := f.owner.QueryRow(ctx, `SELECT count(*) FROM projects WHERE name='stolen'
		UNION ALL SELECT count(*) FROM quality_gates WHERE name='stolen' LIMIT 1`).Scan(&stolen); err != nil {
		t.Fatalf("verify tenant B: %v", err)
	}
	if stolen != 0 {
		t.Fatalf("a cross-tenant update landed after all: %d rows renamed", stolen)
	}
}

// TestConvertedStoresRoundTripUnderRLS is the regression that would have caught "RLS enabled,
// everything returns empty": every store converted for #817 does a create-then-read round trip on
// the restricted runtime pool, under a bound tenant, and must get its row back. Without the
// WithTenant conversion each read here returns zero rows and each write is rejected by WITH CHECK.
func TestConvertedStoresRoundTripUnderRLS(t *testing.T) {
	f := newRLS817Fixture(t)
	pool := f.runtime
	ctx := shared.WithTenant(context.Background(), rls817TenantA)
	tenant := rls817TenantA
	projectID := shared.ID("rls817-rt-project")
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("quality_gate_store", func(t *testing.T) {
		store := NewQualityGateStore(pool)
		gate := qualitygate.Gate{Key: "rls817-gate", Name: "Gate", Conditions: []qualitygate.Condition{{Metric: "bugs", Op: qualitygate.OpLE, Threshold: 0}}}
		if err := store.Create(ctx, tenant, gate); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.Get(ctx, tenant, gate.Key)
		if err != nil || got.Name != "Gate" || len(got.Conditions) != 1 {
			t.Fatalf("get after create returned %+v err=%v", got, err)
		}
		gates, err := store.List(ctx, tenant)
		if err != nil || len(gates) != 1 {
			t.Fatalf("list after create returned %d gates, err=%v", len(gates), err)
		}
		if _, err := store.Get(ctx, rls817TenantB, gate.Key); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("cross-tenant get must be not-found, got %v", err)
		}
		if _, err := store.Get(context.Background(), "", gate.Key); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("empty tenant must fail closed, got %v", err)
		}
	})

	t.Run("quality_profile_store", func(t *testing.T) {
		store := NewQualityProfileStore(pool)
		profile := qualityprofile.Profile{Key: "rls817-profile", Name: "Profile", Language: "go", ActivatedRules: map[string]qualityprofile.RuleActivation{}}
		if err := store.Create(ctx, tenant, profile); err != nil {
			t.Fatalf("create: %v", err)
		}
		got, err := store.Get(ctx, tenant, profile.Key)
		if err != nil || got.Name != "Profile" {
			t.Fatalf("get after create returned %+v err=%v", got, err)
		}
		profiles, err := store.List(ctx, tenant)
		if err != nil || len(profiles) != 1 {
			t.Fatalf("list after create returned %d profiles, err=%v", len(profiles), err)
		}
	})

	t.Run("project_repo", func(t *testing.T) {
		repo := NewProjectRepository(pool)
		p, err := project.New(projectID, tenant, "Round Trip", "rls817-rt", project.SourceBinding{Kind: project.SourceGit, Value: "https://example.com/repo.git"}, nil, "", now)
		if err != nil {
			t.Fatalf("build project: %v", err)
		}
		if err := repo.Create(ctx, p); err != nil {
			t.Fatalf("create: %v", err)
		}
		byKey, err := repo.GetByKey(ctx, tenant, "rls817-rt")
		if err != nil || byKey.ID != projectID {
			t.Fatalf("get by key returned %+v err=%v", byKey, err)
		}
		byID, err := repo.GetByID(ctx, tenant, projectID)
		if err != nil || byID.Key != "rls817-rt" {
			t.Fatalf("get by id returned %+v err=%v", byID, err)
		}
		list, err := repo.List(ctx, tenant)
		if err != nil || len(list) != 1 {
			t.Fatalf("list returned %d projects, err=%v", len(list), err)
		}
		if err := repo.AssignProfile(ctx, tenant, "rls817-rt", "go", "rls817-profile"); err != nil {
			t.Fatalf("assign profile: %v", err)
		}
		if err := repo.UpdateGate(ctx, tenant, "rls817-rt", "rls817-gate"); err != nil {
			t.Fatalf("update gate: %v", err)
		}
		n, err := repo.CountByGate(ctx, tenant, "rls817-gate")
		if err != nil || n != 1 {
			t.Fatalf("count by gate = %d, err=%v", n, err)
		}
		// Tenant B must not see it, and an unbound tenant must fail closed rather than widen.
		if _, err := repo.GetByKey(ctx, rls817TenantB, "rls817-rt"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("cross-tenant get by key must be not-found, got %v", err)
		}
		if _, err := repo.List(context.Background(), ""); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("empty-tenant list must fail closed, got %v", err)
		}
	})

	t.Run("quality_gate_mutator", func(t *testing.T) {
		mutator := NewQualityGateMutator(pool)
		audit := ports.AuditEntry{Actor: "tester", Action: "quality_gate.assign", Target: "rls817-rt", At: now}
		if err := mutator.AssignProjectGate(ctx, tenant, "rls817-rt", "rls817-gate", audit); err != nil {
			t.Fatalf("assign project gate: %v", err)
		}
		managed := qualitygate.Gate{Key: "rls817-managed", Name: "Managed", Conditions: []qualitygate.Condition{{Metric: "bugs", Op: qualitygate.OpLE, Threshold: 1}}}
		if err := mutator.CreateGate(ctx, tenant, managed, ports.AuditEntry{Actor: "tester", Action: "quality_gate.create", Target: managed.Key, At: now}); err != nil {
			t.Fatalf("create gate: %v", err)
		}
		got, err := NewQualityGateStore(pool).Get(ctx, tenant, managed.Key)
		if err != nil || got.Name != "Managed" {
			t.Fatalf("managed gate round trip returned %+v err=%v", got, err)
		}
	})

	t.Run("project_analysis_store", func(t *testing.T) {
		store := NewProjectAnalysisStore(pool)
		analysis := projectanalysis.Analysis{ID: "rls817-analysis-1", TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: now}
		if err := store.SaveWithResult(ctx, analysis, []byte(`{"r":1}`)); err != nil {
			t.Fatalf("save with result: %v", err)
		}
		got, err := store.Get(ctx, tenant, projectID, "rls817-analysis-1")
		if err != nil || got.ID != "rls817-analysis-1" {
			t.Fatalf("get after save returned %+v err=%v", got, err)
		}
		listed, _, err := store.List(ctx, tenant, projectID, "", 10, time.Time{}, "")
		if err != nil || len(listed) != 1 {
			t.Fatalf("list returned %d analyses, err=%v", len(listed), err)
		}
		latest, result, err := store.LatestWithResult(ctx, tenant, projectID, "")
		if err != nil || latest.ID != "rls817-analysis-1" || len(result) == 0 {
			t.Fatalf("latest with result returned %+v result=%q err=%v", latest, result, err)
		}
		byProject, err := store.LatestForProjects(ctx, tenant, []shared.ID{projectID})
		if err != nil || len(byProject) != 1 {
			t.Fatalf("latest for projects returned %d entries, err=%v", len(byProject), err)
		}
		if _, err := store.Get(ctx, rls817TenantB, projectID, "rls817-analysis-1"); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("cross-tenant analysis get must be not-found, got %v", err)
		}
	})

	t.Run("hotspot_and_issue_projections", func(t *testing.T) {
		store := NewProjectAnalysisStore(pool)
		analysis := projectanalysis.Analysis{ID: "rls817-analysis-2", TenantID: tenant.String(), ProjectID: projectID.String(), CreatedAt: now.Add(time.Minute)}
		hot := hotspot.Candidate{Key: "sast:rls817:main.go:1", FindingIdentity: "sast:rls817:main.go:1", RuleKey: "rls817-rule", Title: "hot", Description: "hot", Severity: shared.SeverityHigh, Kind: finding.KindSAST, Location: "main.go:1"}
		iss := issue.Candidate{Key: "sast:rls817-issue:app.go:2", FindingIdentity: "sast:rls817-issue:app.go:2", RuleKey: "rls817-issue-rule", Type: rule.TypeCodeSmell, Title: "smell", Description: "smell", Severity: shared.SeverityLow, Kind: finding.KindSAST, Language: "go", File: "app.go", Location: "app.go:2"}
		if err := store.SaveWithResultAndProjections(ctx, analysis, []byte(`{"r":2}`), []hotspot.Candidate{hot}, []issue.Candidate{iss}); err != nil {
			t.Fatalf("save with projections: %v", err)
		}

		hotspotID := hotspot.DeterministicID(tenant, projectID, hot.Key)
		gotHotspot, err := store.GetHotspot(ctx, tenant, projectID, hotspotID)
		if err != nil || gotHotspot.Title != "hot" {
			t.Fatalf("get hotspot returned %+v err=%v", gotHotspot, err)
		}
		hotPage, err := store.ListHotspots(ctx, tenant, projectID, hotspot.ListFilter{Limit: 10})
		if err != nil || len(hotPage.Items) != 1 || hotPage.Summary.Total != 1 {
			t.Fatalf("list hotspots returned %+v err=%v", hotPage, err)
		}
		analysisPage, summary, err := store.ListAnalysisHotspots(ctx, tenant, projectID, shared.ID(analysis.ID), hotspot.LensOverall, hotspot.ListFilter{Limit: 10})
		if err != nil || len(analysisPage.Items) != 1 || summary.Total != 1 {
			t.Fatalf("list analysis hotspots returned %+v summary=%+v err=%v", analysisPage, summary, err)
		}
		transitioned, event, err := store.TransitionHotspot(ctx, hotspot.TransitionCommand{
			TenantID: tenant, ProjectID: projectID, HotspotID: hotspotID, To: hotspot.StatusAcknowledged,
			Actor: "tester", Rationale: "reviewed", ExpectedVersion: gotHotspot.Version, EventID: "rls817-hotspot-event",
		})
		if err != nil || transitioned.Status != hotspot.StatusAcknowledged {
			t.Fatalf("transition hotspot returned %+v err=%v", transitioned, err)
		}
		history, err := store.HotspotHistory(ctx, tenant, projectID, hotspotID)
		if err != nil || len(history) != 1 || history[0].ID != event.ID {
			t.Fatalf("hotspot history returned %+v err=%v", history, err)
		}

		issueID := issue.DeterministicID(tenant, projectID, iss.Key)
		gotIssue, err := store.GetIssue(ctx, tenant, projectID, issueID)
		if err != nil || gotIssue.Title != "smell" {
			t.Fatalf("get issue returned %+v err=%v", gotIssue, err)
		}
		issuePage, err := store.ListIssues(ctx, tenant, projectID, issue.ListFilter{Limit: 10})
		if err != nil || len(issuePage.Items) != 1 || issuePage.Summary.Total != 1 {
			t.Fatalf("list issues returned %+v err=%v", issuePage, err)
		}
		updatedIssue, issueEvent, err := store.TransitionIssue(ctx, issue.TransitionCommand{
			TenantID: tenant, ProjectID: projectID, IssueID: issueID, To: issue.StatusAccepted,
			Actor: "tester", Rationale: "accepted", ExpectedVersion: gotIssue.Version, EventID: "rls817-issue-event",
		})
		if err != nil || updatedIssue.Status != issue.StatusAccepted {
			t.Fatalf("transition issue returned %+v err=%v", updatedIssue, err)
		}
		issueHistory, err := store.IssueHistory(ctx, tenant, projectID, issueID)
		if err != nil || len(issueHistory) != 1 || issueHistory[0].ID != issueEvent.ID {
			t.Fatalf("issue history returned %+v err=%v", issueHistory, err)
		}
		statuses, err := store.CurrentFindingStatuses(ctx, tenant, projectID, []string{hot.Key, iss.Key})
		if err != nil || len(statuses) != 2 {
			t.Fatalf("current finding statuses returned %+v err=%v", statuses, err)
		}
		resolved, err := store.ResolvedIssueKeys(ctx, tenant, projectID)
		if err != nil || !resolved[iss.Key] {
			t.Fatalf("resolved issue keys returned %+v err=%v", resolved, err)
		}
	})

	t.Run("threat_model_repo", func(t *testing.T) {
		repo := NewThreatModelRepository(pool)
		model := threatmodel.Model{}
		if err := repo.Save(ctx, rls817EngA, tenant, model); err != nil {
			t.Fatalf("save: %v", err)
		}
		_, ok, err := repo.Get(ctx, rls817EngA)
		if err != nil || !ok {
			t.Fatalf("get after save: ok=%v err=%v", ok, err)
		}
		// Tenant B may not read tenant A's engagement model even though it knows the id.
		if _, ok, err := repo.Get(shared.WithTenant(context.Background(), rls817TenantB), rls817EngA); err != nil || ok {
			t.Fatalf("cross-tenant threat model read: ok=%v err=%v", ok, err)
		}
		if _, _, err := repo.Get(context.Background(), rls817EngA); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("unbound threat model read must fail closed, got %v", err)
		}
	})

	t.Run("agent_session_store", func(t *testing.T) {
		store := NewAgentSessionStore(pool)
		session, err := agent.NewSession("rls817-session", rls817EngA, "alice", "goal", "m", "http://localhost:1/v1", "h", now, 1000)
		if err != nil {
			t.Fatalf("build session: %v", err)
		}
		session.TenantID = tenant
		if err := store.SaveSession(ctx, session); err != nil {
			t.Fatalf("save session: %v", err)
		}
		got, err := store.GetSession(ctx, session.ID)
		if err != nil || got.InitiatedBy != "alice" {
			t.Fatalf("get session returned %+v err=%v", got, err)
		}
		listed, err := store.ListByEngagement(ctx, rls817EngA)
		if err != nil || len(listed) != 1 {
			t.Fatalf("list by engagement returned %d sessions, err=%v", len(listed), err)
		}
		if err := store.AppendMessage(ctx, session.ID, 0, agent.Message{Role: agent.RoleUser, Content: "hi"}); err != nil {
			t.Fatalf("append message: %v", err)
		}
		msgs, err := store.Messages(ctx, session.ID)
		if err != nil || len(msgs) != 1 || msgs[0].Content != "hi" {
			t.Fatalf("messages returned %+v err=%v", msgs, err)
		}
		// ListResumable is the cross-tenant sweep: it must still find the session with no
		// ambient tenant, because it fans out over the tenants table itself.
		resumable, err := store.ListResumable(context.Background(), time.Nanosecond, time.Now().Add(time.Hour), 100)
		if err != nil {
			t.Fatalf("list resumable: %v", err)
		}
		found := false
		for _, s := range resumable {
			if s.ID == session.ID && s.TenantID == tenant {
				found = true
			}
		}
		if !found {
			t.Fatalf("cross-tenant resumable sweep did not return the session: %+v", resumable)
		}
	})

	t.Run("approval_store", func(t *testing.T) {
		store := NewApprovalStore(pool)
		action := agent.ProposedAction{
			ID: "rls817-action", SessionID: "rls817-session", EngagementID: rls817EngA, Tool: "start_recon", Action: "recon.naabu",
			Target: engagement.Target{Kind: engagement.TargetIP, Value: "1.1.1.1"}, Argv: []string{"naabu"}, Risk: agent.RiskActive, ProposedAt: now,
		}
		if err := store.Enqueue(ctx, action); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if err := store.Enqueue(ctx, action); err != nil {
			t.Fatalf("idempotent re-enqueue: %v", err)
		}
		pending, err := store.Pending(ctx, rls817EngA)
		if err != nil || len(pending) != 1 {
			t.Fatalf("pending returned %d actions, err=%v", len(pending), err)
		}
		gotAction, decision, err := store.Get(ctx, action.ID)
		if err != nil || gotAction.Tool != "start_recon" || decision.State != agent.ApprovalPending {
			t.Fatalf("get returned %+v %+v err=%v", gotAction, decision, err)
		}
		// The sweeper's fan-out has no ambient tenant and must still find the scope.
		scopes, err := store.EngagementsWithPending(context.Background())
		if err != nil {
			t.Fatalf("engagements with pending: %v", err)
		}
		found := false
		for _, s := range scopes {
			if s.TenantID == tenant && s.EngagementID == rls817EngA {
				found = true
			}
		}
		if !found {
			t.Fatalf("sweeper fan-out missed the pending scope: %+v", scopes)
		}
		// A decision from another tenant must not land on this action.
		if err := store.Decide(shared.WithTenant(context.Background(), rls817TenantB), agent.ApprovalDecision{ActionID: action.ID, State: agent.ApprovalApproved, DecidedBy: "attacker", DecidedAt: now}); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("cross-tenant decide must be not-found, got %v", err)
		}
		if err := store.Decide(ctx, agent.ApprovalDecision{ActionID: action.ID, State: agent.ApprovalApproved, DecidedBy: "bob", DecidedAt: now}); err != nil {
			t.Fatalf("decide: %v", err)
		}
		if err := store.Consume(shared.WithTenant(context.Background(), rls817TenantB), action.ID); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("cross-tenant consume must be not-found, got %v", err)
		}
		if err := store.Consume(ctx, action.ID); err != nil {
			t.Fatalf("consume: %v", err)
		}
	})

	t.Run("agent_plan_store", func(t *testing.T) {
		store := NewAgentPlanStore(pool)
		plan := agent.Plan{ID: "rls817-plan", SessionID: "rls817-session", EngagementID: rls817EngA, Goal: "goal", Status: agent.PlanDraft, Revision: 1, CreatedAt: now, UpdatedAt: now}
		if err := store.CreatePlan(ctx, plan); err != nil {
			t.Fatalf("create plan: %v", err)
		}
		got, ok, err := store.GetBySession(ctx, plan.SessionID)
		if err != nil || !ok || got.Goal != "goal" {
			t.Fatalf("get by session returned %+v ok=%v err=%v", got, ok, err)
		}
		if err := store.SavePlan(ctx, got); err != nil {
			t.Fatalf("save plan: %v", err)
		}
		after, ok, err := store.GetBySession(ctx, plan.SessionID)
		if err != nil || !ok || after.Revision != got.Revision+1 {
			t.Fatalf("save plan did not advance the revision: %+v ok=%v err=%v", after, ok, err)
		}
		// Another tenant cannot see or CAS the plan.
		if _, ok, err := store.GetBySession(shared.WithTenant(context.Background(), rls817TenantB), plan.SessionID); err != nil || ok {
			t.Fatalf("cross-tenant plan read: ok=%v err=%v", ok, err)
		}
		if err := store.SavePlan(shared.WithTenant(context.Background(), rls817TenantB), after); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("cross-tenant plan CAS must conflict, got %v", err)
		}
	})
}
