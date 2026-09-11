package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	findingsuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findings"
	ownershipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ownershipHTTPClock struct{}

func (ownershipHTTPClock) Now() time.Time { return time.Now().UTC() }

type ownershipHTTPIDs struct{ n atomic.Int64 }

func (i *ownershipHTTPIDs) NewID() shared.ID {
	return shared.ID(fmt.Sprintf("ownership-http-%06d", i.n.Add(1)))
}

// Real migrations, real router/use cases, and a separate runtime role that does
// not own tables and cannot bypass RLS. This is intentionally not a memory fake.
func ownershipHTTPPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("SYNAPSE_TEST_DB_DSN required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("own_http_%d", time.Now().UnixNano())
	owner, runtime := name+"_owner", name+"_runtime"
	quote := func(v string) string { return pgx.Identifier{v}.Sanitize() }
	for _, role := range []string{owner, runtime} {
		if _, err := admin.Exec(ctx, `CREATE ROLE `+quote(role)+` LOGIN PASSWORD 'ownership-test' NOSUPERUSER NOBYPASSRLS`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quote(name)+` OWNER `+quote(owner)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := admin.Exec(ctx, `DROP DATABASE `+quote(name)+` WITH (FORCE)`)
		if err != nil {
			t.Error(err)
		}
		for _, role := range []string{runtime, owner} {
			if _, err := admin.Exec(ctx, `DROP ROLE `+quote(role)); err != nil {
				t.Error(err)
			}
		}
		_ = admin.Close(ctx)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	u.RawPath = ""
	u.User = url.UserPassword(owner, "ownership-test")
	if err := postgres.Migrate(ctx, u.String()); err != nil {
		t.Fatal(err)
	}
	ownerConn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{"USAGE ON SCHEMA public", "SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public", "USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public"} {
		if _, err := ownerConn.Exec(ctx, `GRANT `+grant+` TO `+quote(runtime)); err != nil {
			t.Fatal(err)
		}
	}
	_ = ownerConn.Close(ctx)
	u.User = url.UserPassword(runtime, "ownership-test")
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := postgres.CheckRLSRuntimeRole(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestHostileHarnessOwnershipPostgres(t *testing.T) {
	pool := ownershipHTTPPool(t)
	ctx := shared.WithTenant(context.Background(), "own-a")
	clock := ownershipHTTPClock{}
	ids := &ownershipHTTPIDs{}
	audit := postgres.NewAuditLog(pool)
	repo, err := postgres.NewOwnershipRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	findings := postgres.NewFindingRepository(pool)
	svc, err := ownershipuc.NewService(repo, repo, findings, postgres.NewTenantTransactionRunner(pool), audit, clock, ids, "observe", false)
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsuc.NewService(findings, nil, nil, audit, clock, ids)
	fs.SetAssigneeWriter(svc)
	rt := &Router{log: discardLog(), eng: enguc.NewService(postgres.NewEngagementRepository(pool), clock, ids, audit), findings: fs}
	rt.SetOwnership(svc, "observe", "")
	routes := rt.routes()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('own-a','A'),('own-b','B'); INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('alice','Alice','admin','own-http-a','own-a'),('bob','Bob','consultant','own-http-b','own-a'),('reader','Reader','readonly','own-http-r','own-a'),('outsider','Other','admin','own-http-o','own-b')`); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own-a", "own-b"} {
		if err := postgres.WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'Public engagement')`, tenant+"-eng", tenant); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES($3,$2,$1,'Visible'),($4,$2,$1,'Second')`, tenant+"-eng", tenant, tenant+"-f1", tenant+"-f2")
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Hidden project scan contexts must not appear in either inbox rows or counts.
	if err := postgres.WithTenant(ctx, pool, "own-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,key,source_binding) VALUES('hidden-project','own-a','Hidden','hidden','{}'); INSERT INTO engagements(id,tenant_id,name,project_id) VALUES('hidden-eng','own-a','Hidden','hidden-project'); INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES('hidden-finding','own-a','hidden-eng','Never expose')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := postgres.WithTenant(ctx, pool, "own-a", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sla_policies(tenant_id,config_version,config,sha256,created_by,created_at) VALUES('own-a','http-policy','{}',repeat('a',64),'alice',now())`); err != nil {
			return err
		}
		for _, pair := range [][2]string{{"own-a-eng", "own-a-f1"}, {"hidden-eng", "hidden-finding"}} {
			if _, err := tx.Exec(ctx, `INSERT INTO sla_assessments(tenant_id,id,engagement_id,finding_id,inputs,result,input_hash,config_hash,config_version,tier,score,mitigate_by,remediate_by,deadline_anchor_at,assessed_at,created_at) VALUES('own-a',$2,$1,$2,'{}','{"remediate_by":"2026-01-02T00:00:00Z"}',repeat('b',64),repeat('a',64),'http-policy','high',60,'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',now())`, pair[0], pair[1]); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sla_current_assessments(tenant_id,engagement_id,finding_id,assessment_id,updated_at) VALUES('own-a',$1,$2,$2,now())`, pair[0], pair[1]); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sla_lifecycles(tenant_id,engagement_id,finding_id,assessment_id,status,version,updated_by,updated_at) VALUES('own-a',$1,$2,$2,'open',1,'alice',now())`, pair[0], pair[1]); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request := func(actor, role, tenant, method, path, key string, body any) *httptest.ResponseRecorder {
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(string(data)))
		req.Header.Set("Idempotency-Key", key)
		// Conflicting ambient tenant cannot override the authenticated principal.
		c := context.WithValue(shared.WithTenant(context.Background(), "own-b"), principalKey, Principal{ID: actor, Role: role, TenantID: tenant})
		req = req.WithContext(c)
		rr := httptest.NewRecorder()
		routes.ServeHTTP(rr, req)
		return rr
	}
	call := func(method, path, key string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		rr := request("alice", "admin", "own-a", method, path, key, body)
		if rr.Code != status {
			t.Fatalf("%s %s: %d want %d: %s", method, path, rr.Code, status, rr.Body.String())
		}
		return rr
	}
	var team ownership.Team
	_ = json.Unmarshal(call("POST", "/api/v1/ownership/teams", "", map[string]any{"slug": "payments", "name": "Payments"}, 201).Body.Bytes(), &team)
	call("PUT", "/api/v1/ownership/teams/"+team.ID.String()+"/members/bob", "", map[string]int{"revision": 1}, 204)
	call("PUT", "/api/v1/ownership/teams/"+team.ID.String()+"/members/reader", "", map[string]int{"revision": 1}, 409)
	call("PUT", "/api/v1/ownership/teams/"+team.ID.String()+"/members/outsider", "", map[string]int{"revision": 2}, 404)
	// Owner tokens are bounded separately from IDs; a valid long token must be
	// usable as the continuation position rather than trapping pagination.
	ownerToken := "@org/" + strings.Repeat("a", 230)
	mapping := map[string]any{"engagement_id": "own-a-eng", "mapping": ownership.Mapping{Repository: "repo", Owner: ownerToken, TeamID: team.ID}, "revision": 1}
	call("PUT", "/api/v1/ownership/mappings", "", mapping, 204)
	mapping["mapping"] = ownership.Mapping{Repository: "repo", Owner: ownerToken + "b", TeamID: team.ID}
	call("PUT", "/api/v1/ownership/mappings", "", mapping, 204)
	call("GET", "/api/v1/ownership/mappings?engagement_id=own-a-eng", "", nil, 400)
	mappingPath := "/api/v1/ownership/mappings?engagement_id=own-a-eng&repository=repo&limit=1"
	var mappingPage ownershipList[ports.OwnershipMapping]
	_ = json.Unmarshal(call("GET", mappingPath, "", nil, 200).Body.Bytes(), &mappingPage)
	if len(mappingPage.Items) != 1 || mappingPage.Next == "" {
		t.Fatalf("mapping pagination: %+v", mappingPage)
	}
	call("GET", mappingPath+"&cursor="+url.QueryEscape(mappingPage.Next), "", nil, 200)
	mapping["revision"] = 2
	call("PUT", "/api/v1/ownership/mappings", "", mapping, 204)
	call("PUT", "/api/v1/ownership/mappings", "", mapping, 409)
	call("DELETE", "/api/v1/ownership/mappings", "", mapping, 204)
	for _, tenant := range []string{"own-a", "own-b"} {
		if err := postgres.WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO fleet_business_services(id,tenant_id,name,owner,key) VALUES($1,$2,'Service','Free-text owner',$1)`, tenant+"-asset", tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	assetMap := ports.OwnershipAssetMapping{Mapping: ownership.AssetMapping{AssetID: "own-b-asset", TeamID: team.ID}, Revision: 1}
	call("PUT", "/api/v1/ownership/asset-mappings", "", assetMap, 404)
	assetMap.Mapping.AssetID = "own-a-asset"
	call("PUT", "/api/v1/ownership/asset-mappings", "", assetMap, 204)
	call("GET", "/api/v1/ownership/asset-mappings", "", nil, 200)
	call("DELETE", "/api/v1/ownership/asset-mappings", "", assetMap, 204)
	for _, p := range []string{"/api/v1/ownership/policies?engagement_id=own-b-eng", "/api/v1/ownership/snapshots?engagement_id=hidden-eng", "/api/v1/engagements/hidden-eng/findings/hidden-finding/ownership", "/api/v1/engagements/own-b-eng/findings/own-b-f1/ownership/history"} {
		call("GET", p, "", nil, 404)
	}
	var inbox ports.OwnershipInboxPage
	_ = json.Unmarshal(call("GET", "/api/v1/ownership/findings?limit=1", "", nil, 200).Body.Bytes(), &inbox)
	if inbox.Total != 2 || len(inbox.Items) != 1 || inbox.Next == "" {
		t.Fatalf("inbox %+v", inbox)
	}
	page := call("GET", "/api/v1/ownership/findings?limit=1&cursor="+url.QueryEscape(inbox.Next), "", nil, 200)
	var next ports.OwnershipInboxPage
	_ = json.Unmarshal(page.Body.Bytes(), &next)
	if len(next.Items) != 1 || next.Items[0].ID == inbox.Items[0].ID || next.Total != 2 {
		t.Fatalf("pagination %+v", next)
	}
	call("GET", "/api/v1/ownership/findings?limit=1&severity=high&cursor="+url.QueryEscape(inbox.Next), "", nil, 400)
	var due ports.OwnershipInboxPage
	_ = json.Unmarshal(call("GET", "/api/v1/ownership/findings?sla_status=open&due_before=2026-02-01T00:00:00Z", "", nil, 200).Body.Bytes(), &due)
	if due.Total != 1 || len(due.Items) != 1 || due.Items[0].ID != "own-a-f1" || due.Items[0].SLAStatus != "open" || due.Items[0].RemediateBy == nil || due.Items[0].RemediateBy.UTC().Format(time.RFC3339) != "2026-01-02T00:00:00Z" {
		t.Fatalf("SLA count/visibility or persisted deadline: %+v", due)
	}
	for _, query := range []string{"?tenant_id=own-b", "?limit=201", "?limit=1&limit=2", "?cursor=invalid", "?my_teams=nope", "?sla_status=oops"} {
		call("GET", "/api/v1/ownership/findings"+query, "", nil, 400)
	}
	for _, role := range []string{"readonly", "consultant", "reviewer", "member", "agent", "mcp", "unknown"} {
		rr := request("alice", role, "own-a", "POST", "/api/v1/ownership/teams", "", map[string]string{"name": "forbidden"})
		if rr.Code != 403 {
			t.Fatalf("role=%s status=%d", role, rr.Code)
		}
	}
	call("POST", "/api/v1/ownership/teams", "", map[string]any{"name": "Attack", "slug": "attack", "tenant_id": "own-b"}, 400)
	input := ownershipuc.AssignmentInput{EngagementID: "own-a-eng", FindingID: "own-a-f1", Action: "assign", TeamID: team.ID, AssigneeID: "bob", FindingVersion: 1}
	foreign := input
	foreign.EngagementID = "own-b-eng"
	foreign.FindingID = "own-b-f1"
	hidden := input
	hidden.EngagementID = "hidden-eng"
	hidden.FindingID = "hidden-finding"
	body := map[string]any{"items": []ownershipuc.AssignmentInput{input, foreign, hidden}}
	rr := call("POST", "/api/v1/ownership/bulk", "bulk-key", body, 200)
	var result struct {
		Items []ownershipuc.BulkResult `json:"items"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &result)
	if len(result.Items) != 3 || result.Items[0].Status != 200 || result.Items[1].Status != 404 || result.Items[2].Status != 404 {
		t.Fatalf("bulk %s", rr.Body.String())
	}
	replay := call("POST", "/api/v1/ownership/bulk", "bulk-key", body, 200)
	if replay.Body.String() != rr.Body.String() {
		t.Fatal("bulk replay changed result")
	}
	changed := input
	changed.TeamID = "different"
	call("POST", "/api/v1/ownership/bulk", "bulk-key", map[string]any{"items": []ownershipuc.AssignmentInput{changed}}, 409)
	mine := request("bob", "consultant", "own-a", "GET", "/api/v1/ownership/findings?mine=true", "", nil)
	if mine.Code != 200 || !strings.Contains(mine.Body.String(), "own-a-f1") {
		t.Fatalf("mine %s", mine.Body.String())
	}
	myTeams := request("bob", "consultant", "own-a", "GET", "/api/v1/ownership/findings?my_teams=true", "", nil)
	if myTeams.Code != 200 || !strings.Contains(myTeams.Body.String(), `"total":1`) || !strings.Contains(myTeams.Body.String(), "own-a-f1") {
		t.Fatalf("my teams %s", myTeams.Body.String())
	}
	denied := request("reader", "readonly", "own-a", "POST", "/api/v1/ownership/bulk", "reader", body)
	if denied.Code != 403 {
		t.Fatal("readonly mutation accepted")
	}
	// Transfer preserves an eligible assignee, and never silently drops an owner.
	var ops, emptyTeam ownership.Team
	_ = json.Unmarshal(call("POST", "/api/v1/ownership/teams", "", map[string]string{"slug": "ops", "name": "Ops"}, 201).Body.Bytes(), &ops)
	_ = json.Unmarshal(call("POST", "/api/v1/ownership/teams", "", map[string]string{"slug": "empty", "name": "Empty"}, 201).Body.Bytes(), &emptyTeam)
	call("PUT", "/api/v1/ownership/teams/"+ops.ID.String()+"/members/bob", "", map[string]int{"revision": 1}, 204)
	transfer := ownershipuc.AssignmentInput{Action: "transfer", TeamID: ops.ID, FindingVersion: 2, OwnershipRevision: 1, ManualGeneration: 1}
	ownPath := "/api/v1/engagements/own-a-eng/findings/own-a-f1/ownership"
	transferred := call("POST", ownPath, "transfer", transfer, 200)
	var decision ownership.Decision
	_ = json.Unmarshal(transferred.Body.Bytes(), &decision)
	if decision.After.AssigneeID != "bob" || decision.After.TeamID != ops.ID {
		t.Fatalf("transfer dropped owner: %s", transferred.Body.String())
	}
	if call("POST", ownPath, "transfer", transfer, 200).Body.String() != transferred.Body.String() {
		t.Fatal("transfer replay changed decision")
	}
	transfer.TeamID, transfer.FindingVersion, transfer.OwnershipRevision, transfer.ManualGeneration = emptyTeam.ID, 3, 2, 2
	call("POST", ownPath, "transfer-empty", transfer, 409)
	transfer.ClearAssignee = true
	cleared := call("POST", ownPath, "transfer-clear", transfer, 200)
	decision = ownership.Decision{}
	_ = json.Unmarshal(cleared.Body.Bytes(), &decision)
	if decision.After.AssigneeID != "" || decision.After.LegacyAssignee != "" || decision.After.Mode != "manual" {
		t.Fatalf("explicit clear failed: %s", cleared.Body.String())
	}
	transfer.AssigneeID = "bob"
	call("POST", ownPath, "invalid-clear", transfer, 400)
	// Claim cannot substitute another user, and requires membership of the current team.
	claim := ownershipuc.AssignmentInput{Action: "claim", TeamID: emptyTeam.ID, FindingVersion: 4, OwnershipRevision: 3, ManualGeneration: 3}
	call("POST", ownPath, "claim-nonmember", claim, 400)
	call("PUT", "/api/v1/ownership/teams/"+emptyTeam.ID.String()+"/members/alice", "", map[string]int{"revision": 1}, 204)
	claim.AssigneeID = "bob"
	call("POST", ownPath, "claim-other", claim, 400)
	claim.AssigneeID = ""
	call("POST", ownPath, "claim", claim, 200)
	call("POST", ownPath, "release", ownershipuc.AssignmentInput{Action: "release", FindingVersion: 5, OwnershipRevision: 4, ManualGeneration: 4}, 503)
	// Same-value legacy clears still advance version and preserve manual protection.
	legacyPath := "/api/v1/engagements/own-a-eng/findings/own-a-f2/assignee"
	call("PUT", legacyPath, "", map[string]any{"assignee": "", "version": 1}, 200)
	call("PUT", legacyPath, "", map[string]any{"assignee": "", "version": 1}, 409)
	current, err := repo.GetAssignment(ctx, "own-a-eng", "own-a-f2")
	if err != nil || current.FindingVersion != 2 || current.Assignment.Mode != "manual" || current.Assignment.ManualGeneration != 1 {
		t.Fatalf("legacy %+v %v", current, err)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses <- request("bob", "consultant", "own-a", "PUT", legacyPath, "", map[string]any{"assignee": "Free text owner", "version": 2}).Code
		}()
	}
	wg.Wait()
	close(statuses)
	sum := 0
	for code := range statuses {
		sum += code
	}
	if sum != 609 {
		t.Fatalf("CAS statuses sum=%d", sum)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET disabled=true WHERE id='bob'`); err != nil {
		t.Fatal(err)
	}
	denied = request("bob", "admin", "own-a", "POST", "/api/v1/ownership/teams", "", map[string]string{"name": "Disabled", "slug": "disabled"})
	if denied.Code != 403 {
		t.Fatalf("disabled user accepted %s", denied.Body.String())
	}
	// Source content/trust/actor are server-controlled. Approval creates a new snapshot.
	snapBody := ownershipuc.SnapshotInput{EngagementID: "own-a-eng", Repository: "repo", SourceRevision: "git:" + strings.Repeat("1", 40), FilePath: "CODEOWNERS", Content: "* @org/pay"}
	var snapshot ownershipuc.SnapshotView
	_ = json.Unmarshal(call("POST", "/api/v1/ownership/snapshots", "", snapBody, 201).Body.Bytes(), &snapshot)
	if snapshot.Trust != "untrusted" || snapshot.Hash == "" {
		t.Fatalf("snapshot %+v", snapshot)
	}
	call("POST", "/api/v1/ownership/snapshots/"+snapshot.ID.String()+"/approve", "", map[string]any{"content_hash": "bad"}, 409)
	var approved ownershipuc.SnapshotView
	_ = json.Unmarshal(call("POST", "/api/v1/ownership/snapshots/"+snapshot.ID.String()+"/approve", "", map[string]any{"content_hash": snapshot.Hash}, 201).Body.Bytes(), &approved)
	if approved.ID == snapshot.ID || approved.Trust != "admin_import" || approved.ApprovedBy != "alice" {
		t.Fatalf("approval %+v", approved)
	}
	policy := ownershipuc.PolicyInput{EngagementID: "own-a-eng", Repository: "repo", Version: 1, SnapshotID: approved.ID, Mappings: []ownership.Mapping{{Repository: "repo", Owner: "@org/pay", TeamID: team.ID}}}
	var pv struct {
		Policy ownership.PolicyVersion `json:"policy"`
		Hash   string                  `json:"content_hash"`
	}
	_ = json.Unmarshal(call("POST", "/api/v1/ownership/policies", "", policy, 201).Body.Bytes(), &pv)
	policyPath := "/api/v1/ownership/policies/" + pv.Policy.PolicyID.String()
	call("POST", policyPath+"/activate", "", map[string]any{"version": 1, "revision": 1, "content_hash": pv.Hash}, 204)
	call("POST", policyPath+"/activate", "", map[string]any{"version": 1, "revision": 1, "content_hash": pv.Hash}, 409)
	call("POST", policyPath+"/preview", "preview", map[string]any{"version": 1, "policy_revision": 2, "policy_hash": pv.Hash, "filter": map[string]any{}}, 503)
	call("POST", policyPath+"/preview", "preview", map[string]any{"version": 1, "policy_revision": 2, "policy_hash": pv.Hash, "filter": map[string]any{"engagement_id": "hidden-eng"}}, 400)
	other := request("outsider", "admin", "own-b", "GET", policyPath, "", nil)
	if other.Code != 404 {
		t.Fatalf("foreign policy %d", other.Code)
	}
	cap := call("GET", "/api/v1/ownership/capabilities", "", nil, 200)
	if !strings.Contains(cap.Body.String(), `"routing_available":false`) {
		t.Fatal("invented worker capability")
	}
	run := ports.OwnershipRun{ID: "run", EngagementID: "own-a-eng", PolicyID: pv.Policy.PolicyID, PolicyVersion: 1, PolicyRevision: 2, PolicyHash: pv.Hash, Mode: "preview", State: "queued", Revision: 1, Cutoff: clock.Now(), Total: 0, Filter: json.RawMessage(`{}`), CreatedAt: clock.Now()}
	if err := repo.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	call("GET", "/api/v1/ownership/runs/run/items", "", nil, 200)
	call("POST", "/api/v1/ownership/runs/run/cancel", "", map[string]int{"revision": 1}, 204)
	call("POST", "/api/v1/ownership/runs/run/cancel", "", map[string]int{"revision": 1}, 409)
	// Legacy bootstrap users with empty tenant IDs use the default tenant, even
	// when a conflicting ambient context and other tenants' data are present.
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('bootstrap','Bootstrap','admin','own-http-default','')`); err != nil {
		t.Fatal(err)
	}
	if err := postgres.WithTenant(ctx, pool, "default", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES('default-eng','default','Default'); INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES('default-finding','default','default-eng','Default finding')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defaultInbox := request("bootstrap", "admin", "", "GET", "/api/v1/ownership/findings", "", nil)
	var defaultPage ports.OwnershipInboxPage
	_ = json.Unmarshal(defaultInbox.Body.Bytes(), &defaultPage)
	if defaultInbox.Code != 200 || defaultPage.Total != 1 || len(defaultPage.Items) != 1 || defaultPage.Items[0].ID != "default-finding" {
		t.Fatalf("default tenant isolation: %d %s", defaultInbox.Code, defaultInbox.Body.String())
	}
}

func TestOwnershipCapabilitiesDisabledAndMemory(t *testing.T) {
	for _, tc := range []struct{ mode, reason string }{{"off", "disabled"}, {"observe", "postgres_required"}} {
		rt := &Router{log: discardLog()}
		rt.SetOwnership(nil, tc.mode, tc.reason)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ownership/capabilities", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "admin", Role: "admin"}))
		rr := httptest.NewRecorder()
		rt.routes().ServeHTTP(rr, req)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), tc.reason) || !strings.Contains(rr.Body.String(), `"enabled":false`) {
			t.Fatalf("capability %s", rr.Body.String())
		}
		req = httptest.NewRequest(http.MethodGet, "/api/v1/ownership/teams", nil)
		rr = httptest.NewRecorder()
		rt.routes().ServeHTTP(rr, req)
		if rr.Code != 404 {
			t.Fatal("disabled routes registered")
		}
	}
}
