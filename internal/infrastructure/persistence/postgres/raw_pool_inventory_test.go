package postgres

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// rawPoolException is one reviewed statement site that reaches PostgreSQL on the raw pool rather
// than through WithTenant/WithContextTenant/TenantTransactionRunner. Keys are "file:function".
type rawPoolException struct {
	calls  int
	reason string
}

// Reasons, kept deliberately coarse so a reviewer can see what kind of global access each is.
const (
	rawTenantPrimitive  = "tenant binding primitive: opens the transaction that sets app.current_tenant"
	rawTenantEnumerate  = "tenant enumeration: SELECT id FROM tenants to fan a sweep out per tenant"
	rawGlobalCatalog    = "global catalog table without a tenant column (advisories, sources, sync runs, retention)"
	rawProcessControl   = "process-level control table or advisory lock (leader, run locks, timestamps)"
	rawCatalogInspect   = "catalog/role inspection (pg_class, pg_roles, row_security_active, goose version)"
	rawLegacyGlobal     = "legacy global-chain store that predates tenant RLS on its table"
	rawUserAPIKey       = "legacy users api-key exact-hash lookup; users has no RLS and api_key_hash is a global unique digest"
	rawUserLegacy       = "legacy users read or bootstrap write predicated explicitly on ownership tenant; users has no RLS"
	rawInboundWebhook   = "inbound webhook exact public-ID routing via synapse_lookup_inbound_webhook (separate HMAC plane)"
	rawIdentityDigest   = "identity exact-digest routing via synapse_identity_route_credential"
	rawIdentityPerson   = "identity exact-authenticated-person projection via synapse_identity_person_memberships/_epoch"
	rawIdentityPlatform = "identity platform-owned person command via synapse_identity_person_command"
)

// rawPoolExceptions is the complete reviewed inventory. A new raw-pool statement anywhere in this
// package fails TestRawPoolInventory until it is reviewed and listed here.
var rawPoolExceptions = map[string]rawPoolException{
	"accuracy_store.go:Recent":                                   {1, rawLegacyGlobal},
	"accuracy_store.go:Save":                                     {1, rawLegacyGlobal},
	"advisory_bulk_writer.go:NewMaterializingAdvisoryWriter":     {1, rawLegacyGlobal},
	"advisory_repo.go:AdvisoryAliasEdges":                        {1, rawGlobalCatalog},
	"advisory_repo.go:AdvisoryFreshness":                         {1, rawGlobalCatalog},
	"advisory_repo.go:ByCPE":                                     {1, rawGlobalCatalog},
	"advisory_repo.go:ByPackage":                                 {1, rawGlobalCatalog},
	"advisory_repo.go:CoveredEcosystems":                         {1, rawGlobalCatalog},
	"advisory_repo.go:Upsert":                                    {1, rawGlobalCatalog},
	"agent_decision_store.go:AppendDecision":                     {2, rawLegacyGlobal},
	"agent_decision_store.go:ListBySession":                      {1, rawLegacyGlobal},
	"aup_audit.go:Accepted":                                      {1, rawLegacyGlobal},
	"aup_audit.go:MigrationMetadata":                             {1, rawCatalogInspect},
	"aup_audit.go:Save":                                          {1, rawLegacyGlobal},
	"aup_audit.go:VerifyGlobal":                                  {1, rawLegacyGlobal},
	"aup_audit.go:recordOnce":                                    {1, rawTenantPrimitive},
	"db.go:AcquireSingletonLock":                                 {1, rawProcessControl},
	"engagement_repo.go:ListPromotionReconciliationScopes":       {1, rawTenantEnumerate},
	"engagement_repo.go:ListTenantIDs":                           {1, rawTenantEnumerate},
	"evidence_repo.go:ListEvidenceChains":                        {1, rawLegacyGlobal},
	"evidence_repo.go:NewReadOnlyEvidenceStore":                  {1, rawCatalogInspect},
	"identity_foundation.go:ActiveMembershipsForPerson":          {1, rawIdentityPerson},
	"identity_foundation.go:ApplyPersonCommand":                  {1, rawIdentityPlatform},
	"identity_foundation.go:PersonEpoch":                         {1, rawIdentityPerson},
	"identity_foundation.go:RouteCredentialDigest":               {1, rawIdentityDigest},
	"inbound_webhook.go:LookupInboundWebhook":                    {1, rawInboundWebhook},
	"jobqueue.go:AggregateJobQueueStats":                         {1, rawTenantEnumerate},
	"jobqueue.go:Claim":                                          {1, rawTenantEnumerate},
	"leader_store.go:Acquire":                                    {1, rawLegacyGlobal},
	"leader_store.go:Resign":                                     {1, rawLegacyGlobal},
	"notification_source.go:Poll":                                {1, rawTenantEnumerate},
	"ownership_execution.go:DispatchOwnership":                   {1, rawTenantEnumerate},
	"recon_run_repo.go:Get":                                      {1, rawLegacyGlobal},
	"recon_run_repo.go:ListByEngagement":                         {1, rawLegacyGlobal},
	"recon_run_repo.go:ListStaleRunning":                         {1, rawLegacyGlobal},
	"recon_run_repo.go:Save":                                     {1, rawLegacyGlobal},
	"runlock.go:TryLock":                                         {1, rawProcessControl},
	"runlock_lease.go:TryLockLeased":                             {2, rawLegacyGlobal},
	"runlock_lease.go:renew":                                     {1, rawLegacyGlobal},
	"scan_job_repo.go:GetJob":                                    {1, rawLegacyGlobal},
	"scan_job_repo.go:LatestForEngagement":                       {1, rawLegacyGlobal},
	"scan_job_repo.go:LatestForEngagements":                      {1, rawLegacyGlobal},
	"scan_job_repo.go:ListStaleRunning":                          {1, rawLegacyGlobal},
	"scan_job_repo.go:execSourceJob":                             {1, rawLegacyGlobal},
	"scan_result_repo.go:LatestResult":                           {1, rawLegacyGlobal},
	"scan_result_repo.go:SaveResult":                             {1, rawLegacyGlobal},
	"siem_repository.go:TenantIDs":                               {1, rawTenantEnumerate},
	"sync_run_store.go:MarkRunning":                              {1, rawLegacyGlobal},
	"sync_run_store.go:Supersede":                                {1, rawLegacyGlobal},
	"sync_run_store.go:WithGlobalRead":                           {1, rawLegacyGlobal},
	"telemetry_repo.go:Footprint":                                {2, rawCatalogInspect},
	"tenant.go:CheckRLSRuntimeRole":                              {1, rawCatalogInspect},
	"tenant.go:WithTenant":                                       {1, rawTenantPrimitive},
	"tenant.go:listTenantIDs":                                    {1, rawTenantEnumerate},
	"timestamp_store.go:Get":                                     {1, rawProcessControl},
	"timestamp_store.go:LatestHead":                              {1, rawProcessControl},
	"timestamp_store.go:Put":                                     {1, rawProcessControl},
	"user_repo.go:Bootstrap":                                     {1, rawUserLegacy},
	"user_repo.go:GetByAPIKeyHash":                               {1, rawUserAPIKey},
	"user_repo.go:GetByID":                                       {1, rawUserLegacy},
	"vulnerability_retention_store.go:RunVulnerabilityRetention": {1, rawLegacyGlobal},
	"vulnerability_source_store.go:Archive":                      {1, rawGlobalCatalog},
	"vulnerability_source_store.go:Create":                       {1, rawGlobalCatalog},
	"vulnerability_source_store.go:Get":                          {1, rawGlobalCatalog},
	"vulnerability_source_store.go:List":                         {1, rawGlobalCatalog},
	"vulnerability_source_store.go:SetEnabled":                   {1, rawGlobalCatalog},
	"vulnerability_source_store.go:Update":                       {1, rawGlobalCatalog},
	"vulnerability_source_store.go:classifySourceUpdateMiss":     {1, rawGlobalCatalog},
}

var rawPoolMethods = map[string]bool{
	"Query": true, "QueryRow": true, "Exec": true, "Begin": true, "BeginTx": true,
	"SendBatch": true, "CopyFrom": true, "Acquire": true,
}

// observedRawPoolCalls counts, per "file:function", calls of pool methods whose receiver is a value
// or field named pool. Advisory-materializer calls are grouped per file because that file is one
// global-catalog writer.
func observedRawPoolCalls(t *testing.T) map[string]int {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !rawPoolMethods[sel.Sel.Name] || !isPoolReceiver(sel.X) {
					return true
				}
				key := file + ":" + fn.Name.Name
				if file == "advisory_materializer.go" {
					key = file + ":*"
				}
				out[key]++
				return true
			})
		}
	}
	return out
}

func isPoolReceiver(x ast.Expr) bool {
	switch v := x.(type) {
	case *ast.Ident:
		return v.Name == "pool"
	case *ast.SelectorExpr:
		return v.Sel.Name == "pool"
	}
	return false
}

func TestRawPoolInventory(t *testing.T) {
	expected := map[string]rawPoolException{"advisory_materializer.go:*": {18, rawGlobalCatalog}}
	for k, v := range rawPoolExceptions {
		expected[k] = v
	}
	observed := observedRawPoolCalls(t)
	var problems []string
	for key, count := range observed {
		want, ok := expected[key]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("unreviewed raw-pool access %s (%d call(s)); route it through WithTenant or add a reviewed exception", key, count))
		case want.calls != count:
			problems = append(problems, fmt.Sprintf("raw-pool access %s changed from %d to %d call(s); re-review it", key, want.calls, count))
		}
	}
	for key := range expected {
		if _, ok := observed[key]; !ok {
			problems = append(problems, fmt.Sprintf("stale raw-pool exception %s; remove it", key))
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatal(strings.Join(problems, "\n"))
	}
}

// securityDefinerExceptions is every SECURITY DEFINER function the migrations create. Trigger
// functions run only as table side effects; the callable ones are the global-access exceptions and
// each must have a narrow EXECUTE grant.
var securityDefinerExceptions = map[string]string{
	"fn_sync_scan_run_engagement_tenant":              "trigger: scan run tenant bridge",
	"fn_assign_scan_run_tenant":                       "trigger: scan run tenant bridge",
	"synapse_bridge_finding_assignee":                 "trigger: finding assignee canonical user bridge",
	"synapse_track_assignee_review":                   "trigger: finding assignee review queue",
	"synapse_lookup_inbound_webhook":                  "callable: inbound webhook exact public-ID routing",
	"synapse_admit_inbound_webhook":                   "callable: inbound webhook row-locked admission",
	"synapse_lock_inbound_webhook_event":              "callable: inbound webhook enqueue lock",
	"synapse_provision_github_inbound_webhook":        "callable: tenant-bound GitHub webhook endpoint provisioning",
	"synapse_rotate_github_inbound_webhook":           "callable: tenant-bound GitHub webhook secret rotation",
	"synapse_identity_index_membership":               "trigger: identity person-membership routing index",
	"synapse_identity_guard_membership_representable": "trigger: identity representability guard",
	"synapse_identity_index_credential":               "trigger: identity exact-digest routing index",
	"synapse_identity_route_credential":               "callable: identity exact-digest routing",
	"synapse_identity_person_memberships":             "callable: identity exact-authenticated-person projection",
	"synapse_identity_person_epoch":                   "callable: identity exact-authenticated-person epoch",
	"synapse_identity_person_command":                 "callable: identity platform-owned person command (owner only)",
	"synapse_identity_create_person":                  "callable: identity create-only person command",
}

// runtimeExecuteGrants is the complete set of function EXECUTE grants GrantRuntimePrivileges gives
// the runtime role.
var runtimeExecuteGrants = []string{
	"synapse_lookup_inbound_webhook(TEXT)",
	"synapse_admit_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT,BOOLEAN)",
	"synapse_lock_inbound_webhook_event(TEXT,TEXT,TEXT,TEXT,TEXT)",
	"synapse_provision_github_inbound_webhook(TEXT,TEXT,TEXT,TEXT,INT)",
	"synapse_rotate_github_inbound_webhook(TEXT,TEXT,TEXT,INT,TEXT,TIMESTAMPTZ)",
	"synapse_identity_route_credential(TEXT)",
	"synapse_identity_person_memberships(TEXT,TEXT)",
	"synapse_identity_person_epoch(TEXT,TEXT)",
	"synapse_identity_create_person(TEXT,TEXT)",
}

var (
	createFunctionPattern = regexp.MustCompile(`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([a-z_][a-z0-9_]*)\s*\((.*?)\$`)
	executeGrantPattern   = regexp.MustCompile(`GRANT EXECUTE ON FUNCTION ([a-z_]+\([A-Z,]*\)) TO`)
)

func upMigrationSQL(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "migrations", "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("list migrations: %v", err)
	}
	out := map[string]string{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		up := string(raw)
		if i := strings.Index(up, "-- +goose Down"); i >= 0 {
			up = up[:i]
		}
		out[filepath.Base(file)] = up
	}
	return out
}

func TestSecurityDefinerInventory(t *testing.T) {
	seen := map[string]bool{}
	for file, up := range upMigrationSQL(t) {
		for _, m := range createFunctionPattern.FindAllStringSubmatch(up, -1) {
			header := strings.ToUpper(m[2])
			if !strings.Contains(header, "SECURITY DEFINER") {
				continue
			}
			name := strings.ToLower(m[1])
			if _, ok := securityDefinerExceptions[name]; !ok {
				t.Errorf("%s creates unreviewed SECURITY DEFINER function %s", file, name)
			}
			seen[name] = true
			if !strings.Contains(header, "SET SEARCH_PATH") {
				t.Errorf("%s: SECURITY DEFINER function %s does not pin search_path", file, name)
			}
		}
	}
	for name := range securityDefinerExceptions {
		if !seen[name] {
			t.Errorf("stale SECURITY DEFINER exception %s", name)
		}
	}
	// Every callable definer function is revoked from PUBLIC in its migration.
	all := strings.Join(func() []string {
		var v []string
		for _, up := range upMigrationSQL(t) {
			v = append(v, up)
		}
		return v
	}(), "\n")
	for name, kind := range securityDefinerExceptions {
		if strings.HasPrefix(kind, "callable:") && seen[name] && !regexp.MustCompile(`REVOKE ALL ON FUNCTION `+name+`\(`).MatchString(all) {
			t.Errorf("callable SECURITY DEFINER function %s is not revoked from PUBLIC", name)
		}
	}
}

func TestRuntimeGrantInventory(t *testing.T) {
	raw, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	var grants []string
	for _, m := range executeGrantPattern.FindAllStringSubmatch(src, -1) {
		grants = append(grants, m[1])
	}
	sort.Strings(grants)
	want := append([]string(nil), runtimeExecuteGrants...)
	sort.Strings(want)
	if strings.Join(grants, "\n") != strings.Join(want, "\n") {
		t.Fatalf("runtime EXECUTE grants changed:\n got %v\nwant %v", grants, want)
	}
	// The inbound webhook plane keeps its narrow grant shape: no direct DML, SELECT only under its
	// tenant policy.
	for _, stmt := range []string{
		`"REVOKE ALL ON TABLE inbound_webhook_endpoints FROM "+quotedRole`,
		`"GRANT SELECT ON TABLE inbound_webhook_endpoints TO "+quotedRole`,
		`"REVOKE ALL ON TABLE identity_persons, identity_person_audit, identity_person_membership_index, identity_credential_digests FROM "+quotedRole`,
		`"REVOKE ALL ON FUNCTION synapse_identity_person_command(TEXT,TEXT,TEXT,TEXT) FROM "+quotedRole`,
	} {
		if !strings.Contains(src, stmt) {
			t.Fatalf("GrantRuntimePrivileges no longer contains %s", stmt)
		}
	}
	// The inbound webhook migration itself is unchanged in its routing contract.
	up := upMigrationSQL(t)["0199_inbound_webhook_plane.sql"]
	for _, fragment := range []string{
		"RETURNS TABLE(tenant_id TEXT)",
		"WHERE e.public_id = p_public_id",
		"ALTER TABLE inbound_webhook_endpoints FORCE ROW LEVEL SECURITY;",
		"USING (tenant_id = synapse_current_tenant());",
		"REVOKE ALL ON FUNCTION synapse_lookup_inbound_webhook(TEXT) FROM PUBLIC;",
	} {
		if !strings.Contains(up, fragment) {
			t.Fatalf("inbound webhook routing contract changed: missing %q", fragment)
		}
	}
}
