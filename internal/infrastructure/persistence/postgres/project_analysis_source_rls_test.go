package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Publishing source must work for the role the server actually runs as.
//
// The attachment appended its audit entry with the global-chained writer, which stamps tenant_id
// ” and leaves hash_version at its default. The audit_log policy admits a row only when
// tenant_id is the bound tenant and hash_version is 2, so every publication under RLS failed with
// "new row violates row-level security policy for table audit_log" and rolled the attachment back
// with it. The whole publish-source subcommand was unusable against a deployment with RLS on.
//
// The integration pool connects as the owner, which bypasses RLS even under FORCE ROW LEVEL
// SECURITY, so this has to drop to a NOSUPERUSER NOBYPASSRLS role to reach the policy at all.
// That is exactly why the existing attachment test did not catch it.
func TestProjectAnalysisSourceAttachmentSucceedsUnderRowLevelSecurity(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tenantID := shared.ID("tenant-srcrls-" + uuid.NewString())
	projectID := shared.ID("project-srcrls-" + uuid.NewString())
	analysisID := shared.ID("analysis-srcrls-" + uuid.NewString())
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'source-rls-test')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1,$2,'source-rls-test',$3,'{}'::jsonb)`, projectID.String(), tenantID.String(), "srcrls-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM audit_log WHERE tenant_id=$1`, tenantID.String())
		_, _ = pool.Exec(c, `DELETE FROM project_analyses WHERE id=$1`, analysisID.String())
		_, _ = pool.Exec(c, `DELETE FROM projects WHERE id=$1`, projectID.String())
		_, _ = pool.Exec(c, `DELETE FROM tenants WHERE id=$1`, tenantID.String())
	})

	store := NewProjectAnalysisStore(pool)
	if err := store.Save(ctx, projectanalysis.Analysis{
		ID: analysisID.String(), TenantID: tenantID.String(), ProjectID: projectID.String(), ProjectKey: "srcrls", CreatedAt: now,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Capabilities: projectanalysis.SourceCapabilities{
			Source:       projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
			Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			Highlighting: projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
		},
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile, Language: "Go"}}},
	}); err != nil {
		t.Fatal(err)
	}

	// requireTenant opens its own connection from the pool, so the role has to be the pool's role
	// rather than one set for a single transaction. A dedicated pool under a restricted role is
	// the only way to put AttachSourceWithAudit itself behind the policy.
	const rlsRole = "project_source_rls_role"
	const rlsPassword = "project-source-rls" //nolint:gosec // a throwaway local role for this test
	_, _ = pool.Exec(ctx, `DROP OWNED BY `+rlsRole)
	_, _ = pool.Exec(ctx, `DROP ROLE IF EXISTS `+rlsRole)
	for _, stmt := range []string{
		`CREATE ROLE ` + rlsRole + ` LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '` + rlsPassword + `'`,
		`GRANT USAGE ON SCHEMA public TO ` + rlsRole,
		`GRANT SELECT, INSERT, UPDATE ON project_analyses TO ` + rlsRole,
		`GRANT SELECT, INSERT ON audit_log TO ` + rlsRole,
		`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ` + rlsRole,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("set up rls role (%s): %v", stmt, err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DROP OWNED BY `+rlsRole)
		_, _ = pool.Exec(c, `DROP ROLE IF EXISTS `+rlsRole)
	})

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := Connect(ctx, rewriteDSNCredentials(dsn, rlsRole, rlsPassword))
	if err != nil {
		t.Fatalf("connect as %s: %v (host %s)", rlsRole, err, cfg.Host)
	}
	t.Cleanup(restricted.Close)

	var enforced bool
	if err := restricted.QueryRow(ctx, `SELECT row_security_active('audit_log'::regclass)`).Scan(&enforced); err != nil {
		t.Fatalf("check RLS: %v", err)
	}
	if !enforced {
		t.Fatalf("role %s is not subject to the audit_log policy; the test would prove nothing", rlsRole)
	}

	capture := sourceAttachmentFixture(now)
	entry := sourceAttachmentAudit(analysisID, capture)
	if err := NewProjectAnalysisStore(restricted).AttachSourceWithAudit(ctx, tenantID, projectID, analysisID, capture, entry); err != nil {
		t.Fatalf("attach source under RLS: %v", err)
	}

	var auditTenant string
	var hashVersion int
	if err := pool.QueryRow(ctx,
		`SELECT tenant_id, hash_version FROM audit_log WHERE tenant_id=$1 AND action=$2 ORDER BY id DESC LIMIT 1`,
		tenantID.String(), entry.Action).Scan(&auditTenant, &hashVersion); err != nil {
		t.Fatalf("read the audit row the attachment wrote: %v", err)
	}
	if auditTenant != tenantID.String() || hashVersion != 2 {
		t.Fatalf("audit row tenant=%q hash_version=%d, want %q and 2: the policy admits nothing else", auditTenant, hashVersion, tenantID)
	}
}

// rewriteDSNCredentials swaps the user and password of a postgres URL, keeping everything else.
func rewriteDSNCredentials(dsn, user, password string) string {
	const scheme = "postgres://"
	rest := strings.TrimPrefix(dsn, scheme)
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return scheme + user + ":" + password + "@" + rest
}
