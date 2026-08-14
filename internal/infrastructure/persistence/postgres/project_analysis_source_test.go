package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestProjectAnalysisSourceAttachmentIsCreateOnlyAndAudited(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tenantID := shared.ID("tenant-source-" + uuid.NewString())
	projectID := shared.ID("project-source-" + uuid.NewString())
	analysisID := shared.ID("analysis-source-" + uuid.NewString())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'source-publish-test')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1,$2,'source-publish-test',$3,'{}'::jsonb)`, projectID.String(), tenantID.String(), "source-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		if _, err := pool.Exec(cleanup, `DELETE FROM project_analyses WHERE id=$1`, analysisID.String()); err != nil {
			t.Errorf("cleanup analysis: %v", err)
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM projects WHERE id=$1`, projectID.String()); err != nil {
			t.Errorf("cleanup project: %v", err)
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM tenants WHERE id=$1`, tenantID.String()); err != nil {
			t.Errorf("cleanup tenant: %v", err)
		}
	})

	store := NewProjectAnalysisStore(pool)
	analysis := projectanalysis.Analysis{
		ID: analysisID.String(), TenantID: tenantID.String(), ProjectID: projectID.String(), ProjectKey: "source-test", CreatedAt: now,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Capabilities: projectanalysis.SourceCapabilities{
			Source:       projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
			Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			Highlighting: projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
		},
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile, Language: "Go"}}},
	}
	if err := store.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	capture := sourceAttachmentFixture(now)
	audit := sourceAttachmentAudit(analysisID, capture)
	if err := store.AttachSourceWithAudit(ctx, tenantID, projectID, analysisID, capture, audit); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, tenantID, projectID, analysisID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Capabilities.Source.Available || !got.Capabilities.Highlighting.Available || got.SourceManifest.Digest != capture.Manifest.Digest {
		t.Fatalf("source attachment not persisted: %+v", got.SourceManifest)
	}
	// Late source publication must not manufacture diff capabilities.
	if got.Capabilities.Comparison.Available || got.Capabilities.UnifiedDiff.Available || got.Capabilities.SplitDiff.Available {
		t.Fatalf("source attachment changed comparison capabilities: %+v", got.Capabilities)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1 AND target=$2`, ports.ProjectSourcePublishAuditAction, analysisID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("audit count=%d, want 1", auditCount)
	}
	if err := store.AttachSourceWithAudit(ctx, tenantID, projectID, analysisID, capture, audit); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate attach error=%v, want conflict", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1 AND target=$2`, ports.ProjectSourcePublishAuditAction, analysisID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("duplicate attach emitted audit: count=%d", auditCount)
	}
	if err := store.AttachSourceWithAudit(ctx, shared.ID("foreign-tenant"), projectID, analysisID, capture, audit); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign tenant attach error=%v, want not found", err)
	}
}

func TestProjectAnalysisSourceAttachmentRollsBackWhenAuditAppendFails(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tenantID := shared.ID("tenant-source-rollback-" + uuid.NewString())
	projectID := shared.ID("project-source-rollback-" + uuid.NewString())
	analysisID := shared.ID("analysis-source-rollback-" + uuid.NewString())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'source-publish-rollback-test')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1,$2,'source-publish-rollback-test',$3,'{}'::jsonb)`, projectID.String(), tenantID.String(), "source-rollback-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		if _, err := pool.Exec(cleanup, `DELETE FROM project_analyses WHERE id=$1`, analysisID.String()); err != nil {
			t.Errorf("cleanup analysis: %v", err)
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM projects WHERE id=$1`, projectID.String()); err != nil {
			t.Errorf("cleanup project: %v", err)
		}
		if _, err := pool.Exec(cleanup, `DELETE FROM tenants WHERE id=$1`, tenantID.String()); err != nil {
			t.Errorf("cleanup tenant: %v", err)
		}
	})

	store := NewProjectAnalysisStore(pool)
	analysis := projectanalysis.Analysis{
		ID: analysisID.String(), TenantID: tenantID.String(), ProjectID: projectID.String(), ProjectKey: "source-rollback-test", CreatedAt: now,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Capabilities: projectanalysis.SourceCapabilities{
			Source:       projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
			Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			Highlighting: projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
		},
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
	}
	if err := store.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	// Hold the same session-level advisory lock that appendAudit requests transactionally.
	// The source transaction can update payload, but its audit append must block until the
	// deadline and then roll the entire transaction back.
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, auditChainLock); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, auditChainLock) }()

	capture := sourceAttachmentFixture(now)
	audit := sourceAttachmentAudit(analysisID, capture)
	deadlineCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if err := store.AttachSourceWithAudit(deadlineCtx, tenantID, projectID, analysisID, capture, audit); err == nil {
		t.Fatal("AttachSourceWithAudit unexpectedly succeeded while audit chain was locked")
	}
	got, err := store.Get(ctx, tenantID, projectID, analysisID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities.Source.Available || got.SourceManifest.Digest != "" || len(got.SourceManifest.Files) != 0 || got.SourceManifest.Writer != nil {
		t.Fatalf("analysis payload escaped rolled-back transaction: %+v", got.SourceManifest)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1 AND target=$2`, ports.ProjectSourcePublishAuditAction, analysisID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 0 {
		t.Fatalf("rolled-back source attachment emitted %d audit rows", auditCount)
	}
}

func sourceAttachmentFixture(at time.Time) projectanalysis.SourceCapture {
	writer := projectanalysis.SourceWriter{Actor: "ci-bot", ToolVersion: "synapse-cli/test", PublishedAt: at}
	manifest := projectanalysis.SourceManifest{Writer: &writer, Files: []projectanalysis.SourceFile{{Path: "main.go", Digest: "fixture-digest", Bytes: 13, Lines: 1, Available: true}}}
	manifest.SetArtifactDigest()
	return projectanalysis.SourceCapture{
		Capabilities: projectanalysis.SourceCapabilities{
			Source:       projectanalysis.Capability{Available: true},
			Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			Highlighting: projectanalysis.Capability{Available: true},
		},
		Manifest: manifest,
	}
}

func sourceAttachmentAudit(analysisID shared.ID, capture projectanalysis.SourceCapture) ports.AuditEntry {
	return ports.AuditEntry{
		Actor: capture.Manifest.Writer.Actor, Action: ports.ProjectSourcePublishAuditAction, Target: analysisID.String(), At: capture.Manifest.Writer.PublishedAt,
		Metadata: map[string]string{"artifact_digest": capture.Manifest.Digest, "tool_version": capture.Manifest.Writer.ToolVersion},
	}
}
