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

func TestProjectAnalysisSourceAttachmentConcurrentCASHasOneWinner(t *testing.T) {
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

	tenantID := shared.ID("tenant-source-cas-" + uuid.NewString())
	projectID := shared.ID("project-source-cas-" + uuid.NewString())
	analysisID := shared.ID("analysis-source-cas-" + uuid.NewString())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, 'source-publish-cas-test')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, key, source_binding) VALUES ($1,$2,'source-publish-cas-test',$3,'{}'::jsonb)`, projectID.String(), tenantID.String(), "source-cas-"+uuid.NewString()); err != nil {
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
		ID: analysisID.String(), TenantID: tenantID.String(), ProjectID: projectID.String(), ProjectKey: "source-cas-test", CreatedAt: now,
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

	captureA := sourceAttachmentFixture(now)
	captureB := sourceAttachmentFixture(now.Add(time.Microsecond))
	writerB := *captureB.Manifest.Writer
	writerB.Actor = "ci-bot-2"
	captureB.Manifest.Writer = &writerB
	captureB.Manifest.SetArtifactDigest()
	auditA := sourceAttachmentAudit(analysisID, captureA)
	auditB := sourceAttachmentAudit(analysisID, captureB)

	type result struct {
		digest string
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, contender := range []struct {
		capture projectanalysis.SourceCapture
		audit   ports.AuditEntry
	}{{captureA, auditA}, {captureB, auditB}} {
		contender := contender
		go func() {
			<-start
			err := store.AttachSourceWithAudit(ctx, tenantID, projectID, analysisID, contender.capture, contender.audit)
			results <- result{digest: contender.capture.Manifest.Digest, err: err}
		}()
	}
	close(start)

	winner := ""
	conflicts := 0
	for range 2 {
		got := <-results
		switch {
		case got.err == nil:
			if winner != "" {
				t.Fatalf("multiple DB source publishers succeeded: %q and %q", winner, got.digest)
			}
			winner = got.digest
		case errors.Is(got.err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent DB attach error: %v", got.err)
		}
	}
	if winner == "" || conflicts != 1 {
		t.Fatalf("winner=%q conflicts=%d, want one winner and one conflict", winner, conflicts)
	}
	got, err := store.Get(ctx, tenantID, projectID, analysisID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceManifest.Digest != winner || !got.Capabilities.Source.Available {
		t.Fatalf("persisted source digest=%q, winning digest=%q", got.SourceManifest.Digest, winner)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action=$1 AND target=$2`, ports.ProjectSourcePublishAuditAction, analysisID.String()).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("concurrent CAS emitted %d audit rows, want 1", auditCount)
	}
}
