package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestScanJobStorePersistsDebugEvents(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// t.Cleanup is LIFO. Close must be registered before fixture cleanup so a second suite run sees
	// the same database state as the first one did.
	t.Cleanup(pool.Close)

	store := NewScanJobStore(pool)
	job := ports.ScanJob{
		ID:           "scan-job-debug-" + randHex(t),
		EngagementID: "eng-debug",
		Target:       "local-target",
		Kind:         ports.TargetLocal,
		Status:       ports.ScanRunning,
		Stage:        "scanning vulnerabilities",
		Progress:     55,
		StartedAt:    time.Now().UTC(),
		DebugEvents: []ports.ScanDebugEvent{{
			Stage:     "scanning vulnerabilities",
			Step:      "osv",
			Status:    ports.ScanDebugSucceeded,
			Tool:      "osv",
			Counts:    map[string]int{"raw_findings": 2},
			StartedAt: time.Now().UTC(),
		}},
	}
	if err := store.Save(ctx, job); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM scan_jobs WHERE id=$1", job.ID); err != nil {
			t.Errorf("cleanup scan job %s: %v", job.ID, err)
		}
	})

	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if len(got.DebugEvents) != 1 || got.DebugEvents[0].Step != "osv" || got.DebugEvents[0].Counts["raw_findings"] != 2 {
		t.Fatalf("debug events not round-tripped: %+v", got.DebugEvents)
	}
}

func TestScanJobStoreLatestProjectAnalysisExcludesBoundedSourceJobs(t *testing.T) {
	ctx, pool := setupTestDB(t)
	tenant, engagementID := shared.ID("purpose-tenant"), shared.ID("purpose-engagement")
	ensureTestTenantAndEngagement(t, ctx, pool, tenant, engagementID, "", "")
	ctx = shared.WithTenant(ctx, tenant)
	store := NewScanJobStore(pool)
	started := time.Now().UTC().Truncate(time.Microsecond)
	full := ports.ScanJob{ID: "purpose-full-" + randHex(t), EngagementID: engagementID.String(), Target: "repo", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, Stage: "done", StartedAt: started}
	source := ports.ScanJob{ID: "purpose-source-" + randHex(t), EngagementID: engagementID.String(), Target: "repo/a", Kind: ports.TargetLocal, Purpose: ports.ScanPurposeProjectSource, Status: ports.ScanSucceeded, Stage: "done", StartedAt: started.Add(time.Second)}
	for _, job := range []ports.ScanJob{full, source} {
		if err := store.CreateRunning(ctx, job); err != nil {
			t.Fatalf("create %s: %v", job.ID, err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), "DELETE FROM scan_jobs WHERE id=$1", job.ID)
		})
	}
	got, err := store.LatestProjectAnalysisForEngagement(ctx, engagementID)
	if err != nil || got.ID != full.ID || got.Purpose != "" {
		t.Fatalf("latest project analysis = %+v, %v", got, err)
	}
	all, err := store.LatestProjectAnalysisForEngagements(ctx, []shared.ID{engagementID})
	if err != nil || all[engagementID].ID != full.ID {
		t.Fatalf("latest project analyses = %+v, %v", all, err)
	}
	if _, err := store.LatestProjectAnalysisForEngagement(shared.WithTenant(context.Background(), "other-tenant"), engagementID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant project analysis read = %v, want not found", err)
	}
	source.Purpose = ""
	if err := store.Save(ctx, source); err == nil {
		t.Fatal("scan job purpose rewrite unexpectedly succeeded")
	}
}

func TestScanJobStoreProjectAnalysisReadersUsePartialIndexWithGenericPlan(t *testing.T) {
	ctx, pool := setupTestDB(t)
	tenant, engagementID := shared.ID("purpose-index-tenant"), shared.ID("purpose-index-engagement")
	ensureTestTenantAndEngagement(t, ctx, pool, tenant, engagementID, "", "")
	job := ports.ScanJob{ID: "purpose-index-job-" + randHex(t), EngagementID: engagementID.String(), Target: "repo", Kind: ports.TargetLocal, Status: ports.ScanSucceeded, Stage: "done", StartedAt: time.Now().UTC()}
	if err := NewScanJobStore(pool).CreateRunning(shared.WithTenant(ctx, tenant), job); err != nil {
		t.Fatalf("create full analysis job: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM scan_jobs WHERE id=$1", job.ID)
	})
	if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL plan_cache_mode=force_generic_plan"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SET LOCAL enable_seqscan=off"); err != nil {
			return err
		}
		assertPlanUses := func(query string) error {
			rows, err := tx.Query(ctx, query)
			if err != nil {
				return err
			}
			defer rows.Close()
			var lines []string
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					return err
				}
				lines = append(lines, line)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if !strings.Contains(strings.Join(lines, "\n"), "idx_scan_jobs_project_analysis_latest") {
				return fmt.Errorf("generic plan does not use project-analysis index: %s", strings.Join(lines, "\n"))
			}
			return nil
		}
		if _, err := tx.Exec(ctx, `PREPARE scan_job_project_analysis_one(text,text) AS
			SELECT j.id FROM scan_jobs j JOIN engagements owner ON owner.id=j.engagement_id
			WHERE j.engagement_id=$1 AND owner.tenant_id=$2 AND j.purpose <> 'project_source'
			ORDER BY j.started_at DESC, j.id DESC LIMIT 1`); err != nil {
			return err
		}
		if err := assertPlanUses(`EXPLAIN (COSTS OFF) EXECUTE scan_job_project_analysis_one('purpose-index-engagement','purpose-index-tenant')`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `PREPARE scan_job_project_analysis_many(text[],text) AS
			SELECT j.id FROM unnest($1::text[]) AS e(engagement_id)
			JOIN LATERAL (
				SELECT j.id FROM scan_jobs j JOIN engagements owner ON owner.id=j.engagement_id
				WHERE j.engagement_id=e.engagement_id AND owner.tenant_id=$2 AND j.purpose <> 'project_source'
				ORDER BY j.started_at DESC, j.id DESC LIMIT 1
			) j ON true`); err != nil {
			return err
		}
		return assertPlanUses(`EXPLAIN (COSTS OFF) EXECUTE scan_job_project_analysis_many(ARRAY['purpose-index-engagement'],'purpose-index-tenant')`)
	}); err != nil {
		t.Fatal(err)
	}
}
