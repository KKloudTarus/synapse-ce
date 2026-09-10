package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceupload"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func scanSourceFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, engagementID shared.ID) (*sourceupload.Store, sourcepackage.Package) {
	t.Helper()
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, engagementID, "", "")
	sources := sourceupload.NewStoreWithRepository(blob.NewMemory(), NewEngagementSourceRepository(pool), sourcepackage.MaxArchiveBytes)
	content := []byte("immutable archive fixture")
	digest := sha256.Sum256(content)
	item, err := sources.Save(ctx, tenantID, engagementID, "application.zip", "original-uploader", time.Now().UTC().Truncate(time.Microsecond), int64(len(content)), hex.EncodeToString(digest[:]), bytes.NewReader(content))
	if err != nil {
		t.Fatalf("save owned source fixture: %v", err)
	}
	return sources, item
}

func scanSourceJob(item sourcepackage.Package, id string) ports.ScanJob {
	return ports.ScanJob{ID: id, EngagementID: item.EngagementID.String(), Target: item.Target(), Kind: ports.TargetUpload,
		Status: ports.ScanRunning, Stage: "queued", StartedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond), SourcePackage: &item}
}

func assertFrozenScanSource(t *testing.T, got *sourcepackage.Package, want sourcepackage.Package) {
	t.Helper()
	if got == nil {
		t.Fatal("frozen source package is missing")
	}
	// Storage locators and object keys must never enter either persisted JSON
	// manifest or job status. The remaining metadata is the exact queued version.
	want.Locator, want.ObjectKey = "", ""
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("frozen source package changed: got %+v, want %+v", *got, want)
	}
}

func TestPostgresScanSourceJobRoundTripAndStatusUpdates(t *testing.T) {
	ctx, pool := setupTestDB(t)
	sources, item := scanSourceFixture(t, ctx, pool, "source-tenant", "source-assessment")
	ctx = shared.WithTenant(ctx, item.TenantID)
	store := NewScanJobStore(pool)
	job := scanSourceJob(item, "source-job")
	if err := store.CreateRunning(ctx, job); err != nil {
		t.Fatalf("create source-bound job: %v", err)
	}

	for name, read := range map[string]func() (ports.ScanJob, error){
		"get":    func() (ports.ScanJob, error) { return store.GetJob(ctx, job.ID) },
		"latest": func() (ports.ScanJob, error) { return store.LatestForEngagement(ctx, item.EngagementID) },
		"latest batch": func() (ports.ScanJob, error) {
			jobs, err := store.LatestForEngagements(ctx, []shared.ID{item.EngagementID})
			return jobs[item.EngagementID], err
		},
		"stale running": func() (ports.ScanJob, error) {
			jobs, err := store.ListStaleRunning(ctx, time.Now().UTC(), 10)
			if err != nil {
				return ports.ScanJob{}, err
			}
			if len(jobs) != 1 {
				t.Fatalf("stale running count = %d, want 1", len(jobs))
			}
			return jobs[0], nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := read()
			if err != nil {
				t.Fatal(err)
			}
			assertFrozenScanSource(t, got.SourcePackage, item)
		})
	}

	// Status-only workers from older versions may omit source metadata. They
	// must retain the admitted source, including after a failed scan.
	finished := time.Now().UTC().Truncate(time.Microsecond)
	job.Status, job.Stage, job.Error, job.FinishedAt = ports.ScanFailed, "failed", "scanner unavailable", &finished
	job.SourcePackage = nil
	if err := store.Save(ctx, job); err != nil {
		t.Fatalf("save failed status without rewriting source: %v", err)
	}
	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != ports.ScanFailed || got.Error != "scanner unavailable" {
		t.Fatalf("failed status lost: %+v", got)
	}
	assertFrozenScanSource(t, got.SourcePackage, item)
	if err := sources.Delete(ctx, item.TenantID, item.EngagementID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("failed job did not retain its source: %v", err)
	}

	// Even a valid package owned by another assessment cannot rewrite an
	// existing job through the status upsert path.
	_, other := scanSourceFixture(t, ctx, pool, item.TenantID, "other-assessment")
	changed := scanSourceJob(other, job.ID)
	changed.Status = ports.ScanFailed
	if err := store.Save(ctx, changed); err != nil {
		t.Fatalf("status-only upsert with another source: %v", err)
	}
	got, err = store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EngagementID != item.EngagementID.String() || got.Target != item.Target() {
		t.Fatalf("status upsert changed source owner/target: %+v", got)
	}
	assertFrozenScanSource(t, got.SourcePackage, item)

	for name, tenantCtx := range map[string]context.Context{
		"missing tenant": context.Background(),
		"wrong tenant":   shared.WithTenant(context.Background(), "foreign-tenant"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := store.CreateRunning(tenantCtx, scanSourceJob(item, "forbidden-"+name)); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("source job tenant context not enforced: %v", err)
			}
		})
	}
}

func TestPostgresScanSourceDatabaseRejectsForgedBindings(t *testing.T) {
	ctx, pool := setupTestDB(t)
	_, item := scanSourceFixture(t, ctx, pool, "source-tenant", "source-assessment")
	_, other := scanSourceFixture(t, ctx, pool, item.TenantID, "other-assessment")
	_, foreign := scanSourceFixture(t, ctx, pool, "foreign-tenant", "foreign-assessment")
	store := NewScanJobStore(pool)
	job := scanSourceJob(item, "source-job")
	if err := store.CreateRunning(shared.WithTenant(ctx, item.TenantID), job); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), item.Locator) || strings.Contains(string(encoded), item.ObjectKey) {
		t.Fatalf("source JSON exposed an object-store locator: %s", encoded)
	}
	var metadata map[string]any
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, key string
		value     any
	}{
		{"filename", "filename", "substituted.zip"},
		{"size", "size", item.Size + 1},
		{"digest", "sha256", strings.Repeat("a", 64)},
		{"uploader", "created_by", "forged-actor"},
		{"upload time", "created_at", item.CreatedAt.Add(time.Hour)},
		{"associator", "associated_by", "forged-actor"},
		{"association time", "associated_at", item.AssociatedAt.Add(time.Hour)},
		{"unknown version", "version_id", strings.Repeat("e", 32)},
		{"other assessment version", "version_id", other.VersionID},
		{"foreign tenant version", "version_id", foreign.VersionID},
		{"foreign tenant", "tenant_id", foreign.TenantID},
		{"other owner", "engagement_id", other.EngagementID},
		{"invented reuse", "reused_from_version_id", other.VersionID},
		{"private locator", "locator", "private-object-key"},
		{"missing version", "version_id", nil},
		{"malformed size", "size", "not-a-number"},
		{"malformed timestamp", "created_at", "not-a-timestamp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := make(map[string]any, len(metadata))
			for key, value := range metadata {
				changed[key] = value
			}
			changed[test.key] = test.value
			forged, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			_, err = pool.Exec(ctx, `INSERT INTO scan_jobs (id,engagement_id,target,kind,status,started_at,source_package)
				VALUES ($1,$2,$3,'upload','running',$4,$5)`, "forged-"+test.name, item.EngagementID, item.Target(), job.StartedAt, forged)
			if err == nil {
				t.Fatalf("database accepted forged source %s", test.name)
			}
		})
	}
	for _, statement := range []string{
		`UPDATE scan_jobs SET source_package=NULL WHERE id=$1`,
		`UPDATE scan_jobs SET source_package=jsonb_set(source_package,'{filename}','"changed.zip"') WHERE id=$1`,
		`UPDATE scan_jobs SET engagement_id='other-assessment' WHERE id=$1`,
		`UPDATE scan_jobs SET target='different-target' WHERE id=$1`,
		`UPDATE scan_jobs SET kind='git' WHERE id=$1`,
	} {
		if _, err := pool.Exec(ctx, statement, job.ID); err == nil {
			t.Fatalf("database allowed source-bound job mutation: %s", statement)
		}
	}
	for _, values := range []struct{ kind, target string }{
		{ports.TargetGit, item.Target()},
		{string(ports.TargetUpload), "wrong-target"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs (id,engagement_id,target,kind,status,started_at,source_package)
			VALUES ($1,$2,$3,$4,'running',$5,$6)`, "wrong-target-"+values.kind, item.EngagementID, values.target, values.kind, job.StartedAt, encoded); err == nil {
			t.Fatalf("database accepted source kind/target mismatch: %+v", values)
		}
	}
	got, err := store.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertFrozenScanSource(t, got.SourcePackage, item)
}

func TestPostgresScanSourceRunManifestFrozenForNativeAndLegacy(t *testing.T) {
	for _, native := range []bool{false, true} {
		name := "legacy"
		if native {
			name = "native"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool := setupTestDB(t)
			sources, item := scanSourceFixture(t, ctx, pool, "source-tenant", "source-assessment")
			ctx = shared.WithTenant(ctx, item.TenantID)
			store := NewScanRunStore(pool)
			run := ports.ScanRun{ID: "source-run", EngagementID: item.EngagementID.String(), CreatedAt: time.Now().UTC().Truncate(time.Microsecond), Manifest: ports.ScanManifest{SourcePackage: &item}}
			manifest, err := json.Marshal(run.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			if native {
				err = store.SaveScanRun(ctx, scanrun.ScanRun{TenantID: item.TenantID, EngagementID: item.EngagementID, ID: run.ID,
					Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: 1,
					CreatedAt: run.CreatedAt, UpdatedAt: run.CreatedAt, LegacyManifest: manifest})
			} else {
				err = store.Save(ctx, run)
			}
			if err != nil {
				t.Fatalf("create %s run: %v", name, err)
			}
			if native {
				if _, err := pool.Exec(ctx, `UPDATE scan_runs SET manifest=manifest-'source_package' WHERE id=$1`, run.ID); err == nil {
					t.Fatal("unsealed native run lost its admitted source")
				}
				finished := run.CreatedAt.Add(time.Minute)
				lane := scanrun.Lane{TenantID: item.TenantID, EngagementID: item.EngagementID, ScanRunID: run.ID,
					LaneKey: "sca", Producer: "synapse-sca", TerminalStatus: scanrun.StatusFailed,
					Target:    scanrun.TargetIdentity{TargetKind: scanrun.TargetRepository, TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: item.Target(), EvaluatedRevision: item.SHA256},
					StartedAt: run.CreatedAt, FinishedAt: &finished, ManifestSchemaVersion: 1}
				lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
				if err != nil {
					t.Fatal(err)
				}
				runHash, err := scanrun.ComputeRunManifestHash([]scanrun.Lane{lane})
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SealScanRun(ctx, ports.SealScanRunCommand{TenantID: item.TenantID, RunID: run.ID, TerminalStatus: scanrun.StatusFailed,
					Lanes: []scanrun.Lane{lane}, ManifestSchemaVersion: 1, ManifestHash: runHash, SealedAt: finished}); err != nil {
					t.Fatalf("seal failed native run with frozen source: %v", err)
				}
			}
			got, err := store.Get(ctx, run.ID)
			if err != nil {
				t.Fatal(err)
			}
			assertFrozenScanSource(t, got.Manifest.SourcePackage, item)
			runs, err := store.List(ctx, item.EngagementID)
			if err != nil || len(runs) != 1 {
				t.Fatalf("list source-bound runs: %v %+v", err, runs)
			}
			assertFrozenScanSource(t, runs[0].Manifest.SourcePackage, item)
			aggregate, err := store.GetScanRun(ctx, item.TenantID, run.ID)
			if err != nil {
				t.Fatal(err)
			}
			if native && (!aggregate.IsSealed() || aggregate.TerminalStatus != scanrun.StatusFailed) {
				t.Fatalf("native source binding prevented terminal sealing: %+v", aggregate)
			}
			var roundTrip ports.ScanManifest
			if err := json.Unmarshal(aggregate.LegacyManifest, &roundTrip); err != nil {
				t.Fatal(err)
			}
			assertFrozenScanSource(t, roundTrip.SourcePackage, item)
			aggregates, err := store.ListScanRuns(ctx, item.TenantID, item.EngagementID)
			if err != nil || len(aggregates) != 1 {
				t.Fatalf("list aggregate source-bound runs: %v %+v", err, aggregates)
			}
			if err := json.Unmarshal(aggregates[0].LegacyManifest, &roundTrip); err != nil {
				t.Fatal(err)
			}
			assertFrozenScanSource(t, roundTrip.SourcePackage, item)
			if _, err := store.Get(shared.WithTenant(ctx, "foreign-tenant"), run.ID); !errors.Is(err, shared.ErrNotFound) {
				t.Fatalf("foreign tenant read source-bound run: %v", err)
			}
			for _, statement := range []string{
				`UPDATE scan_runs SET manifest=manifest-'source_package' WHERE id=$1`,
				`UPDATE scan_runs SET manifest=jsonb_set(manifest,'{source_package,filename}','"changed.zip"') WHERE id=$1`,
				`UPDATE scan_runs SET engagement_id='other-assessment' WHERE id=$1`,
				`UPDATE scan_runs SET tenant_id='foreign-tenant' WHERE id=$1`,
			} {
				if _, err := pool.Exec(ctx, statement, run.ID); err == nil {
					t.Fatalf("database allowed source-bound run mutation: %s", statement)
				}
			}
			if err := sources.Delete(ctx, item.TenantID, item.EngagementID); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("%s run did not retain its source: %v", name, err)
			}
			if _, err := sources.Get(ctx, item.TenantID, item.EngagementID); err != nil {
				t.Fatalf("source missing after refused deletion: %v", err)
			}

			forged := run
			forged.ID = "forged-run"
			changed := item
			changed.VersionID = shared.ID(strings.Repeat("d", 32))
			forged.Manifest.SourcePackage = &changed
			if err := store.Save(ctx, forged); err == nil {
				t.Fatal("run accepted nonexistent source version")
			}
			if err := store.Save(shared.WithTenant(ctx, "foreign-tenant"), run); err == nil {
				t.Fatal("run accepted source owned by another tenant")
			}
		})
	}
}

func TestPostgresScanSourceDoesNotReconstructUnboundHistory(t *testing.T) {
	ctx, pool := setupTestDB(t)
	_, item := scanSourceFixture(t, ctx, pool, "source-tenant", "source-assessment")
	ctx = shared.WithTenant(ctx, item.TenantID)
	jobs := NewScanJobStore(pool)
	for _, kind := range []string{ports.TargetGit, ports.TargetLocal, ports.TargetImage, ports.TargetArchive, ports.TargetUpload} {
		t.Run(kind, func(t *testing.T) {
			job := scanSourceJob(item, "unbound-"+kind)
			job.Kind, job.SourcePackage = kind, nil
			if err := jobs.CreateRunning(ctx, job); err != nil {
				t.Fatalf("existing target kind no longer admitted: %v", err)
			}
			job.Status = ports.ScanFailed
			if err := jobs.Save(ctx, job); err != nil {
				t.Fatalf("unbound status transition failed: %v", err)
			}
			got, err := jobs.GetJob(ctx, job.ID)
			if err != nil || got.SourcePackage != nil {
				t.Fatalf("unbound history acquired current source metadata: %+v %v", got.SourcePackage, err)
			}
		})
	}
	runs := NewScanRunStore(pool)
	run := ports.ScanRun{ID: "unbound-run", EngagementID: item.EngagementID.String(), CreatedAt: time.Now().UTC()}
	if err := runs.Save(ctx, run); err != nil {
		t.Fatal(err)
	}
	got, err := runs.Get(ctx, run.ID)
	if err != nil || got.Manifest.SourcePackage != nil {
		t.Fatalf("legacy run acquired current source metadata: %+v %v", got.Manifest.SourcePackage, err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET source_package=$1 WHERE id='unbound-upload'`, encoded); err == nil {
		t.Fatal("database allowed retroactive source reconstruction on an old job")
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_runs SET manifest=jsonb_set(manifest,'{source_package}',$1::jsonb) WHERE id=$2`, encoded, run.ID); err == nil {
		t.Fatal("database allowed retroactive source reconstruction on an old run")
	}
}

func TestPostgresScanSourceMigrationRollbackGuard(t *testing.T) {
	ctx, pool := setupTestDB(t)
	db, err := goose.OpenDBWithDriver("pgx", pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Empty metadata can safely migrate in both directions.
	if err := goose.DownTo(db, ".", 159); err != nil {
		t.Fatalf("empty source binding rollback: %v", err)
	}
	if err := goose.UpTo(db, ".", 160); err != nil {
		t.Fatal(err)
	}
	_, item := scanSourceFixture(t, ctx, pool, "source-tenant", "source-assessment")
	ctx = shared.WithTenant(ctx, item.TenantID)
	job := scanSourceJob(item, "source-job")
	if err := NewScanJobStore(pool).CreateRunning(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 159); err == nil || !strings.Contains(err.Error(), "cannot roll back source bindings") {
		t.Fatalf("rollback discarded queued source binding: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM scan_jobs WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	run := ports.ScanRun{ID: "source-run", EngagementID: item.EngagementID.String(), CreatedAt: time.Now().UTC(), Manifest: ports.ScanManifest{SourcePackage: &item}}
	if err := NewScanRunStore(pool).Save(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 159); err == nil || !strings.Contains(err.Error(), "cannot roll back source bindings") {
		t.Fatalf("rollback discarded historical run source: %v", err)
	}
}
