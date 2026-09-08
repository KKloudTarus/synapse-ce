package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceupload"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sourceDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestPostgresEngagementSourceLifecycleDurabilityAndRetention(t *testing.T) {
	ctx, pool := setupTestDB(t)
	tenant := shared.ID("source-lifecycle-tenant")
	ctx = shared.WithTenant(ctx, tenant)
	for _, eng := range []shared.ID{"source-initial", "source-retest", "source-retest-2", "source-new-upload"} {
		ensureTestTenantAndEngagement(t, ctx, pool, tenant, eng, "", "")
	}
	directory := t.TempDir()
	objects, err := blob.NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	store := sourceupload.NewStoreWithRepository(objects, NewEngagementSourceRepository(pool), 0)
	now := time.Date(2026, 9, 8, 10, 0, 0, 123456789, time.UTC)
	data := []byte("durable uploaded archive")
	initial, err := store.Save(ctx, tenant, "source-initial", "source.zip", "alice", now, int64(len(data)), sourceDigest(data), bytes.NewReader(data))
	if err != nil || initial.VersionID.IsZero() || initial.CreatedAt.Nanosecond() != 123456000 {
		t.Fatalf("initial source: %+v %v", initial, err)
	}
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
	objects, err = blob.NewFilesystem(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	repo := NewEngagementSourceRepository(pool)
	store = sourceupload.NewStoreWithRepository(objects, repo, 0)
	got, err := store.GetByVersion(ctx, tenant, "source-initial", initial.VersionID)
	if err != nil || got != initial {
		t.Fatalf("fresh adapter roundtrip = %+v %v", got, err)
	}
	if replay, err := store.Save(ctx, tenant, "source-initial", "source.zip", "alice", now, int64(len(data)), sourceDigest(data), bytes.NewReader(data)); err != nil || replay.VersionID != initial.VersionID {
		t.Fatalf("upload replay = %+v %v", replay, err)
	}
	child, err := store.Reuse(ctx, tenant, "source-initial", "source-retest", initial.VersionID, "bob", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := store.Reuse(ctx, tenant, "source-retest", "source-retest-2", child.VersionID, "carol", now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []sourcepackage.Package{initial, child, grandchild} {
		if item.ObjectKey != initial.ObjectKey || item.SHA256 != initial.SHA256 || item.CreatedBy != initial.CreatedBy || !item.CreatedAt.Equal(initial.CreatedAt) {
			t.Fatalf("reuse changed original source: %+v", item)
		}
		path, materialized, cleanup, err := store.Materialize(ctx, item.Locator)
		if err != nil {
			t.Fatal(err)
		}
		read, err := os.ReadFile(path)
		_ = cleanup()
		if err != nil || !bytes.Equal(read, data) || materialized.VersionID != item.VersionID {
			t.Fatalf("source materialization = %q %+v %v", read, materialized, err)
		}
	}
	if grandchild.ReusedFromVersionID != child.VersionID || child.ReusedFromVersionID != initial.VersionID || child.AssociatedBy != "bob" {
		t.Fatal("reuse chain or association attribution changed")
	}
	if err := store.Delete(ctx, tenant, "source-initial"); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("parent deletion with child references = %v", err)
	}
	if err := store.Delete(ctx, tenant, "source-retest-2"); err != nil {
		t.Fatal(err)
	}
	reader, err := objects.OpenObject(ctx, initial.ObjectKey)
	if err != nil {
		t.Fatal("deleting child removed shared archive", err)
	}
	_ = reader.Close()
	changed := []byte("new uploaded version")
	newUpload, err := store.Save(ctx, tenant, "source-new-upload", "source.zip", "dave", now.Add(3*time.Hour), int64(len(changed)), sourceDigest(changed), bytes.NewReader(changed))
	if err != nil || newUpload.ObjectKey == initial.ObjectKey || !newUpload.ReusedFromVersionID.IsZero() || newUpload.CreatedBy != "dave" {
		t.Fatalf("new upload = %+v %v", newUpload, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE engagement_source_packages SET created_by='forged' WHERE tenant_id=$1 AND engagement_id=$2`, tenant, "source-new-upload"); !isSourcePGCode(err, "23514") {
		t.Fatalf("metadata mutation = %v", err)
	}
	public := newUpload
	public.ObjectKey, public.Locator = "", ""
	job := ports.ScanJob{ID: "source-bound-job", EngagementID: newUpload.EngagementID.String(), Target: newUpload.Target(), Kind: "upload", SourcePackage: &public, Status: ports.ScanRunning, StartedAt: now}
	if err := NewScanJobStore(pool).CreateRunning(ctx, job); err != nil {
		t.Fatal("source-bound job", err)
	}
	run := ports.ScanRun{ID: "source-bound-run", EngagementID: newUpload.EngagementID.String(), CreatedAt: now, Manifest: ports.ScanManifest{SourcePackage: &public}}
	if err := NewScanRunStore(pool).Save(ctx, run); err != nil {
		t.Fatal("source-bound run", err)
	}
	if err := store.Delete(ctx, tenant, newUpload.EngagementID); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("historical package deletion = %v", err)
	}
	if err := store.DiscardUnpublished(ctx, newUpload); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET source_package=NULL WHERE id=$1`, job.ID); !isSourcePGCode(err, "23514") {
		t.Fatalf("job binding mutation = %v", err)
	}
	gotRun, err := NewScanRunStore(pool).Get(ctx, run.ID)
	if err != nil || gotRun.Manifest.SourcePackage == nil || *gotRun.Manifest.SourcePackage != public {
		t.Fatalf("frozen run metadata = %+v %v", gotRun.Manifest.SourcePackage, err)
	}
}

func isSourcePGCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

func TestPostgresEngagementSourceTenantIsolationAndAtomicCompensation(t *testing.T) {
	ctx, pool := setupTestDB(t)
	tenant := shared.ID("source-owner")
	foreign := shared.ID("source-foreign")
	for _, eng := range []shared.ID{"source-parent", "source-rollback", "source-delete-rollback"} {
		ensureTestTenantAndEngagement(t, ctx, pool, tenant, eng, "", "")
	}
	ensureTestTenantAndEngagement(t, ctx, pool, foreign, "source-foreign-eng", "", "")
	ctx = shared.WithTenant(ctx, tenant)
	objects := blob.NewMemory()
	repo := NewEngagementSourceRepository(pool)
	store := sourceupload.NewStoreWithRepository(objects, repo, 0)
	data := []byte("archive")
	initial, err := store.Save(ctx, tenant, "source-parent", "source.zip", "alice", time.Now(), int64(len(data)), sourceDigest(data), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetByVersion(ctx, foreign, "source-parent", initial.VersionID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant version = %v", err)
	}
	forged := initial
	forged.TenantID, forged.EngagementID = foreign, "source-foreign-eng"
	forged.ReusedFromVersionID, forged.VersionID = initial.VersionID, shared.ID("11111111111111111111111111111111")
	if _, _, err := repo.Create(ctx, forged); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant reuse = %v", err)
	}
	role := pgx.Identifier{fmt.Sprintf("source_rls_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+role+` NOLOGIN NOSUPERUSER NOBYPASSRLS`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DROP OWNED BY `+role)
		_, _ = pool.Exec(ctx, `DROP ROLE `+role)
	})
	if _, err := pool.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT SELECT ON engagement_source_packages TO `+role); err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, foreign.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+role); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM engagement_source_packages`).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("RLS leaked %d packages", count)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var unpublished sourcepackage.Package
	failure := errors.New("completion audit failed")
	err = NewTenantTransactionRunner(pool).Run(ctx, tenant, func(txCtx context.Context) error {
		var err error
		unpublished, err = store.Save(txCtx, tenant, "source-rollback", "source.zip", "alice", time.Now(), int64(len(data)), sourceDigest(data), bytes.NewReader(data))
		if err != nil {
			return err
		}
		if err := store.DiscardUnpublished(txCtx, unpublished); err != nil {
			t.Fatalf("uncommitted discard = %v", err)
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := store.DiscardUnpublished(ctx, unpublished); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.OpenObject(ctx, unpublished.ObjectKey); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unpublished rollback object retained: %v", err)
	}
	err = NewTenantTransactionRunner(pool).Run(ctx, tenant, func(txCtx context.Context) error {
		if err := store.Delete(txCtx, tenant, initial.EngagementID); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if err := store.DiscardUnpublished(ctx, initial); err != nil {
		t.Fatal(err)
	}
	reader, err := objects.OpenObject(ctx, initial.ObjectKey)
	if err != nil {
		t.Fatalf("rolled-back deletion lost original bytes: %v", err)
	}
	read, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || !bytes.Equal(read, data) {
		t.Fatalf("retained original bytes = %q %v", read, err)
	}
}
