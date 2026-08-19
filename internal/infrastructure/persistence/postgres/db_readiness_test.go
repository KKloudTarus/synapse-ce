package postgres

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"testing/fstest"
)

func TestCompareMigrationStates(t *testing.T) {
	tests := []struct {
		name     string
		expected []int64
		actual   []migrationState
		wantErr  bool
	}{
		{name: "all embedded migrations applied", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 3, applied: true}}},
		{name: "newer applied migration", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 3, applied: true}, {version: 4, applied: true}}},
		{name: "multiple newer applied migrations", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 3, applied: true}, {version: 4, applied: true}, {version: 5, applied: true}}},
		{name: "missing embedded migration", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}}, wantErr: true},
		{name: "latest state down", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 3, applied: false}}, wantErr: true},
		{name: "divergent applied migration", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 2, applied: true}, {version: 3, applied: true}}, wantErr: true},
		{name: "divergent down migration", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 2, applied: false}, {version: 3, applied: true}}, wantErr: true},
		{name: "newer down migration", expected: []int64{1, 3}, actual: []migrationState{{version: 1, applied: true}, {version: 3, applied: true}, {version: 4, applied: false}}, wantErr: true},
		{name: "duplicate latest state", expected: []int64{1}, actual: []migrationState{{version: 1, applied: true}, {version: 1, applied: true}}, wantErr: true},
		{name: "duplicate embedded version", expected: []int64{1, 1}, actual: []migrationState{{version: 1, applied: true}}, wantErr: true},
		{name: "empty expected migrations", actual: nil, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := compareMigrationStates(tt.expected, tt.actual)
			if (err != nil) != tt.wantErr {
				t.Fatalf("compareMigrationStates() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestMigrationVersions(t *testing.T) {
	tests := []struct {
		name    string
		files   fstest.MapFS
		want    []int64
		wantErr bool
	}{
		{
			name: "sorted SQL versions",
			files: fstest.MapFS{
				"0010_tenth.sql":  {},
				"0002_second.sql": {},
				"README.md":       {},
			},
			want: []int64{2, 10},
		},
		{name: "missing separator", files: fstest.MapFS{"0001.sql": {}}, wantErr: true},
		{name: "empty description follows Goose", files: fstest.MapFS{"0001_.sql": {}}, want: []int64{1}},
		{name: "non-numeric version", files: fstest.MapFS{"next_change.sql": {}}, wantErr: true},
		{name: "non-positive version", files: fstest.MapFS{"0000_init.sql": {}}, wantErr: true},
		{
			name: "duplicate version",
			files: fstest.MapFS{
				"0001_first.sql":  {},
				"1_duplicate.sql": {},
			},
			wantErr: true,
		},
		{name: "no SQL migrations", files: fstest.MapFS{"README.md": {}}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := migrationVersions(tt.files)
			if (err != nil) != tt.wantErr {
				t.Fatalf("migrationVersions() error = %v, wantErr %t", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("migrationVersions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEmbeddedMigrationVersionsConcurrent(t *testing.T) {
	want, err := embeddedMigrationVersions()
	if err != nil {
		t.Fatal(err)
	}

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := embeddedMigrationVersions()
			if err != nil {
				errs <- err
				return
			}
			if !reflect.DeepEqual(got, want) {
				errs <- fmt.Errorf("embeddedMigrationVersions() = %v, want %v", got, want)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestPostgresReadinessChecks(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	if err := CheckDatabaseReady(ctx, pool); err != nil {
		t.Fatalf("migrated database should be reachable: %v", err)
	}
	if err := CheckMigrationsReady(ctx, pool); err != nil {
		t.Fatalf("all embedded migrations should be ready: %v", err)
	}

	// A migrate-first rollout may leave a newer, applied migration while an older
	// API binary is still serving. A later down record for that version is not ready.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var latest int64
	if err := tx.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	newer := latest + 1
	if _, err := tx.Exec(ctx, `INSERT INTO goose_db_version(version_id, is_applied) VALUES($1, true)`, newer); err != nil {
		t.Fatal(err)
	}
	if err := checkMigrationsReady(ctx, tx); err != nil {
		t.Fatalf("a newer applied migration should be ready: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goose_db_version(version_id, is_applied) VALUES($1, false)`, newer); err != nil {
		t.Fatal(err)
	}
	if err := checkMigrationsReady(ctx, tx); err == nil {
		t.Fatal("a newer down record must make migrations not ready")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// Goose retains migration history. A latest down record for an embedded
	// migration remains not ready even when its historical up record exists.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO goose_db_version(version_id, is_applied) VALUES($1, false)`, latest); err != nil {
		t.Fatal(err)
	}
	if err := checkMigrationsReady(ctx, tx); err == nil {
		t.Fatal("a required migration down record must make migrations not ready")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	pool.Close()
	if err := CheckDatabaseReady(ctx, pool); err == nil {
		t.Fatal("a closed database pool must not be ready")
	}
}
