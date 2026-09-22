package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAdvisoryMaterializerPostgresSnapshotRejectsPayloadIntroducedAlias pins the invariant that makes
// batched snapshot materialization safe.
//
// Chunk classification resolves each record's identities through the alias rows that already exist. That
// is sound for connectivity recorded in the database, but it cannot see connectivity a record introduces
// in its own payload: on a database with no alias row for either advisory, a record declaring an alias to
// a sibling in the same chunk would look independent, and both could take the batched path and write
// contradicting canonical state.
//
// The reason that shape is unreachable is not the classifier, it is an earlier guard:
// normalizeSourceSnapshot requires every snapshot record's identity set to be exactly its own record ID,
// so an authoritative snapshot record cannot carry an alias at all. That check runs before the table lock
// and before any materialization. This test asserts the guard directly, because batching depends on it
// and a future relaxation of it would silently reopen the hole. It is asserted in both lexical directions
// so that identifier ordering is never what provides the safety.
func TestAdvisoryMaterializerPostgresSnapshotRejectsPayloadIntroducedAlias(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	for _, current := range []struct {
		name            string
		declaringSuffix string
		aliasSuffix     string
	}{
		{name: "alias sorts after declaring id", declaringSuffix: "AAA", aliasSuffix: "BBB"},
		{name: "alias sorts before declaring id", declaringSuffix: "BBB", aliasSuffix: "AAA"},
	} {
		t.Run(current.name, func(t *testing.T) {
			ctx := context.Background()
			if err := MigrateLocked(ctx, dsn); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			pool, err := Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)

			suffix := randHex(t)
			sourceID := shared.ID("src-payload-alias-" + suffix)
			tenantID := shared.ID("tenant-payload-alias-" + suffix)
			jobID := "job-payload-alias-" + suffix
			runID := shared.ID("run-payload-alias-" + suffix)
			if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
				(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
				VALUES($1,$2,$2,'oval',$3,3600,7200,'full')`, sourceID.String(), "oval-payload-alias-"+suffix, "https://example.test/"+sourceID.String()); err != nil {
				t.Fatalf("seed source: %v", err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenantID.String()); err != nil {
				t.Fatalf("seed tenant: %v", err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status) VALUES($1,$2,'vulnerability_sync','{}','queued')`, jobID, tenantID.String()); err != nil {
				t.Fatalf("seed job: %v", err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sync_runs
				(id,source_id,adapter_type,mode,trigger,actor,durable_job_id,state)
				VALUES($1,$2,'oval','full','manual','test',$3,'queued')`, runID.String(), sourceID.String(), jobID); err != nil {
				t.Fatalf("seed run: %v", err)
			}

			declaringID := "CVE-2026-PAYLOADALIAS-" + current.declaringSuffix + "-" + strings.ToUpper(suffix)
			siblingID := "CVE-2026-PAYLOADALIAS-" + current.aliasSuffix + "-" + strings.ToUpper(suffix)
			payloadPackage := "example.com/payload-alias-" + suffix

			declaring := postgresObservationRecordForPackage(sourceID.String(), declaringID, declaringID, "payload alias", payloadPackage)
			declaring.Observation.SourceType = "oval"
			declaring.SyncRunID = runID.String()
			declaring.Observation.Advisory.Aliases = []string{siblingID}

			sibling := postgresObservationRecordForPackage(sourceID.String(), siblingID, siblingID, "payload alias", payloadPackage)
			sibling.Observation.SourceType = "oval"
			sibling.SyncRunID = runID.String()

			materializer := NewAdvisoryMaterializer(pool)
			_, err = materializer.PublishSourceSnapshot(shared.WithTenant(ctx, tenantID), ports.SourceSnapshotPublication{
				SyncRunID: runID, NextCheckpoint: []byte(`{"complete":true}`),
			}, []advisory.ObservationRecord{declaring, sibling})
			if err == nil {
				t.Fatal("a snapshot record carrying an alias must be rejected; batched classification cannot see payload-introduced connectivity")
			}
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("rejection must be a validation error, got %v", err)
			}
			if !strings.Contains(err.Error(), "sole identity") {
				t.Fatalf("rejection must name the sole-identity invariant, got %v", err)
			}

			// Nothing may have been written: the guard runs before the publication transaction does work.
			var revisions int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_revisions WHERE advisory_id = ANY($1::text[])`,
				[]string{declaringID, siblingID}).Scan(&revisions); err != nil {
				t.Fatalf("count revisions: %v", err)
			}
			if revisions != 0 {
				t.Fatalf("rejected snapshot wrote %d revisions, want 0", revisions)
			}
			var aliases int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM advisory_aliases WHERE alias_id = ANY($1::text[])`,
				[]string{declaringID, siblingID}).Scan(&aliases); err != nil {
				t.Fatalf("count aliases: %v", err)
			}
			if aliases != 0 {
				t.Fatalf("rejected snapshot wrote %d alias rows, want 0", aliases)
			}
		})
	}
}
