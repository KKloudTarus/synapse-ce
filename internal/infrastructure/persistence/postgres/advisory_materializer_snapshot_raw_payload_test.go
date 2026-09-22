package postgres

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAdvisoryMaterializerPostgresSnapshotPreservesBinaryRawPayload pins byte fidelity for retained raw
// provider payloads across a batched publication.
//
// advisory_observations.raw_payload is BYTEA and the Go field is []byte, so the bulk upsert must bind it
// through a bytea[] parameter. An earlier version of the batched path routed it through text[], which
// PostgreSQL rejects or mangles for bytes that are not valid UTF-8 and cannot carry a NUL at all. The
// existing suite never exercised RawPayload on this path, so that defect was invisible: the fix was as
// untested as the bug. This fixture deliberately includes a NUL byte, an invalid UTF-8 sequence, and a
// high-bit run, and asserts the stored bytes are returned unchanged.
//
// raw_reference is separately covered here because it is NOT NULL DEFAULT ”, and an earlier version
// applied NULLIF(...,”) to it, which turned every empty reference into a constraint violation.
func TestAdvisoryMaterializerPostgresSnapshotPreservesBinaryRawPayload(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	sourceID := shared.ID("src-raw-bytes-" + suffix)
	tenantID := shared.ID("tenant-raw-bytes-" + suffix)
	jobID := "job-raw-bytes-" + suffix
	runID := shared.ID("run-raw-bytes-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO vulnerability_sources
		(id,source_key,display_name,adapter_type,endpoint,cadence_seconds,stale_after_seconds,sync_mode)
		VALUES($1,$2,$2,'oval',$3,3600,7200,'full')`, sourceID.String(), "oval-raw-bytes-"+suffix, "https://example.test/"+sourceID.String()); err != nil {
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

	// Bytes that a text[] round-trip cannot survive: an embedded NUL, a lone continuation byte and a
	// truncated multi-byte sequence (both invalid UTF-8), plus a high-bit run. Gzip-like magic is included
	// because real OVAL payloads are retained compressed.
	binaryPayload := []byte{
		0x1f, 0x8b, 0x08, 0x00, // gzip magic + flags
		0x00,       // NUL
		0x80, 0xbf, // lone continuation bytes, invalid UTF-8
		0xc3,             // truncated 2-byte sequence start
		0xff, 0xfe, 0xfd, // high-bit run
		'o', 'v', 'a', 'l',
		0x00, 0x01, 0x02,
	}
	packageName := "example.com/raw-bytes-" + suffix
	// A snapshot record's identity must be exactly its own record ID, so the record ID IS the advisory ID.
	withPayloadID := "CVE-2026-RAWBYTES-A-" + strings.ToUpper(suffix)
	withPayload := postgresObservationRecordForPackage(sourceID.String(), withPayloadID, withPayloadID, "raw bytes", packageName)
	withPayload.Observation.SourceType = "oval"
	withPayload.SyncRunID = runID.String()
	withPayload.RawPayload = binaryPayload
	withPayload.RawReference = "https://example.test/raw/" + suffix + ".xml.gz"

	// An empty raw reference must remain the empty string, not become NULL.
	withoutPayloadID := "CVE-2026-RAWBYTES-B-" + strings.ToUpper(suffix)
	withoutPayload := postgresObservationRecordForPackage(sourceID.String(), withoutPayloadID, withoutPayloadID, "raw bytes", packageName)
	withoutPayload.Observation.SourceType = "oval"
	withoutPayload.SyncRunID = runID.String()

	materializer := NewAdvisoryMaterializer(pool)
	if _, err := materializer.PublishSourceSnapshot(shared.WithTenant(ctx, tenantID), ports.SourceSnapshotPublication{
		SyncRunID: runID, NextCheckpoint: []byte(`{"complete":true}`),
	}, []advisory.ObservationRecord{withPayload, withoutPayload}); err != nil {
		t.Fatalf("publish source snapshot: %v", err)
	}

	var stored []byte
	var reference string
	if err := pool.QueryRow(ctx, `SELECT raw_payload, raw_reference FROM advisory_observations
		WHERE source_id=$1 AND record_id=$2 AND is_current`, sourceID.String(), withPayload.Observation.RecordID).Scan(&stored, &reference); err != nil {
		t.Fatalf("read retained raw payload: %v", err)
	}
	if !bytes.Equal(stored, binaryPayload) {
		t.Fatalf("raw payload round-trip corrupted the bytes:\n stored %#v\n want   %#v", stored, binaryPayload)
	}
	if reference != withPayload.RawReference {
		t.Fatalf("raw reference = %q, want %q", reference, withPayload.RawReference)
	}

	var emptyReference string
	var absentPayload []byte
	if err := pool.QueryRow(ctx, `SELECT raw_reference, raw_payload FROM advisory_observations
		WHERE source_id=$1 AND record_id=$2 AND is_current`, sourceID.String(), withoutPayload.Observation.RecordID).Scan(&emptyReference, &absentPayload); err != nil {
		t.Fatalf("read observation without raw payload: %v", err)
	}
	if emptyReference != "" {
		t.Fatalf("absent raw reference = %q, want the empty string", emptyReference)
	}
	if len(absentPayload) != 0 {
		t.Fatalf("absent raw payload = %#v, want empty", absentPayload)
	}
}
