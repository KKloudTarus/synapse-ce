-- +goose Up
-- Durable logical-import receipts (#1181).
--
-- This table is additive and intentionally has no production writer in this migration slice. Readers
-- and storage contracts land before #1183 composes ingestion into them, preserving feature-off behavior.
CREATE TABLE import_receipts (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    engagement_id      TEXT NOT NULL,
    source_identity    TEXT NOT NULL CHECK (source_identity <> ''),
    digest             TEXT NOT NULL CHECK (digest <> ''),
    parser_version     TEXT NOT NULL CHECK (parser_version <> ''),
    outcome            TEXT NOT NULL CHECK (outcome IN ('pending','complete','partial','failed')),
    accepted_count     INTEGER NOT NULL DEFAULT 0 CHECK (accepted_count >= 0),
    deduplicated_count INTEGER NOT NULL DEFAULT 0 CHECK (deduplicated_count >= 0),
    refused_count      INTEGER NOT NULL DEFAULT 0 CHECK (refused_count >= 0),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (updated_at >= created_at),
    CHECK (outcome <> 'complete' OR refused_count = 0)
);

-- One receipt represents one logical source document within one tenant engagement. Parser version is
-- metadata, not identity: retries after a parser deployment must resolve the original receipt.
CREATE UNIQUE INDEX import_receipts_idem ON import_receipts
    (tenant_id, engagement_id, source_identity, digest);

CREATE INDEX import_receipts_engagement_created ON import_receipts
    (tenant_id, engagement_id, created_at DESC, id DESC);

CALL synapse_enable_tenant_rls('import_receipts');

-- Identity and parser provenance never change. Outcome/counters have exactly one permitted mutation:
-- a pending receipt may finalize once. This leaves #1183 a narrow recovery seam without exposing a
-- generic rewrite path for historical receipts.
-- +goose StatementBegin
CREATE FUNCTION synapse_guard_import_receipt_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.engagement_id IS DISTINCT FROM OLD.engagement_id
       OR NEW.source_identity IS DISTINCT FROM OLD.source_identity
       OR NEW.digest IS DISTINCT FROM OLD.digest
       OR NEW.parser_version IS DISTINCT FROM OLD.parser_version
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'import receipt identity/provenance is immutable';
    END IF;

    IF OLD.outcome <> 'pending' THEN
        RAISE EXCEPTION 'terminal import receipt is immutable';
    END IF;
    IF NEW.outcome NOT IN ('complete','partial','failed') THEN
        RAISE EXCEPTION 'pending import receipt may only transition to a terminal outcome';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER import_receipts_guard_update
    BEFORE UPDATE ON import_receipts
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_import_receipt_update();

-- +goose Down
DROP TRIGGER IF EXISTS import_receipts_guard_update ON import_receipts;
DROP FUNCTION IF EXISTS synapse_guard_import_receipt_update();
DROP TABLE import_receipts;
