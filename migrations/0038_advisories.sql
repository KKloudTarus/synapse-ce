-- +goose Up
-- E34.1 (ADR-0022, detection independence): the OWNED normalized-advisory store. Advisories are GLOBAL
-- reference data – the feed-agnostic, reproducible vulnerability corpus an OSV/CSAF/NVD ingester normalizes
-- into (like the pre-synced NVD DB), queried by the owned DetectionSource (internal/.../tools/ownadvisory)
-- so a scan matches against OUR store instead of a live third party.
--
-- DELIBERATELY NOT tenant-scoped (no tenant_id, a documented exception to the multi-tenant table convention):
-- advisories are shared reference data, not customer data – every tenant matches against the same corpus and
-- there is nothing tenant-private to leak. The full normalized advisory is stored as a JSONB blob (the domain
-- advisory.Advisory shape); a child advisory_affects table holds one row per affected (ecosystem, package) so
-- ByPackage is a single indexed lookup + join. Upsert is idempotent by id (advisories are re-syncable – a
-- re-ingest REPLACES in place), unlike the append-only evidence/audit ledgers.
CREATE TABLE advisories (
    id         TEXT PRIMARY KEY,
    data       JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per affected (ecosystem, package): the indexed lookup table for ByPackage. ecosystem + package are
-- the OSV-canonical, ingester-normalized keys (Maven = "groupId:artifactId" colon-joined, PyPI PEP 503, Go
-- module path, …) per the ports.AdvisoryStore KEY CONTRACT – they MUST match the SBOM component Name or a CVE
-- is silently missed. CASCADE so a re-ingest's DELETE-then-reinsert (and any future advisory removal) stays
-- consistent.
CREATE TABLE advisory_affects (
    advisory_id TEXT NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    ecosystem   TEXT NOT NULL,
    package     TEXT NOT NULL
);
CREATE INDEX idx_advisory_affects_lookup ON advisory_affects(ecosystem, package);
CREATE INDEX idx_advisory_affects_advisory ON advisory_affects(advisory_id);

-- +goose Down
DROP TABLE IF EXISTS advisory_affects;
DROP TABLE IF EXISTS advisories;
