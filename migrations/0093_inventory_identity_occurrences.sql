-- +goose Up
-- Component identity is the bridge between persisted SBOM inventory and the global advisory matcher.
-- pgcrypto is used only for deterministic SHA-256 fingerprints; no secret material is hashed here.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE components
    ADD COLUMN ecosystem       TEXT NOT NULL DEFAULT '',
    ADD COLUMN package_name    TEXT NOT NULL DEFAULT '',
    ADD COLUMN identity_hash   TEXT NOT NULL DEFAULT '',
    ADD COLUMN identity_status TEXT NOT NULL DEFAULT 'unsupported'
        CHECK (identity_status IN ('resolved', 'unsupported', 'ambiguous')),
    ADD COLUMN identity_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN component_scope TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN reachability TEXT NOT NULL DEFAULT 'unknown',
    ADD COLUMN class_unreferenced BOOLEAN NOT NULL DEFAULT false;

WITH parsed AS (
    SELECT c.id,
           CASE
               WHEN c.purl ~ '^pkg:maven/' THEN 'Maven'
               WHEN c.purl ~ '^pkg:golang/' THEN 'Go'
               WHEN c.purl ~ '^pkg:npm/' THEN 'npm'
               WHEN c.purl ~ '^pkg:pypi/' THEN 'PyPI'
               WHEN c.purl ~ '^pkg:cargo/' THEN 'crates.io'
               WHEN c.purl ~ '^pkg:gem/' THEN 'RubyGems'
               WHEN c.purl ~ '^pkg:nuget/' THEN 'NuGet'
               WHEN c.purl ~ '^pkg:deb/.+\?[^ ]*distro=debian-[0-9]' THEN 'Debian:' || substring(c.purl FROM 'distro=debian-([0-9]+)')
               WHEN c.purl ~ '^pkg:deb/.+\?[^ ]*distro=ubuntu-[0-9]+\.[0-9]+' THEN 'Ubuntu:' || substring(c.purl FROM 'distro=(ubuntu-[0-9]+\.[0-9]+)')
               WHEN c.purl ~ '^pkg:apk/.+\?[^ ]*distro=alpine-[0-9]+\.[0-9]+' THEN 'Alpine:v' || substring(c.purl FROM 'distro=alpine-([0-9]+\.[0-9]+)')
               ELSE ''
           END AS ecosystem,
           CASE
               WHEN c.purl ~ '^pkg:maven/' THEN split_part(split_part(split_part(c.purl, '?', 1), '@', 1), '/', 2)
                   || ':' || split_part(split_part(split_part(c.purl, '?', 1), '@', 1), '/', 3)
               WHEN c.purl ~ '^pkg:golang/' THEN replace(split_part(split_part(c.purl, '?', 1), '@', 1), 'pkg:golang/', '')
               WHEN c.purl ~ '^pkg:npm/' THEN replace(split_part(split_part(c.purl, '?', 1), '@', 1), 'pkg:npm/', '')
               WHEN c.purl ~ '^pkg:pypi/' THEN regexp_replace(lower(replace(split_part(split_part(c.purl, '?', 1), '@', 1), 'pkg:pypi/', '')), '[-_.]+', '-', 'g')
               WHEN c.purl ~ '^pkg:cargo/' THEN replace(split_part(split_part(c.purl, '?', 1), '@', 1), 'pkg:cargo/', '')
               WHEN c.purl ~ '^pkg:gem/' THEN replace(split_part(split_part(c.purl, '?', 1), '@', 1), 'pkg:gem/', '')
               WHEN c.purl ~ '^pkg:nuget/' THEN replace(split_part(split_part(c.purl, '?', 1), '@', 1), 'pkg:nuget/', '')
               WHEN c.purl ~ '^pkg:(deb|apk|rpm)/' THEN regexp_replace(split_part(split_part(c.purl, '?', 1), '@', 1), '^.*/', '')
               ELSE ''
           END AS package_name
    FROM components c
    WHERE c.identity_hash = ''
)
UPDATE components c
SET ecosystem = p.ecosystem,
    package_name = p.package_name,
    identity_status = CASE WHEN p.ecosystem <> '' AND p.package_name <> '' AND c.version <> '' THEN 'resolved' ELSE 'unsupported' END,
    identity_reason = CASE WHEN p.ecosystem <> '' AND p.package_name <> '' AND c.version <> '' THEN '' ELSE 'legacy_backfill_unresolved' END,
    identity_hash = CASE WHEN p.ecosystem <> '' AND p.package_name <> '' AND c.version <> ''
        THEN encode(digest(
            convert_to(p.ecosystem, 'UTF8') || decode('00', 'hex') ||
            convert_to(p.package_name, 'UTF8') || decode('00', 'hex') ||
            convert_to(c.version, 'UTF8') || decode('00', 'hex') ||
            convert_to(c.purl, 'UTF8'),
            'sha256'
        ), 'hex')
        ELSE '' END
FROM parsed p
WHERE c.id = p.id;

CREATE INDEX idx_components_identity_lookup
    ON components(tenant_id, ecosystem, package_name, identity_hash, id)
    WHERE identity_status = 'resolved';
CREATE INDEX idx_components_identity_status
    ON components(tenant_id, identity_status, id);

CREATE TABLE vulnerability_occurrences (
    tenant_id             TEXT NOT NULL REFERENCES tenants(id),
    id                    TEXT NOT NULL,
    engagement_id         TEXT NOT NULL,
    advisory_id           TEXT NOT NULL REFERENCES advisories(id),
    component_id          TEXT NOT NULL,
    sbom_id               TEXT NOT NULL,
    component_fingerprint TEXT NOT NULL,
    ecosystem             TEXT NOT NULL,
    package_name          TEXT NOT NULL,
    component_version     TEXT NOT NULL,
    fixed_version         TEXT NOT NULL DEFAULT '',
    match_method          TEXT NOT NULL CHECK (match_method IN ('package_range', 'explicit_version', 'cpe')),
    confidence            TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low', 'unknown')),
    advisory_revision     BIGINT NOT NULL CHECK (advisory_revision > 0),
    scope                 TEXT NOT NULL DEFAULT 'unknown',
    reachability          TEXT NOT NULL DEFAULT 'unknown',
    class_unreferenced    BOOLEAN NOT NULL DEFAULT false,
    state                 TEXT NOT NULL CHECK (state IN ('detected', 'no_longer_detected', 'withdrawn')),
    first_detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_evaluated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_reexposed_at     TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, engagement_id, advisory_id, component_fingerprint),
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagements(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, component_id) REFERENCES components(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, sbom_id) REFERENCES sboms(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_vulnerability_occurrences_current
    ON vulnerability_occurrences(tenant_id, engagement_id, state, advisory_id, updated_at DESC);
CREATE INDEX idx_vulnerability_occurrences_advisory
    ON vulnerability_occurrences(tenant_id, advisory_id, state, component_fingerprint);
CALL synapse_enable_tenant_rls('vulnerability_occurrences');

CREATE TABLE vulnerability_occurrence_events (
    tenant_id         TEXT NOT NULL REFERENCES tenants(id),
    id                TEXT NOT NULL,
    occurrence_id     TEXT NOT NULL,
    event_type        TEXT NOT NULL CHECK (event_type IN ('detected', 'updated', 'no_longer_detected', 'withdrawn', 'reexposed')),
    advisory_revision BIGINT NOT NULL CHECK (advisory_revision > 0),
    from_state        TEXT NOT NULL DEFAULT '',
    to_state          TEXT NOT NULL,
    details           JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, occurrence_id, event_type, advisory_revision, created_at),
    FOREIGN KEY (tenant_id, occurrence_id) REFERENCES vulnerability_occurrences(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX idx_vulnerability_occurrence_events_lookup
    ON vulnerability_occurrence_events(tenant_id, occurrence_id, created_at DESC);
CALL synapse_enable_tenant_rls('vulnerability_occurrence_events');

-- +goose Down
DROP TABLE IF EXISTS vulnerability_occurrence_events;
DROP TABLE IF EXISTS vulnerability_occurrences;
DROP INDEX IF EXISTS idx_components_identity_status;
DROP INDEX IF EXISTS idx_components_identity_lookup;
ALTER TABLE components
    DROP COLUMN IF EXISTS class_unreferenced,
    DROP COLUMN IF EXISTS reachability,
    DROP COLUMN IF EXISTS component_scope,
    DROP COLUMN IF EXISTS identity_reason,
    DROP COLUMN IF EXISTS identity_status,
    DROP COLUMN IF EXISTS identity_hash,
    DROP COLUMN IF EXISTS package_name,
    DROP COLUMN IF EXISTS ecosystem;
