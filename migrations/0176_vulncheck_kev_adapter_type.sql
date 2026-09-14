-- +goose Up
-- Keep PostgreSQL source validation aligned with the code-owned adapter registry. VulnCheck KEV is
-- credential-backed, but the database stores only its secret-manager reference like every other source.
ALTER TABLE vulnerability_sources DROP CONSTRAINT vulnerability_sources_adapter_type_check;
ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_adapter_type_check
    CHECK (adapter_type IN ('osv','csaf','oval','nvd','ghsa','gitlab','cisa_kev','vulncheck_kev','first_epss','public_exploit'));

-- +goose Down
ALTER TABLE vulnerability_sources DROP CONSTRAINT vulnerability_sources_adapter_type_check;
ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_adapter_type_check
    CHECK (adapter_type IN ('osv','csaf','oval','nvd','ghsa','gitlab','cisa_kev','first_epss','public_exploit'));
