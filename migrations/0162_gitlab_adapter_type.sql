-- +goose Up
-- Allow a direct GitLab (gemnasium-db) advisory provider (EPIC #860 D1.10). Widening the adapter_type CHECK
-- is backward-compatible: every existing row still satisfies it.
ALTER TABLE vulnerability_sources DROP CONSTRAINT vulnerability_sources_adapter_type_check;
ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_adapter_type_check
    CHECK (adapter_type IN ('osv','csaf','oval','nvd','ghsa','gitlab','cisa_kev','first_epss','public_exploit'));

-- +goose Down
ALTER TABLE vulnerability_sources DROP CONSTRAINT vulnerability_sources_adapter_type_check;
ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_adapter_type_check
    CHECK (adapter_type IN ('osv','csaf','oval','nvd','ghsa','cisa_kev','first_epss','public_exploit'));
