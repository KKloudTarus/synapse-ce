-- +goose Up
-- Allow a direct GitHub Advisory Database provider (EPIC #860 D1.10). Widening the adapter_type CHECK is
-- backward-compatible: every existing row still satisfies it. The constraint is the inline auto-named one
-- from migration 0090 (vulnerability_sources_adapter_type_check).
ALTER TABLE vulnerability_sources DROP CONSTRAINT vulnerability_sources_adapter_type_check;
ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_adapter_type_check
    CHECK (adapter_type IN ('osv','csaf','oval','nvd','ghsa','cisa_kev','first_epss','public_exploit'));

-- +goose Down
ALTER TABLE vulnerability_sources DROP CONSTRAINT vulnerability_sources_adapter_type_check;
ALTER TABLE vulnerability_sources ADD CONSTRAINT vulnerability_sources_adapter_type_check
    CHECK (adapter_type IN ('osv','csaf','oval','nvd','cisa_kev','first_epss','public_exploit'));
