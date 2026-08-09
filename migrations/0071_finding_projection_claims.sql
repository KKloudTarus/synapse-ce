-- +goose Up
-- One publishable CapSAST judgment has exactly one durable finding projection.
CREATE TABLE finding_projection_claims (
    tenant_id     TEXT NOT NULL REFERENCES tenants(id),
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    judgment_id   TEXT NOT NULL,
    mode          TEXT NOT NULL CHECK (mode IN ('sast', 'dast')),
    PRIMARY KEY (tenant_id, engagement_id, judgment_id)
);

CALL synapse_enable_tenant_rls('finding_projection_claims');

-- +goose StatementBegin
CREATE FUNCTION finding_projection_claim_tenant_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM engagements e
        WHERE e.id = NEW.engagement_id
          AND COALESCE(NULLIF(e.tenant_id, ''), 'default') = NEW.tenant_id
    ) THEN
        RAISE EXCEPTION 'finding projection claim tenant does not own engagement';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER finding_projection_claim_tenant_guard
    BEFORE INSERT OR UPDATE ON finding_projection_claims
    FOR EACH ROW EXECUTE FUNCTION finding_projection_claim_tenant_guard();

-- +goose Down
DROP TRIGGER finding_projection_claim_tenant_guard ON finding_projection_claims;
DROP FUNCTION finding_projection_claim_tenant_guard();
DROP TABLE finding_projection_claims;
