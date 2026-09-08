-- +goose Up
-- A visible Assessment's optional Project is distinct from the hidden analysis
-- context in engagements.project_id. Neither association can cross a tenant.
ALTER TABLE engagements ADD COLUMN assessment_project_id TEXT;
ALTER TABLE engagements ADD CONSTRAINT engagements_assessment_project_fk
    FOREIGN KEY (tenant_id, assessment_project_id) REFERENCES projects(tenant_id,id) ON DELETE RESTRICT;
ALTER TABLE engagements ADD CONSTRAINT engagements_visible_project_check
    CHECK (assessment_project_id IS NULL OR (project_id IS NULL AND host_asset_id IS NULL));

-- Recover the already-frozen association without changing Cycle ownership.
UPDATE engagements e SET assessment_project_id=c.project_id
FROM assessment_cycle_members m JOIN assessment_cycles c ON c.tenant_id=m.tenant_id AND c.id=m.cycle_id
WHERE e.tenant_id=m.tenant_id AND e.id=m.assessment_id AND e.project_id IS NULL AND e.host_asset_id IS NULL AND c.project_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_visible_assessment_boundary() RETURNS trigger AS $$
BEGIN
    IF (NEW.assessment_project_id,NEW.project_id,NEW.host_asset_id,NEW.business_asset_id)
        IS DISTINCT FROM (OLD.assessment_project_id,OLD.project_id,OLD.host_asset_id,OLD.business_asset_id)
       AND EXISTS (SELECT 1 FROM assessment_cycle_members WHERE tenant_id=OLD.tenant_id AND assessment_id=OLD.id) THEN
        IF NEW.business_asset_id IS DISTINCT FROM OLD.business_asset_id THEN
            RAISE EXCEPTION 'Assessment Cycle membership freezes the Business Asset boundary'
                USING ERRCODE='23514', CONSTRAINT='assessment_cycle_frozen_business_asset';
        END IF;
        RAISE EXCEPTION 'Assessment Cycle membership freezes the Project boundary'
            USING ERRCODE='23514', CONSTRAINT='assessment_cycle_frozen_project';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER engagements_visible_assessment_boundary_guard
    BEFORE UPDATE OF assessment_project_id,project_id,host_asset_id,business_asset_id ON engagements
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_visible_assessment_boundary();

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_assessment_member_boundary() RETURNS trigger AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM engagements e JOIN assessment_cycles c ON c.tenant_id=e.tenant_id
        WHERE e.tenant_id=NEW.tenant_id AND e.id=NEW.assessment_id AND c.id=NEW.cycle_id
          AND e.project_id IS NULL AND e.host_asset_id IS NULL
          AND e.business_asset_id IS NOT DISTINCT FROM c.business_asset_id
          AND e.assessment_project_id IS NOT DISTINCT FROM c.project_id
    ) THEN
        RAISE EXCEPTION 'Assessment must match the exact frozen Cycle boundary' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER assessment_cycle_members_boundary_guard
    BEFORE INSERT OR UPDATE OF tenant_id,cycle_id,assessment_id ON assessment_cycle_members
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_assessment_member_boundary();

-- +goose StatementBegin
CREATE FUNCTION synapse_guard_cycle_boundary() RETURNS trigger AS $$
BEGIN
    IF (NEW.tenant_id,NEW.id,NEW.boundary_kind,NEW.business_asset_id,NEW.project_id,NEW.root_assessment_id)
        IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.boundary_kind,OLD.business_asset_id,OLD.project_id,OLD.root_assessment_id) THEN
        RAISE EXCEPTION 'Assessment Cycle identity, root and boundary are immutable'
            USING ERRCODE='23514', CONSTRAINT='assessment_cycle_frozen_boundary';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER assessment_cycles_boundary_guard
    BEFORE UPDATE ON assessment_cycles
    FOR EACH ROW EXECUTE FUNCTION synapse_guard_cycle_boundary();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM engagements WHERE assessment_project_id IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot roll back visible Assessment Projects while associations exist';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER assessment_cycle_members_boundary_guard ON assessment_cycle_members;
DROP TRIGGER assessment_cycles_boundary_guard ON assessment_cycles;
DROP FUNCTION synapse_guard_cycle_boundary();
DROP FUNCTION synapse_guard_assessment_member_boundary();
DROP TRIGGER engagements_visible_assessment_boundary_guard ON engagements;
DROP FUNCTION synapse_guard_visible_assessment_boundary();
ALTER TABLE engagements DROP CONSTRAINT engagements_visible_project_check;
ALTER TABLE engagements DROP CONSTRAINT engagements_assessment_project_fk;
ALTER TABLE engagements DROP COLUMN assessment_project_id;
