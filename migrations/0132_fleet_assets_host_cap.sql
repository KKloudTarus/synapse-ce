-- +goose Up
-- One enrolled agent may create at most 16 host assets (docs/guide/fleet-blue-team.md). The use case
-- counts before it writes, but two syncs from the same agent can both read 15 and both insert. This
-- trigger is the transactional backstop: it serialises new host rows per (tenant, agent) with an
-- advisory lock held to the end of the transaction, recounts under that lock, and refuses the row
-- past the cap. Re-observation of an existing key (the ON CONFLICT update path, which still fires
-- BEFORE INSERT) is exempt so a capped agent keeps syncing the hosts it owns. The number must match
-- hostinventory.MaxHostsPerAgent; migration_0132_test.go pins them together.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION synapse_guard_host_cap_per_agent()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    reporting_agent TEXT;
    owned BIGINT;
BEGIN
    IF NEW.kind <> 'host' THEN
        RETURN NEW;
    END IF;
    reporting_agent := NULLIF(btrim(NEW.attributes ->> 'reporting_agent_id'), '');
    IF reporting_agent IS NULL THEN
        RETURN NEW;
    END IF;
    IF EXISTS (
        SELECT 1
          FROM fleet_assets
         WHERE tenant_id = NEW.tenant_id AND kind = NEW.kind AND "key" = NEW."key"
    ) THEN
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('fleet_assets_host_cap:' || NEW.tenant_id || ':' || reporting_agent, 0));
    SELECT count(*) INTO owned
      FROM fleet_assets
     WHERE tenant_id = NEW.tenant_id
       AND kind = 'host'
       AND NULLIF(btrim(attributes ->> 'reporting_agent_id'), '') = reporting_agent;
    IF owned >= 16 THEN
        RAISE EXCEPTION 'agent % already reports % host assets; a new host key is refused',
            reporting_agent, owned
            USING ERRCODE = '23514', CONSTRAINT = 'fleet_assets_host_cap_per_agent';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER fleet_assets_guard_host_cap
BEFORE INSERT ON fleet_assets
FOR EACH ROW EXECUTE FUNCTION synapse_guard_host_cap_per_agent();

-- +goose Down
DROP TRIGGER IF EXISTS fleet_assets_guard_host_cap ON fleet_assets;
DROP FUNCTION IF EXISTS synapse_guard_host_cap_per_agent();
