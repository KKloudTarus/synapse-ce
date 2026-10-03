-- +goose Up
-- Break-glass recovery secrets are high-entropy values held only by their recipient. This schema
-- retains their SHA-256 digest, one-use consumption evidence, and a non-secret alert obligation.
ALTER TABLE identity_policies ADD COLUMN activation_time TIMESTAMPTZ;
ALTER TABLE identity_policies ADD COLUMN grace_enabled BOOLEAN NOT NULL DEFAULT false;
CREATE TABLE identity_recovery_policies (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) CHECK (tenant_id <> ''),
    alert_configured BOOLEAN NOT NULL DEFAULT false,
    last_rehearsed_at TIMESTAMPTZ,
	last_alert_tested_at TIMESTAMPTZ,
    version INT NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (last_rehearsed_at IS NULL OR last_rehearsed_at <= updated_at)
);
CALL synapse_enable_tenant_rls('identity_recovery_policies');

CREATE TABLE identity_recovery_activations (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    membership_id TEXT NOT NULL,
    person_id TEXT NOT NULL,
    secret_digest TEXT NOT NULL CHECK (secret_digest ~ '^[0-9a-f]{64}$'),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 256),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_session_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,id),
    UNIQUE (secret_digest),
    FOREIGN KEY (tenant_id,membership_id) REFERENCES identity_memberships(tenant_id,id),
    CHECK (expires_at > created_at),
    CHECK ((consumed_at IS NULL) = (consumed_session_id IS NULL))
);
CALL synapse_enable_tenant_rls('identity_recovery_activations');
CREATE INDEX identity_recovery_activations_active ON identity_recovery_activations(tenant_id,membership_id) WHERE consumed_at IS NULL;

-- This owner-only index is the sole global recovery lookup surface. Tenant RLS stays FORCE on
-- activations; the index holds only an exact digest and tenant routing state.
CREATE TABLE identity_recovery_activation_routes (
    secret_digest TEXT PRIMARY KEY CHECK (secret_digest ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    active BOOLEAN NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
REVOKE ALL ON identity_recovery_activation_routes FROM PUBLIC;
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_index_recovery_activation()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $index$
BEGIN
  IF TG_OP = 'DELETE' THEN
    DELETE FROM public.identity_recovery_activation_routes WHERE secret_digest=OLD.secret_digest;
    RETURN OLD;
  END IF;
  INSERT INTO public.identity_recovery_activation_routes(secret_digest,tenant_id,active,expires_at)
  VALUES(NEW.secret_digest,NEW.tenant_id,NEW.consumed_at IS NULL,NEW.expires_at)
  ON CONFLICT(secret_digest) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,active=EXCLUDED.active,expires_at=EXCLUDED.expires_at;
  RETURN NEW;
END;
$index$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_index_recovery_activation() FROM PUBLIC;
CREATE TRIGGER identity_recovery_activations_route AFTER INSERT OR UPDATE OR DELETE ON identity_recovery_activations
 FOR EACH ROW EXECUTE FUNCTION synapse_identity_index_recovery_activation();

CREATE TABLE identity_recovery_alerts (
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    id TEXT NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    membership_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','delivered','exhausted')),
    attempts INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INT NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	lease_until TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 512),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id),
    UNIQUE (tenant_id,session_id),
    FOREIGN KEY (tenant_id,membership_id) REFERENCES identity_memberships(tenant_id,id),
    FOREIGN KEY (tenant_id,session_id) REFERENCES identity_sessions(tenant_id,id)
);
CALL synapse_enable_tenant_rls('identity_recovery_alerts');
CREATE INDEX identity_recovery_alerts_due ON identity_recovery_alerts(tenant_id,next_attempt_at) WHERE state='pending';

-- Locate a tenant only for an exact, active digest. The runtime role receives execute via the
-- grant helper; it never receives an enumeration or prefix-search capability.
-- +goose StatementBegin
CREATE FUNCTION synapse_identity_recovery_activation_tenant(p_digest TEXT)
RETURNS TEXT LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $locator$
 SELECT a.tenant_id FROM public.identity_recovery_activation_routes a
 WHERE p_digest ~ '^[0-9a-f]{64}$' AND a.secret_digest=p_digest
   AND a.active AND a.expires_at > clock_timestamp()
 LIMIT 1
$locator$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_recovery_activation_tenant(TEXT) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION synapse_identity_recovery_person_epoch(p_digest TEXT, p_person_id TEXT)
RETURNS BIGINT LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $epoch$
 SELECT p.epoch FROM public.identity_recovery_activations a
 JOIN public.identity_persons p ON p.id=a.person_id AND p.state='active'
 WHERE p_digest ~ '^[0-9a-f]{64}$' AND a.secret_digest=p_digest
   AND a.person_id=p_person_id AND a.consumed_at IS NULL AND a.expires_at > clock_timestamp()
 LIMIT 1
$epoch$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION synapse_identity_recovery_person_epoch(TEXT,TEXT) FROM PUBLIC;

-- +goose Down
ALTER TABLE identity_recovery_alerts NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_recovery_activations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_recovery_policies NO FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM identity_recovery_alerts) OR EXISTS(SELECT 1 FROM identity_recovery_activations) OR EXISTS(SELECT 1 FROM identity_recovery_policies) THEN
  RAISE EXCEPTION 'populated identity recovery state requires forward repair';
 END IF;
END $$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS synapse_identity_recovery_person_epoch(TEXT,TEXT);
DROP FUNCTION IF EXISTS synapse_identity_recovery_activation_tenant(TEXT);
DROP TRIGGER IF EXISTS identity_recovery_activations_route ON identity_recovery_activations;
DROP FUNCTION IF EXISTS synapse_identity_index_recovery_activation();
DROP TABLE IF EXISTS identity_recovery_alerts;
DROP TABLE IF EXISTS identity_recovery_activation_routes;
DROP TABLE IF EXISTS identity_recovery_activations;
DROP TABLE IF EXISTS identity_recovery_policies;
ALTER TABLE identity_policies DROP COLUMN IF EXISTS grace_enabled;
ALTER TABLE identity_policies DROP COLUMN IF EXISTS activation_time;
