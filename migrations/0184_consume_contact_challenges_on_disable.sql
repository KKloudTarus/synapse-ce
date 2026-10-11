-- +goose Up
-- Disabling a principal must burn outstanding verification challenges even when
-- the update does not go through the contact service. Delivery also rechecks
-- disabled at send time; this fence stops a code that was already mailed.
-- +goose StatementBegin
CREATE FUNCTION synapse_consume_contact_challenges() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous_tenant TEXT;
BEGIN
  IF NEW.disabled AND NOT OLD.disabled THEN
    previous_tenant := current_setting('app.current_tenant', true);
    PERFORM set_config('app.current_tenant', NEW.ownership_tenant_id, true);
    UPDATE user_contact_challenges
       SET consumed_at = now()
     WHERE tenant_id = NEW.ownership_tenant_id
       AND user_id = NEW.id
       AND consumed_at IS NULL;
    PERFORM set_config('app.current_tenant', coalesce(previous_tenant, ''), true);
  END IF;
  RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER users_consume_contact_challenges
  AFTER UPDATE OF disabled ON users
  FOR EACH ROW EXECUTE FUNCTION synapse_consume_contact_challenges();

-- +goose Down
DROP TRIGGER users_consume_contact_challenges ON users;
DROP FUNCTION synapse_consume_contact_challenges();
