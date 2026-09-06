-- +goose Up
-- Offensive rules of engagement on the engagement aggregate. The offensive governance policy (#418)
-- refuses adversary emulation and exploitation chains until an engagement declares who to contact when an
-- action goes wrong (customer_contact, emergency_contact), the highest risk class an action may carry
-- (risk_ceiling), and that the out-of-scope list was reviewed (exclusions_checked). Backward-compatible:
-- every column defaults to the "unset" value, which the policy then refuses on, so existing engagements
-- keep working and simply cannot run offensive actions until an operator fills the RoE in.
ALTER TABLE engagements ADD COLUMN customer_contact   TEXT    NOT NULL DEFAULT '';
ALTER TABLE engagements ADD COLUMN emergency_contact  TEXT    NOT NULL DEFAULT '';
ALTER TABLE engagements ADD COLUMN risk_ceiling       TEXT    NOT NULL DEFAULT '';
ALTER TABLE engagements ADD COLUMN exclusions_checked BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE engagements ADD CONSTRAINT engagements_risk_ceiling_valid
    CHECK (risk_ceiling IN ('', 'low', 'medium', 'high', 'prohibited'));

-- +goose Down
ALTER TABLE engagements DROP CONSTRAINT IF EXISTS engagements_risk_ceiling_valid;
ALTER TABLE engagements DROP COLUMN IF EXISTS exclusions_checked;
ALTER TABLE engagements DROP COLUMN IF EXISTS risk_ceiling;
ALTER TABLE engagements DROP COLUMN IF EXISTS emergency_contact;
ALTER TABLE engagements DROP COLUMN IF EXISTS customer_contact;
