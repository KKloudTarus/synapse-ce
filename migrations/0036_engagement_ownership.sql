-- +goose Up
-- Phase E ownership: engagements record who created + last modified them, populated from the
-- authenticated actor (PR5b). Default '' = system/unknown (legacy rows + single-tenant bootstrap).
-- created_by is the engagement OWNER – the basis for the per-engagement RBAC ownership checks in
-- PR6. Additive + backward-compatible.
ALTER TABLE engagements ADD COLUMN created_by TEXT NOT NULL DEFAULT '';
ALTER TABLE engagements ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE engagements DROP COLUMN updated_by;
ALTER TABLE engagements DROP COLUMN created_by;
