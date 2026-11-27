-- +goose Up
-- #1703, second half. 0273 added hash_scheme with DEFAULT 1 so that a binary from before the column could
-- keep inserting. Every writer since v0.3.0 names the scheme, and this release writes scheme 2, so the
-- default can only hide a writer that forgot the column by stamping its row legacy. Without it such an
-- insert fails on NOT NULL. A v0.3.0 binary still running during the rollout names the column and is
-- unaffected. DROP DEFAULT changes the catalog only; lock_timeout keeps the brief ACCESS EXCLUSIVE lock
-- from queueing behind a long transaction on either table.
SET LOCAL lock_timeout = '5s';
ALTER TABLE audit_log ALTER COLUMN hash_scheme DROP DEFAULT;
ALTER TABLE evidence ALTER COLUMN hash_scheme DROP DEFAULT;

-- +goose Down
SET LOCAL lock_timeout = '5s';
ALTER TABLE audit_log ALTER COLUMN hash_scheme SET DEFAULT 1;
ALTER TABLE evidence ALTER COLUMN hash_scheme SET DEFAULT 1;
