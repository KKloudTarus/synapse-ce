-- +goose Up
-- #638 governed response: the telemetry-verified post-condition axis. A command that was APPLIED
-- (state='applied') is NOT the same as an effect that was VERIFIED — a kill whose syscall returned but
-- whose process is still observed alive is verification='failed', not a success. Separate column so the
-- two axes never collapse. '' = pending/not-verified (default for existing rows).
ALTER TABLE response_actions ADD COLUMN verification TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE response_actions DROP COLUMN verification;
