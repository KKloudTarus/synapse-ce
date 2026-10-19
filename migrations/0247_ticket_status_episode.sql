-- +goose Up
ALTER TABLE ticket_status_sync
    ADD COLUMN episode INTEGER NOT NULL DEFAULT 1 CHECK (episode > 0);

-- +goose Down
LOCK TABLE ticket_status_sync IN ACCESS EXCLUSIVE MODE;
ALTER TABLE ticket_status_sync DROP COLUMN episode;
