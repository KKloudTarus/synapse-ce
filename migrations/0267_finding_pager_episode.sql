-- +goose Up
ALTER TABLE findings ADD COLUMN pager_episode BIGINT NOT NULL DEFAULT 1 CHECK (pager_episode > 0);

-- +goose Down
ALTER TABLE findings DROP COLUMN pager_episode;
