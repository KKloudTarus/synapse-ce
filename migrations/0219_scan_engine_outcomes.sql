-- +goose Up
ALTER TABLE scan_run_lanes ADD COLUMN engine_outcomes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE scan_run_lanes ADD CONSTRAINT scan_run_lanes_engine_outcomes_bounded
    CHECK (jsonb_typeof(engine_outcomes) = 'array' AND jsonb_array_length(engine_outcomes) <= 64);

ALTER TABLE scan_jobs ADD COLUMN engine_outcomes JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_engine_outcomes_bounded
    CHECK (jsonb_typeof(engine_outcomes) = 'array' AND jsonb_array_length(engine_outcomes) <= 64);

-- +goose Down
-- +goose StatementBegin
LOCK TABLE scan_run_lanes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE scan_jobs IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM scan_run_lanes WHERE engine_outcomes <> '[]'::jsonb)
       OR EXISTS (SELECT 1 FROM scan_jobs WHERE engine_outcomes <> '[]'::jsonb) THEN
        RAISE EXCEPTION 'cannot remove recorded scan engine outcomes';
    END IF;
END;
$$;
-- +goose StatementEnd
ALTER TABLE scan_jobs DROP COLUMN engine_outcomes;
ALTER TABLE scan_run_lanes DROP COLUMN engine_outcomes;
