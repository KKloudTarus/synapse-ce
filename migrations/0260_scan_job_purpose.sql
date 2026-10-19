-- +goose Up
ALTER TABLE scan_jobs ADD COLUMN purpose TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_purpose_known
    CHECK (purpose IN ('', 'project_source'));

-- Purpose selects an operator-visible lifecycle and must not be rewritten after
-- admission, including by a later terminal-state update.
-- +goose StatementBegin
CREATE FUNCTION synapse_guard_scan_job_purpose() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP = 'UPDATE' AND NEW.purpose IS DISTINCT FROM OLD.purpose THEN
  RAISE EXCEPTION 'scan job purpose is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER scan_jobs_immutable_purpose BEFORE INSERT OR UPDATE ON scan_jobs
 FOR EACH ROW EXECUTE FUNCTION synapse_guard_scan_job_purpose();

-- The Project analysis readers must find the newest full-analysis job even when
-- newer bounded source scans exist for the same hidden engagement.
CREATE INDEX idx_scan_jobs_project_analysis_latest
    ON scan_jobs (engagement_id, started_at DESC, id DESC)
    WHERE purpose <> 'project_source';

-- +goose Down
DROP INDEX IF EXISTS idx_scan_jobs_project_analysis_latest;
DROP TRIGGER scan_jobs_immutable_purpose ON scan_jobs;
DROP FUNCTION synapse_guard_scan_job_purpose();
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_purpose_known;
ALTER TABLE scan_jobs DROP COLUMN purpose;
