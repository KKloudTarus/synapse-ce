-- +goose Up
ALTER TABLE project_issues
    ADD COLUMN source_file TEXT,
    ADD COLUMN start_line INTEGER,
    ADD COLUMN end_line INTEGER,
    ADD COLUMN start_column INTEGER,
    ADD COLUMN end_column INTEGER,
    ADD CONSTRAINT project_issues_source_range CHECK (
        (source_file IS NULL AND start_line IS NULL AND end_line IS NULL AND start_column IS NULL AND end_column IS NULL) OR
        (source_file IS NOT NULL AND start_line >= 1 AND end_line >= start_line AND
         ((start_column IS NULL AND end_column IS NULL) OR (start_column >= 0 AND end_column >= 0)))
    );

ALTER TABLE project_hotspots
    ADD COLUMN source_file TEXT,
    ADD COLUMN start_line INTEGER,
    ADD COLUMN end_line INTEGER,
    ADD COLUMN start_column INTEGER,
    ADD COLUMN end_column INTEGER,
    ADD CONSTRAINT project_hotspots_source_range CHECK (
        (source_file IS NULL AND start_line IS NULL AND end_line IS NULL AND start_column IS NULL AND end_column IS NULL) OR
        (source_file IS NOT NULL AND start_line >= 1 AND end_line >= start_line AND
         ((start_column IS NULL AND end_column IS NULL) OR (start_column >= 0 AND end_column >= 0)))
    );

-- Backfill only unambiguous canonical path:line locations. Legacy text remains authoritative
-- compatibility data when it cannot be safely normalized.
UPDATE project_issues
SET source_file = file,
    start_line = (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[2]::INTEGER,
    end_line = (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[2]::INTEGER
WHERE file <> ''
  AND location ~ '^.+:[1-9][0-9]*$'
  AND file !~ '(^|/)\.\.(/|$)'
  AND file !~ '(^|/)\./';

UPDATE project_hotspots
SET source_file = (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[1],
    start_line = (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[2]::INTEGER,
    end_line = (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[2]::INTEGER
WHERE location ~ '^.+:[1-9][0-9]*$'
  AND (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[1] !~ '(^|/)\.\.(/|$)'
  AND (regexp_match(location, '^(.+):([1-9][0-9]*)$'))[1] !~ '(^|/)\./';

-- +goose Down
ALTER TABLE project_hotspots
    DROP CONSTRAINT project_hotspots_source_range,
    DROP COLUMN end_column,
    DROP COLUMN start_column,
    DROP COLUMN end_line,
    DROP COLUMN start_line,
    DROP COLUMN source_file;

ALTER TABLE project_issues
    DROP CONSTRAINT project_issues_source_range,
    DROP COLUMN end_column,
    DROP COLUMN start_column,
    DROP COLUMN end_line,
    DROP COLUMN start_line,
    DROP COLUMN source_file;
