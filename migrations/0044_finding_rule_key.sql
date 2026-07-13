-- +goose Up
-- +goose StatementBegin
ALTER TABLE findings ADD COLUMN rule_key TEXT NOT NULL DEFAULT '';

-- Safe regex-based backfill extracting the rule_id from the colon-delimited dedup_key.
-- Format: <kind>:<rule-id>:<file>:<line>
-- The rule-id is the capture group (.+).
-- The file path (?:(?:[a-zA-Z]:[/\\])?[^:]+) safely handles optional Windows drive letters
-- without capturing, ensuring colons inside the rule_id are safely matched.
UPDATE findings
SET rule_key = COALESCE(
    substring(dedup_key from '^(?:sast|secret|misconfig|quality|reliability):(.+?):(?:(?:[a-zA-Z]:[/\\])?[^:]+):\d+$'),
    ''
)
WHERE kind IN ('sast', 'secret', 'misconfig', 'quality', 'reliability')
  AND rule_key = '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE findings DROP COLUMN rule_key;
-- +goose StatementEnd
