-- +goose Up
-- +goose StatementBegin
ALTER TABLE findings ADD COLUMN rule_key TEXT NOT NULL DEFAULT '';

-- Conservatively backfill only the pre-RuleKey legacy format:
-- <kind>:<colon-free-rule-id>:<path>:<numeric-line>.
--
-- The prefix must match the stored kind. Paths may use an optional
-- Windows drive prefix, but ambiguous colon-containing rule IDs are
-- deliberately left empty.
UPDATE findings
SET rule_key = split_part(dedup_key, ':', 2)
WHERE rule_key = ''
  AND kind::text IN (
      'sast',
      'secret',
      'misconfig',
      'quality',
      'reliability'
  )
  AND dedup_key ~ (
      '^'
      || kind::text
      || ':[^:[:space:][:cntrl:]]+:'
      || '([A-Za-z]:[/\\])?'
      || '[^:]+:[0-9]+$'
  );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE findings DROP COLUMN rule_key;
-- +goose StatementEnd
