-- +goose Up
-- 0252 originally removed the anonymous foundation marker check while replacing
-- the action check. Restore the immutable correlation marker invariant before
-- any document command can be dispatched.
-- +goose StatementBegin
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='document_intents'::regclass AND contype='c'
   AND pg_get_constraintdef(oid) LIKE '%correlation_marker%' AND pg_get_constraintdef(oid) LIKE '%synapse-intent-%') THEN
  ALTER TABLE document_intents ADD CONSTRAINT document_intents_marker_check
   CHECK (length(correlation_marker) BETWEEN 16 AND 256 AND correlation_marker='synapse-intent-' || id);
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE document_intents DROP CONSTRAINT IF EXISTS document_intents_marker_check;
