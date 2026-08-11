-- +goose Up
-- P1.3 (migration 0078): retain the provider/model-family identity used by the deterministic
-- separation-of-duties policy in the durable P1.2 human-review queue.
ALTER TABLE ai_triage_reviews
    ADD COLUMN proposer_provider TEXT NOT NULL DEFAULT '',
    ADD COLUMN proposer_model_family TEXT NOT NULL DEFAULT '',
    ADD COLUMN verifier_provider TEXT NOT NULL DEFAULT '',
    ADD COLUMN verifier_model_family TEXT NOT NULL DEFAULT '',
    ADD COLUMN independence_policy TEXT NOT NULL DEFAULT '';

-- The P1.2 identity did not include provider policy, so a terminal review could swallow a new
-- recommendation after an operator changed provider/family policy. Find and replace that generated
-- constraint by its exact column definition rather than relying on PostgreSQL's truncated auto-name.
-- +goose StatementBegin
DO $$
DECLARE
    old_constraint TEXT;
BEGIN
    SELECT c.conname INTO old_constraint
      FROM pg_constraint c
      JOIN pg_class t ON t.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace
     WHERE n.nspname = current_schema()
       AND t.relname = 'ai_triage_reviews'
       AND c.contype = 'u'
       AND pg_get_constraintdef(c.oid) =
           'UNIQUE (tenant_id, engagement_id, dedup_key, policy_version, prompt_version, proposer_model, verifier_model)';
    IF old_constraint IS NULL THEN
        RAISE EXCEPTION 'P1.2 AI-triage identity constraint not found';
    END IF;
    EXECUTE format('ALTER TABLE ai_triage_reviews DROP CONSTRAINT %I', old_constraint);
END $$;
-- +goose StatementEnd

ALTER TABLE ai_triage_reviews
    ADD CONSTRAINT ai_triage_reviews_independent_identity_unique UNIQUE
        (tenant_id, engagement_id, dedup_key, policy_version, prompt_version,
         proposer_provider, proposer_model, proposer_model_family,
         verifier_provider, verifier_model, verifier_model_family, independence_policy),
    ADD CONSTRAINT ai_triage_reviews_independence_metadata_check CHECK (
        policy_version <> 'fp-gate-v4' OR (
            proposer_provider <> '' AND proposer_model_family <> ''
            AND independence_policy IN ('model_family', 'provider')
            AND proposer_provider = lower(btrim(proposer_provider))
            AND verifier_provider = lower(btrim(verifier_provider))
            AND (
                (verifier_model = '' AND verifier_provider = '' AND verifier_model_family = '')
                OR (verifier_model <> '' AND verifier_provider <> '' AND verifier_model_family <> '')
            )
        )
    );

-- +goose Down
ALTER TABLE ai_triage_reviews
    DROP CONSTRAINT ai_triage_reviews_independence_metadata_check,
    DROP CONSTRAINT ai_triage_reviews_independent_identity_unique;

ALTER TABLE ai_triage_reviews
    ADD CONSTRAINT ai_triage_reviews_p1_2_identity_unique UNIQUE
        (tenant_id, engagement_id, dedup_key, policy_version, prompt_version, proposer_model, verifier_model);

ALTER TABLE ai_triage_reviews
    DROP COLUMN independence_policy,
    DROP COLUMN verifier_model_family,
    DROP COLUMN verifier_provider,
    DROP COLUMN proposer_model_family,
    DROP COLUMN proposer_provider;
