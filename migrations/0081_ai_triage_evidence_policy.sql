-- +goose Up
-- P2.1: fp-gate-v5 adds a deterministic-evidence receipt to the authorization contract.
-- Only explicitly historical v1-v3 rows are exempt from provider/model-family metadata. Any
-- unknown/future policy version is protected by default so a version bump cannot disable separation
-- of duties by omission.
ALTER TABLE ai_triage_reviews
    DROP CONSTRAINT ai_triage_reviews_independence_metadata_check;

ALTER TABLE ai_triage_reviews
    ADD CONSTRAINT ai_triage_reviews_independence_metadata_check CHECK (
        policy_version IN ('fp-gate-v1', 'fp-gate-v2', 'fp-gate-v3') OR (
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
    DROP CONSTRAINT ai_triage_reviews_independence_metadata_check;

ALTER TABLE ai_triage_reviews
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
