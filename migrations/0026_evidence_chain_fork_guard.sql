-- +goose Up
-- Phase 3 (E10.4): make the hash-chained evidence vault safe under MULTIPLE writers (the
-- API + the synapse-worker both sealing to an engagement's chain). One child per parent:
-- a unique link on (engagement_id, previous_hash) – COALESCE so the genesis link (NULL/'')
-- is also unique per engagement – so two concurrent appends can never FORK the chain (the
-- loser gets a unique violation → re-reads the advanced head + re-chains). Protects custody
-- integrity (golden rules 5/6) for the worker era.
CREATE UNIQUE INDEX evidence_chain_link_uniq ON evidence (engagement_id, COALESCE(previous_hash, ''));

-- +goose Down
DROP INDEX evidence_chain_link_uniq;
