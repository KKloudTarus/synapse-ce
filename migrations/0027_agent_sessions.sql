-- +goose Up
-- Phase 4 (E18.3): durable agent sessions + transcripts so an AI orchestration run is
-- resumable across a HITL pause/restart and replayable for audit. The (session_id, seq)
-- primary key is the transcript fork-guard – a redelivery cannot fork a session's history
-- (mirrors the evidence chain's one-child-per-parent rule).
CREATE TABLE agent_sessions (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT,
    engagement_id    TEXT NOT NULL REFERENCES engagements(id),
    initiated_by     TEXT NOT NULL,            -- the human who started it (attribution)
    goal             TEXT NOT NULL,
    model            TEXT NOT NULL DEFAULT '',
    provider_base    TEXT NOT NULL DEFAULT '', -- LLM base URL; never the API key
    prompt_hash      TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'running',
    steps            INT  NOT NULL DEFAULT 0,
    tokens_used      INT  NOT NULL DEFAULT 0,
    token_budget_max INT  NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_sessions_engagement ON agent_sessions(engagement_id);

CREATE TABLE agent_messages (
    session_id   TEXT NOT NULL REFERENCES agent_sessions(id),
    seq          INT  NOT NULL,
    role         TEXT NOT NULL,                -- system|user|assistant|tool
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   JSONB,                        -- assistant-turn proposed tool-calls
    tool_call_id TEXT NOT NULL DEFAULT '',     -- tool-turn: which call this answers
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, seq)              -- fork-guard: one message per (session, seq)
);

-- +goose Down
DROP TABLE agent_messages;
DROP TABLE agent_sessions;
