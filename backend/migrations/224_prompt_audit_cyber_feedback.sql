-- OpenAI OAuth cyber_policy feedback and replay protection.
-- Raw prompts and unhashed prompt digests are intentionally never persisted.

CREATE TABLE IF NOT EXISTS prompt_audit_cyber_signatures (
    id                  BIGSERIAL PRIMARY KEY,
    group_id            BIGINT NOT NULL,
    protocol            VARCHAR(64) NOT NULL,
    stage               VARCHAR(32) NOT NULL,
    signature_version   VARCHAR(32) NOT NULL,
    prompt_signature    BYTEA NOT NULL,
    confirm_count       BIGINT NOT NULL DEFAULT 0,
    first_confirmed_at  TIMESTAMPTZ,
    last_confirmed_at   TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_prompt_audit_cyber_signature
        UNIQUE (group_id, signature_version, prompt_signature),
    CONSTRAINT chk_prompt_audit_cyber_signature_count CHECK (confirm_count >= 0)
);

CREATE TABLE IF NOT EXISTS prompt_audit_cyber_feedback (
    id                       BIGSERIAL PRIMARY KEY,
    signature_id             BIGINT REFERENCES prompt_audit_cyber_signatures(id) ON DELETE RESTRICT,
    event_key                VARCHAR(64) NOT NULL UNIQUE,
    request_id               VARCHAR(128) NOT NULL DEFAULT '',
    turn_number              INT NOT NULL DEFAULT 0,
    api_key_id               BIGINT,
    group_id                 BIGINT NOT NULL,
    account_id               BIGINT NOT NULL,
    model                    VARCHAR(255) NOT NULL DEFAULT '',
    endpoint                 VARCHAR(128) NOT NULL DEFAULT '',
    protocol                 VARCHAR(64) NOT NULL,
    transport                VARCHAR(16) NOT NULL,
    stage                    VARCHAR(32) NOT NULL,
    upstream_status          INT NOT NULL DEFAULT 0,
    redacted_preview         TEXT NOT NULL DEFAULT '',
    signature_confirm_count  BIGINT NOT NULL DEFAULT 0,
    generation_status        VARCHAR(32) NOT NULL DEFAULT 'pending',
    generation_error_code    VARCHAR(64) NOT NULL DEFAULT '',
    candidate_rule_text      VARCHAR(1600) NOT NULL DEFAULT '',
    review_status            VARCHAR(32) NOT NULL DEFAULT 'pending',
    reviewed_by              BIGINT,
    reviewed_at              TIMESTAMPTZ,
    rule_id                  VARCHAR(128) NOT NULL DEFAULT '',
    config_version           BIGINT NOT NULL DEFAULT 0,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_cyber_feedback_turn CHECK (turn_number >= 0),
    CONSTRAINT chk_prompt_audit_cyber_feedback_status
        CHECK (review_status IN ('pending', 'approved', 'rejected')),
    CONSTRAINT chk_prompt_audit_cyber_generation_status
        CHECK (generation_status IN ('pending', 'generated', 'failed')),
    CONSTRAINT chk_prompt_audit_cyber_transport CHECK (transport IN ('http', 'websocket')),
    CONSTRAINT chk_prompt_audit_cyber_upstream_status CHECK (upstream_status BETWEEN 0 AND 599),
    CONSTRAINT chk_prompt_audit_cyber_signature_confirm_count CHECK (signature_confirm_count >= 0),
    CONSTRAINT chk_prompt_audit_cyber_config_version CHECK (config_version >= 0)
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_cyber_signatures_active
    ON prompt_audit_cyber_signatures(group_id, expires_at DESC)
    WHERE confirm_count > 0;
CREATE INDEX IF NOT EXISTS idx_prompt_audit_cyber_signatures_warm
    ON prompt_audit_cyber_signatures(signature_version, group_id, id)
    WHERE confirm_count > 0;
CREATE INDEX IF NOT EXISTS idx_prompt_audit_cyber_feedback_created
    ON prompt_audit_cyber_feedback(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_cyber_feedback_review
    ON prompt_audit_cyber_feedback(review_status, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_cyber_feedback_group
    ON prompt_audit_cyber_feedback(group_id, created_at DESC, id DESC);
