-- Per-audit-group probe governance. Runtime windows and singleflight locks live
-- in Redis; PostgreSQL stores administrator intent, durable aggregate events,
-- and explicit real-monitor exemptions.

CREATE TABLE IF NOT EXISTS prompt_audit_probe_group_configs (
    group_id                   BIGINT PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
    enabled                    BOOLEAN NOT NULL DEFAULT FALSE,
    interval_seconds           INT NOT NULL DEFAULT 300,
    health_scope               VARCHAR(64) NOT NULL DEFAULT 'group_model_protocol',
    allow_first_real_probe     BOOLEAN NOT NULL DEFAULT TRUE,
    skip_repeat_audit          BOOLEAN NOT NULL DEFAULT TRUE,
    skip_repeat_upstream       BOOLEAN NOT NULL DEFAULT TRUE,
    healthy_response           TEXT NOT NULL DEFAULT '服务正常。为避免重复检测，探针最小间隔为 5 分钟。',
    violation_response         TEXT NOT NULL DEFAULT '服务正常，但无法协助该请求。为避免重复检测，探针最小间隔为 5 分钟。',
    unknown_response           TEXT NOT NULL DEFAULT '网关在线，上游状态正在刷新。探针最小间隔为 5 分钟。',
    config_version             BIGINT NOT NULL DEFAULT 1,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by                 BIGINT REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_prompt_audit_probe_interval CHECK (interval_seconds BETWEEN 60 AND 86400),
    CONSTRAINT chk_prompt_audit_probe_health_scope CHECK (health_scope = 'group_model_protocol'),
    CONSTRAINT chk_prompt_audit_probe_responses CHECK (
        char_length(healthy_response) BETWEEN 1 AND 1000 AND
        char_length(violation_response) BETWEEN 1 AND 1000 AND
        char_length(unknown_response) BETWEEN 1 AND 1000
    )
);

CREATE TABLE IF NOT EXISTS prompt_audit_probe_events (
    id                       BIGSERIAL PRIMARY KEY,
    group_id                 BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    group_name_snapshot      VARCHAR(255) NOT NULL DEFAULT '',
    family_fingerprint       VARCHAR(64) NOT NULL,
    family_preview           VARCHAR(255) NOT NULL DEFAULT '',
    classification           VARCHAR(32) NOT NULL DEFAULT 'candidate',
    verdict                  VARCHAR(32) NOT NULL DEFAULT 'unknown',
    subject_user_id          BIGINT NOT NULL DEFAULT 0,
    user_id                  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    user_email_snapshot      VARCHAR(320) NOT NULL DEFAULT '',
    api_key_id               BIGINT REFERENCES api_keys(id) ON DELETE SET NULL,
    api_key_name_snapshot    VARCHAR(255) NOT NULL DEFAULT '',
    model                    VARCHAR(255) NOT NULL DEFAULT '',
    protocol                 VARCHAR(64) NOT NULL DEFAULT '',
    stream                   BOOLEAN NOT NULL DEFAULT FALSE,
    max_tokens               INT NOT NULL DEFAULT 0,
    policy_version           BIGINT NOT NULL DEFAULT 1,
    audit_config_version     BIGINT NOT NULL DEFAULT 1,
    probe_config_version     BIGINT NOT NULL DEFAULT 1,
    evidence                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_source              VARCHAR(64) NOT NULL DEFAULT '',
    handling                 VARCHAR(64) NOT NULL DEFAULT '',
    response_kind            VARCHAR(32) NOT NULL DEFAULT '',
    prompt_snapshot          JSONB NOT NULL DEFAULT '{}'::jsonb,
    total_count              BIGINT NOT NULL DEFAULT 0,
    local_response_count     BIGINT NOT NULL DEFAULT 0,
    audit_skipped_count      BIGINT NOT NULL DEFAULT 0,
    upstream_skipped_count   BIGINT NOT NULL DEFAULT 0,
    audit_call_count         BIGINT NOT NULL DEFAULT 0,
    upstream_call_count      BIGINT NOT NULL DEFAULT 0,
    linked_audit_event_id    BIGINT REFERENCES prompt_audit_events(id) ON DELETE SET NULL,
    first_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_real_health_at      TIMESTAMPTZ,
    window_expires_at        TIMESTAMPTZ,
    next_real_probe_at       TIMESTAMPTZ,
    cleared_at               TIMESTAMPTZ,
    cleared_by               BIGINT REFERENCES users(id) ON DELETE SET NULL,
    clear_reason             VARCHAR(500) NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_probe_event_classification CHECK (
        classification IN ('known_health','candidate','healthy','confirmed_violation','unknown','cleared')
    ),
    CONSTRAINT chk_prompt_audit_probe_event_verdict CHECK (
        verdict IN ('healthy','confirmed_violation','unknown')
    ),
    CONSTRAINT chk_prompt_audit_probe_event_counts CHECK (
        total_count >= 0 AND local_response_count >= 0 AND audit_skipped_count >= 0 AND
        upstream_skipped_count >= 0 AND audit_call_count >= 0 AND upstream_call_count >= 0
    ),
    CONSTRAINT chk_prompt_audit_probe_event_json CHECK (
        jsonb_typeof(evidence) = 'object' AND jsonb_typeof(prompt_snapshot) = 'object'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_prompt_audit_probe_family
    ON prompt_audit_probe_events(group_id, subject_user_id, audit_config_version, probe_config_version, family_fingerprint);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_probe_events_group_last
    ON prompt_audit_probe_events(group_id, last_seen_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_probe_events_verdict_last
    ON prompt_audit_probe_events(verdict, last_seen_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_probe_events_user_last
    ON prompt_audit_probe_events(user_id, last_seen_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_probe_events_key_last
    ON prompt_audit_probe_events(api_key_id, last_seen_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS prompt_audit_probe_hourly_stats (
    group_id                 BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    bucket_at                TIMESTAMPTZ NOT NULL,
    local_response_count     BIGINT NOT NULL DEFAULT 0,
    audit_skipped_count      BIGINT NOT NULL DEFAULT 0,
    upstream_skipped_count   BIGINT NOT NULL DEFAULT 0,
    last_probe_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, bucket_at),
    CONSTRAINT chk_prompt_audit_probe_hourly_counts CHECK (
        local_response_count >= 0 AND audit_skipped_count >= 0 AND
        upstream_skipped_count >= 0
    )
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_probe_hourly_time
    ON prompt_audit_probe_hourly_stats(bucket_at DESC);

CREATE TABLE IF NOT EXISTS prompt_audit_probe_exemptions (
    id                    BIGSERIAL PRIMARY KEY,
    group_id              BIGINT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id               BIGINT REFERENCES users(id) ON DELETE CASCADE,
    api_key_id            BIGINT REFERENCES api_keys(id) ON DELETE CASCADE,
    user_email_snapshot   VARCHAR(320) NOT NULL DEFAULT '',
    api_key_name_snapshot VARCHAR(255) NOT NULL DEFAULT '',
    reason                VARCHAR(500) NOT NULL,
    expires_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by            BIGINT REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_prompt_audit_probe_exemption_subject CHECK ((user_id IS NULL) <> (api_key_id IS NULL)),
    CONSTRAINT chk_prompt_audit_probe_exemption_reason CHECK (char_length(reason) BETWEEN 1 AND 500)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_prompt_audit_probe_exemption_subject
    ON prompt_audit_probe_exemptions(group_id, COALESCE(user_id, 0), COALESCE(api_key_id, 0));
CREATE INDEX IF NOT EXISTS idx_prompt_audit_probe_exemptions_group
    ON prompt_audit_probe_exemptions(group_id, created_at DESC, id DESC);
