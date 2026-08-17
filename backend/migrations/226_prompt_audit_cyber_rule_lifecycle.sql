-- Reversible lifecycle projection for administrator-adopted CYB rules.
--
-- Active rules intentionally remain in prompt_audit_config exactly as before.
-- Disabled/deleted state lives on the 1:1 feedback row so an older binary can
-- still parse and activate the prompt-audit config during rollback.

SET LOCAL lock_timeout = '5s';

ALTER TABLE prompt_audit_cyber_feedback
    ADD COLUMN IF NOT EXISTS adopted_rule_text TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rule_lifecycle_status VARCHAR(16) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rule_text_source VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rule_state_config_version BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rule_state_updated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rule_state_updated_by BIGINT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_prompt_audit_cyber_rule_lifecycle_status'
    ) THEN
        ALTER TABLE prompt_audit_cyber_feedback
            ADD CONSTRAINT chk_prompt_audit_cyber_rule_lifecycle_status
            CHECK (rule_lifecycle_status IN ('', 'active', 'disabled', 'deleted'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_prompt_audit_cyber_rule_text_source'
    ) THEN
        ALTER TABLE prompt_audit_cyber_feedback
            ADD CONSTRAINT chk_prompt_audit_cyber_rule_text_source
            CHECK (rule_text_source IN ('', 'reviewed', 'recovered_candidate', 'unavailable'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_prompt_audit_cyber_rule_state_config_version'
    ) THEN
        ALTER TABLE prompt_audit_cyber_feedback
            ADD CONSTRAINT chk_prompt_audit_cyber_rule_state_config_version
            CHECK (rule_state_config_version >= 0);
    END IF;
END $$;

-- The current config is the authoritative source for rules that are active at
-- migration time, including any administrator-edited text.
WITH config AS (
    SELECT CASE
        WHEN value ~ '^\s*\{' THEN value::jsonb
        ELSE '{}'::jsonb
    END AS body
    FROM settings
    WHERE key = 'prompt_audit_config'
), active_rules AS (
    SELECT rule,
        COALESCE(NULLIF(body->>'config_version', '')::BIGINT, 0) AS current_config_version
    FROM config
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(body->'cyber_supplement_rules') = 'array'
                THEN body->'cyber_supplement_rules'
            ELSE '[]'::jsonb
        END
    ) AS item(rule)
    WHERE COALESCE(rule->>'id', '') ~ '^cyb-feedback-[1-9][0-9]*$'
      AND COALESCE(rule->>'source_feedback_id', '') ~ '^[1-9][0-9]*$'
      AND COALESCE(rule->>'rule_text', '') <> ''
      AND rule->>'id' = 'cyb-feedback-' || (rule->>'source_feedback_id')
)
UPDATE prompt_audit_cyber_feedback AS feedback
SET review_status = 'approved',
    rule_id = active_rules.rule->>'id',
    reviewed_at = COALESCE(
        NULLIF(active_rules.rule->>'reviewed_at', '')::TIMESTAMPTZ,
        feedback.reviewed_at,
        feedback.updated_at,
        NOW()
    ),
    reviewed_by = COALESCE(
        CASE
            WHEN COALESCE(active_rules.rule->>'reviewed_by', '') ~ '^[1-9][0-9]*$'
                THEN (active_rules.rule->>'reviewed_by')::BIGINT
            ELSE NULL
        END,
        feedback.reviewed_by
    ),
    config_version = GREATEST(feedback.config_version, active_rules.current_config_version),
    adopted_rule_text = active_rules.rule->>'rule_text',
    rule_lifecycle_status = 'active',
    rule_text_source = 'reviewed',
    rule_state_config_version = GREATEST(
        feedback.config_version,
        active_rules.current_config_version,
        COALESCE(NULLIF(active_rules.rule->>'config_version', '')::BIGINT, 0)
    ),
    rule_state_updated_at = COALESCE(
        NULLIF(active_rules.rule->>'reviewed_at', '')::TIMESTAMPTZ,
        feedback.reviewed_at,
        feedback.updated_at,
        NOW()
    ),
    rule_state_updated_by = COALESCE(
        CASE
            WHEN COALESCE(active_rules.rule->>'reviewed_by', '') ~ '^[1-9][0-9]*$'
                THEN (active_rules.rule->>'reviewed_by')::BIGINT
            ELSE NULL
        END,
        feedback.reviewed_by
    )
FROM active_rules
WHERE feedback.id = (active_rules.rule->>'source_feedback_id')::BIGINT
  AND (
      (feedback.review_status = 'approved' AND feedback.rule_id = active_rules.rule->>'id')
      OR (feedback.review_status = 'pending' AND feedback.rule_id = '')
  );

-- Older revoke operations physically removed the rule from config. Its exact
-- administrator-edited text was not retained, so only recover the candidate
-- with an explicit provenance marker; it remains disabled until reviewed and
-- restored by an administrator.
WITH config AS (
    SELECT CASE
        WHEN value ~ '^\s*\{' THEN value::jsonb
        ELSE '{}'::jsonb
    END AS body
    FROM settings
    WHERE key = 'prompt_audit_config'
), active_feedback AS (
    SELECT (rule->>'source_feedback_id')::BIGINT AS feedback_id
    FROM config
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(body->'cyber_supplement_rules') = 'array'
                THEN body->'cyber_supplement_rules'
            ELSE '[]'::jsonb
        END
    ) AS item(rule)
    WHERE COALESCE(rule->>'id', '') ~ '^cyb-feedback-[1-9][0-9]*$'
      AND COALESCE(rule->>'source_feedback_id', '') ~ '^[1-9][0-9]*$'
      AND rule->>'id' = 'cyb-feedback-' || (rule->>'source_feedback_id')
)
UPDATE prompt_audit_cyber_feedback AS feedback
SET adopted_rule_text = candidate_rule_text,
    rule_lifecycle_status = 'disabled',
    rule_text_source = CASE
        WHEN candidate_rule_text <> '' THEN 'recovered_candidate'
        ELSE 'unavailable'
    END,
    rule_state_config_version = config_version,
    rule_state_updated_at = COALESCE(reviewed_at, updated_at, NOW()),
    rule_state_updated_by = reviewed_by
WHERE review_status = 'approved'
  AND rule_id <> ''
  AND rule_lifecycle_status = ''
  AND NOT EXISTS (
      SELECT 1 FROM active_feedback WHERE active_feedback.feedback_id = feedback.id
  );

CREATE INDEX IF NOT EXISTS idx_prompt_audit_cyber_rule_lifecycle
    ON prompt_audit_cyber_feedback(rule_lifecycle_status, reviewed_at DESC, id DESC)
    WHERE rule_lifecycle_status IN ('active', 'disabled');
