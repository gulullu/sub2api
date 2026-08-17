-- Administrator-review evidence for confirmed OpenAI OAuth cyber_policy events.
-- Keep the exact turn snapshot captured by the CYB recorder. It must not be
-- reconstructed from prompt_audit_events: one request can be transformed or
-- audited more than once, and a request-id match is not proof of equal content.

SET LOCAL lock_timeout = '5s';

ALTER TABLE prompt_audit_cyber_feedback
    ADD COLUMN IF NOT EXISTS user_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS username_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_email_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS api_key_name_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS api_key_prefix_snapshot VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS group_name_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS account_name_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS credential_account_id BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS credential_account_name_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS credential_account_email_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS client_request_id_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS client_ip_snapshot VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS user_agent_snapshot TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS upstream_code VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS upstream_message TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS full_prompt TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS prompt_length BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS message_count INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS full_prompt_truncated BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill the account label for already-confirmed feedback without adding a
-- foreign key: CYB evidence must survive account deletion.
UPDATE prompt_audit_cyber_feedback AS f
SET account_name_snapshot = COALESCE(a.name, '')
FROM accounts AS a
WHERE f.account_id = a.id
  AND f.account_name_snapshot = '';

UPDATE prompt_audit_cyber_feedback AS f
SET group_name_snapshot = COALESCE(g.name, '')
FROM groups AS g
WHERE f.group_id = g.id
  AND f.group_name_snapshot = '';

UPDATE prompt_audit_cyber_feedback AS f
SET credential_account_id = COALESCE(a.parent_account_id, f.account_id)
FROM accounts AS a
WHERE f.account_id = a.id
  AND f.credential_account_id = 0;

UPDATE prompt_audit_cyber_feedback AS f
SET credential_account_name_snapshot = COALESCE(a.name, '')
FROM accounts AS a
WHERE f.credential_account_id = a.id
  AND f.credential_account_name_snapshot = '';

-- Legacy identity fields and raw evidence deliberately stay empty. Rebuilding
-- them from current users, keys, credentials, or prompt_audit_events would not
-- be a trustworthy snapshot of the confirmed upstream turn.

UPDATE prompt_audit_cyber_feedback
SET prompt_length = COALESCE(NULLIF(substring(redacted_preview FROM 'characters=([0-9]+)'), '')::BIGINT, 0),
    message_count = COALESCE(NULLIF(substring(redacted_preview FROM 'messages=([0-9]+)'), '')::INT, 0)
WHERE prompt_length = 0
  AND redacted_preview ~ '^\[content withheld; characters=[0-9]+; messages=[0-9]+\]$';

-- Legacy rows deliberately keep an empty full_prompt. Their exact CYB turn was
-- never persisted, and showing a merely similar audit event would be a data
-- disclosure bug. New confirmations populate this column directly.
