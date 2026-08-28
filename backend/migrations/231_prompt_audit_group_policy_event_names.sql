-- Per-group Prompt Audit policies are stored in the existing encrypted
-- prompt_audit_config JSON document. This forward-only migration adds the
-- endpoint display-name snapshot used by the event list/detail filters.
ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS guard_endpoint_name VARCHAR(255) NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_guard_endpoint
    ON prompt_audit_events(guard_endpoint_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_guard_endpoint_name
    ON prompt_audit_events(guard_endpoint_name);
