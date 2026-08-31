-- Keep raw probe prompt evidence out of list/detail payloads while allowing an
-- administrator to review the exact captured text through the separately
-- audited, no-store evidence endpoint.
ALTER TABLE prompt_audit_probe_events
    ADD COLUMN IF NOT EXISTS full_prompt TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN prompt_audit_probe_events.full_prompt IS
    'Exact normalized probe prompt; exposed only by the administrator evidence endpoint.';
