package migrations

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration231PromptAuditGroupPolicyEventNamesIsIdempotent(t *testing.T) {
	content, err := FS.ReadFile("231_prompt_audit_group_policy_event_names.sql")
	require.NoError(t, err)
	sql := strings.Join(strings.Fields(string(content)), " ")
	require.Contains(t, sql, "ALTER TABLE prompt_audit_events ADD COLUMN IF NOT EXISTS guard_endpoint_name VARCHAR(255) NOT NULL DEFAULT ''")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_guard_endpoint")
	require.Contains(t, sql, "CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_guard_endpoint_name")
}
