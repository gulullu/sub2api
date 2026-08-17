package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestMigration226KeepsDisabledRulesOutOfRollbackSensitiveConfig(t *testing.T) {
	content, err := FS.ReadFile("226_prompt_audit_cyber_rule_lifecycle.sql")
	require.NoError(t, err)
	sql := string(content)

	require.Contains(t, sql, "SET LOCAL lock_timeout = '5s'")
	require.Contains(t, sql, "ADD COLUMN IF NOT EXISTS adopted_rule_text")
	require.Contains(t, sql, "rule_lifecycle_status")
	require.Contains(t, sql, "recovered_candidate")
	require.Contains(t, sql, "body->'cyber_supplement_rules'")
	require.Contains(t, sql, "rule_lifecycle_status = 'disabled'")
	require.NotContains(t, sql, "UPDATE settings")
	require.NotContains(t, sql, "INSERT INTO settings")
	require.Equal(t, 2, strings.Count(sql, "UPDATE prompt_audit_cyber_feedback AS feedback"))
	require.Contains(t, sql, "NOT EXISTS (\n      SELECT 1 FROM active_feedback")
	require.Less(t, strings.Index(sql, "NULLIF(active_rules.rule->>'reviewed_at'"), strings.Index(sql, "feedback.reviewed_at,"),
		"active config review metadata must win when repairing a partial write")
	require.Equal(t, 2, strings.Count(sql, "NULLIF(active_rules.rule->>'reviewed_at', '')::TIMESTAMPTZ"),
		"reviewed_at and rule_state_updated_at must use the same stable source expression")
}

func TestMigration226PostgresSecondRunIsByteStable(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PROMPT_AUDIT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("PROMPT_AUDIT_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	schema := fmt.Sprintf("cyb_lifecycle_226_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err = conn.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE") })
	_, err = conn.ExecContext(ctx, "SET search_path TO "+quotedSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `
		CREATE TABLE settings (
			key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE TABLE prompt_audit_cyber_feedback (
			id BIGINT PRIMARY KEY,
			candidate_rule_text TEXT NOT NULL DEFAULT '',
			review_status VARCHAR(16) NOT NULL DEFAULT 'pending',
			reviewed_by BIGINT, reviewed_at TIMESTAMPTZ,
			rule_id VARCHAR(64) NOT NULL DEFAULT '', config_version BIGINT NOT NULL DEFAULT 0,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		INSERT INTO settings(key,value) VALUES (
			'prompt_audit_config',
			'{"config_version":42,"cyber_supplement_rules":[{"id":"cyb-feedback-1","rule_text":"exact reviewed rule","source_feedback_id":1,"status":"active","created_at":"2026-08-17T01:00:00Z","created_by":7,"reviewed_at":"2026-08-17T02:00:00Z","reviewed_by":8,"config_version":42}]}'
		);
		INSERT INTO prompt_audit_cyber_feedback(
			id,candidate_rule_text,review_status,rule_id,config_version,created_at,updated_at
		) VALUES (1,'candidate rule','pending','',0,'2026-08-17T00:00:00Z','2026-08-17T00:30:00Z');
	`)
	require.NoError(t, err)

	migration, err := FS.ReadFile("226_prompt_audit_cyber_rule_lifecycle.sql")
	require.NoError(t, err)
	run := func() {
		t.Helper()
		tx, beginErr := conn.BeginTx(ctx, nil)
		require.NoError(t, beginErr)
		_, execErr := tx.ExecContext(ctx, string(migration))
		if execErr != nil {
			_ = tx.Rollback()
			require.NoError(t, execErr)
		}
		require.NoError(t, tx.Commit())
	}
	snapshot := func() []byte {
		t.Helper()
		var raw []byte
		require.NoError(t, conn.QueryRowContext(ctx, `
			SELECT convert_to(jsonb_build_object(
				'feedback', to_jsonb(feedback),
				'config', (SELECT value FROM settings WHERE key='prompt_audit_config')
			)::text, 'UTF8')
			FROM prompt_audit_cyber_feedback AS feedback WHERE id=1
		`).Scan(&raw))
		return raw
	}

	run()
	first := snapshot()
	run()
	second := snapshot()
	require.Equal(t, first, second, "the second PostgreSQL execution must be byte-for-byte stable")
}
