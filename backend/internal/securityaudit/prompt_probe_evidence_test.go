package securityaudit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestGetProbeEventEvidenceReturnsExactPromptFromDedicatedRead(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectQuery(`(?s)SELECT COALESCE\(NULLIF\(e\.full_prompt.*LEFT JOIN LATERAL.*p\.request_id`).
		WithArgs(int64(91)).
		WillReturnRows(sqlmock.NewRows([]string{"full_prompt", "request_id", "source"}).
			AddRow("exact probe prompt", "req-91", "probe_event"))

	evidence, err := NewPostgreSQLRepository(db).GetProbeEventEvidence(context.Background(), 91)
	require.NoError(t, err)
	require.Equal(t, &ProbeEventEvidence{
		Available: true, FullPrompt: "exact probe prompt", PromptLength: 18,
		RequestID: "req-91", Source: "probe_event",
	}, evidence)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetProbeEventEvidenceReportsMissingEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectQuery(`SELECT COALESCE\(NULLIF\(e\.full_prompt`).
		WithArgs(int64(92)).WillReturnError(sql.ErrNoRows)

	evidence, err := NewPostgreSQLRepository(db).GetProbeEventEvidence(context.Background(), 92)
	require.Nil(t, evidence)
	require.ErrorIs(t, err, ErrProbeEventNotFound)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestGetProbeEventEvidenceKeepsLegacyUnrecoverableRowsUnavailable(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectQuery(`SELECT COALESCE\(NULLIF\(e\.full_prompt`).
		WithArgs(int64(93)).
		WillReturnRows(sqlmock.NewRows([]string{"full_prompt", "request_id", "source"}).
			AddRow("", "legacy-req", "unavailable"))

	evidence, err := NewPostgreSQLRepository(db).GetProbeEventEvidence(context.Background(), 93)
	require.NoError(t, err)
	require.False(t, evidence.Available)
	require.Empty(t, evidence.FullPrompt)
	require.Zero(t, evidence.PromptLength)
	require.Equal(t, "unavailable", evidence.Source)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRecordProbeEventBindsFullPromptAfterExistingConflictCutoffArgument(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	const eventID, groupID, subjectID = int64(94), int64(17), int64(23)
	const auditVersion, probeVersion = int64(57), int64(4)
	policyVersion := combinedProbePolicyVersion(auditVersion, probeVersion)
	queryArgs := make([]driver.Value, 34)
	for index := range queryArgs {
		queryArgs[index] = sqlmock.AnyArg()
	}
	queryArgs[33] = "system context\n\nexact probe prompt"
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)INSERT INTO prompt_audit_probe_events.*next_real_probe_at,full_prompt\).*\$32,\$34\).*cleared_at < \$33`).
		WithArgs(queryArgs...).
		WillReturnRows(probeTestEventRows(eventID, groupID, subjectID, policyVersion, auditVersion, probeVersion, ProbeClassificationHealthy))
	mock.ExpectExec(`INSERT INTO prompt_audit_probe_hourly_stats`).
		WithArgs(groupID, 1, 1, 1).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	observedAt := time.Unix(1_900_000_000, 0).UTC()
	result, err := NewPostgreSQLRepository(db).RecordProbeEvent(context.Background(), probeEventDelta{
		ObservedAt: observedAt,
		Request: Request{
			RequestID: "req-94", UserID: subjectID, GroupID: func() *int64 { value := groupID; return &value }(),
			GroupName: "claude-max", Model: "claude-haiku", Protocol: service.ContentModerationProtocolAnthropicMessages,
		},
		Shape: probeRequestShape{
			Fingerprint: "family-a", Preview: "redacted", ScanText: "exact probe prompt",
			FullPrompt: "system context\n\nexact probe prompt",
		},
		Classification: ProbeClassificationHealthy, Verdict: ProbeVerdictHealthy,
		PolicyVersion: policyVersion, LocalResponse: true, AuditSkipped: true, UpstreamSkipped: true,
	})
	require.NoError(t, err)
	require.Equal(t, eventID, result.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestProbeEventEvidenceMigrationAddsSeparateRawPromptColumn(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/233_prompt_audit_probe_event_full_prompt.sql")
	require.NoError(t, err)
	sqlText := string(raw)
	require.Contains(t, sqlText, "ADD COLUMN IF NOT EXISTS full_prompt TEXT NOT NULL DEFAULT ''")
	require.Contains(t, sqlText, "administrator evidence endpoint")
}
