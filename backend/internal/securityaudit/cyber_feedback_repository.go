package securityaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const cyberFeedbackSelectColumns = `
	f.id, COALESCE(f.signature_id,0), COALESCE(s.signature_version,''), COALESCE(s.prompt_signature,''::bytea),
	f.request_id, f.turn_number, f.api_key_id, f.group_id, f.account_id,
	f.model, f.endpoint, f.protocol, f.transport, f.stage, f.upstream_status,
	f.redacted_preview, COALESCE(s.confirm_count,0), s.first_confirmed_at, s.last_confirmed_at,
	f.generation_status, f.generation_error_code,
	f.candidate_rule_text, f.review_status, f.reviewed_by, f.reviewed_at,
	f.rule_id, f.config_version, f.created_at, f.updated_at`

func (r *PostgreSQLRepository) Confirm(ctx context.Context, input CyberConfirmInput) (CyberFeedback, bool, error) {
	if r == nil || r.db == nil {
		return CyberFeedback{}, false, errors.New("cyber feedback database unavailable")
	}
	if input.AccountID <= 0 || strings.TrimSpace(input.EventKey) == "" {
		return CyberFeedback{}, false, errors.New("cyber feedback confirmation input invalid")
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CyberFeedback{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if len(input.Scope.PromptSignature) == 0 || input.GroupID <= 0 {
		var feedbackID int64
		err = tx.QueryRowContext(ctx, `
			INSERT INTO prompt_audit_cyber_feedback (
				signature_id, event_key, request_id, turn_number, api_key_id, group_id, account_id,
				model, endpoint, protocol, transport, stage, upstream_status, redacted_preview,
				signature_confirm_count, generation_status, generation_error_code
			) VALUES (NULL,$1,$2,$3,NULLIF($4,0),$5,$6,$7,$8,$9,$10,$11,$12,$13,0,'failed','fingerprint_unavailable')
			ON CONFLICT (event_key) DO NOTHING
			RETURNING id`, input.EventKey, input.RequestID, input.TurnNumber, input.APIKeyID,
			input.GroupID, input.AccountID, input.Model, input.Endpoint, input.Protocol,
			input.Transport, input.Stage, input.UpstreamStatus, input.RedactedPreview).Scan(&feedbackID)
		if errors.Is(err, sql.ErrNoRows) {
			_ = tx.Rollback()
			feedback, getErr := r.getCyberFeedbackByEventKey(ctx, input.EventKey)
			return feedback, false, getErr
		}
		if err != nil {
			return CyberFeedback{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return CyberFeedback{}, false, err
		}
		feedback, getErr := r.GetCyberFeedback(ctx, feedbackID)
		return feedback, true, getErr
	}

	var signatureID int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_cyber_signatures (
			group_id, protocol, stage, signature_version, prompt_signature, confirm_count, expires_at
		) VALUES ($1,$2,$3,$4,$5,0,$6)
		ON CONFLICT (group_id, signature_version, prompt_signature) DO NOTHING
		RETURNING id`, input.GroupID, input.Protocol, input.Stage, input.Scope.SignatureVersion,
		input.Scope.PromptSignature, input.ExpiresAt.UTC()).Scan(&signatureID)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, `
			SELECT id FROM prompt_audit_cyber_signatures
			WHERE group_id=$1 AND signature_version=$2 AND prompt_signature=$3
			FOR UPDATE`, input.GroupID, input.Scope.SignatureVersion,
			input.Scope.PromptSignature).Scan(&signatureID)
	}
	if err != nil {
		return CyberFeedback{}, false, err
	}

	var feedbackID int64
	var createdAt time.Time
	err = tx.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_cyber_feedback (
			signature_id, event_key, request_id, turn_number, api_key_id, group_id, account_id,
			model, endpoint, protocol, transport, stage, upstream_status, redacted_preview
		) VALUES ($1,$2,$3,$4,NULLIF($5,0),$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (event_key) DO NOTHING
		RETURNING id, created_at`, signatureID, input.EventKey, input.RequestID, input.TurnNumber,
		input.APIKeyID, input.GroupID, input.AccountID, input.Model, input.Endpoint, input.Protocol,
		input.Transport, input.Stage, input.UpstreamStatus, input.RedactedPreview).Scan(&feedbackID, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		feedback, getErr := r.getCyberFeedbackByEventKey(ctx, input.EventKey)
		return feedback, false, getErr
	}
	if err != nil {
		return CyberFeedback{}, false, err
	}

	var confirmCount int64
	err = tx.QueryRowContext(ctx, `
		UPDATE prompt_audit_cyber_signatures
		SET confirm_count=confirm_count+1,
			first_confirmed_at=COALESCE(first_confirmed_at,NOW()), last_confirmed_at=NOW(),
			expires_at=$2, updated_at=NOW()
		WHERE id=$1
		RETURNING confirm_count`, signatureID, input.ExpiresAt.UTC()).Scan(&confirmCount)
	if err != nil {
		return CyberFeedback{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET signature_confirm_count=$2, updated_at=NOW()
		WHERE id=$1`, feedbackID, confirmCount); err != nil {
		return CyberFeedback{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return CyberFeedback{}, false, err
	}
	feedback, err := r.GetCyberFeedback(ctx, feedbackID)
	if err != nil {
		return CyberFeedback{}, false, err
	}
	feedback.CreatedAt = createdAt.UTC()
	return feedback, true, nil
}

func (r *PostgreSQLRepository) MatchActiveSignature(ctx context.Context, scope CyberFingerprintScope) (bool, error) {
	if r == nil || r.db == nil || scope.GroupID <= 0 || len(scope.PromptSignature) == 0 {
		return false, nil
	}
	var matched bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM prompt_audit_cyber_signatures
			WHERE group_id=$1 AND signature_version=$2
				AND prompt_signature=$3 AND confirm_count > 0 AND expires_at > NOW()
		)`, scope.GroupID, scope.SignatureVersion, scope.PromptSignature).Scan(&matched)
	return matched, err
}

func (r *PostgreSQLRepository) ListActiveSignatures(ctx context.Context, groupID int64, signatureVersion string, afterID int64, limit int) ([]CyberActiveSignature, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("cyber feedback database unavailable")
	}
	signatureVersion = strings.TrimSpace(signatureVersion)
	if groupID <= 0 || signatureVersion == "" {
		return nil, errors.New("cyber signature version is required")
	}
	if afterID < 0 {
		afterID = 0
	}
	if limit < 1 {
		limit = cyberReplayWarmPageSize
	}
	if limit > cyberReplayWarmPageSize {
		limit = cyberReplayWarmPageSize
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, group_id, signature_version, prompt_signature, expires_at
		FROM prompt_audit_cyber_signatures
		WHERE signature_version=$1 AND group_id=$2 AND confirm_count > 0 AND expires_at > NOW() AND id > $3
		ORDER BY id ASC
		LIMIT $4`, signatureVersion, groupID, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]CyberActiveSignature, 0, limit)
	for rows.Next() {
		var item CyberActiveSignature
		if err := rows.Scan(&item.ID, &item.GroupID, &item.SignatureVersion, &item.PromptSignature, &item.ExpiresAt); err != nil {
			return nil, err
		}
		item.ExpiresAt = item.ExpiresAt.UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *PostgreSQLRepository) ListCyberFeedback(ctx context.Context, filter CyberFeedbackFilter, page, pageSize int) ([]CyberFeedback, int64, error) {
	if r == nil || r.db == nil {
		return nil, 0, errors.New("cyber feedback database unavailable")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where, args := cyberFeedbackWhere(filter)
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_cyber_feedback f `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+cyberFeedbackSelectColumns+`
		FROM prompt_audit_cyber_feedback f
		LEFT JOIN prompt_audit_cyber_signatures s ON s.id=f.signature_id `+where+`
		ORDER BY f.created_at DESC, f.id DESC
		LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]CyberFeedback, 0)
	for rows.Next() {
		item, scanErr := scanCyberFeedback(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (r *PostgreSQLRepository) GetCyberFeedback(ctx context.Context, id int64) (CyberFeedback, error) {
	if r == nil || r.db == nil {
		return CyberFeedback{}, errors.New("cyber feedback database unavailable")
	}
	return scanCyberFeedback(r.db.QueryRowContext(ctx, `
		SELECT `+cyberFeedbackSelectColumns+`
		FROM prompt_audit_cyber_feedback f
		LEFT JOIN prompt_audit_cyber_signatures s ON s.id=f.signature_id
		WHERE f.id=$1`, id))
}

func (r *PostgreSQLRepository) getCyberFeedbackByEventKey(ctx context.Context, eventKey string) (CyberFeedback, error) {
	return scanCyberFeedback(r.db.QueryRowContext(ctx, `
		SELECT `+cyberFeedbackSelectColumns+`
		FROM prompt_audit_cyber_feedback f
		LEFT JOIN prompt_audit_cyber_signatures s ON s.id=f.signature_id
		WHERE f.event_key=$1`, eventKey))
}

func (r *PostgreSQLRepository) ReviewCyberFeedback(ctx context.Context, id int64, status string, actorID int64, ruleID string, configVersion int64) (CyberFeedback, error) {
	status = strings.TrimSpace(status)
	if status != CyberReviewApproved && status != CyberReviewRejected {
		return CyberFeedback{}, errors.New("cyber feedback review status invalid")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET review_status=$2, reviewed_by=NULLIF($3,0), reviewed_at=NOW(),
			rule_id=$4, config_version=$5, updated_at=NOW()
		WHERE id=$1 AND review_status='pending'`, id, status, actorID, strings.TrimSpace(ruleID), configVersion)
	if err != nil {
		return CyberFeedback{}, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return CyberFeedback{}, err
	}
	if rows == 0 {
		var exists bool
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prompt_audit_cyber_feedback WHERE id=$1)`, id).Scan(&exists); err != nil {
			return CyberFeedback{}, err
		}
		if !exists {
			return CyberFeedback{}, ErrCyberFeedbackNotFound
		}
		return CyberFeedback{}, ErrCyberFeedbackReviewConflict
	}
	return r.GetCyberFeedback(ctx, id)
}

func (r *PostgreSQLRepository) CompleteCyberRuleGeneration(ctx context.Context, id int64, candidateRuleText, errorCode string) error {
	status := CyberGenerationGenerated
	if strings.TrimSpace(errorCode) != "" {
		status = CyberGenerationFailed
		candidateRuleText = ""
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET generation_status=$2, candidate_rule_text=$3, generation_error_code=$4, updated_at=NOW()
		WHERE id=$1 AND generation_status='pending'`, id, status, candidateRuleText, errorCode)
	return requireOneRow(result, err, ErrCyberFeedbackNotFound)
}

func (r *PostgreSQLRepository) ResetCyberRuleGeneration(ctx context.Context, id int64) error {
	if r == nil || r.db == nil {
		return errors.New("cyber feedback database unavailable")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET generation_status='pending', candidate_rule_text='', generation_error_code='', updated_at=NOW()
		WHERE id=$1 AND review_status='pending' AND generation_status IN ('generated','failed')`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows > 0 {
		return nil
	}
	var exists bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prompt_audit_cyber_feedback WHERE id=$1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrCyberFeedbackNotFound
	}
	return ErrCyberFeedbackGenerationConflict
}

// BeginCyberRuleRegeneration is the admin-service CAS boundary. It is kept as
// a named alias so regeneration cannot overwrite a reviewed feedback item.
func (r *PostgreSQLRepository) BeginCyberRuleRegeneration(ctx context.Context, id int64) error {
	return r.ResetCyberRuleGeneration(ctx, id)
}

type cyberFeedbackScanner interface {
	Scan(dest ...any) error
}

func scanCyberFeedback(row cyberFeedbackScanner) (CyberFeedback, error) {
	var item CyberFeedback
	err := row.Scan(
		&item.ID, &item.SignatureID, &item.SignatureVersion, &item.PromptSignature,
		&item.RequestID, &item.TurnNumber, &item.APIKeyID, &item.GroupID, &item.AccountID,
		&item.Model, &item.Endpoint, &item.Protocol, &item.Transport, &item.Stage, &item.UpstreamStatus,
		&item.RedactedPreview, &item.SignatureConfirmCount, &item.FirstConfirmedAt, &item.LastConfirmedAt,
		&item.GenerationStatus, &item.GenerationErrorCode,
		&item.CandidateRuleText, &item.ReviewStatus, &item.ReviewedBy, &item.ReviewedAt,
		&item.RuleID, &item.ConfigVersion, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CyberFeedback{}, ErrCyberFeedbackNotFound
	}
	return item, err
}

func cyberFeedbackWhere(filter CyberFeedbackFilter) (string, []any) {
	clauses := make([]string, 0, 3)
	args := make([]any, 0, 3)
	if filter.GroupID != nil && *filter.GroupID > 0 {
		args = append(args, *filter.GroupID)
		clauses = append(clauses, fmt.Sprintf("f.group_id=$%d", len(args)))
	}
	if value := strings.TrimSpace(filter.ReviewStatus); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("f.review_status=$%d", len(args)))
	}
	if value := strings.TrimSpace(filter.GenerationStatus); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("f.generation_status=$%d", len(args)))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}
