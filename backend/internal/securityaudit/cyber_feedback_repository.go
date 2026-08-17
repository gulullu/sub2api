package securityaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const cyberFeedbackListSelectColumns = `
	f.id, COALESCE(f.signature_id,0), COALESCE(s.signature_version,''), COALESCE(s.prompt_signature,''::bytea),
	f.request_id, f.turn_number, f.api_key_id, f.group_id, f.account_id, ''::text,
	0::bigint, ''::text,
	f.model, f.endpoint, f.protocol, f.transport, f.stage, f.upstream_status,
	''::text, ''::text, f.redacted_preview, f.prompt_length, f.message_count, f.full_prompt_truncated,
	COALESCE(s.confirm_count,0), s.first_confirmed_at, s.last_confirmed_at,
	f.generation_status, f.generation_error_code,
	f.candidate_rule_text, f.review_status, f.reviewed_by, f.reviewed_at,
	f.rule_id, f.config_version, f.created_at, f.updated_at`

const cyberFeedbackMetadataSelectColumns = `
	f.id, COALESCE(f.signature_id,0), COALESCE(s.signature_version,''), COALESCE(s.prompt_signature,''::bytea),
	f.request_id, f.turn_number, f.api_key_id, f.group_id, f.account_id, f.account_name_snapshot,
	f.credential_account_id, f.credential_account_name_snapshot,
	f.model, f.endpoint, f.protocol, f.transport, f.stage, f.upstream_status,
	f.upstream_code, f.upstream_message, f.redacted_preview, f.prompt_length, f.message_count, f.full_prompt_truncated,
	COALESCE(s.confirm_count,0), s.first_confirmed_at, s.last_confirmed_at,
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
	if input.CredentialAccountID <= 0 {
		input.CredentialAccountID = input.AccountID
	}
	input.APIKeyPrefix = boundedCyberEvidenceText(input.APIKeyPrefix, 8)
	r.populateCyberIdentitySnapshots(ctx, &input)
	input.APIKeyPrefix = boundedCyberEvidenceText(input.APIKeyPrefix, 8)
	input.AccountName = r.cyberAccountName(ctx, input.AccountID, input.AccountName)
	input.CredentialAccountName = r.cyberAccountName(ctx, input.CredentialAccountID, input.CredentialAccountName)
	if strings.TrimSpace(input.CredentialAccountEmail) == "" {
		_ = r.db.QueryRowContext(ctx, `SELECT COALESCE(credentials->>'email','') FROM accounts WHERE id=$1`, input.CredentialAccountID).Scan(&input.CredentialAccountEmail)
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
				signature_id, event_key, request_id, turn_number, api_key_id,
				user_id, username_snapshot, user_email_snapshot, api_key_name_snapshot, api_key_prefix_snapshot,
				group_id, group_name_snapshot, account_id, account_name_snapshot,
				credential_account_id, credential_account_name_snapshot, credential_account_email_snapshot,
				client_request_id_snapshot, client_ip_snapshot, user_agent_snapshot,
				model, endpoint, protocol, transport, stage, upstream_status,
				upstream_code, upstream_message, redacted_preview, full_prompt,
				prompt_length, message_count, full_prompt_truncated,
				signature_confirm_count, generation_status, generation_error_code
			) VALUES (NULL,$1,$2,$3,NULLIF($4,0),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,0,'failed','fingerprint_unavailable')
			ON CONFLICT (event_key) DO NOTHING
			RETURNING id`, input.EventKey, input.RequestID, input.TurnNumber, input.APIKeyID,
			input.UserID, input.Username, input.UserEmail, input.APIKeyName, input.APIKeyPrefix,
			input.GroupID, input.GroupName, input.AccountID, input.AccountName, input.CredentialAccountID,
			input.CredentialAccountName, input.CredentialAccountEmail,
			input.ClientRequestID, input.ClientIP, input.UserAgent,
			input.Model, input.Endpoint, input.Protocol, input.Transport, input.Stage,
			input.UpstreamStatus, input.UpstreamCode, input.UpstreamMessage,
			input.RedactedPreview, input.FullPrompt, input.PromptLength, input.MessageCount,
			input.FullPromptTruncated).Scan(&feedbackID)
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
			signature_id, event_key, request_id, turn_number, api_key_id,
			user_id, username_snapshot, user_email_snapshot, api_key_name_snapshot, api_key_prefix_snapshot,
			group_id, group_name_snapshot, account_id, account_name_snapshot,
			credential_account_id, credential_account_name_snapshot, credential_account_email_snapshot,
			client_request_id_snapshot, client_ip_snapshot, user_agent_snapshot,
			model, endpoint, protocol, transport, stage, upstream_status,
			upstream_code, upstream_message, redacted_preview, full_prompt,
			prompt_length, message_count, full_prompt_truncated
		) VALUES ($1,$2,$3,$4,NULLIF($5,0),$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
		ON CONFLICT (event_key) DO NOTHING
		RETURNING id, created_at`, signatureID, input.EventKey, input.RequestID, input.TurnNumber,
		input.APIKeyID, input.UserID, input.Username, input.UserEmail, input.APIKeyName, input.APIKeyPrefix,
		input.GroupID, input.GroupName, input.AccountID, input.AccountName, input.CredentialAccountID,
		input.CredentialAccountName, input.CredentialAccountEmail,
		input.ClientRequestID, input.ClientIP, input.UserAgent,
		input.Model, input.Endpoint, input.Protocol, input.Transport, input.Stage,
		input.UpstreamStatus, input.UpstreamCode, input.UpstreamMessage,
		input.RedactedPreview, input.FullPrompt, input.PromptLength, input.MessageCount,
		input.FullPromptTruncated).Scan(&feedbackID, &createdAt)
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

func (r *PostgreSQLRepository) cyberAccountName(ctx context.Context, accountID int64, current string) string {
	if value := strings.TrimSpace(current); value != "" || accountID <= 0 || r == nil || r.db == nil {
		return value
	}
	var value string
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(name,'') FROM accounts WHERE id=$1`, accountID).Scan(&value); err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}

func (r *PostgreSQLRepository) populateCyberIdentitySnapshots(ctx context.Context, input *CyberConfirmInput) {
	if r == nil || r.db == nil || input == nil {
		return
	}
	if input.APIKeyID > 0 {
		var userID, groupID sql.NullInt64
		var username, userEmail, keyName, keyPrefix, groupName string
		err := r.db.QueryRowContext(ctx, `
			SELECT ak.user_id, ak.group_id, COALESCE(u.username,''), COALESCE(u.email,''),
				COALESCE(ak.name,''),
				CASE WHEN char_length(COALESCE(ak.key,'')) > 8 THEN LEFT(ak.key,8) ELSE '' END,
				COALESCE(g.name,'')
			FROM api_keys ak
			LEFT JOIN users u ON u.id=ak.user_id
			LEFT JOIN groups g ON g.id=ak.group_id
			WHERE ak.id=$1`, input.APIKeyID).Scan(
			&userID, &groupID, &username, &userEmail, &keyName, &keyPrefix, &groupName,
		)
		if err == nil {
			if input.UserID <= 0 && userID.Valid {
				input.UserID = userID.Int64
			}
			if input.GroupID <= 0 && groupID.Valid {
				input.GroupID = groupID.Int64
			}
			fillCyberSnapshotString(&input.Username, username)
			fillCyberSnapshotString(&input.UserEmail, userEmail)
			fillCyberSnapshotString(&input.APIKeyName, keyName)
			fillCyberSnapshotString(&input.APIKeyPrefix, keyPrefix)
			fillCyberSnapshotString(&input.GroupName, groupName)
		}
	}
	if input.UserID > 0 && (strings.TrimSpace(input.Username) == "" || strings.TrimSpace(input.UserEmail) == "") {
		var username, email string
		if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(username,''), COALESCE(email,'') FROM users WHERE id=$1`, input.UserID).Scan(&username, &email); err == nil {
			fillCyberSnapshotString(&input.Username, username)
			fillCyberSnapshotString(&input.UserEmail, email)
		}
	}
	if input.GroupID > 0 && strings.TrimSpace(input.GroupName) == "" {
		_ = r.db.QueryRowContext(ctx, `SELECT COALESCE(name,'') FROM groups WHERE id=$1`, input.GroupID).Scan(&input.GroupName)
	}
}

func fillCyberSnapshotString(target *string, value string) {
	if target != nil && strings.TrimSpace(*target) == "" {
		*target = strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
	}
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
		SELECT `+cyberFeedbackListSelectColumns+`
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
		SELECT `+cyberFeedbackMetadataSelectColumns+`
		FROM prompt_audit_cyber_feedback f
		LEFT JOIN prompt_audit_cyber_signatures s ON s.id=f.signature_id
		WHERE f.id=$1`, id))
}

func (r *PostgreSQLRepository) GetCyberFeedbackEvidence(ctx context.Context, id int64) (CyberFeedbackEvidence, error) {
	if r == nil || r.db == nil {
		return CyberFeedbackEvidence{}, errors.New("cyber feedback database unavailable")
	}
	var item CyberFeedbackEvidence
	err := r.db.QueryRowContext(ctx, `
		SELECT f.id, f.full_prompt, f.prompt_length, f.message_count, f.full_prompt_truncated,
			COALESCE(NULLIF(f.user_id,0),u.id,ak.user_id,0),
			COALESCE(NULLIF(f.username_snapshot,''),u.username,''),
			COALESCE(NULLIF(f.user_email_snapshot,''),u.email,''),
			COALESCE(f.api_key_id,0),
			COALESCE(NULLIF(f.api_key_name_snapshot,''),ak.name,''),
			COALESCE(NULLIF(f.api_key_prefix_snapshot,''),
				CASE WHEN char_length(COALESCE(ak.key,'')) > 8 THEN LEFT(op.api_key_prefix,8) ELSE '' END,''),
			f.group_id, COALESCE(NULLIF(f.group_name_snapshot,''),g.name,''),
			f.account_id, COALESCE(NULLIF(f.account_name_snapshot,''),selected_account.name,''),
			COALESCE(NULLIF(f.credential_account_id,0),selected_account.parent_account_id,f.account_id),
			COALESCE(NULLIF(f.credential_account_name_snapshot,''),credential_account.name,''),
			COALESCE(NULLIF(f.credential_account_email_snapshot,''),credential_account.credentials->>'email',''),
			CASE
				WHEN f.credential_account_email_snapshot <> '' THEN 'snapshot'
				WHEN COALESCE(credential_account.credentials->>'email','') <> '' THEN 'current'
				ELSE 'unavailable'
			END,
			CASE
				WHEN f.user_id > 0 OR f.username_snapshot <> '' OR f.user_email_snapshot <> ''
					OR f.api_key_name_snapshot <> '' OR f.api_key_prefix_snapshot <> ''
					OR f.client_request_id_snapshot <> '' OR f.client_ip_snapshot <> ''
					OR f.user_agent_snapshot <> '' THEN 'snapshot'
				WHEN ak.id IS NOT NULL OR u.id IS NOT NULL OR g.id IS NOT NULL THEN 'current'
				ELSE 'unavailable'
			END,
			COALESCE(NULLIF(f.client_request_id_snapshot,''),op.client_request_id,''),
			COALESCE(NULLIF(f.client_ip_snapshot,''),op.client_ip,''),
			COALESCE(NULLIF(f.user_agent_snapshot,''),op.user_agent,'')
		FROM prompt_audit_cyber_feedback f
		LEFT JOIN api_keys ak ON ak.id=f.api_key_id
		LEFT JOIN users u ON u.id=COALESCE(NULLIF(f.user_id,0),ak.user_id)
		LEFT JOIN groups g ON g.id=f.group_id
		LEFT JOIN accounts selected_account ON selected_account.id=f.account_id
		LEFT JOIN accounts credential_account ON credential_account.id=COALESCE(NULLIF(f.credential_account_id,0),selected_account.parent_account_id,f.account_id)
		LEFT JOIN LATERAL (
			SELECT MAX(o.api_key_prefix) AS api_key_prefix,
				MAX(o.client_request_id) AS client_request_id,
				MAX(host(o.client_ip)) AS client_ip,
				MAX(o.user_agent) AS user_agent
			FROM ops_error_logs o
			WHERE f.request_id <> '' AND o.request_id=f.request_id
				AND o.account_id=f.account_id AND o.error_type='cyber_policy'
			HAVING COUNT(*)=1
		) op ON TRUE
		WHERE f.id=$1`, id).Scan(
		&item.ID, &item.FullPrompt, &item.PromptLength, &item.MessageCount, &item.FullPromptTruncated,
		&item.UserID, &item.Username, &item.UserEmail, &item.APIKeyID, &item.APIKeyName, &item.APIKeyPrefix,
		&item.GroupID, &item.GroupName, &item.SelectedAccountID, &item.SelectedAccountName,
		&item.CredentialAccountID, &item.CredentialAccountName, &item.CredentialAccountEmail,
		&item.CredentialAccountEmailSource, &item.IdentitySource,
		&item.ClientRequestID, &item.ClientIP, &item.UserAgent,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CyberFeedbackEvidence{}, ErrCyberFeedbackNotFound
	}
	return item, err
}

func (r *PostgreSQLRepository) getCyberFeedbackByEventKey(ctx context.Context, eventKey string) (CyberFeedback, error) {
	return scanCyberFeedback(r.db.QueryRowContext(ctx, `
		SELECT `+cyberFeedbackMetadataSelectColumns+`
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

func (r *PostgreSQLRepository) ListCyberRuleProjections(ctx context.Context) ([]CyberRuleProjection, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("cyber feedback database unavailable")
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, rule_id,
			CASE WHEN rule_lifecycle_status='' THEN candidate_rule_text ELSE adopted_rule_text END,
			CASE WHEN rule_lifecycle_status='' THEN 'disabled' ELSE rule_lifecycle_status END,
			CASE WHEN rule_lifecycle_status='' THEN
				CASE WHEN candidate_rule_text<>'' THEN 'recovered_candidate' ELSE 'unavailable' END
			ELSE rule_text_source END,
			(rule_lifecycle_status=''),
			rule_state_config_version, rule_state_updated_at, rule_state_updated_by,
			created_at, reviewed_at, reviewed_by
		FROM prompt_audit_cyber_feedback
		WHERE review_status='approved'
			AND (rule_lifecycle_status IN ('active','disabled')
				OR (rule_lifecycle_status='' AND rule_id<>''))
		ORDER BY reviewed_at DESC NULLS LAST, id DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]CyberRuleProjection, 0)
	for rows.Next() {
		item, scanErr := scanCyberRuleProjection(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *PostgreSQLRepository) GetCyberRuleProjection(ctx context.Context, feedbackID int64) (CyberRuleProjection, error) {
	if r == nil || r.db == nil {
		return CyberRuleProjection{}, errors.New("cyber feedback database unavailable")
	}
	return scanCyberRuleProjection(r.db.QueryRowContext(ctx, `
		SELECT id, rule_id,
			CASE WHEN rule_lifecycle_status='' THEN candidate_rule_text ELSE adopted_rule_text END,
			CASE WHEN rule_lifecycle_status='' THEN 'disabled' ELSE rule_lifecycle_status END,
			CASE WHEN rule_lifecycle_status='' THEN
				CASE WHEN candidate_rule_text<>'' THEN 'recovered_candidate' ELSE 'unavailable' END
			ELSE rule_text_source END,
			(rule_lifecycle_status=''),
			rule_state_config_version, rule_state_updated_at, rule_state_updated_by,
			created_at, reviewed_at, reviewed_by
		FROM prompt_audit_cyber_feedback
		WHERE id=$1 AND review_status='approved'`, feedbackID))
}

func (r *PostgreSQLRepository) SaveCyberRuleProjection(
	ctx context.Context,
	feedbackID int64,
	ruleID, ruleText, lifecycleStatus, textSource string,
	actorID, configVersion int64,
) error {
	if r == nil || r.db == nil {
		return errors.New("cyber feedback database unavailable")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET adopted_rule_text=$3, rule_lifecycle_status=$4, rule_text_source=$5,
			rule_state_config_version=$6, rule_state_updated_at=NOW(),
			rule_state_updated_by=NULLIF($7,0), updated_at=NOW()
		WHERE id=$1 AND rule_id=$2 AND review_status='approved'
			AND rule_lifecycle_status <> 'deleted'`, feedbackID, strings.TrimSpace(ruleID),
		strings.TrimSpace(ruleText), strings.TrimSpace(lifecycleStatus), strings.TrimSpace(textSource),
		configVersion, actorID)
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
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prompt_audit_cyber_feedback WHERE id=$1)`, feedbackID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrCyberFeedbackNotFound
	}
	return ErrCyberRuleLifecycleConflict
}

// ReconcileActiveCyberRuleProjection repairs lifecycle metadata from an exact
// rule that is already present in the runtime config. Config membership is the
// authority for this exceptional path; an earlier reject or partial review is
// still retained in the administrator audit log. A deletion tombstone remains
// terminal and is never overwritten.
func (r *PostgreSQLRepository) ReconcileActiveCyberRuleProjection(
	ctx context.Context,
	rule CyberSupplementRule,
	lifecycleStatus string,
	actorID, configVersion int64,
) (CyberRuleProjection, error) {
	if r == nil || r.db == nil {
		return CyberRuleProjection{}, errors.New("cyber feedback database unavailable")
	}
	projection, err := scanCyberRuleProjection(r.db.QueryRowContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET review_status='approved', reviewed_by=NULLIF($6,0), reviewed_at=$5,
			rule_id=$2, config_version=$8,
			adopted_rule_text=$3, rule_lifecycle_status=$4, rule_text_source='reviewed',
			rule_state_config_version=$8, rule_state_updated_at=NOW(),
			rule_state_updated_by=NULLIF($7,0), updated_at=NOW()
		WHERE id=$1 AND rule_lifecycle_status <> 'deleted'
		RETURNING id, rule_id, adopted_rule_text, rule_lifecycle_status, rule_text_source,
			FALSE,
			rule_state_config_version, rule_state_updated_at, rule_state_updated_by,
			created_at, reviewed_at, reviewed_by`,
		rule.SourceFeedbackID, strings.TrimSpace(rule.ID), strings.TrimSpace(rule.RuleText),
		strings.TrimSpace(lifecycleStatus), rule.ReviewedAt, rule.ReviewedBy,
		actorID, configVersion,
	))
	if err == nil {
		return projection, nil
	}
	if !errors.Is(err, ErrCyberFeedbackNotFound) {
		return CyberRuleProjection{}, err
	}
	projection, getErr := scanCyberRuleProjection(r.db.QueryRowContext(ctx, `
		SELECT id, rule_id, adopted_rule_text, rule_lifecycle_status, rule_text_source,
			FALSE,
			rule_state_config_version, rule_state_updated_at, rule_state_updated_by,
			created_at, reviewed_at, reviewed_by
		FROM prompt_audit_cyber_feedback WHERE id=$1`, rule.SourceFeedbackID))
	if getErr != nil {
		return CyberRuleProjection{}, getErr
	}
	if projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return projection, ErrCyberRuleLifecycleDeleted
	}
	return projection, ErrCyberRuleLifecycleConflict
}

func (r *PostgreSQLRepository) DeleteCyberRuleProjection(ctx context.Context, feedbackID int64, ruleID string, actorID, configVersion int64) error {
	if r == nil || r.db == nil {
		return errors.New("cyber feedback database unavailable")
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE prompt_audit_cyber_feedback
		SET adopted_rule_text='', rule_lifecycle_status='deleted', rule_text_source='',
			rule_state_config_version=$3, rule_state_updated_at=NOW(),
			rule_state_updated_by=NULLIF($4,0), updated_at=NOW()
		WHERE id=$1 AND rule_id=$2 AND review_status='approved'
			AND rule_lifecycle_status='disabled'`, feedbackID, strings.TrimSpace(ruleID), configVersion, actorID)
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
	projection, getErr := r.GetCyberRuleProjection(ctx, feedbackID)
	if errors.Is(getErr, ErrCyberFeedbackNotFound) {
		return getErr
	}
	if getErr != nil {
		return getErr
	}
	if projection.RuleID == strings.TrimSpace(ruleID) && projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return nil
	}
	return ErrCyberRuleLifecycleConflict
}

func scanCyberRuleProjection(row cyberFeedbackScanner) (CyberRuleProjection, error) {
	var item CyberRuleProjection
	err := row.Scan(
		&item.FeedbackID, &item.RuleID, &item.RuleText, &item.LifecycleStatus, &item.RuleTextSource,
		&item.LegacyUnprojected,
		&item.StateConfigVersion, &item.StateUpdatedAt, &item.StateUpdatedBy,
		&item.CreatedAt, &item.ReviewedAt, &item.ReviewedBy,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CyberRuleProjection{}, ErrCyberFeedbackNotFound
	}
	return item, err
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
		&item.RequestID, &item.TurnNumber, &item.APIKeyID, &item.GroupID, &item.AccountID, &item.AccountNameSnapshot,
		&item.CredentialAccountID, &item.CredentialAccountName,
		&item.Model, &item.Endpoint, &item.Protocol, &item.Transport, &item.Stage, &item.UpstreamStatus,
		&item.UpstreamCode, &item.UpstreamMessage, &item.RedactedPreview,
		&item.PromptLength, &item.MessageCount, &item.FullPromptTruncated,
		&item.SignatureConfirmCount, &item.FirstConfirmedAt, &item.LastConfirmedAt,
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
