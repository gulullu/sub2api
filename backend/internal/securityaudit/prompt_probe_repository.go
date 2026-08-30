package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

var (
	ErrProbeGroupNotFound     = errors.New("prompt audit probe group not found")
	ErrProbeEventNotFound     = errors.New("prompt audit probe event not found")
	ErrProbeExemptionNotFound = errors.New("prompt audit probe exemption not found")
)

func (r *PostgreSQLRepository) GetProbeGroupConfig(ctx context.Context, groupID int64) (ProbeGroupConfig, error) {
	if r == nil || r.db == nil || groupID <= 0 {
		return ProbeGroupConfig{}, ErrProbeGroupNotFound
	}
	var cfg ProbeGroupConfig
	err := r.db.QueryRowContext(ctx, `
		SELECT g.id,g.name,COALESCE(c.enabled,FALSE),COALESCE(c.interval_seconds,300),
			COALESCE(c.health_scope,'group_model_protocol'),COALESCE(c.allow_first_real_probe,TRUE),
			COALESCE(c.skip_repeat_audit,TRUE),COALESCE(c.skip_repeat_upstream,TRUE),
			COALESCE(c.healthy_response,$2),COALESCE(c.violation_response,$3),COALESCE(c.unknown_response,$4),
			COALESCE(c.config_version,1),COALESCE(c.created_at,g.created_at),COALESCE(c.updated_at,g.updated_at),c.updated_by
		FROM groups g LEFT JOIN prompt_audit_probe_group_configs c ON c.group_id=g.id
		WHERE g.id=$1 AND g.deleted_at IS NULL`, groupID,
		DefaultProbeHealthyResponse, DefaultProbeViolationResponse, DefaultProbeUnknownResponse).
		Scan(&cfg.GroupID, &cfg.GroupName, &cfg.Enabled, &cfg.IntervalSeconds, &cfg.HealthScope,
			&cfg.AllowFirstRealProbe, &cfg.SkipRepeatAudit, &cfg.SkipRepeatUpstream,
			&cfg.HealthyResponse, &cfg.ViolationResponse, &cfg.UnknownResponse,
			&cfg.PolicyVersion, &cfg.CreatedAt, &cfg.UpdatedAt, &cfg.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return ProbeGroupConfig{}, ErrProbeGroupNotFound
	}
	return cfg, err
}

func (r *PostgreSQLRepository) SaveProbeGroupConfig(ctx context.Context, cfg ProbeGroupConfig, actorID int64) (ProbeGroupConfig, error) {
	if r == nil || r.db == nil || cfg.GroupID <= 0 {
		return ProbeGroupConfig{}, ErrProbeGroupNotFound
	}
	var exists bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id=$1 AND deleted_at IS NULL)`, cfg.GroupID).Scan(&exists); err != nil {
		return ProbeGroupConfig{}, err
	}
	if !exists {
		return ProbeGroupConfig{}, ErrProbeGroupNotFound
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO prompt_audit_probe_group_configs(
			group_id,enabled,interval_seconds,health_scope,allow_first_real_probe,
			skip_repeat_audit,skip_repeat_upstream,healthy_response,violation_response,
			unknown_response,updated_at,updated_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NULLIF($11,0))
		ON CONFLICT(group_id) DO UPDATE SET
			enabled=EXCLUDED.enabled,interval_seconds=EXCLUDED.interval_seconds,
			health_scope=EXCLUDED.health_scope,allow_first_real_probe=EXCLUDED.allow_first_real_probe,
			skip_repeat_audit=EXCLUDED.skip_repeat_audit,skip_repeat_upstream=EXCLUDED.skip_repeat_upstream,
			healthy_response=EXCLUDED.healthy_response,violation_response=EXCLUDED.violation_response,
			unknown_response=EXCLUDED.unknown_response,config_version=prompt_audit_probe_group_configs.config_version+1,
			updated_at=NOW(),updated_by=EXCLUDED.updated_by`,
		cfg.GroupID, cfg.Enabled, cfg.IntervalSeconds, cfg.HealthScope, cfg.AllowFirstRealProbe,
		cfg.SkipRepeatAudit, cfg.SkipRepeatUpstream, cfg.HealthyResponse, cfg.ViolationResponse,
		cfg.UnknownResponse, actorID)
	if err != nil {
		return ProbeGroupConfig{}, err
	}
	return r.GetProbeGroupConfig(ctx, cfg.GroupID)
}

func (r *PostgreSQLRepository) ListProbeGroupConfigs(ctx context.Context, groupIDs []int64, keyword, status string, page, pageSize int) (*ProbeGroupPage, error) {
	groupIDs = canonicalInt64s(groupIDs)
	page, pageSize = normalizeProbePage(page, pageSize)
	if len(groupIDs) == 0 {
		return &ProbeGroupPage{Items: []ProbeGroupConfig{}, Page: page, PageSize: pageSize}, nil
	}
	clauses := []string{"g.deleted_at IS NULL", "g.id=ANY($1)"}
	args := []any{pq.Array(groupIDs)}
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		args = append(args, "%"+TrimRunes(keyword, 128)+"%")
		clauses = append(clauses, fmt.Sprintf("(g.name ILIKE $%d OR CAST(g.id AS TEXT) ILIKE $%d)", len(args), len(args)))
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "enabled", "on", "true":
		clauses = append(clauses, "COALESCE(c.enabled,FALSE)=TRUE")
	case "disabled", "off", "false":
		clauses = append(clauses, "COALESCE(c.enabled,FALSE)=FALSE")
	}
	where := " WHERE " + strings.Join(clauses, " AND ")
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups g LEFT JOIN prompt_audit_probe_group_configs c ON c.group_id=g.id`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `
		SELECT g.id,g.name,COALESCE(c.enabled,FALSE),COALESCE(c.interval_seconds,300),
			COALESCE(c.health_scope,'group_model_protocol'),COALESCE(c.allow_first_real_probe,TRUE),
			COALESCE(c.skip_repeat_audit,TRUE),COALESCE(c.skip_repeat_upstream,TRUE),
			COALESCE(c.healthy_response,'服务正常。为避免重复检测，探针最小间隔为 5 分钟。'),
			COALESCE(c.violation_response,'服务正常，但无法协助该请求。为避免重复检测，探针最小间隔为 5 分钟。'),
			COALESCE(c.unknown_response,'网关在线，上游状态正在刷新。探针最小间隔为 5 分钟。'),
			COALESCE(c.config_version,1),
			COALESCE(stats.local_responses,0),COALESCE(stats.skipped_audits,0),
			COALESCE(stats.skipped_upstream,0),stats.last_probe_at,
			COALESCE(c.created_at,g.created_at),COALESCE(c.updated_at,g.updated_at),c.updated_by
		FROM groups g
		LEFT JOIN prompt_audit_probe_group_configs c ON c.group_id=g.id
		LEFT JOIN LATERAL (
			SELECT SUM(h.local_response_count) local_responses,SUM(h.audit_skipped_count) skipped_audits,
				SUM(h.upstream_skipped_count) skipped_upstream,MAX(h.last_probe_at) last_probe_at
			FROM prompt_audit_probe_hourly_stats h
			WHERE h.group_id=g.id AND h.bucket_at >= date_trunc('hour',NOW()-INTERVAL '23 hours')
		) stats ON TRUE`+where+
		fmt.Sprintf(" ORDER BY COALESCE(c.enabled,FALSE) DESC,g.name,g.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]ProbeGroupConfig, 0, pageSize)
	for rows.Next() {
		var item ProbeGroupConfig
		if err := rows.Scan(&item.GroupID, &item.GroupName, &item.Enabled, &item.IntervalSeconds,
			&item.HealthScope, &item.AllowFirstRealProbe, &item.SkipRepeatAudit, &item.SkipRepeatUpstream,
			&item.HealthyResponse, &item.ViolationResponse, &item.UnknownResponse,
			&item.PolicyVersion,
			&item.LocalResponses24H, &item.SkippedAudits24H, &item.SkippedUpstream24H, &item.LastProbeAt,
			&item.CreatedAt, &item.UpdatedAt, &item.UpdatedBy); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := 0
	if total > 0 {
		pages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &ProbeGroupPage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

func normalizeProbePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func (r *PostgreSQLRepository) RecordProbeEvent(ctx context.Context, delta probeEventDelta) (*ProbeEvent, error) {
	if r == nil || r.db == nil || delta.Request.GroupID == nil || *delta.Request.GroupID <= 0 {
		return nil, errors.New("prompt probe event input invalid")
	}
	evidence, _ := json.Marshal(delta.Shape.Evidence)
	snapshot, _ := json.Marshal(map[string]any{
		"redacted_preview": delta.Shape.Preview, "prompt_hash": delta.Shape.Fingerprint,
		"prompt_length": len([]rune(delta.Shape.ScanText)), "request_id": delta.Request.RequestID,
	})
	var userID, keyID any
	if delta.Request.UserID > 0 {
		userID = delta.Request.UserID
	}
	if delta.Request.APIKeyID > 0 {
		keyID = delta.Request.APIKeyID
	}
	auditConfigVersion, probeConfigVersion := splitCombinedProbePolicyVersion(delta.PolicyVersion)
	observedAt := delta.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	row := tx.QueryRowContext(ctx, `
		INSERT INTO prompt_audit_probe_events(
			group_id,group_name_snapshot,family_fingerprint,family_preview,classification,verdict,
			subject_user_id,user_id,user_email_snapshot,api_key_id,api_key_name_snapshot,model,protocol,stream,max_tokens,
			policy_version,audit_config_version,probe_config_version,evidence,risk_source,handling,response_kind,prompt_snapshot,
			total_count,local_response_count,audit_skipped_count,upstream_skipped_count,audit_call_count,
			upstream_call_count,linked_audit_event_id,last_real_health_at,window_expires_at,next_real_probe_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
			1,$24,$25,$26,$27,$28,$29,$30,$31,$32)
		ON CONFLICT(group_id,subject_user_id,audit_config_version,probe_config_version,family_fingerprint) DO UPDATE SET
			group_name_snapshot=EXCLUDED.group_name_snapshot,family_preview=EXCLUDED.family_preview,
			classification=EXCLUDED.classification,verdict=EXCLUDED.verdict,
			user_email_snapshot=EXCLUDED.user_email_snapshot,api_key_id=EXCLUDED.api_key_id,
			api_key_name_snapshot=EXCLUDED.api_key_name_snapshot,model=EXCLUDED.model,protocol=EXCLUDED.protocol,
			stream=EXCLUDED.stream,max_tokens=EXCLUDED.max_tokens,policy_version=EXCLUDED.policy_version,
			audit_config_version=EXCLUDED.audit_config_version,probe_config_version=EXCLUDED.probe_config_version,
			evidence=EXCLUDED.evidence,risk_source=EXCLUDED.risk_source,handling=EXCLUDED.handling,
			response_kind=EXCLUDED.response_kind,prompt_snapshot=EXCLUDED.prompt_snapshot,
			total_count=prompt_audit_probe_events.total_count+1,
			local_response_count=prompt_audit_probe_events.local_response_count+EXCLUDED.local_response_count,
			audit_skipped_count=prompt_audit_probe_events.audit_skipped_count+EXCLUDED.audit_skipped_count,
			upstream_skipped_count=prompt_audit_probe_events.upstream_skipped_count+EXCLUDED.upstream_skipped_count,
			audit_call_count=prompt_audit_probe_events.audit_call_count+EXCLUDED.audit_call_count,
			upstream_call_count=prompt_audit_probe_events.upstream_call_count+EXCLUDED.upstream_call_count,
			linked_audit_event_id=COALESCE(EXCLUDED.linked_audit_event_id,prompt_audit_probe_events.linked_audit_event_id),
			last_real_health_at=COALESCE(EXCLUDED.last_real_health_at,prompt_audit_probe_events.last_real_health_at),
			window_expires_at=EXCLUDED.window_expires_at,next_real_probe_at=EXCLUDED.next_real_probe_at,
			last_seen_at=NOW(),updated_at=NOW(),cleared_at=NULL,cleared_by=NULL,clear_reason=''
		WHERE prompt_audit_probe_events.cleared_at IS NULL OR prompt_audit_probe_events.cleared_at < $33
		RETURNING `+probeEventColumns(),
		*delta.Request.GroupID, delta.Request.GroupName, delta.Shape.Fingerprint, delta.Shape.Preview,
		delta.Classification, delta.Verdict, delta.Request.UserID, userID, delta.Request.UserEmail, keyID, delta.Request.APIKeyName,
		delta.Request.Model, delta.Request.Protocol, delta.Shape.Stream, delta.Shape.MaxTokens,
		delta.PolicyVersion, auditConfigVersion, probeConfigVersion, evidence, delta.RiskSource, delta.Handling, delta.ResponseKind, snapshot,
		boolInt(delta.LocalResponse), boolInt(delta.AuditSkipped), boolInt(delta.UpstreamSkipped),
		boolInt(delta.AuditCalled), boolInt(delta.UpstreamCalled), delta.LinkedAuditEventID,
		delta.LastRealHealthAt, delta.WindowExpiresAt, delta.NextRealProbeAt, observedAt)
	event, err := scanProbeEvent(row)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO prompt_audit_probe_hourly_stats(
			group_id,bucket_at,local_response_count,audit_skipped_count,upstream_skipped_count,last_probe_at)
		VALUES($1,date_trunc('hour',NOW()),$2,$3,$4,NOW())
		ON CONFLICT(group_id,bucket_at) DO UPDATE SET
			local_response_count=prompt_audit_probe_hourly_stats.local_response_count+EXCLUDED.local_response_count,
			audit_skipped_count=prompt_audit_probe_hourly_stats.audit_skipped_count+EXCLUDED.audit_skipped_count,
			upstream_skipped_count=prompt_audit_probe_hourly_stats.upstream_skipped_count+EXCLUDED.upstream_skipped_count,
			last_probe_at=GREATEST(prompt_audit_probe_hourly_stats.last_probe_at,EXCLUDED.last_probe_at)`,
		event.GroupID, boolInt(delta.LocalResponse), boolInt(delta.AuditSkipped), boolInt(delta.UpstreamSkipped)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return event, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (r *PostgreSQLRepository) DeleteOldProbeHourlyStats(ctx context.Context, limit int) (int64, error) {
	if limit <= 0 || limit > 10_000 {
		limit = 10_000
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM prompt_audit_probe_hourly_stats WHERE ctid IN (
		SELECT ctid FROM prompt_audit_probe_hourly_stats
		WHERE bucket_at < NOW()-INTERVAL '90 days' ORDER BY bucket_at LIMIT $1)`, limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func probeEventColumns() string {
	return `id,group_id,group_name_snapshot,family_fingerprint,family_preview,classification,verdict,
		subject_user_id,user_id,user_email_snapshot,api_key_id,api_key_name_snapshot,model,protocol,stream,max_tokens,
		policy_version,audit_config_version,probe_config_version,evidence,risk_source,handling,response_kind,prompt_snapshot,total_count,
		local_response_count,audit_skipped_count,upstream_skipped_count,audit_call_count,upstream_call_count,
		linked_audit_event_id,first_seen_at,last_seen_at,last_real_health_at,window_expires_at,next_real_probe_at,
		created_at,updated_at`
}

type probeRowScanner interface{ Scan(...any) error }

func scanProbeEvent(row probeRowScanner) (*ProbeEvent, error) {
	var event ProbeEvent
	var evidence, snapshot []byte
	err := row.Scan(&event.ID, &event.GroupID, &event.GroupName, &event.FamilyFingerprint, &event.FamilyPreview,
		&event.Classification, &event.Verdict, &event.SubjectUserID, &event.UserID, &event.UserEmail, &event.APIKeyID, &event.APIKeyName,
		&event.Model, &event.Protocol, &event.Stream, &event.MaxTokens, &event.PolicyVersion, &event.AuditConfigVersion,
		&event.ProbeConfigVersion, &evidence, &event.RiskSource,
		&event.Handling, &event.ResponseKind, &snapshot, &event.TotalCount, &event.LocalResponseCount,
		&event.AuditSkippedCount, &event.UpstreamSkippedCount, &event.AuditCallCount, &event.UpstreamCallCount,
		&event.LinkedAuditEventID, &event.FirstSeenAt, &event.LastSeenAt, &event.LastRealHealthAt, &event.WindowExpiresAt,
		&event.NextRealProbeAt, &event.CreatedAt, &event.UpdatedAt)
	if err != nil {
		return nil, err
	}
	event.Evidence = map[string]any{}
	event.PromptSnapshot = map[string]any{}
	_ = json.Unmarshal(evidence, &event.Evidence)
	_ = json.Unmarshal(snapshot, &event.PromptSnapshot)
	return &event, nil
}

func (r *PostgreSQLRepository) ListProbeEvents(ctx context.Context, groupID int64, filter ProbeEventFilter, page, pageSize int) (*ProbeEventPage, error) {
	page, pageSize = normalizeProbePage(page, pageSize)
	where, args := buildProbeEventWhere(groupID, filter)
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_probe_events e`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT `+probeEventColumns()+` FROM prompt_audit_probe_events e`+where+
		fmt.Sprintf(" ORDER BY e.last_seen_at DESC,e.id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]ProbeEventSummary, 0, pageSize)
	for rows.Next() {
		item, err := scanProbeEvent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item.Summary())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := 0
	if total > 0 {
		pages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &ProbeEventPage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

func buildProbeEventWhere(groupID int64, filter ProbeEventFilter) (string, []any) {
	clauses := []string{"e.group_id=$1"}
	args := []any{groupID}
	add := func(format string, value any) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(format, len(args)))
	}
	if value := strings.TrimSpace(filter.Verdict); value != "" {
		add("e.verdict=$%d", value)
	}
	if filter.UserID != nil {
		add("e.user_id=$%d", *filter.UserID)
	}
	if value := strings.TrimSpace(filter.UserEmail); value != "" {
		add("e.user_email_snapshot ILIKE $%d", "%"+TrimRunes(value, 128)+"%")
	}
	if filter.APIKeyID != nil {
		add("e.api_key_id=$%d", *filter.APIKeyID)
	}
	if value := strings.TrimSpace(filter.APIKeyName); value != "" {
		add("e.api_key_name_snapshot ILIKE $%d", "%"+TrimRunes(value, 128)+"%")
	}
	if value := strings.TrimSpace(filter.Model); value != "" {
		add("e.model ILIKE $%d", "%"+TrimRunes(value, 128)+"%")
	}
	if value := strings.TrimSpace(filter.Protocol); value != "" {
		add("e.protocol=$%d", value)
	}
	if filter.StartAt != nil {
		add("e.last_seen_at >= $%d", filter.StartAt.UTC())
	}
	if filter.EndAt != nil {
		add("e.last_seen_at <= $%d", filter.EndAt.UTC())
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (r *PostgreSQLRepository) GetProbeEvent(ctx context.Context, id int64) (*ProbeEvent, error) {
	event, err := scanProbeEvent(r.db.QueryRowContext(ctx, `SELECT `+probeEventColumns()+` FROM prompt_audit_probe_events WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProbeEventNotFound
	}
	return event, err
}

func (r *PostgreSQLRepository) ClearProbeEvent(ctx context.Context, id, actorID int64, reason string) (*ProbeEvent, error) {
	row := r.db.QueryRowContext(ctx, `UPDATE prompt_audit_probe_events SET classification='cleared',verdict='unknown',
		cleared_at=NOW(),cleared_by=NULLIF($2,0),clear_reason=$3,updated_at=NOW() WHERE id=$1 RETURNING `+probeEventColumns(), id, actorID, reason)
	event, err := scanProbeEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProbeEventNotFound
	}
	return event, err
}

func (r *PostgreSQLRepository) FindLatestPromptAuditEventID(ctx context.Context, groupID int64, promptHash string) (*int64, error) {
	var id int64
	err := r.db.QueryRowContext(ctx, `SELECT id FROM prompt_audit_events WHERE group_id=$1 AND prompt_hash=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, groupID, promptHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (r *PostgreSQLRepository) IsProbeExempt(ctx context.Context, groupID, userID, apiKeyID int64) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM prompt_audit_probe_exemptions
		WHERE group_id=$1 AND (expires_at IS NULL OR expires_at>NOW()) AND
		((user_id IS NOT NULL AND user_id=$2) OR (api_key_id IS NOT NULL AND api_key_id=$3)))`, groupID, userID, apiKeyID).Scan(&exists)
	return exists, err
}

func (r *PostgreSQLRepository) ListProbeExemptions(ctx context.Context, groupID int64, keyword string, page, pageSize int) (*ProbeExemptionPage, error) {
	page, pageSize = normalizeProbePage(page, pageSize)
	args := []any{groupID}
	where := " WHERE e.group_id=$1"
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		args = append(args, "%"+TrimRunes(keyword, 128)+"%")
		where += fmt.Sprintf(` AND (e.user_email_snapshot ILIKE $%[1]d OR e.api_key_name_snapshot ILIKE $%[1]d OR CAST(e.user_id AS TEXT) ILIKE $%[1]d OR CAST(e.api_key_id AS TEXT) ILIKE $%[1]d)`, len(args))
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM prompt_audit_probe_exemptions e`+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, `SELECT id,group_id,user_id,user_email_snapshot,api_key_id,api_key_name_snapshot,reason,expires_at,created_at,created_by FROM prompt_audit_probe_exemptions e`+where+fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]ProbeExemption, 0, pageSize)
	for rows.Next() {
		var item ProbeExemption
		if err := rows.Scan(&item.ID, &item.GroupID, &item.UserID, &item.UserEmail, &item.APIKeyID, &item.APIKeyName, &item.Reason, &item.ExpiresAt, &item.CreatedAt, &item.CreatedBy); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := 0
	if total > 0 {
		pages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &ProbeExemptionPage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

func (r *PostgreSQLRepository) CreateProbeExemption(ctx context.Context, groupID int64, req CreateProbeExemptionRequest, actorID int64) (*ProbeExemption, error) {
	var userEmail, keyName string
	if req.UserID != nil {
		if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(email,'') FROM users WHERE id=$1 AND deleted_at IS NULL`, *req.UserID).Scan(&userEmail); err != nil {
			return nil, err
		}
	}
	if req.APIKeyID != nil {
		if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(name,'') FROM api_keys WHERE id=$1 AND group_id=$2 AND deleted_at IS NULL`, *req.APIKeyID, groupID).Scan(&keyName); err != nil {
			return nil, err
		}
	}
	row := r.db.QueryRowContext(ctx, `INSERT INTO prompt_audit_probe_exemptions(group_id,user_id,api_key_id,user_email_snapshot,api_key_name_snapshot,reason,expires_at,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,NULLIF($8,0)) ON CONFLICT(group_id,(COALESCE(user_id,0)),(COALESCE(api_key_id,0))) DO UPDATE SET reason=EXCLUDED.reason,expires_at=EXCLUDED.expires_at,user_email_snapshot=EXCLUDED.user_email_snapshot,api_key_name_snapshot=EXCLUDED.api_key_name_snapshot,created_at=NOW(),created_by=EXCLUDED.created_by
		RETURNING id,group_id,user_id,user_email_snapshot,api_key_id,api_key_name_snapshot,reason,expires_at,created_at,created_by`, groupID, req.UserID, req.APIKeyID, userEmail, keyName, req.Reason, req.ExpiresAt, actorID)
	var item ProbeExemption
	if err := row.Scan(&item.ID, &item.GroupID, &item.UserID, &item.UserEmail, &item.APIKeyID, &item.APIKeyName, &item.Reason, &item.ExpiresAt, &item.CreatedAt, &item.CreatedBy); err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *PostgreSQLRepository) DeleteProbeExemption(ctx context.Context, groupID, id int64) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM prompt_audit_probe_exemptions WHERE group_id=$1 AND id=$2`, groupID, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return ErrProbeExemptionNotFound
	}
	return nil
}

func (r *PostgreSQLRepository) GetProbeExemption(ctx context.Context, groupID, id int64) (*ProbeExemption, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id,group_id,user_id,user_email_snapshot,api_key_id,api_key_name_snapshot,
		reason,expires_at,created_at,created_by FROM prompt_audit_probe_exemptions WHERE group_id=$1 AND id=$2`, groupID, id)
	var item ProbeExemption
	if err := row.Scan(&item.ID, &item.GroupID, &item.UserID, &item.UserEmail, &item.APIKeyID,
		&item.APIKeyName, &item.Reason, &item.ExpiresAt, &item.CreatedAt, &item.CreatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrProbeExemptionNotFound
		}
		return nil, err
	}
	return &item, nil
}

// keep time imported on older Go compilers when build tags omit filters.
var _ = time.Time{}
