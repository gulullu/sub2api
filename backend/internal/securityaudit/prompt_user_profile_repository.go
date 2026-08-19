package securityaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (r *PostgreSQLRepository) ListUserProfiles(ctx context.Context, filter PromptAuditUserProfileFilter, page, pageSize int) (*PromptAuditUserProfilePage, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("prompt audit profile database unavailable")
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
	now := time.Now().UTC()
	if r.clock != nil {
		now = r.clock.Now().UTC()
	}
	query, args := buildUserProfileQuery(filter, now)
	var total int64
	if err := r.db.QueryRowContext(ctx, query.count, args...).Scan(&total); err != nil {
		return nil, err
	}
	queryArgs := append([]any(nil), args...)
	limitPos := len(queryArgs) + 1
	offsetPos := len(queryArgs) + 2
	queryArgs = append(queryArgs, pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx, query.list+fmt.Sprintf(" LIMIT $%d OFFSET $%d", limitPos, offsetPos), queryArgs...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]*PromptAuditUserProfile, 0, pageSize)
	for rows.Next() {
		item, err := scanPromptAuditUserProfile(rows)
		if err != nil {
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
	return &PromptAuditUserProfilePage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

type userProfileQuery struct {
	count string
	list  string
}

func buildUserProfileQuery(filter PromptAuditUserProfileFilter, now time.Time) (userProfileQuery, []any) {
	days := filter.Days
	if days <= 0 {
		days = 30
	}
	if days > 3650 {
		days = 3650
	}
	startAt := now.AddDate(0, 0, -days)
	endAt := now
	args := []any{startAt, endAt}
	jobGroupClause := ""
	usageGroupClause := ""
	moderationGroupClause := ""
	if filter.GroupID != nil && *filter.GroupID > 0 {
		groupIdx := len(args) + 1
		args = append(args, *filter.GroupID)
		jobGroupClause = fmt.Sprintf(" AND j.group_id = $%d", groupIdx)
		usageGroupClause = fmt.Sprintf(" AND ul.group_id = $%d", groupIdx)
		moderationGroupClause = fmt.Sprintf(" AND l.group_id = $%d", groupIdx)
	}
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	searchIdx := len(args) + 1
	args = append(args, search)
	minSamples := filter.MinSamples
	if minSamples < 0 {
		minSamples = 0
	}
	minSamplesIdx := len(args) + 1
	args = append(args, minSamples)
	base := fmt.Sprintf(`
WITH job_stats AS (
	SELECT
		j.user_id,
		COUNT(*) AS audit_jobs,
		COUNT(*) FILTER (WHERE e.risk_level = 'high') AS high_risk_jobs,
		COUNT(*) FILTER (WHERE e.risk_level = 'critical') AS critical_risk_jobs,
		MAX(j.created_at) AS last_audit_at,
		MAX(e.created_at) AS last_risk_at
	FROM prompt_audit_jobs j
	LEFT JOIN prompt_audit_events e ON e.job_id = j.id
	WHERE j.user_id IS NOT NULL
		AND j.created_at >= $1
		AND j.created_at < $2%s
	GROUP BY j.user_id
), usage_stats AS (
	SELECT
		ul.user_id,
		COUNT(*) AS usage_total,
		COUNT(*) FILTER (WHERE ul.request_type = 4) AS cyber_blocked_total,
		MAX(ul.created_at) AS last_usage_at
	FROM usage_logs ul
	WHERE ul.user_id IS NOT NULL
		AND ul.created_at >= $1
		AND ul.created_at < $2%s
	GROUP BY ul.user_id
), moderation_stats AS (
	SELECT
		l.user_id,
		COUNT(*) AS moderation_total,
		COUNT(*) FILTER (WHERE l.action = 'cyber_policy') AS cyber_recorded_total,
		MAX(l.created_at) AS last_recorded_at
	FROM content_moderation_logs l
	WHERE l.user_id IS NOT NULL
		AND l.created_at >= $1
		AND l.created_at < $2%s
	GROUP BY l.user_id
), profile_rows AS (
	SELECT
		u.id AS user_id,
		COALESCE(u.username, '') AS username,
		COALESCE(u.email, '') AS email,
		COALESCE(u.status, '') AS status,
		COALESCE(u.deleted_at IS NOT NULL, FALSE) AS deleted,
		COALESCE(j.audit_jobs, 0) AS audit_jobs,
		COALESCE(j.high_risk_jobs, 0) AS high_risk_jobs,
		COALESCE(j.critical_risk_jobs, 0) AS critical_risk_jobs,
		COALESCE(uq.usage_total, 0) AS usage_total,
		COALESCE(uq.cyber_blocked_total, 0) AS cyber_blocked_total,
		COALESCE(cm.cyber_recorded_total, 0) AS cyber_recorded_total,
		(COALESCE(j.audit_jobs, 0) + COALESCE(uq.usage_total, 0) + COALESCE(cm.moderation_total, 0)) AS sample_total,
		CASE WHEN COALESCE(uq.usage_total, 0) > 0 THEN COALESCE(j.audit_jobs, 0)::double precision / NULLIF(uq.usage_total, 0) ELSE 0 END AS audit_coverage,
		CASE WHEN COALESCE(uq.usage_total, 0) > 0 THEN COALESCE(uq.cyber_blocked_total, 0)::double precision / NULLIF(uq.usage_total, 0) ELSE 0 END AS cyber_ratio,
		CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(j.high_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END AS high_risk_ratio,
		CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(j.critical_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END AS critical_risk_ratio,
		(
			CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(j.critical_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END * 100.0 +
			CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(j.high_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END * 10.0 +
			CASE WHEN COALESCE(uq.usage_total, 0) > 0 THEN COALESCE(uq.cyber_blocked_total, 0)::double precision / NULLIF(uq.usage_total, 0) ELSE 0 END
		) AS score,
		j.last_audit_at,
		uq.last_usage_at,
		cm.last_recorded_at
	FROM (
		SELECT user_id FROM job_stats
		UNION
		SELECT user_id FROM usage_stats
		UNION
		SELECT user_id FROM moderation_stats
	) ids
	LEFT JOIN users u ON u.id = ids.user_id
	LEFT JOIN job_stats j ON j.user_id = ids.user_id
	LEFT JOIN usage_stats uq ON uq.user_id = ids.user_id
	LEFT JOIN moderation_stats cm ON cm.user_id = ids.user_id
)
`, jobGroupClause, usageGroupClause, moderationGroupClause)
	count := base + fmt.Sprintf(`
SELECT COUNT(*)
FROM profile_rows
WHERE ($%d = '' OR LOWER(username) LIKE '%%' || $%d || '%%' OR LOWER(email) LIKE '%%' || $%d || '%%')
  AND ($%d <= 0 OR sample_total >= $%d)
`, searchIdx, searchIdx, searchIdx, minSamplesIdx, minSamplesIdx)
	list := base + fmt.Sprintf(`
SELECT
	user_id, username, email, status, deleted,
	audit_jobs, high_risk_jobs, critical_risk_jobs,
	usage_total, cyber_blocked_total, cyber_recorded_total,
	sample_total, audit_coverage, cyber_ratio, high_risk_ratio, critical_risk_ratio, score,
	last_audit_at, last_usage_at, last_recorded_at
FROM profile_rows
WHERE ($%d = '' OR LOWER(username) LIKE '%%' || $%d || '%%' OR LOWER(email) LIKE '%%' || $%d || '%%')
  AND ($%d <= 0 OR sample_total >= $%d)
ORDER BY critical_risk_ratio DESC, high_risk_ratio DESC, cyber_ratio DESC, sample_total DESC, user_id DESC
`, searchIdx, searchIdx, searchIdx, minSamplesIdx, minSamplesIdx)
	return userProfileQuery{count: count, list: list}, args
}

func scanPromptAuditUserProfile(row rowScanner) (*PromptAuditUserProfile, error) {
	item := &PromptAuditUserProfile{}
	var lastAudit, lastUsage, lastRecorded sql.NullTime
	if err := row.Scan(
		&item.UserID, &item.Username, &item.Email, &item.Status, &item.Deleted,
		&item.AuditJobs, &item.HighRiskJobs, &item.CriticalRiskJobs,
		&item.UsageTotal, &item.CyberBlockedTotal, &item.CyberRecordedTotal,
		&item.SampleTotal, &item.AuditCoverage, &item.CyberRatio, &item.HighRiskRatio, &item.CriticalRiskRatio, &item.Score,
		&lastAudit, &lastUsage, &lastRecorded,
	); err != nil {
		return nil, err
	}
	if lastAudit.Valid {
		value := lastAudit.Time.UTC()
		item.LastAuditAt = &value
	}
	if lastUsage.Valid {
		value := lastUsage.Time.UTC()
		item.LastUsageAt = &value
	}
	if lastRecorded.Valid {
		value := lastRecorded.Time.UTC()
		item.LastRecordedAt = &value
	}
	return item, nil
}
