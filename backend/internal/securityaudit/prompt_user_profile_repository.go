package securityaudit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	promptAuditUserProfileCacheTTL        = 15 * time.Second
	promptAuditUserProfileCacheMaxEntries = 64
)

type promptAuditUserProfileCacheEntry struct {
	page      *PromptAuditUserProfilePage
	expiresAt time.Time
	usedAt    time.Time
}

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
	if pageSize > MaxPromptAuditUserProfilePageSize {
		pageSize = MaxPromptAuditUserProfilePageSize
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if r.clock != nil {
		now = r.clock.Now().UTC()
	}
	cacheKey, cacheable := promptAuditUserProfileCacheKey(filter, page, pageSize)
	if cacheable {
		if cached := r.getPromptAuditUserProfileCache(cacheKey, now); cached != nil {
			return cached, nil
		}
	}
	query, args := buildUserProfileQuery(filter, now)
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
	var total int64
	for rows.Next() {
		var rowTotal int64
		item, err := scanPromptAuditUserProfile(rows, &rowTotal)
		if err != nil {
			return nil, err
		}
		if total == 0 {
			total = rowTotal
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// COUNT(*) OVER() avoids evaluating the large profile CTE twice on the
	// normal path. An out-of-range page has no row to carry the window count,
	// so only that edge case falls back to the count query.
	if total == 0 && page > 1 {
		if err := r.db.QueryRowContext(ctx, query.count, args...).Scan(&total); err != nil {
			return nil, err
		}
	}
	pages := 0
	if total > 0 {
		pages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	result := &PromptAuditUserProfilePage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}
	if cacheable {
		r.setPromptAuditUserProfileCache(cacheKey, result, now)
	}
	return result, nil
}

// Profile aggregation reads millions of usage rows on a busy installation. A
// short process-local cache keeps tab reloads and concurrent admin views from
// repeating that expensive read while keeping the dashboard's data effectively
// real-time. Large bulk-selection pages intentionally bypass the cache.
func promptAuditUserProfileCacheKey(filter PromptAuditUserProfileFilter, page, pageSize int) (string, bool) {
	if pageSize > 100 {
		return "", false
	}
	days := filter.Days
	if days <= 0 {
		days = DefaultPromptAuditUserProfileDays
	}
	if days > MaxPromptAuditUserProfileDays {
		days = MaxPromptAuditUserProfileDays
	}
	minSamples := filter.MinSamples
	if minSamples < 0 {
		minSamples = 0
	}
	var userID int64
	if filter.UserID != nil {
		userID = *filter.UserID
	}
	groupKey := "all"
	if filter.GroupID != nil {
		if *filter.GroupID == 0 {
			groupKey = "unassigned"
		} else {
			groupKey = strconv.FormatInt(*filter.GroupID, 10)
		}
	}
	pinnedDigest := sha256.Sum256([]byte(promptAuditUserProfileIDListKey(filter.pinnedUserIDs)))
	// The entry expiry, rather than a clock bucket, bounds staleness. Including
	// a bucket here can make two otherwise identical requests miss when the
	// first query happens to cross a bucket boundary while the database is
	// still being read.
	return fmt.Sprintf("%d|%d|%s|%q|%d|%x|%d|%d", days, userID, groupKey, strings.ToLower(strings.TrimSpace(filter.Search)), minSamples, pinnedDigest, page, pageSize), true
}

func promptAuditUserProfileIDListKey(ids []int64) string {
	canonical := canonicalInt64s(ids)
	if len(canonical) == 0 {
		return ""
	}
	var builder strings.Builder
	for _, id := range canonical {
		_, _ = builder.WriteString(strconv.FormatInt(id, 10))
		_ = builder.WriteByte(',')
	}
	return builder.String()
}

func (r *PostgreSQLRepository) getPromptAuditUserProfileCache(key string, now time.Time) *PromptAuditUserProfilePage {
	r.profileCacheMu.Lock()
	defer r.profileCacheMu.Unlock()
	entry, ok := r.profileCache[key]
	if !ok {
		return nil
	}
	if !now.Before(entry.expiresAt) {
		delete(r.profileCache, key)
		return nil
	}
	entry.usedAt = now
	r.profileCache[key] = entry
	return clonePromptAuditUserProfilePage(entry.page)
}

func (r *PostgreSQLRepository) setPromptAuditUserProfileCache(key string, page *PromptAuditUserProfilePage, now time.Time) {
	if page == nil {
		return
	}
	r.profileCacheMu.Lock()
	defer r.profileCacheMu.Unlock()
	if r.profileCache == nil {
		r.profileCache = make(map[string]promptAuditUserProfileCacheEntry)
	}
	for existingKey, entry := range r.profileCache {
		if !now.Before(entry.expiresAt) {
			delete(r.profileCache, existingKey)
		}
	}
	if len(r.profileCache) >= promptAuditUserProfileCacheMaxEntries {
		oldestKey := ""
		var oldest time.Time
		for existingKey, entry := range r.profileCache {
			if oldestKey == "" || entry.usedAt.Before(oldest) {
				oldestKey, oldest = existingKey, entry.usedAt
			}
		}
		if oldestKey != "" {
			delete(r.profileCache, oldestKey)
		}
	}
	r.profileCache[key] = promptAuditUserProfileCacheEntry{
		page:      clonePromptAuditUserProfilePage(page),
		expiresAt: now.Add(promptAuditUserProfileCacheTTL),
		usedAt:    now,
	}
}

func clonePromptAuditUserProfilePage(page *PromptAuditUserProfilePage) *PromptAuditUserProfilePage {
	if page == nil {
		return nil
	}
	clone := *page
	clone.Items = make([]*PromptAuditUserProfile, len(page.Items))
	for index, item := range page.Items {
		if item == nil {
			continue
		}
		itemClone := *item
		if item.LastAuditAt != nil {
			value := *item.LastAuditAt
			itemClone.LastAuditAt = &value
		}
		if item.LastUsageAt != nil {
			value := *item.LastUsageAt
			itemClone.LastUsageAt = &value
		}
		if item.LastCyberAt != nil {
			value := *item.LastCyberAt
			itemClone.LastCyberAt = &value
		}
		if item.LastRecordedAt != nil {
			value := *item.LastRecordedAt
			itemClone.LastRecordedAt = &value
		}
		clone.Items[index] = &itemClone
	}
	return &clone
}

type userProfileQuery struct {
	count string
	list  string
}

func buildUserProfileQuery(filter PromptAuditUserProfileFilter, now time.Time) (userProfileQuery, []any) {
	days := filter.Days
	if days <= 0 {
		days = DefaultPromptAuditUserProfileDays
	}
	if days > MaxPromptAuditUserProfileDays {
		days = MaxPromptAuditUserProfileDays
	}
	startAt := now.AddDate(0, 0, -days)
	endAt := now
	args := []any{startAt, endAt}
	jobGroupClause := ""
	usageGroupClause := ""
	moderationGroupClause := ""
	directoryMembershipCondition := "TRUE"
	if filter.GroupID != nil {
		if *filter.GroupID == 0 {
			// The unassigned/default bucket is persisted as SQL NULL because
			// group_id has a foreign-key relationship to groups.
			jobGroupClause = " AND j.group_id IS NULL"
			usageGroupClause = " AND ul.group_id IS NULL"
			moderationGroupClause = " AND l.group_id IS NULL"
			directoryMembershipCondition = `EXISTS (
			SELECT 1
			FROM api_keys k
			WHERE k.user_id = u.id
				AND k.group_id IS NULL
				AND k.deleted_at IS NULL
		)`
		} else if *filter.GroupID > 0 {
			groupIdx := len(args) + 1
			args = append(args, *filter.GroupID)
			jobGroupClause = fmt.Sprintf(" AND j.group_id = $%d", groupIdx)
			usageGroupClause = fmt.Sprintf(" AND ul.group_id = $%d", groupIdx)
			moderationGroupClause = fmt.Sprintf(" AND l.group_id = $%d", groupIdx)
			directoryMembershipCondition = fmt.Sprintf(`EXISTS (
			SELECT 1
			FROM api_keys k
			WHERE k.user_id = u.id
				AND k.group_id = $%d
				AND k.deleted_at IS NULL
		)`, groupIdx)
		}
	}
	requestedUserID := int64(0)
	if filter.UserID != nil && *filter.UserID > 0 {
		requestedUserID = *filter.UserID
	}
	requestedUserIDIdx := len(args) + 1
	args = append(args, requestedUserID)
	jobUserClause := fmt.Sprintf(" AND ($%d <= 0 OR j.user_id = $%d)", requestedUserIDIdx, requestedUserIDIdx)
	usageUserClause := fmt.Sprintf(" AND ($%d <= 0 OR ul.user_id = $%d)", requestedUserIDIdx, requestedUserIDIdx)
	moderationUserClause := fmt.Sprintf(" AND ($%d <= 0 OR l.user_id = $%d)", requestedUserIDIdx, requestedUserIDIdx)
	search := strings.ToLower(strings.TrimSpace(filter.Search))
	searchIdx := len(args) + 1
	args = append(args, search)
	searchUserID := int64(0)
	if parsed, err := strconv.ParseInt(strings.TrimSpace(filter.Search), 10, 64); err == nil && parsed > 0 {
		searchUserID = parsed
	}
	searchUserIDIdx := len(args) + 1
	args = append(args, searchUserID)
	minSamples := filter.MinSamples
	if minSamples < 0 {
		minSamples = 0
	}
	minSamplesIdx := len(args) + 1
	args = append(args, minSamples)
	pinnedUserIDs := canonicalInt64s(filter.pinnedUserIDs)
	pinnedUserIDsIdx := len(args) + 1
	args = append(args, pq.Array(pinnedUserIDs))
	base := fmt.Sprintf(`
WITH job_scope AS (
	SELECT
		j.id AS job_id,
		j.user_id,
		j.created_at,
		j.username_snapshot,
		j.user_email_snapshot
	FROM prompt_audit_jobs j
	WHERE j.user_id IS NOT NULL
		AND j.status = 'done'
		AND j.created_at >= $1
		AND j.created_at < $2%s%s
), latest_events AS (
	SELECT
		j.job_id,
		j.user_id,
		e.risk_level,
		e.matched_scanners
	FROM job_scope j
	JOIN LATERAL (
		SELECT e.risk_level, e.matched_scanners
		FROM prompt_audit_events e
		WHERE e.job_id = j.job_id
		ORDER BY e.created_at DESC, e.id DESC
		LIMIT 1
	) e ON TRUE
), risk_scope AS (
	SELECT
		e.job_id,
		e.user_id,
		e.risk_level,
		(
			jsonb_array_length(e.matched_scanners) > 0
			AND e.matched_scanners <@ '["audit_unavailable", "input_too_large"]'::jsonb
		) AS system_exception
	FROM latest_events e
	WHERE e.risk_level IN ('high', 'critical')
), job_stats AS (
	SELECT
		j.user_id,
		COUNT(*) AS audit_jobs,
		MAX(j.created_at) AS last_audit_at
	FROM job_scope j
	GROUP BY j.user_id
), risk_stats AS (
	SELECT
		r.user_id,
		COUNT(*) FILTER (WHERE r.risk_level = 'high' AND NOT r.system_exception) AS high_risk_jobs,
		COUNT(*) FILTER (WHERE r.risk_level = 'critical' AND NOT r.system_exception) AS critical_risk_jobs,
		COUNT(*) FILTER (WHERE NOT r.system_exception) AS high_or_critical_jobs,
		COUNT(*) FILTER (WHERE r.system_exception) AS system_exception_jobs
	FROM risk_scope r
	GROUP BY r.user_id
), job_snapshots AS (
	SELECT DISTINCT ON (j.user_id)
		j.user_id,
		j.username_snapshot,
		j.user_email_snapshot
	FROM job_scope j
	ORDER BY j.user_id, j.created_at DESC, j.job_id DESC
), usage_stats AS (
	SELECT
		ul.user_id,
		COUNT(*) AS usage_total,
		COUNT(*) FILTER (WHERE ul.request_type = 4) AS cyber_blocked_total,
		MAX(ul.created_at) AS last_usage_at,
		MAX(ul.created_at) FILTER (WHERE ul.request_type = 4) AS last_cyber_at
	FROM usage_logs ul
	WHERE ul.user_id IS NOT NULL
		AND ul.created_at >= $1
		AND ul.created_at < $2%s%s
	GROUP BY ul.user_id
), moderation_stats AS (
	SELECT
		l.user_id,
		COUNT(*) FILTER (WHERE l.action = 'cyber_policy') AS cyber_recorded_total,
		MAX(l.created_at) FILTER (WHERE l.action = 'cyber_policy') AS last_recorded_at
	FROM content_moderation_logs l
	WHERE l.user_id IS NOT NULL
		AND l.created_at >= $1
		AND l.created_at < $2%s%s
	GROUP BY l.user_id
), directory_scope AS (
	SELECT u.id AS user_id
	FROM users u
	WHERE u.deleted_at IS NULL
		AND ($%d <= 0 OR $%d > 0 OR $%d <> '')
		AND ($%d > 0 OR $%d <> '' OR (%s))
		AND ($%d <= 0 OR u.id = $%d)
		AND ($%d = '' OR u.username ILIKE '%%' || $%d || '%%' OR u.email ILIKE '%%' || $%d || '%%' OR ($%d > 0 AND u.id = $%d))
), pinned_scope AS (
	SELECT UNNEST($%d::bigint[]) AS user_id
), profile_rows AS (
	SELECT
		COALESCE(u.id, ids.user_id) AS user_id,
		COALESCE(NULLIF(u.username, ''), NULLIF(js.username_snapshot, ''), '') AS username,
		COALESCE(NULLIF(u.email, ''), NULLIF(js.user_email_snapshot, ''), '') AS email,
		CASE WHEN u.id IS NULL THEN 'deleted' ELSE COALESCE(u.status, '') END AS status,
		(u.id IS NULL OR u.deleted_at IS NOT NULL) AS deleted,
		COALESCE(j.audit_jobs, 0) AS audit_jobs,
		COALESCE(r.high_risk_jobs, 0) AS high_risk_jobs,
		COALESCE(r.critical_risk_jobs, 0) AS critical_risk_jobs,
		COALESCE(r.high_or_critical_jobs, 0) AS high_or_critical_jobs,
		COALESCE(r.system_exception_jobs, 0) AS system_exception_jobs,
		GREATEST(COALESCE(j.audit_jobs, 0) - COALESCE(r.high_or_critical_jobs, 0) - COALESCE(r.system_exception_jobs, 0), 0) AS unclassified_jobs,
		COALESCE(uq.usage_total, 0) AS usage_total,
		COALESCE(uq.cyber_blocked_total, 0) AS cyber_blocked_total,
		COALESCE(cm.cyber_recorded_total, 0) AS cyber_recorded_total,
		(COALESCE(j.audit_jobs, 0) > 0 OR COALESCE(uq.usage_total, 0) > 0 OR COALESCE(cm.cyber_recorded_total, 0) > 0) AS has_profile,
		GREATEST(COALESCE(j.audit_jobs, 0), COALESCE(uq.usage_total, 0)) AS sample_total,
		CASE WHEN COALESCE(uq.usage_total, 0) > 0 THEN COALESCE(j.audit_jobs, 0)::double precision / NULLIF(uq.usage_total, 0) ELSE 0 END AS audit_coverage,
		CASE WHEN COALESCE(uq.usage_total, 0) > 0 THEN COALESCE(uq.cyber_blocked_total, 0)::double precision / NULLIF(uq.usage_total, 0) ELSE 0 END AS cyber_ratio,
		CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(r.high_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END AS high_risk_ratio,
		CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(r.critical_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END AS critical_risk_ratio,
		CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(r.high_or_critical_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END AS high_or_critical_ratio,
		(
			CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(r.critical_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END * 100.0 +
			CASE WHEN COALESCE(j.audit_jobs, 0) > 0 THEN COALESCE(r.high_risk_jobs, 0)::double precision / NULLIF(j.audit_jobs, 0) ELSE 0 END * 10.0 +
			CASE WHEN COALESCE(uq.usage_total, 0) > 0 THEN COALESCE(uq.cyber_blocked_total, 0)::double precision / NULLIF(uq.usage_total, 0) ELSE 0 END
		) AS score,
		j.last_audit_at,
		uq.last_usage_at,
		uq.last_cyber_at,
		cm.last_recorded_at
	FROM (
		SELECT user_id FROM job_stats
		UNION
		SELECT user_id FROM usage_stats
		UNION
		SELECT user_id FROM moderation_stats
		UNION
		SELECT user_id FROM directory_scope
		UNION
		SELECT user_id FROM pinned_scope
	) ids
	LEFT JOIN users u ON u.id = ids.user_id
	LEFT JOIN job_snapshots js ON js.user_id = ids.user_id
	LEFT JOIN job_stats j ON j.user_id = ids.user_id
	LEFT JOIN risk_stats r ON r.user_id = ids.user_id
	LEFT JOIN usage_stats uq ON uq.user_id = ids.user_id
	LEFT JOIN moderation_stats cm ON cm.user_id = ids.user_id
)
`, jobGroupClause, jobUserClause, usageGroupClause, usageUserClause, moderationGroupClause, moderationUserClause,
		minSamplesIdx, requestedUserIDIdx, searchIdx,
		requestedUserIDIdx, searchIdx, directoryMembershipCondition,
		requestedUserIDIdx, requestedUserIDIdx,
		searchIdx, searchIdx, searchIdx, searchUserIDIdx, searchUserIDIdx,
		pinnedUserIDsIdx)
	count := base + fmt.Sprintf(`
SELECT COUNT(*)
FROM profile_rows
WHERE ($%d <= 0 OR user_id = $%d)
  AND ($%d = '' OR LOWER(username) LIKE '%%' || $%d || '%%' OR LOWER(email) LIKE '%%' || $%d || '%%' OR ($%d > 0 AND user_id = $%d))
  AND ($%d <= 0 OR $%d > 0 OR $%d <> '' OR user_id = ANY($%d) OR high_or_critical_jobs > 0 OR cyber_blocked_total > 0 OR cyber_recorded_total > 0 OR audit_jobs >= $%d OR usage_total >= $%d)
`, requestedUserIDIdx, requestedUserIDIdx, searchIdx, searchIdx, searchIdx, searchUserIDIdx, searchUserIDIdx, minSamplesIdx, requestedUserIDIdx, searchIdx, pinnedUserIDsIdx, minSamplesIdx, minSamplesIdx)
	list := base + fmt.Sprintf(`
SELECT
	COUNT(*) OVER() AS profile_total,
	user_id, username, email, status, deleted,
	has_profile,
	audit_jobs, high_risk_jobs, critical_risk_jobs, high_or_critical_jobs,
	system_exception_jobs, unclassified_jobs,
	usage_total, cyber_blocked_total, cyber_recorded_total,
	sample_total, audit_coverage, cyber_ratio, high_risk_ratio, critical_risk_ratio, high_or_critical_ratio, score,
	last_audit_at, last_usage_at, last_cyber_at, last_recorded_at
FROM profile_rows
WHERE ($%d <= 0 OR user_id = $%d)
  AND ($%d = '' OR LOWER(username) LIKE '%%' || $%d || '%%' OR LOWER(email) LIKE '%%' || $%d || '%%' OR ($%d > 0 AND user_id = $%d))
  AND ($%d <= 0 OR $%d > 0 OR $%d <> '' OR user_id = ANY($%d) OR high_or_critical_jobs > 0 OR cyber_blocked_total > 0 OR cyber_recorded_total > 0 OR audit_jobs >= $%d OR usage_total >= $%d)
ORDER BY (user_id = ANY($%d)) DESC, high_or_critical_ratio DESC, critical_risk_ratio DESC, high_or_critical_jobs DESC, cyber_ratio DESC, sample_total DESC, user_id DESC
`, requestedUserIDIdx, requestedUserIDIdx, searchIdx, searchIdx, searchIdx, searchUserIDIdx, searchUserIDIdx, minSamplesIdx, requestedUserIDIdx, searchIdx, pinnedUserIDsIdx, minSamplesIdx, minSamplesIdx, pinnedUserIDsIdx)
	return userProfileQuery{count: count, list: list}, args
}

func scanPromptAuditUserProfile(row rowScanner, total *int64) (*PromptAuditUserProfile, error) {
	item := &PromptAuditUserProfile{}
	var lastAudit, lastUsage, lastCyber, lastRecorded sql.NullTime
	if err := row.Scan(
		total,
		&item.UserID, &item.Username, &item.Email, &item.Status, &item.Deleted,
		&item.HasProfile,
		&item.AuditJobs, &item.HighRiskJobs, &item.CriticalRiskJobs, &item.HighOrCriticalJobs,
		&item.SystemExceptionJobs, &item.UnclassifiedJobs,
		&item.UsageTotal, &item.CyberBlockedTotal, &item.CyberRecordedTotal,
		&item.SampleTotal, &item.AuditCoverage, &item.CyberRatio, &item.HighRiskRatio, &item.CriticalRiskRatio, &item.HighOrCriticalRatio, &item.Score,
		&lastAudit, &lastUsage, &lastCyber, &lastRecorded,
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
	if lastCyber.Valid {
		value := lastCyber.Time.UTC()
		item.LastCyberAt = &value
	}
	if lastRecorded.Valid {
		value := lastRecorded.Time.UTC()
		item.LastRecordedAt = &value
	}
	return item, nil
}
