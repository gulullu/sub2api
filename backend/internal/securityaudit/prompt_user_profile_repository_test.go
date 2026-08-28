package securityaudit

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBuildUserProfileQueryUsesDoneJobsAndSeparatesSystemExceptions(t *testing.T) {
	requestedUserID := int64(77)
	filter := PromptAuditUserProfileFilter{
		Days:       7,
		Search:     "42",
		UserID:     &requestedUserID,
		MinSamples: 3,
	}
	query, args := buildUserProfileQuery(filter, time.Unix(1_000, 0).UTC())

	require.Len(t, args, 6)
	require.Equal(t, int64(77), args[2])
	require.Equal(t, int64(42), args[4])
	require.Contains(t, query.count, "j.status = 'done'")
	require.Contains(t, query.count, `e.matched_scanners <@ '["audit_unavailable", "input_too_large"]'::jsonb`)
	require.Contains(t, query.count, "JOIN LATERAL")
	require.Contains(t, query.count, "ORDER BY e.created_at DESC, e.id DESC")
	require.Contains(t, query.count, "high_or_critical_jobs")
	require.Contains(t, query.count, "system_exception_jobs")
	require.Contains(t, query.count, "j.user_id = $3")
	require.Contains(t, query.count, "user_id = $5")
	require.True(t, strings.Contains(query.list, "job_scope"), "job-level aggregation should drive the profile query")
	require.True(t, strings.Contains(query.list, "job_snapshots"), "deleted-user fallback should keep the latest snapshots available")
	require.Contains(t, query.list, "usage_total >= $6")
}

func TestBuildUserProfileQueryClampsProfileWindow(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	_, args := buildUserProfileQuery(PromptAuditUserProfileFilter{Days: MaxPromptAuditUserProfileDays + 1}, now)
	require.Equal(t, now.AddDate(0, 0, -MaxPromptAuditUserProfileDays), args[0])
	require.Equal(t, now, args[1])
}

func TestBuildUserProfileQueryTriStateUnassignedGroupUsesNullPredicates(t *testing.T) {
	groupID := int64(0)
	query, args := buildUserProfileQuery(PromptAuditUserProfileFilter{GroupID: &groupID}, time.Unix(1_000, 0).UTC())
	require.Len(t, args, 6, "unassigned filtering must not add a bind parameter")
	require.Contains(t, query.count, "j.group_id IS NULL")
	require.Contains(t, query.count, "ul.group_id IS NULL")
	require.Contains(t, query.count, "l.group_id IS NULL")
}

func TestPromptAuditUserProfileCacheKeyDistinguishesAllAndUnassignedGroups(t *testing.T) {
	allKey, allCacheable := promptAuditUserProfileCacheKey(PromptAuditUserProfileFilter{}, 1, 20)
	groupID := int64(0)
	unassignedKey, unassignedCacheable := promptAuditUserProfileCacheKey(PromptAuditUserProfileFilter{GroupID: &groupID}, 1, 20)
	require.True(t, allCacheable)
	require.True(t, unassignedCacheable)
	require.NotEqual(t, allKey, unassignedKey)
}
