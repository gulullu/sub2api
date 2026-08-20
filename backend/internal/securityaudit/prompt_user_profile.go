package securityaudit

import "time"

const (
	DefaultPromptAuditUserProfileDays       = 30
	MaxPromptAuditUserProfileDays           = 180
	DefaultPromptAuditUserProfileMinSamples = 20
	MaxPromptAuditUserProfilePageSize       = 1000
)

type PromptAuditUserProfileFilter struct {
	Days       int
	Search     string
	UserID     *int64
	GroupID    *int64
	MinSamples int
}

type PromptAuditUserProfile struct {
	UserID              int64      `json:"user_id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	Status              string     `json:"status"`
	Deleted             bool       `json:"deleted"`
	Excluded            bool       `json:"excluded"`
	AuditJobs           int64      `json:"audit_jobs"`
	HighRiskJobs        int64      `json:"high_risk_jobs"`
	CriticalRiskJobs    int64      `json:"critical_risk_jobs"`
	HighOrCriticalJobs  int64      `json:"high_or_critical_jobs"`
	SystemExceptionJobs int64      `json:"system_exception_jobs"`
	UnclassifiedJobs    int64      `json:"unclassified_jobs"`
	UsageTotal          int64      `json:"usage_total"`
	CyberBlockedTotal   int64      `json:"cyber_blocked_total"`
	CyberRecordedTotal  int64      `json:"cyber_recorded_total"`
	SampleTotal         int64      `json:"sample_total"`
	AuditCoverage       float64    `json:"audit_coverage"`
	CyberRatio          float64    `json:"cyber_ratio"`
	HighRiskRatio       float64    `json:"high_risk_ratio"`
	CriticalRiskRatio   float64    `json:"critical_risk_ratio"`
	HighOrCriticalRatio float64    `json:"high_or_critical_ratio"`
	Score               float64    `json:"score"`
	LastAuditAt         *time.Time `json:"last_audit_at,omitempty"`
	LastUsageAt         *time.Time `json:"last_usage_at,omitempty"`
	LastCyberAt         *time.Time `json:"last_cyber_at,omitempty"`
	LastRecordedAt      *time.Time `json:"last_recorded_at,omitempty"`
}

type PromptAuditUserProfilePage struct {
	Items    []*PromptAuditUserProfile `json:"items"`
	Total    int64                     `json:"total"`
	Page     int                       `json:"page"`
	PageSize int                       `json:"page_size"`
	Pages    int                       `json:"pages"`
}
