package securityaudit

import "time"

const (
	DefaultProbeIntervalSeconds = 300
	MinProbeIntervalSeconds     = 60
	MaxProbeIntervalSeconds     = 86400
	ProbeHealthScopeDefault     = "group_model_protocol"

	ProbeClassificationKnownHealth        = "known_health"
	ProbeClassificationCandidate          = "candidate"
	ProbeClassificationHealthy            = "healthy"
	ProbeClassificationConfirmedViolation = "confirmed_violation"
	ProbeClassificationUnknown            = "unknown"
	ProbeClassificationCleared            = "cleared"

	ProbeVerdictHealthy            = "healthy"
	ProbeVerdictConfirmedViolation = "confirmed_violation"
	ProbeVerdictUnknown            = "unknown"

	DefaultProbeHealthyResponse   = "服务正常。为避免重复检测，探针最小间隔为 5 分钟。"
	DefaultProbeViolationResponse = "服务正常，但无法协助该请求。为避免重复检测，探针最小间隔为 5 分钟。"
	DefaultProbeUnknownResponse   = "网关在线，上游状态正在刷新。探针最小间隔为 5 分钟。"
)

// ProbeGroupConfig is persisted independently from the main Prompt Audit JSON
// document. A missing row is the explicit, backwards-compatible off state.
type ProbeGroupConfig struct {
	GroupID             int64      `json:"group_id"`
	GroupName           string     `json:"group_name"`
	Enabled             bool       `json:"enabled"`
	IntervalSeconds     int        `json:"interval_seconds"`
	HealthScope         string     `json:"health_scope"`
	AllowFirstRealProbe bool       `json:"allow_first_real_probe"`
	SkipRepeatAudit     bool       `json:"skip_repeat_audit"`
	SkipRepeatUpstream  bool       `json:"skip_repeat_upstream"`
	HealthyResponse     string     `json:"healthy_response"`
	ViolationResponse   string     `json:"violation_response"`
	UnknownResponse     string     `json:"unknown_response"`
	PolicyVersion       int64      `json:"policy_version"`
	LocalResponses24H   int64      `json:"local_responses_24h"`
	SkippedAudits24H    int64      `json:"skipped_audits_24h"`
	SkippedUpstream24H  int64      `json:"skipped_upstream_24h"`
	LastProbeAt         *time.Time `json:"last_probe_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	UpdatedBy           *int64     `json:"updated_by,omitempty"`
}

func DefaultProbeGroupConfig(groupID int64, groupName string) ProbeGroupConfig {
	return ProbeGroupConfig{
		GroupID: groupID, GroupName: groupName, IntervalSeconds: DefaultProbeIntervalSeconds,
		HealthScope: ProbeHealthScopeDefault, AllowFirstRealProbe: true,
		SkipRepeatAudit: true, SkipRepeatUpstream: true,
		HealthyResponse: DefaultProbeHealthyResponse, ViolationResponse: DefaultProbeViolationResponse,
		UnknownResponse: DefaultProbeUnknownResponse,
	}
}

// UpdateProbeGroupConfigRequest intentionally has pointer fields: the row
// operations use PUT with patch semantics so a quick enable does not overwrite
// the rest of an administrator's policy.
type UpdateProbeGroupConfigRequest struct {
	Enabled             *bool   `json:"enabled"`
	IntervalSeconds     *int    `json:"interval_seconds"`
	HealthScope         *string `json:"health_scope"`
	AllowFirstRealProbe *bool   `json:"allow_first_real_probe"`
	SkipRepeatAudit     *bool   `json:"skip_repeat_audit"`
	SkipRepeatUpstream  *bool   `json:"skip_repeat_upstream"`
	HealthyResponse     *string `json:"healthy_response"`
	ViolationResponse   *string `json:"violation_response"`
	UnknownResponse     *string `json:"unknown_response"`
}

type ProbeGroupPage struct {
	Items    []ProbeGroupConfig `json:"items"`
	Total    int64              `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"page_size"`
	Pages    int                `json:"pages"`
}

type ProbeEvent struct {
	ID                   int64          `json:"id"`
	GroupID              int64          `json:"group_id"`
	GroupName            string         `json:"group_name"`
	FamilyFingerprint    string         `json:"family_fingerprint"`
	FamilyPreview        string         `json:"family_preview"`
	Classification       string         `json:"classification"`
	Verdict              string         `json:"verdict"`
	SubjectUserID        int64          `json:"-"`
	UserID               *int64         `json:"user_id,omitempty"`
	UserEmail            string         `json:"user_email"`
	APIKeyID             *int64         `json:"api_key_id,omitempty"`
	APIKeyName           string         `json:"api_key_name"`
	Model                string         `json:"model"`
	Protocol             string         `json:"protocol"`
	Stream               bool           `json:"stream"`
	MaxTokens            int            `json:"max_tokens"`
	PolicyVersion        int64          `json:"-"`
	AuditConfigVersion   int64          `json:"audit_config_version"`
	ProbeConfigVersion   int64          `json:"probe_config_version"`
	Evidence             map[string]any `json:"evidence"`
	RiskSource           string         `json:"risk_source"`
	Handling             string         `json:"handling"`
	ResponseKind         string         `json:"response_kind"`
	PromptSnapshot       map[string]any `json:"prompt_snapshot"`
	TotalCount           int64          `json:"total_count"`
	LocalResponseCount   int64          `json:"local_response_count"`
	AuditSkippedCount    int64          `json:"audit_skipped_count"`
	UpstreamSkippedCount int64          `json:"upstream_skipped_count"`
	AuditCallCount       int64          `json:"audit_call_count"`
	UpstreamCallCount    int64          `json:"upstream_call_count"`
	LinkedAuditEventID   *int64         `json:"linked_audit_event_id,omitempty"`
	FirstSeenAt          time.Time      `json:"first_seen_at"`
	LastSeenAt           time.Time      `json:"last_seen_at"`
	LastRealHealthAt     *time.Time     `json:"last_real_health_at,omitempty"`
	WindowExpiresAt      *time.Time     `json:"window_expires_at,omitempty"`
	NextRealProbeAt      *time.Time     `json:"next_real_probe_at,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
}

type ProbeEventPage struct {
	Items    []ProbeEventSummary `json:"items"`
	Total    int64               `json:"total"`
	Page     int                 `json:"page"`
	PageSize int                 `json:"page_size"`
	Pages    int                 `json:"pages"`
}

type ProbeEventSummary struct {
	ID                   int64      `json:"id"`
	GroupID              int64      `json:"group_id"`
	GroupName            string     `json:"group_name"`
	FamilyFingerprint    string     `json:"family_fingerprint"`
	FamilyPreview        string     `json:"family_preview"`
	Classification       string     `json:"classification"`
	Verdict              string     `json:"verdict"`
	UserID               *int64     `json:"user_id,omitempty"`
	UserEmail            string     `json:"user_email"`
	APIKeyID             *int64     `json:"api_key_id,omitempty"`
	APIKeyName           string     `json:"api_key_name"`
	Model                string     `json:"model"`
	Protocol             string     `json:"protocol"`
	Stream               bool       `json:"stream"`
	MaxTokens            int        `json:"max_tokens"`
	FirstSeenAt          time.Time  `json:"first_seen_at"`
	LastSeenAt           time.Time  `json:"last_seen_at"`
	TotalCount           int64      `json:"total_count"`
	LocalResponseCount   int64      `json:"local_response_count"`
	AuditSkippedCount    int64      `json:"audit_skipped_count"`
	UpstreamSkippedCount int64      `json:"upstream_skipped_count"`
	AuditCallCount       int64      `json:"audit_call_count"`
	UpstreamCallCount    int64      `json:"upstream_call_count"`
	Handling             string     `json:"handling"`
	LastRealHealthAt     *time.Time `json:"last_real_health_at,omitempty"`
	LinkedAuditEventID   *int64     `json:"linked_audit_event_id,omitempty"`
}

func (e ProbeEvent) Summary() ProbeEventSummary {
	return ProbeEventSummary{
		ID: e.ID, GroupID: e.GroupID, GroupName: e.GroupName, FamilyFingerprint: e.FamilyFingerprint,
		FamilyPreview: e.FamilyPreview, Classification: e.Classification, Verdict: e.Verdict,
		UserID: e.UserID, UserEmail: e.UserEmail, APIKeyID: e.APIKeyID, APIKeyName: e.APIKeyName,
		Model: e.Model, Protocol: e.Protocol, Stream: e.Stream, MaxTokens: e.MaxTokens,
		FirstSeenAt: e.FirstSeenAt, LastSeenAt: e.LastSeenAt, TotalCount: e.TotalCount,
		LocalResponseCount: e.LocalResponseCount, AuditSkippedCount: e.AuditSkippedCount,
		UpstreamSkippedCount: e.UpstreamSkippedCount, AuditCallCount: e.AuditCallCount,
		UpstreamCallCount: e.UpstreamCallCount, Handling: e.Handling,
		LastRealHealthAt: e.LastRealHealthAt, LinkedAuditEventID: e.LinkedAuditEventID,
	}
}

type ProbeEventFilter struct {
	Verdict    string
	UserID     *int64
	UserEmail  string
	APIKeyID   *int64
	APIKeyName string
	Model      string
	Protocol   string
	StartAt    *time.Time
	EndAt      *time.Time
}

type ClearProbeEventRequest struct {
	Reason string `json:"reason"`
}

type ProbeExemption struct {
	ID         int64      `json:"id"`
	GroupID    int64      `json:"group_id"`
	UserID     *int64     `json:"user_id,omitempty"`
	UserEmail  string     `json:"user_email"`
	APIKeyID   *int64     `json:"api_key_id,omitempty"`
	APIKeyName string     `json:"api_key_name"`
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  *int64     `json:"created_by,omitempty"`
}

type CreateProbeExemptionRequest struct {
	UserID    *int64     `json:"user_id"`
	APIKeyID  *int64     `json:"api_key_id"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type ProbeExemptionPage struct {
	Items    []ProbeExemption `json:"items"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
	Pages    int              `json:"pages"`
}

// ProbeLocalResponse is returned before account selection, user/account
// concurrency and billing. The handler renders it in the client's native API
// protocol, including a complete SSE sequence for streaming requests.
type ProbeLocalResponse struct {
	Protocol string `json:"protocol"`
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Message  string `json:"message"`
	Kind     string `json:"kind"`
}

type probeRequestShape struct {
	Fingerprint string
	Preview     string
	ScanText    string
	Stream      bool
	MaxTokens   int
	KnownHealth bool
	Candidate   bool
	Evidence    map[string]any
}

type probeEventDelta struct {
	ObservedAt         time.Time
	Request            Request
	Shape              probeRequestShape
	Classification     string
	Verdict            string
	RiskSource         string
	Handling           string
	ResponseKind       string
	PolicyVersion      int64
	LocalResponse      bool
	AuditSkipped       bool
	UpstreamSkipped    bool
	AuditCalled        bool
	UpstreamCalled     bool
	LinkedAuditEventID *int64
	LastRealHealthAt   *time.Time
	WindowExpiresAt    *time.Time
	NextRealProbeAt    *time.Time
}
