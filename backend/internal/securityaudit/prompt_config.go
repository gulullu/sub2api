package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	DefaultWorkerCount        = 4
	MaxWorkerCount            = 32
	DefaultQueueCapacity      = 32768
	MaxQueueCapacity          = 100000
	DefaultTimeoutMS          = 3000
	MinTimeoutMS              = 100
	MaxTimeoutMS              = 40000
	MinEndpointPriority       = 1
	MaxEndpointPriority       = 1000
	DefaultInputLimit         = 4000
	MinInputLimit             = 128
	MaxInputLimit             = 400000
	DefaultMaxTotalInputChars = 40000
	MinMaxTotalInputChars     = 128
	MaxMaxTotalInputChars     = 400000
	MaxExcludedUserIDs        = 10000
	DefaultPayloadTTL         = 30 * time.Minute
	// Group policy fallback controls what happens when a finding cannot be
	// routed to a configured account pool.  "block" is the secure default and
	// preserves the historical fail-closed behavior; administrators may opt in
	// to "allow" for groups that intentionally have no spare account.
	DefaultNoRouteFallbackMode = "block"
	NoRouteFallbackAllow       = "allow"
	NoRouteFallbackBlock       = "block"
)

type SecretEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// ConfigStore is the injectable boundary between hot-path prompt auditing and
// the concrete settings/PostgreSQL/Redis-backed configuration manager.
type ConfigStore interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Active() (ActiveConfig, bool)
	EffectiveMode() Mode
	// BlockingActivationDegraded is true when storage intent requires blocking
	// but no usable blocking snapshot is active (cold start or failed reload).
	// It must stay false when blocking is not intended, even if config is
	// untrusted—otherwise default-off deployments fail closed for all traffic.
	BlockingActivationDegraded() bool
	Public() (PublicConfig, error)
	Save(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error)
	RuntimeState() (expected int64, active int64, loadedAt *time.Time, loadError string)
	Encrypt(value string) (string, error)
	Decrypt(value string) (string, error)
}

type StorageEndpoint struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Priority        int    `json:"priority"`
	Protocol        string `json:"protocol"`
	Adapter         string `json:"adapter"`
	BaseURL         string `json:"base_url"`
	Model           string `json:"model"`
	TokenCiphertext string `json:"token_ciphertext,omitempty"`
	TimeoutMS       int    `json:"timeout_ms"`
	InputLimit      int    `json:"input_limit"`
	Enabled         bool   `json:"enabled"`
}

// GroupPolicy is the per-audit-group override.  Prompt Audit configuration is
// persisted as one encrypted settings JSON document, so keeping this as an
// additive array avoids a second table/transaction while retaining CAS and
// Redis invalidation semantics.  A missing group entry intentionally falls
// back to the legacy top-level fields.
//
// The fields are concrete on the wire so the admin UI can render a complete
// editable row.  During JSON decoding we retain a private presence map; this
// lets older/partial clients omit fields and inherit the top-level value while
// still allowing an explicit empty list or false value to override it.
type GroupPolicy struct {
	GroupID                 int64    `json:"group_id"`
	Enabled                 bool     `json:"enabled"`
	BlockingEnabled         bool     `json:"blocking_enabled"`
	BlockingLatestTurnOnly  bool     `json:"blocking_latest_turn_only"`
	StorePassEvents         bool     `json:"store_pass_events"`
	Strategy                string   `json:"strategy"`
	Scanners                []string `json:"scanners"`
	MaxTotalInputChars      int      `json:"max_total_input_chars"`
	ActivePromptTemplateID  string   `json:"active_prompt_template_id"`
	FlagThreshold           float64  `json:"flag_threshold"`
	BlockThreshold          float64  `json:"block_threshold"`
	BlockHTTPStatus         int      `json:"block_http_status"`
	BlockMessage            string   `json:"block_message"`
	RiskRouteAccountIDs     []int64  `json:"risk_route_account_ids"`
	CyberFeedbackAccountIDs []int64  `json:"cyber_feedback_account_ids"`
	ExcludedUserIDs         []int64  `json:"excluded_user_ids"`
	NoRouteFallbackMode     string   `json:"no_route_fallback_mode"`
	present                 map[string]bool
}

// UnmarshalJSON records which fields were actually sent.  This is important
// for PUT requests from older admin bundles that only know group_id and one or
// two new fields: omitted values inherit the top-level policy instead of
// accidentally disabling a group.
func (p *GroupPolicy) UnmarshalJSON(data []byte) error {
	type plain GroupPolicy
	var decoded plain
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*p = GroupPolicy(decoded)
	p.present = make(map[string]bool, len(fields))
	for key := range fields {
		p.present[key] = true
	}
	return nil
}

func (p GroupPolicy) hasField(name string) bool {
	if p.present != nil {
		return p.present[name]
	}
	// Struct literals in tests/internal callers have no presence map. Treat
	// non-zero values and non-nil slices as explicitly supplied; zero-valued
	// booleans/numbers inherit the top-level value for compatibility.
	switch name {
	case "enabled":
		return p.Enabled
	case "blocking_enabled":
		return p.BlockingEnabled
	case "blocking_latest_turn_only":
		return p.BlockingLatestTurnOnly
	case "store_pass_events":
		return p.StorePassEvents
	case "strategy":
		return strings.TrimSpace(p.Strategy) != ""
	case "scanners":
		return p.Scanners != nil
	case "max_total_input_chars":
		return p.MaxTotalInputChars != 0
	case "active_prompt_template_id":
		return strings.TrimSpace(p.ActivePromptTemplateID) != ""
	case "flag_threshold":
		return p.FlagThreshold != 0
	case "block_threshold":
		return p.BlockThreshold != 0
	case "block_http_status":
		return p.BlockHTTPStatus != 0
	case "block_message":
		return strings.TrimSpace(p.BlockMessage) != ""
	case "risk_route_account_ids":
		return p.RiskRouteAccountIDs != nil
	case "cyber_feedback_account_ids":
		return p.CyberFeedbackAccountIDs != nil
	case "excluded_user_ids":
		return p.ExcludedUserIDs != nil
	case "no_route_fallback_mode":
		return strings.TrimSpace(p.NoRouteFallbackMode) != ""
	default:
		return false
	}
}

func (p GroupPolicy) clone() GroupPolicy {
	p.Scanners = append([]string(nil), p.Scanners...)
	p.RiskRouteAccountIDs = append([]int64(nil), p.RiskRouteAccountIDs...)
	p.CyberFeedbackAccountIDs = append([]int64(nil), p.CyberFeedbackAccountIDs...)
	p.ExcludedUserIDs = append([]int64(nil), p.ExcludedUserIDs...)
	if p.present != nil {
		present := make(map[string]bool, len(p.present))
		for key, value := range p.present {
			present[key] = value
		}
		p.present = present
	}
	return p
}

type storageConfig struct {
	Enabled                 bool          `json:"enabled"`
	BlockingEnabled         bool          `json:"blocking_enabled"`
	BlockingLatestTurnOnly  bool          `json:"blocking_latest_turn_only"`
	StorePassEvents         bool          `json:"store_pass_events"`
	Strategy                string        `json:"strategy"`
	WorkerCount             int           `json:"worker_count"`
	QueueCapacity           int           `json:"queue_capacity"`
	Scanners                []string      `json:"scanners"`
	AllGroups               bool          `json:"all_groups"`
	GroupIDs                []int64       `json:"group_ids"`
	GroupPolicies           []GroupPolicy `json:"group_policies"`
	RiskRouteAccountIDs     []int64       `json:"risk_route_account_ids"`
	CyberFeedbackAccountIDs []int64       `json:"cyber_feedback_account_ids"`
	ExcludedUserIDs         []int64       `json:"excluded_user_ids"`
	// NoRouteFallbackMode is the legacy/global fallback used by groups that do
	// not provide an explicit override.  It is persisted explicitly on new
	// saves; an omitted value from an older document normalizes to the secure
	// "block" default.
	NoRouteFallbackMode    string                `json:"no_route_fallback_mode"`
	MaxTotalInputChars     int                   `json:"max_total_input_chars"`
	PromptTemplates        []PromptTemplate      `json:"prompt_templates"`
	ActivePromptTemplateID string                `json:"active_prompt_template_id"`
	CyberSupplementRules   []CyberSupplementRule `json:"cyber_supplement_rules"`
	FlagThreshold          *float64              `json:"flag_threshold"`
	BlockThreshold         *float64              `json:"block_threshold"`
	BlockHTTPStatus        int                   `json:"block_http_status"`
	BlockMessage           string                `json:"block_message"`
	Endpoints              []StorageEndpoint     `json:"endpoints"`
	ConfigVersion          int64                 `json:"config_version"`
	UpdatedAt              time.Time             `json:"updated_at"`
	UpdatedBy              int64                 `json:"updated_by"`
	ChangeSummary          string                `json:"change_summary"`
}

type ActiveEndpoint struct {
	ID                     string
	Name                   string
	Priority               int
	Protocol               string
	Adapter                string
	BaseURL                string
	Model                  string
	Token                  string
	TimeoutMS              int
	InputLimit             int
	Enabled                bool
	PromptTemplateID       string
	SystemPrompt           string
	SupportsSystemPrompt   bool
	CyberSupplementApplied bool
	FlagThreshold          float64
	BlockThreshold         float64
	// TokenInvalid marks an endpoint whose persisted token ciphertext cannot be
	// decrypted with the current encryption key (key changed or auto-generated
	// on restart). The endpoint is kept visible for admins but excluded from
	// runtime use until the token is re-entered or cleared (issue #4887).
	TokenInvalid bool
}

type ActiveConfig struct {
	RiskControlEnabled      bool
	Enabled                 bool
	BlockingEnabled         bool
	BlockingLatestTurnOnly  bool
	StorePassEvents         bool
	Strategy                string
	WorkerCount             int
	QueueCapacity           int
	Scanners                []string
	AllGroups               bool
	GroupIDs                []int64
	GroupPolicies           []GroupPolicy
	RiskRouteAccountIDs     []int64
	CyberFeedbackAccountIDs []int64
	ExcludedUserIDs         []int64
	MaxTotalInputChars      int
	NoRouteFallbackMode     string
	PromptTemplates         []PromptTemplate
	ActivePromptTemplateID  string
	CyberSupplementRules    []CyberSupplementRule
	FlagThreshold           float64
	BlockThreshold          float64
	BlockHTTPStatus         int
	BlockMessage            string
	Endpoints               []ActiveEndpoint
	ConfigVersion           int64
	UpdatedAt               time.Time
	UpdatedBy               int64
	ChangeSummary           string
}

type PublicEndpoint struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Priority               int    `json:"priority"`
	Protocol               string `json:"protocol"`
	Adapter                string `json:"adapter"`
	BaseURL                string `json:"base_url"`
	Model                  string `json:"model"`
	TimeoutMS              int    `json:"timeout_ms"`
	InputLimit             int    `json:"input_limit"`
	Enabled                bool   `json:"enabled"`
	HasToken               bool   `json:"has_token"`
	TokenStatus            string `json:"token_status"`
	SupportsSystemPrompt   bool   `json:"supports_system_prompt"`
	CyberSupplementApplied bool   `json:"cyber_supplement_applied"`
}

type PublicConfig struct {
	Enabled                 bool                  `json:"enabled"`
	BlockingEnabled         bool                  `json:"blocking_enabled"`
	BlockingLatestTurnOnly  bool                  `json:"blocking_latest_turn_only"`
	StorePassEvents         bool                  `json:"store_pass_events"`
	EffectiveMode           Mode                  `json:"effective_mode"`
	Strategy                string                `json:"strategy"`
	WorkerCount             int                   `json:"worker_count"`
	QueueCapacity           int                   `json:"queue_capacity"`
	Scanners                []string              `json:"scanners"`
	AllGroups               bool                  `json:"all_groups"`
	GroupIDs                []int64               `json:"group_ids"`
	GroupPolicies           []GroupPolicy         `json:"group_policies"`
	RiskRouteAccountIDs     []int64               `json:"risk_route_account_ids"`
	CyberFeedbackAccountIDs []int64               `json:"cyber_feedback_account_ids"`
	ExcludedUserIDs         []int64               `json:"excluded_user_ids"`
	NoRouteFallbackMode     string                `json:"no_route_fallback_mode"`
	MaxTotalInputChars      int                   `json:"max_total_input_chars"`
	PromptTemplates         []PromptTemplate      `json:"prompt_templates"`
	ActivePromptTemplateID  string                `json:"active_prompt_template_id"`
	CyberSupplementRules    []CyberSupplementRule `json:"cyber_supplement_rules"`
	FlagThreshold           float64               `json:"flag_threshold"`
	BlockThreshold          float64               `json:"block_threshold"`
	BlockHTTPStatus         int                   `json:"block_http_status"`
	BlockMessage            string                `json:"block_message"`
	Endpoints               []PublicEndpoint      `json:"endpoints"`
	ConfigVersion           int64                 `json:"config_version"`
	UpdatedAt               time.Time             `json:"updated_at"`
	UpdatedBy               int64                 `json:"updated_by"`
	ChangeSummary           string                `json:"change_summary"`
}

type UpdateEndpoint struct {
	ID       string `json:"id" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Priority int    `json:"priority"`
	Protocol string `json:"protocol"`
	Adapter  string `json:"adapter"`
	BaseURL  string `json:"base_url" binding:"required"`
	Model    string `json:"model"`
	Token    string `json:"token,omitempty"`
	// CredentialSource is an administrator-only one-shot import instruction.
	// It is resolved in memory and is never persisted or returned by PublicConfig.
	CredentialSource string `json:"credential_source,omitempty"`
	ClearToken       bool   `json:"clear_token"`
	TimeoutMS        int    `json:"timeout_ms"`
	InputLimit       int    `json:"input_limit"`
	Enabled          bool   `json:"enabled"`
}

type UpdateConfigRequest struct {
	ExpectedConfigVersion   int64             `json:"expected_config_version" binding:"required"`
	Enabled                 bool              `json:"enabled"`
	BlockingEnabled         bool              `json:"blocking_enabled"`
	BlockingLatestTurnOnly  bool              `json:"blocking_latest_turn_only"`
	StorePassEvents         bool              `json:"store_pass_events"`
	Strategy                string            `json:"strategy"`
	WorkerCount             int               `json:"worker_count"`
	QueueCapacity           int               `json:"queue_capacity"`
	Scanners                []string          `json:"scanners"`
	AllGroups               bool              `json:"all_groups"`
	GroupIDs                []int64           `json:"group_ids"`
	GroupPolicies           *[]GroupPolicy    `json:"group_policies,omitempty"`
	RiskRouteAccountIDs     *[]int64          `json:"risk_route_account_ids,omitempty"`
	CyberFeedbackAccountIDs *[]int64          `json:"cyber_feedback_account_ids,omitempty"`
	ExcludedUserIDs         *[]int64          `json:"excluded_user_ids,omitempty"`
	NoRouteFallbackMode     string            `json:"no_route_fallback_mode"`
	MaxTotalInputChars      *int              `json:"max_total_input_chars,omitempty"`
	PromptTemplates         *[]PromptTemplate `json:"prompt_templates,omitempty"`
	ActivePromptTemplateID  *string           `json:"active_prompt_template_id,omitempty"`
	FlagThreshold           *float64          `json:"flag_threshold,omitempty"`
	BlockThreshold          *float64          `json:"block_threshold,omitempty"`
	BlockHTTPStatus         *int              `json:"block_http_status,omitempty"`
	BlockMessage            *string           `json:"block_message,omitempty"`
	Endpoints               []UpdateEndpoint  `json:"endpoints"`
	// cyberSupplementRules is intentionally not part of the ordinary config
	// API. Rules may only be changed through reviewed CYB feedback actions.
	cyberSupplementRules *[]CyberSupplementRule `json:"-"`
}

func storageRequiresBlocking(cfg storageConfig, riskControlEnabled bool) bool {
	// This helper is also used while observing a raw/possibly partial settings
	// document after a reload failure.  Normalize first so omitted group fields
	// inherit the legacy top-level policy before deciding whether fail-closed
	// protection is required.
	normalizeStorageConfig(&cfg)
	return (ActiveConfig{
		RiskControlEnabled: riskControlEnabled,
		Enabled:            cfg.Enabled,
		BlockingEnabled:    cfg.BlockingEnabled,
		AllGroups:          cfg.AllGroups,
		GroupIDs:           cfg.GroupIDs,
		GroupPolicies:      cfg.GroupPolicies,
	}).RequiresBlockingActivation()
}

func DefaultStorageConfig() storageConfig {
	flagThreshold := DefaultFlagThreshold
	blockThreshold := DefaultBlockThreshold
	return storageConfig{
		Enabled:                 false,
		BlockingEnabled:         false,
		BlockingLatestTurnOnly:  false,
		StorePassEvents:         false,
		Strategy:                "priority",
		WorkerCount:             DefaultWorkerCount,
		QueueCapacity:           DefaultQueueCapacity,
		Scanners:                append([]string(nil), AllScannerIDs...),
		AllGroups:               true,
		GroupIDs:                []int64{},
		GroupPolicies:           []GroupPolicy{},
		RiskRouteAccountIDs:     []int64{},
		CyberFeedbackAccountIDs: []int64{},
		ExcludedUserIDs:         []int64{},
		NoRouteFallbackMode:     DefaultNoRouteFallbackMode,
		MaxTotalInputChars:      DefaultMaxTotalInputChars,
		PromptTemplates:         []PromptTemplate{DefaultPromptTemplate()},
		ActivePromptTemplateID:  DefaultPromptTemplateID,
		CyberSupplementRules:    []CyberSupplementRule{},
		FlagThreshold:           &flagThreshold,
		BlockThreshold:          &blockThreshold,
		BlockHTTPStatus:         DefaultBlockHTTPStatus,
		BlockMessage:            DefaultBlockMessage,
		Endpoints:               []StorageEndpoint{},
		ConfigVersion:           1,
	}
}

func ParseStorageConfig(raw string) (storageConfig, error) {
	cfg := DefaultStorageConfig()
	if strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return storageConfig{}, fmt.Errorf("decode prompt audit config: %w", err)
	}
	normalizeStorageConfig(&cfg)
	if err := validateStorageConfig(cfg); err != nil {
		return storageConfig{}, err
	}
	return cfg, nil
}

func normalizeStorageConfig(cfg *storageConfig) {
	if cfg == nil {
		return
	}
	if cfg.ConfigVersion < 1 {
		cfg.ConfigVersion = 1
	}
	if strings.TrimSpace(cfg.Strategy) == "" {
		cfg.Strategy = "priority"
	}
	if cfg.WorkerCount == 0 {
		cfg.WorkerCount = DefaultWorkerCount
	}
	if cfg.QueueCapacity == 0 {
		cfg.QueueCapacity = DefaultQueueCapacity
	}
	if len(cfg.Scanners) == 0 {
		cfg.Scanners = append([]string(nil), AllScannerIDs...)
	}
	cfg.Scanners = canonicalScannerIDs(cfg.Scanners)
	cfg.GroupIDs = canonicalInt64s(cfg.GroupIDs)
	cfg.RiskRouteAccountIDs = canonicalInt64s(cfg.RiskRouteAccountIDs)
	cfg.CyberFeedbackAccountIDs = canonicalInt64s(cfg.CyberFeedbackAccountIDs)
	cfg.ExcludedUserIDs = canonicalInt64s(cfg.ExcludedUserIDs)
	cfg.NoRouteFallbackMode = normalizeNoRouteFallbackMode(cfg.NoRouteFallbackMode)
	if cfg.MaxTotalInputChars == 0 {
		cfg.MaxTotalInputChars = DefaultMaxTotalInputChars
	}
	cfg.PromptTemplates = normalizePromptTemplates(cfg.PromptTemplates)
	cfg.CyberSupplementRules = normalizeCyberSupplementRules(cfg.CyberSupplementRules)
	if strings.TrimSpace(cfg.ActivePromptTemplateID) == "" {
		cfg.ActivePromptTemplateID = DefaultPromptTemplateID
	} else {
		cfg.ActivePromptTemplateID = strings.TrimSpace(cfg.ActivePromptTemplateID)
	}
	if cfg.FlagThreshold == nil {
		value := DefaultFlagThreshold
		cfg.FlagThreshold = &value
	}
	if cfg.BlockThreshold == nil {
		value := DefaultBlockThreshold
		cfg.BlockThreshold = &value
	}
	if cfg.BlockHTTPStatus == 0 {
		cfg.BlockHTTPStatus = DefaultBlockHTTPStatus
	}
	if strings.TrimSpace(cfg.BlockMessage) == "" {
		cfg.BlockMessage = DefaultBlockMessage
	} else {
		cfg.BlockMessage = strings.TrimSpace(cfg.BlockMessage)
	}
	cfg.GroupPolicies = normalizeGroupPolicies(cfg.GroupPolicies, *cfg)
	// Preserve an invalid blocking-without-audit combination so validation can
	// reject it instead of silently changing administrator intent.
	for i := range cfg.Endpoints {
		ep := &cfg.Endpoints[i]
		// Legacy persisted configurations had no explicit priority. Preserve
		// their existing array order by deriving a one-based priority in memory;
		// the value is persisted on the next ordinary admin save.
		if ep.Priority == 0 {
			ep.Priority = i + 1
		}
		ep.ID = strings.TrimSpace(ep.ID)
		ep.Name = strings.TrimSpace(ep.Name)
		ep.Protocol = strings.TrimSpace(ep.Protocol)
		if ep.Protocol == "" {
			ep.Protocol = "openai_compatible"
		}
		ep.Adapter = strings.TrimSpace(ep.Adapter)
		if ep.Adapter == "" {
			ep.Adapter = AdapterQwen3Guard
		}
		ep.BaseURL = strings.TrimSpace(ep.BaseURL)
		ep.Model = strings.TrimSpace(ep.Model)
		if ep.Model == "" {
			ep.Model = defaultModelForPromptAdapter(ep.Adapter)
		}
		if ep.TimeoutMS == 0 {
			ep.TimeoutMS = DefaultTimeoutMS
		}
		if ep.InputLimit == 0 {
			ep.InputLimit = DefaultInputLimit
		}
	}
}

func normalizeGroupPolicies(policies []GroupPolicy, global storageConfig) []GroupPolicy {
	if len(policies) == 0 {
		return []GroupPolicy{}
	}
	result := make([]GroupPolicy, 0, len(policies))
	for _, source := range policies {
		policy := source.clone()
		policy.Strategy = strings.TrimSpace(policy.Strategy)
		if !policy.hasField("strategy") {
			policy.Strategy = strings.TrimSpace(global.Strategy)
		}
		if !policy.hasField("enabled") {
			policy.Enabled = global.Enabled
		}
		if !policy.hasField("blocking_enabled") {
			policy.BlockingEnabled = global.BlockingEnabled
		}
		if !policy.hasField("blocking_latest_turn_only") {
			policy.BlockingLatestTurnOnly = global.BlockingLatestTurnOnly
		}
		if !policy.hasField("store_pass_events") {
			policy.StorePassEvents = global.StorePassEvents
		}
		if !policy.hasField("scanners") {
			policy.Scanners = append([]string(nil), global.Scanners...)
		}
		policy.Scanners = canonicalScannerIDs(policy.Scanners)
		if !policy.hasField("max_total_input_chars") || policy.MaxTotalInputChars == 0 {
			policy.MaxTotalInputChars = global.MaxTotalInputChars
		}
		if !policy.hasField("active_prompt_template_id") || strings.TrimSpace(policy.ActivePromptTemplateID) == "" {
			policy.ActivePromptTemplateID = global.ActivePromptTemplateID
		}
		if !policy.hasField("flag_threshold") {
			policy.FlagThreshold = thresholdValue(global.FlagThreshold, DefaultFlagThreshold)
		}
		if !policy.hasField("block_threshold") {
			policy.BlockThreshold = thresholdValue(global.BlockThreshold, DefaultBlockThreshold)
		}
		if !policy.hasField("block_http_status") || policy.BlockHTTPStatus == 0 {
			policy.BlockHTTPStatus = global.BlockHTTPStatus
		}
		if !policy.hasField("block_message") || strings.TrimSpace(policy.BlockMessage) == "" {
			policy.BlockMessage = global.BlockMessage
		}
		if !policy.hasField("risk_route_account_ids") {
			policy.RiskRouteAccountIDs = append([]int64(nil), global.RiskRouteAccountIDs...)
		}
		if !policy.hasField("cyber_feedback_account_ids") {
			policy.CyberFeedbackAccountIDs = append([]int64(nil), global.CyberFeedbackAccountIDs...)
		}
		if !policy.hasField("excluded_user_ids") {
			policy.ExcludedUserIDs = append([]int64(nil), global.ExcludedUserIDs...)
		}
		policy.RiskRouteAccountIDs = canonicalInt64s(policy.RiskRouteAccountIDs)
		policy.CyberFeedbackAccountIDs = canonicalInt64s(policy.CyberFeedbackAccountIDs)
		policy.ExcludedUserIDs = canonicalInt64s(policy.ExcludedUserIDs)
		if !policy.hasField("no_route_fallback_mode") {
			policy.NoRouteFallbackMode = global.NoRouteFallbackMode
		}
		policy.NoRouteFallbackMode = normalizeNoRouteFallbackMode(policy.NoRouteFallbackMode)
		result = append(result, policy)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].GroupID < result[j].GroupID })
	return result
}

func normalizeNoRouteFallbackMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return DefaultNoRouteFallbackMode
	case NoRouteFallbackAllow:
		return NoRouteFallbackAllow
	case "reject", "deny", NoRouteFallbackBlock:
		return NoRouteFallbackBlock
	default:
		// Keep unknown values visible so validation can reject them instead of
		// silently changing administrator intent.
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func validateGroupPolicies(policies []GroupPolicy) error {
	seen := make(map[int64]struct{}, len(policies))
	for _, policy := range policies {
		if policy.GroupID < 0 {
			return infraerrors.BadRequest("prompt_audit_invalid_group_policy_group", "分组策略分组 ID 无效")
		}
		if _, exists := seen[policy.GroupID]; exists {
			return infraerrors.BadRequest("prompt_audit_duplicate_group_policy", "分组策略不能重复")
		}
		seen[policy.GroupID] = struct{}{}
		if policy.BlockingEnabled && !policy.Enabled {
			return infraerrors.BadRequest("prompt_audit_group_requires_enabled", "分组开启同步阻止前必须先启用该分组审计")
		}
		if policy.Strategy != "priority" {
			return infraerrors.BadRequest("prompt_audit_invalid_group_policy_strategy", "分组审计策略仅支持 priority")
		}
		if len(policy.Scanners) == 0 {
			return infraerrors.BadRequest("prompt_audit_group_scanners_required", "分组策略至少需要启用一个风险分类")
		}
		for _, scanner := range policy.Scanners {
			if _, ok := ScannerCatalog[NormalizeCategory(scanner)]; !ok {
				return infraerrors.BadRequest("prompt_audit_invalid_group_scanner", "分组策略风险分类无效")
			}
		}
		if policy.MaxTotalInputChars < MinMaxTotalInputChars || policy.MaxTotalInputChars > MaxMaxTotalInputChars {
			return infraerrors.BadRequest("prompt_audit_invalid_group_max_total_input_chars", "分组审计总字符上限超出允许范围")
		}
		if policy.FlagThreshold < 0 || policy.FlagThreshold > 1 {
			return infraerrors.BadRequest("prompt_audit_invalid_group_flag_threshold", "分组标记阈值必须在 0 到 1 之间")
		}
		if policy.BlockThreshold < 0 || policy.BlockThreshold > 1 || policy.FlagThreshold >= policy.BlockThreshold {
			return infraerrors.BadRequest("prompt_audit_invalid_group_block_threshold", "分组标记阈值必须小于阻断阈值")
		}
		if policy.BlockHTTPStatus < 400 || policy.BlockHTTPStatus > 499 {
			return infraerrors.BadRequest("prompt_audit_invalid_group_block_http_status", "分组阻断状态码必须在 400 到 499 之间")
		}
		if strings.TrimSpace(policy.BlockMessage) == "" || len([]rune(policy.BlockMessage)) > MaxBlockMessageRunes {
			return infraerrors.BadRequest("prompt_audit_invalid_group_block_message", "分组阻断提示文案为空或过长")
		}
		mode := normalizeNoRouteFallbackMode(policy.NoRouteFallbackMode)
		if mode != NoRouteFallbackAllow && mode != NoRouteFallbackBlock {
			return infraerrors.BadRequest("prompt_audit_invalid_no_route_fallback_mode", "无分流账号处理方式必须为 allow 或 block")
		}
		if err := validatePositiveIDs(policy.RiskRouteAccountIDs, "prompt_audit_invalid_group_risk_route_account", "分组高风险分流账号 ID 无效"); err != nil {
			return err
		}
		if err := validatePositiveIDs(policy.CyberFeedbackAccountIDs, "prompt_audit_invalid_group_cyber_feedback_account", "分组 CYB 反馈账号 ID 无效"); err != nil {
			return err
		}
		if err := validatePositiveIDs(policy.ExcludedUserIDs, "prompt_audit_invalid_group_excluded_user", "分组排除用户 ID 无效"); err != nil {
			return err
		}
		if len(policy.ExcludedUserIDs) > MaxExcludedUserIDs {
			return infraerrors.BadRequest("prompt_audit_too_many_group_excluded_users", "分组排除用户数量超出允许范围")
		}
	}
	return nil
}

func valueOrInt(value *int, fallback int) int {
	if value != nil {
		return *value
	}
	return fallback
}

func valueOrString(value *string, fallback string) string {
	if value != nil {
		return *value
	}
	return fallback
}

func valueOrFloat(value *float64, fallback float64) float64 {
	if value != nil {
		return *value
	}
	return fallback
}

func validateStorageConfig(cfg storageConfig) error {
	if cfg.BlockingEnabled && !cfg.Enabled {
		return infraerrors.BadRequest(ErrorCodeRequiresEnabled, "开启同步阻止前必须先启用提示词审计")
	}
	if cfg.Strategy != "priority" {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 priority")
	}
	if cfg.WorkerCount < 1 || cfg.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if cfg.QueueCapacity < 1 || cfg.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if !cfg.AllGroups && len(cfg.GroupIDs) == 0 && len(cfg.GroupPolicies) == 0 {
		return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
	}
	if err := validateGroupPolicies(cfg.GroupPolicies); err != nil {
		return err
	}
	if err := validatePositiveIDs(cfg.RiskRouteAccountIDs, "prompt_audit_invalid_risk_route_account", "高风险分流账号 ID 无效"); err != nil {
		return err
	}
	if err := validatePositiveIDs(cfg.CyberFeedbackAccountIDs, "prompt_audit_invalid_cyber_feedback_account", "CYB 反馈账号 ID 无效"); err != nil {
		return err
	}
	if mode := normalizeNoRouteFallbackMode(cfg.NoRouteFallbackMode); mode != NoRouteFallbackAllow && mode != NoRouteFallbackBlock {
		return infraerrors.BadRequest("prompt_audit_invalid_no_route_fallback_mode", "无分流账号处理方式必须为 allow 或 block")
	}
	if len(cfg.ExcludedUserIDs) > MaxExcludedUserIDs {
		return infraerrors.BadRequest("prompt_audit_too_many_excluded_users", "排除用户数量超出允许范围")
	}
	if cfg.MaxTotalInputChars < MinMaxTotalInputChars || cfg.MaxTotalInputChars > MaxMaxTotalInputChars {
		return infraerrors.BadRequest("prompt_audit_invalid_max_total_input_chars", "审计总字符上限超出允许范围")
	}
	if len(cfg.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	if err := validatePromptPolicy(cfg.PromptTemplates, cfg.ActivePromptTemplateID, cfg.FlagThreshold, cfg.BlockThreshold, cfg.BlockHTTPStatus, cfg.BlockMessage); err != nil {
		return err
	}
	if err := validateGroupPolicyTemplates(cfg.GroupPolicies, cfg.PromptTemplates); err != nil {
		return err
	}
	if err := validateCyberSupplementRules(cfg.CyberSupplementRules); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(cfg.Endpoints))
	enabled := 0
	for _, ep := range cfg.Endpoints {
		if ep.ID == "" || ep.Name == "" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint", "审计节点 ID 和名称不能为空")
		}
		if _, ok := seen[ep.ID]; ok {
			return infraerrors.BadRequest("prompt_audit_duplicate_endpoint", "审计节点 ID 不能重复")
		}
		seen[ep.ID] = struct{}{}
		if ep.Protocol != "openai_compatible" {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_protocol", "审计节点仅支持 OpenAI 兼容协议")
		}
		if ep.Priority < MinEndpointPriority || ep.Priority > MaxEndpointPriority {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_priority", "审计节点优先级必须在 1 到 1000 之间")
		}
		if !validPromptAdapter(ep.Adapter) {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_adapter", "审计节点适配器无效")
		}
		if _, err := NormalizeBaseURL(ep.BaseURL); err != nil {
			return err
		}
		if ep.TimeoutMS < MinTimeoutMS || ep.TimeoutMS > MaxTimeoutMS {
			return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时超出允许范围")
		}
		if ep.InputLimit < MinInputLimit || ep.InputLimit > MaxInputLimit {
			return infraerrors.BadRequest("prompt_audit_invalid_input_limit", "审计节点输入上限超出允许范围")
		}
		if ep.Enabled {
			enabled++
		}
	}
	if cfg.Enabled && enabled == 0 {
		return infraerrors.BadRequest("prompt_audit_endpoint_required", "启用提示词审计前至少需要启用一个审计节点")
	}
	return nil
}

func validateGroupPolicyTemplates(policies []GroupPolicy, templates []PromptTemplate) error {
	if len(policies) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(templates))
	for _, template := range templates {
		known[strings.TrimSpace(template.ID)] = struct{}{}
	}
	for _, policy := range policies {
		id := strings.TrimSpace(policy.ActivePromptTemplateID)
		if id == "" {
			return infraerrors.BadRequest("prompt_audit_group_template_required", "分组审核提示词模板不能为空")
		}
		if _, ok := known[id]; !ok {
			return infraerrors.BadRequest("prompt_audit_group_template_not_found", "分组审核提示词模板不存在")
		}
	}
	return nil
}

func validateUpdateConfigRequest(req UpdateConfigRequest) error {
	if strings.TrimSpace(req.Strategy) != "priority" {
		return infraerrors.BadRequest("prompt_audit_invalid_strategy", "提示词审计策略仅支持 priority")
	}
	if mode := normalizeNoRouteFallbackMode(req.NoRouteFallbackMode); mode != NoRouteFallbackAllow && mode != NoRouteFallbackBlock {
		return infraerrors.BadRequest("prompt_audit_invalid_no_route_fallback_mode", "无分流账号处理方式必须为 allow 或 block")
	}
	if req.WorkerCount < 1 || req.WorkerCount > MaxWorkerCount {
		return infraerrors.BadRequest("prompt_audit_invalid_worker_count", "Worker 数量超出允许范围")
	}
	if req.QueueCapacity < 1 || req.QueueCapacity > MaxQueueCapacity {
		return infraerrors.BadRequest("prompt_audit_invalid_queue_capacity", "队列容量超出允许范围")
	}
	if len(req.Scanners) == 0 {
		return infraerrors.BadRequest("prompt_audit_scanners_required", "至少需要启用一个风险分类")
	}
	for _, scanner := range req.Scanners {
		if _, ok := ScannerCatalog[NormalizeCategory(scanner)]; !ok {
			return infraerrors.BadRequest("prompt_audit_invalid_scanner", "提示词审计风险分类无效")
		}
	}
	if !req.AllGroups {
		if len(req.GroupIDs) == 0 && (req.GroupPolicies == nil || len(*req.GroupPolicies) == 0) {
			return infraerrors.BadRequest("prompt_audit_groups_required", "指定分组模式至少需要选择一个分组")
		}
		for _, groupID := range req.GroupIDs {
			if groupID <= 0 {
				return infraerrors.BadRequest("prompt_audit_invalid_group", "提示词审计分组 ID 无效")
			}
		}
	}
	if req.GroupPolicies != nil {
		templates := []PromptTemplate{DefaultPromptTemplate()}
		if req.PromptTemplates != nil {
			templates = clonePromptTemplates(*req.PromptTemplates)
		}
		policies := normalizeGroupPolicies(*req.GroupPolicies, storageConfig{
			Enabled: req.Enabled, BlockingEnabled: req.BlockingEnabled,
			BlockingLatestTurnOnly: req.BlockingLatestTurnOnly, StorePassEvents: req.StorePassEvents,
			Strategy: req.Strategy, Scanners: req.Scanners, MaxTotalInputChars: valueOrInt(req.MaxTotalInputChars, DefaultMaxTotalInputChars),
			ActivePromptTemplateID: valueOrString(req.ActivePromptTemplateID, DefaultPromptTemplateID),
			NoRouteFallbackMode:    req.NoRouteFallbackMode,
			PromptTemplates:        templates,
			FlagThreshold:          float64Pointer(valueOrFloat(req.FlagThreshold, DefaultFlagThreshold)),
			BlockThreshold:         float64Pointer(valueOrFloat(req.BlockThreshold, DefaultBlockThreshold)),
			BlockHTTPStatus:        valueOrInt(req.BlockHTTPStatus, DefaultBlockHTTPStatus), BlockMessage: valueOrString(req.BlockMessage, DefaultBlockMessage),
			RiskRouteAccountIDs: nil, CyberFeedbackAccountIDs: nil, ExcludedUserIDs: nil,
		})
		if err := validateGroupPolicies(policies); err != nil {
			return err
		}
		if req.PromptTemplates != nil {
			if err := validateGroupPolicyTemplates(policies, templates); err != nil {
				return err
			}
		}
	}
	if req.RiskRouteAccountIDs != nil {
		if err := validatePositiveIDs(*req.RiskRouteAccountIDs, "prompt_audit_invalid_risk_route_account", "高风险分流账号 ID 无效"); err != nil {
			return err
		}
	}
	if req.CyberFeedbackAccountIDs != nil {
		if err := validatePositiveIDs(*req.CyberFeedbackAccountIDs, "prompt_audit_invalid_cyber_feedback_account", "CYB 反馈账号 ID 无效"); err != nil {
			return err
		}
	}
	if req.ExcludedUserIDs != nil {
		if err := validatePositiveIDs(*req.ExcludedUserIDs, "prompt_audit_invalid_excluded_user", "排除用户 ID 无效"); err != nil {
			return err
		}
		if len(canonicalInt64s(*req.ExcludedUserIDs)) > MaxExcludedUserIDs {
			return infraerrors.BadRequest("prompt_audit_too_many_excluded_users", "排除用户数量超出允许范围")
		}
	}
	if req.MaxTotalInputChars != nil && (*req.MaxTotalInputChars < MinMaxTotalInputChars || *req.MaxTotalInputChars > MaxMaxTotalInputChars) {
		return infraerrors.BadRequest("prompt_audit_invalid_max_total_input_chars", "审计总字符上限超出允许范围")
	}
	if req.PromptTemplates != nil && len(*req.PromptTemplates) > MaxPromptTemplateCount {
		return infraerrors.BadRequest("prompt_audit_too_many_templates", "审核提示词模板数量超出允许范围")
	}
	if req.FlagThreshold != nil && (*req.FlagThreshold < 0 || *req.FlagThreshold > 1) {
		return infraerrors.BadRequest("prompt_audit_invalid_flag_threshold", "标记阈值必须在 0 到 1 之间")
	}
	if req.BlockThreshold != nil && (*req.BlockThreshold < 0 || *req.BlockThreshold > 1) {
		return infraerrors.BadRequest("prompt_audit_invalid_block_threshold", "阻断阈值必须在 0 到 1 之间")
	}
	if req.BlockHTTPStatus != nil && (*req.BlockHTTPStatus < 400 || *req.BlockHTTPStatus > 499) {
		return infraerrors.BadRequest("prompt_audit_invalid_block_http_status", "阻断状态码必须在 400 到 499 之间")
	}
	if req.BlockMessage != nil {
		message := strings.TrimSpace(*req.BlockMessage)
		if message == "" || len([]rune(message)) > MaxBlockMessageRunes {
			return infraerrors.BadRequest("prompt_audit_invalid_block_message", "阻断提示文案为空或过长")
		}
	}
	for _, endpoint := range req.Endpoints {
		// Zero means an older client omitted the newly introduced field. The
		// storage builder derives/preserves a valid value before final validation.
		if endpoint.Priority < 0 || endpoint.Priority > MaxEndpointPriority {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_priority", "审计节点优先级必须在 1 到 1000 之间")
		}
		if strings.TrimSpace(endpoint.Adapter) != "" && !validPromptAdapter(strings.TrimSpace(endpoint.Adapter)) {
			return infraerrors.BadRequest("prompt_audit_invalid_endpoint_adapter", "审计节点适配器无效")
		}
		if source := strings.TrimSpace(endpoint.CredentialSource); source != "" {
			if source != CredentialSourceContentModeration {
				return infraerrors.BadRequest("prompt_audit_invalid_credential_source", "审计节点凭据来源无效")
			}
			if strings.TrimSpace(endpoint.Adapter) != AdapterOpenAIModeration {
				return infraerrors.BadRequest("prompt_audit_credential_source_adapter_mismatch", "仅 OpenAI Moderation 节点可复用内容审计凭据")
			}
			if strings.TrimSpace(endpoint.Token) != "" || endpoint.ClearToken {
				return infraerrors.BadRequest("prompt_audit_credential_source_conflict", "不能同时提交节点 Token、清除 Token 与凭据复用")
			}
		}
		if endpoint.TimeoutMS < MinTimeoutMS || endpoint.TimeoutMS > MaxTimeoutMS {
			return infraerrors.BadRequest("prompt_audit_invalid_timeout", "审计节点超时超出允许范围")
		}
		if endpoint.InputLimit < MinInputLimit || endpoint.InputLimit > MaxInputLimit {
			return infraerrors.BadRequest("prompt_audit_invalid_input_limit", "审计节点输入上限超出允许范围")
		}
	}
	return nil
}

func (cfg ActiveConfig) EffectiveMode() Mode {
	if !cfg.RiskControlEnabled || !cfg.Enabled {
		return ModeOff
	}
	if cfg.BlockingEnabled {
		return ModeBlocking
	}
	return ModeAsync
}

// RequiresBlockingActivation reports whether the currently persisted policy
// has any in-scope synchronous-blocking path.  The legacy top-level blocking
// flag remains the fallback for configurations without per-group policies;
// once group policies are present, each policy controls its own mode.  This
// distinction is used by ConfigManager's fail-closed reload guard, which must
// still protect a blocking group even when the global default is async.
func (cfg ActiveConfig) RequiresBlockingActivation() bool {
	if !cfg.RiskControlEnabled || !cfg.Enabled {
		return false
	}
	if len(cfg.GroupPolicies) == 0 {
		return cfg.BlockingEnabled
	}
	covered := make(map[int64]struct{}, len(cfg.GroupPolicies))
	for _, policy := range cfg.GroupPolicies {
		covered[policy.GroupID] = struct{}{}
		if policy.Enabled && policy.BlockingEnabled {
			return true
		}
	}
	// Groups without an explicit policy inherit the legacy top-level fields.
	// Preserve that fallback for all-groups mode and for selected IDs that are
	// not represented in the policy array.
	if cfg.BlockingEnabled {
		if cfg.AllGroups {
			return true
		}
		for _, groupID := range cfg.GroupIDs {
			if _, ok := covered[groupID]; !ok {
				return true
			}
		}
	}
	return false
}

func (cfg ActiveConfig) IncludesGroup(groupID *int64) bool {
	if cfg.AllGroups {
		return true
	}
	if _, ok := cfg.GroupPolicyFor(groupID); ok {
		return true
	}
	if groupID == nil {
		return false
	}
	i := sort.Search(len(cfg.GroupIDs), func(i int) bool { return cfg.GroupIDs[i] >= *groupID })
	return i < len(cfg.GroupIDs) && cfg.GroupIDs[i] == *groupID
}

// GroupPolicyFor returns the normalized override for one request group.  The
// caller receives a copy of the slice element and may safely mutate it.
func (cfg ActiveConfig) GroupPolicyFor(groupID *int64) (GroupPolicy, bool) {
	target := int64(0) // nil denotes the explicit ungrouped/default bucket.
	if groupID != nil {
		target = *groupID
		if target < 0 {
			return GroupPolicy{}, false
		}
	}
	for _, policy := range cfg.GroupPolicies {
		if policy.GroupID == target {
			return policy.clone(), true
		}
	}
	return GroupPolicy{}, false
}

// EffectiveForGroup overlays a group's policy on the legacy top-level config.
// It is intentionally pure: each request/worker receives an independent
// snapshot, preventing one group's thresholds or route pool from leaking into
// another group's decision.
func (cfg ActiveConfig) EffectiveForGroup(groupID *int64) ActiveConfig {
	effective := cloneActiveConfig(cfg)
	policy, ok := cfg.GroupPolicyFor(groupID)
	if !ok {
		return effective
	}
	// The global audit switch remains the master gate.  Blocking, however, is a
	// policy dimension: once a group policy exists its mode must be controlled by
	// that group's setting rather than by the legacy top-level default.  This is
	// what makes a blocking group and an async group coexist in one audit config.
	// A disabled global audit switch still wins and can never be re-enabled by a
	// stale or independently edited group policy.
	effective.Enabled = cfg.Enabled && policy.Enabled
	effective.BlockingEnabled = effective.Enabled && policy.BlockingEnabled
	effective.BlockingLatestTurnOnly = effective.BlockingEnabled && policy.BlockingLatestTurnOnly
	effective.StorePassEvents = policy.StorePassEvents
	effective.Strategy = policy.Strategy
	effective.Scanners = append([]string(nil), policy.Scanners...)
	effective.MaxTotalInputChars = policy.MaxTotalInputChars
	effective.ActivePromptTemplateID = policy.ActivePromptTemplateID
	effective.FlagThreshold = policy.FlagThreshold
	effective.BlockThreshold = policy.BlockThreshold
	effective.BlockHTTPStatus = policy.BlockHTTPStatus
	effective.BlockMessage = policy.BlockMessage
	effective.RiskRouteAccountIDs = append([]int64(nil), policy.RiskRouteAccountIDs...)
	effective.CyberFeedbackAccountIDs = append([]int64(nil), policy.CyberFeedbackAccountIDs...)
	effective.ExcludedUserIDs = append([]int64(nil), policy.ExcludedUserIDs...)
	effective.NoRouteFallbackMode = normalizeNoRouteFallbackMode(policy.NoRouteFallbackMode)
	applyGroupPromptTemplate(&effective, policy.ActivePromptTemplateID)
	return effective
}

// EffectiveConfigForGroup is a descriptive alias used by callers that want
// to make the per-group resolution explicit.
func (cfg ActiveConfig) EffectiveConfigForGroup(groupID *int64) ActiveConfig {
	return cfg.EffectiveForGroup(groupID)
}

func (cfg ActiveConfig) IncludesUserForGroup(groupID *int64, userID int64) bool {
	effective := cfg.EffectiveForGroup(groupID)
	return effective.IncludesUser(userID)
}

func (cfg ActiveConfig) IncludesCyberFeedbackSourceForGroup(groupID *int64, accountID int64, platform, accountType string) bool {
	platform = strings.ToLower(strings.TrimSpace(platform))
	accountType = strings.ToLower(strings.TrimSpace(accountType))
	// Historical behavior always captures real OpenAI OAuth CYB responses.
	// Group policies add/override the administrator-selected non-OAuth pool;
	// they never disable this independent safety-evidence path.
	if platform == service.PlatformOpenAI && accountType == service.AccountTypeOAuth {
		return true
	}
	effective := cfg.EffectiveForGroup(groupID)
	return accountID > 0 && containsCanonicalInt64(effective.CyberFeedbackAccountIDs, accountID)
}

func (cfg ActiveConfig) AllowsNoRouteFallback() bool {
	return strings.EqualFold(strings.TrimSpace(cfg.NoRouteFallbackMode), NoRouteFallbackAllow)
}

func applyGroupPromptTemplate(cfg *ActiveConfig, templateID string) {
	if cfg == nil {
		return
	}
	template := activePromptTemplate(cfg.PromptTemplates, strings.TrimSpace(templateID))
	if template.ID == "" {
		template = activePromptTemplate(cfg.PromptTemplates, cfg.ActivePromptTemplateID)
	}
	if template.ID == "" {
		return
	}
	cfg.ActivePromptTemplateID = template.ID
	for index := range cfg.Endpoints {
		endpoint := &cfg.Endpoints[index]
		endpoint.PromptTemplateID = template.ID
		endpoint.FlagThreshold = cfg.FlagThreshold
		endpoint.BlockThreshold = cfg.BlockThreshold
		if endpoint.Adapter == AdapterOpenAIModeration {
			endpoint.SystemPrompt = ""
			continue
		}
		endpoint.SystemPrompt = template.SystemPrompt
		if adapterSupportsSystemPrompt(endpoint.Adapter) {
			if compiled, err := CompileCyberSupplement(template.SystemPrompt, cfg.CyberSupplementRules); err == nil {
				endpoint.SystemPrompt = compiled
			}
		}
	}
}

// IncludesCyberFeedbackSource is deliberately independent of IncludesGroup
// and EffectiveMode. It controls only whether a real upstream cyber_policy
// response is captured for administrator feedback and rule learning; it never
// causes the request to be sent to a Prompt Audit endpoint.
func (cfg ActiveConfig) IncludesCyberFeedbackSource(accountID int64, platform, accountType string) bool {
	platform = strings.ToLower(strings.TrimSpace(platform))
	accountType = strings.ToLower(strings.TrimSpace(accountType))
	if platform == service.PlatformOpenAI && accountType == service.AccountTypeOAuth {
		return true
	}
	return accountID > 0 && containsCanonicalInt64(cfg.CyberFeedbackAccountIDs, accountID)
}

func (cfg ActiveConfig) IncludesUser(userID int64) bool {
	if userID <= 0 || len(cfg.ExcludedUserIDs) == 0 {
		return true
	}
	return !containsCanonicalInt64(cfg.ExcludedUserIDs, userID)
}

func (cfg ActiveConfig) EnabledEndpoints() []ActiveEndpoint {
	result := make([]ActiveEndpoint, 0, len(cfg.Endpoints))
	for index, ep := range cfg.Endpoints {
		if ep.Enabled {
			if ep.Priority == 0 {
				ep.Priority = index + 1
			}
			result = append(result, ep)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Priority < result[j].Priority
	})
	return result
}

// InvalidTokenEndpointIDs lists endpoints whose stored token could not be
// decrypted with the current encryption key.
func (cfg ActiveConfig) InvalidTokenEndpointIDs() []string {
	ids := make([]string, 0)
	for _, ep := range cfg.Endpoints {
		if ep.TokenInvalid {
			ids = append(ids, ep.ID)
		}
	}
	return ids
}

func PublicFromStorage(cfg storageConfig, riskControlEnabled bool, invalidTokenEndpointIDs []string) PublicConfig {
	invalid := make(map[string]struct{}, len(invalidTokenEndpointIDs))
	for _, id := range invalidTokenEndpointIDs {
		invalid[id] = struct{}{}
	}
	scanners := append([]string{}, cfg.Scanners...)
	groupIDs := append([]int64{}, cfg.GroupIDs...)
	groupPolicies := cloneGroupPolicies(cfg.GroupPolicies)
	riskRouteAccountIDs := append([]int64{}, cfg.RiskRouteAccountIDs...)
	cyberFeedbackAccountIDs := append([]int64{}, cfg.CyberFeedbackAccountIDs...)
	excludedUserIDs := append([]int64{}, cfg.ExcludedUserIDs...)
	endpoints := make([]PublicEndpoint, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		hasToken := strings.TrimSpace(ep.TokenCiphertext) != ""
		status := "missing"
		if hasToken {
			status = "configured"
			if _, ok := invalid[ep.ID]; ok {
				status = "invalid"
			}
		}
		endpoints = append(endpoints, PublicEndpoint{
			ID: ep.ID, Name: ep.Name, Priority: ep.Priority, Protocol: ep.Protocol, Adapter: ep.Adapter, BaseURL: ep.BaseURL,
			Model: ep.Model, TimeoutMS: ep.TimeoutMS, InputLimit: ep.InputLimit,
			Enabled: ep.Enabled, HasToken: hasToken, TokenStatus: status,
			SupportsSystemPrompt:   adapterSupportsSystemPrompt(ep.Adapter),
			CyberSupplementApplied: adapterSupportsSystemPrompt(ep.Adapter) && len(cfg.CyberSupplementRules) > 0,
		})
	}
	active := ActiveConfig{RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled}
	return PublicConfig{
		Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled, BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly, StorePassEvents: cfg.StorePassEvents,
		EffectiveMode: active.EffectiveMode(), Strategy: cfg.Strategy, WorkerCount: cfg.WorkerCount,
		QueueCapacity: cfg.QueueCapacity, Scanners: scanners, AllGroups: cfg.AllGroups,
		GroupIDs: groupIDs, GroupPolicies: groupPolicies, RiskRouteAccountIDs: riskRouteAccountIDs,
		CyberFeedbackAccountIDs: cyberFeedbackAccountIDs, ExcludedUserIDs: excludedUserIDs, MaxTotalInputChars: cfg.MaxTotalInputChars,
		NoRouteFallbackMode:    normalizeNoRouteFallbackMode(cfg.NoRouteFallbackMode),
		PromptTemplates:        clonePromptTemplates(cfg.PromptTemplates),
		CyberSupplementRules:   cloneCyberSupplementRules(cfg.CyberSupplementRules),
		ActivePromptTemplateID: cfg.ActivePromptTemplateID, FlagThreshold: thresholdValue(cfg.FlagThreshold, DefaultFlagThreshold),
		BlockThreshold: thresholdValue(cfg.BlockThreshold, DefaultBlockThreshold), BlockHTTPStatus: cfg.BlockHTTPStatus,
		BlockMessage: cfg.BlockMessage, Endpoints: endpoints, ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
	}
}

func ActiveFromStorage(cfg storageConfig, riskControlEnabled bool, encryptor SecretEncryptor) (ActiveConfig, error) {
	normalizeStorageConfig(&cfg)
	template := activePromptTemplate(cfg.PromptTemplates, cfg.ActivePromptTemplateID)
	active := ActiveConfig{
		RiskControlEnabled: riskControlEnabled, Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled,
		BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly,
		StorePassEvents:        cfg.StorePassEvents, Strategy: cfg.Strategy, WorkerCount: cfg.WorkerCount,
		QueueCapacity: cfg.QueueCapacity, Scanners: append([]string(nil), cfg.Scanners...), AllGroups: cfg.AllGroups,
		GroupIDs: append([]int64(nil), cfg.GroupIDs...), GroupPolicies: cloneGroupPolicies(cfg.GroupPolicies), RiskRouteAccountIDs: append([]int64(nil), cfg.RiskRouteAccountIDs...),
		CyberFeedbackAccountIDs: append([]int64(nil), cfg.CyberFeedbackAccountIDs...), ExcludedUserIDs: append([]int64(nil), cfg.ExcludedUserIDs...), MaxTotalInputChars: cfg.MaxTotalInputChars,
		NoRouteFallbackMode:    normalizeNoRouteFallbackMode(cfg.NoRouteFallbackMode),
		PromptTemplates:        clonePromptTemplates(cfg.PromptTemplates),
		CyberSupplementRules:   cloneCyberSupplementRules(cfg.CyberSupplementRules),
		ActivePromptTemplateID: template.ID, FlagThreshold: thresholdValue(cfg.FlagThreshold, DefaultFlagThreshold),
		BlockThreshold: thresholdValue(cfg.BlockThreshold, DefaultBlockThreshold), BlockHTTPStatus: cfg.BlockHTTPStatus,
		BlockMessage: cfg.BlockMessage, ConfigVersion: cfg.ConfigVersion,
		UpdatedAt: cfg.UpdatedAt, UpdatedBy: cfg.UpdatedBy, ChangeSummary: cfg.ChangeSummary,
		Endpoints: make([]ActiveEndpoint, 0, len(cfg.Endpoints)),
	}
	for _, ep := range cfg.Endpoints {
		systemPrompt := template.SystemPrompt
		supplementApplied := false
		if adapterSupportsSystemPrompt(ep.Adapter) {
			var err error
			systemPrompt, err = CompileCyberSupplement(template.SystemPrompt, cfg.CyberSupplementRules)
			if err != nil {
				return ActiveConfig{}, err
			}
			supplementApplied = len(cfg.CyberSupplementRules) > 0
		}
		if ep.Adapter == AdapterOpenAIModeration {
			systemPrompt = ""
		}
		token := ""
		tokenInvalid := false
		if ep.TokenCiphertext != "" {
			if encryptor == nil {
				return ActiveConfig{}, fmt.Errorf("prompt audit secret encryptor unavailable")
			}
			plain, err := encryptor.Decrypt(ep.TokenCiphertext)
			if err != nil {
				// An undecryptable token (encryption key changed or regenerated)
				// must not take the whole config down: admins would otherwise be
				// locked out of the real config version and unable to recover
				// (issue #4887). Keep the ciphertext persisted, but exclude the
				// endpoint from runtime use until the token is re-entered.
				tokenInvalid = true
			} else {
				token = plain
			}
		}
		active.Endpoints = append(active.Endpoints, ActiveEndpoint{
			ID: ep.ID, Name: ep.Name, Priority: ep.Priority, Protocol: ep.Protocol, Adapter: ep.Adapter, BaseURL: ep.BaseURL, Model: ep.Model,
			Token: token, TimeoutMS: ep.TimeoutMS, InputLimit: ep.InputLimit,
			PromptTemplateID: template.ID, SystemPrompt: systemPrompt,
			SupportsSystemPrompt: adapterSupportsSystemPrompt(ep.Adapter), CyberSupplementApplied: supplementApplied,
			FlagThreshold: active.FlagThreshold, BlockThreshold: active.BlockThreshold,
			Enabled: ep.Enabled && !tokenInvalid, TokenInvalid: tokenInvalid,
		})
	}
	return active, nil
}

func changeSummary(cfg storageConfig) string {
	summary := struct {
		Enabled                   bool    `json:"enabled"`
		BlockingEnabled           bool    `json:"blocking_enabled"`
		BlockingLatestTurnOnly    bool    `json:"blocking_latest_turn_only"`
		StorePassEvents           bool    `json:"store_pass_events"`
		EndpointCount             int     `json:"endpoint_count"`
		ScannerCount              int     `json:"scanner_count"`
		AllGroups                 bool    `json:"all_groups"`
		GroupCount                int     `json:"group_count"`
		GroupHash                 string  `json:"group_hash"`
		GroupPolicyCount          int     `json:"group_policy_count"`
		GroupPolicyHash           string  `json:"group_policy_hash"`
		NoRouteFallbackMode       string  `json:"no_route_fallback_mode"`
		RiskRouteAccountCount     int     `json:"risk_route_account_count"`
		CyberFeedbackAccountCount int     `json:"cyber_feedback_account_count"`
		CyberFeedbackAccountHash  string  `json:"cyber_feedback_account_hash"`
		ExcludedUserCount         int     `json:"excluded_user_count"`
		ExcludedUserHash          string  `json:"excluded_user_hash"`
		MaxTotalInputChars        int     `json:"max_total_input_chars"`
		TemplateCount             int     `json:"template_count"`
		CyberSupplementCount      int     `json:"cyber_supplement_count"`
		ActiveTemplateID          string  `json:"active_template_id"`
		FlagThreshold             float64 `json:"flag_threshold"`
		BlockThreshold            float64 `json:"block_threshold"`
		BlockHTTPStatus           int     `json:"block_http_status"`
	}{
		Enabled: cfg.Enabled, BlockingEnabled: cfg.BlockingEnabled,
		BlockingLatestTurnOnly: cfg.BlockingLatestTurnOnly, StorePassEvents: cfg.StorePassEvents,
		EndpointCount: len(cfg.Endpoints), ScannerCount: len(cfg.Scanners), AllGroups: cfg.AllGroups,
		GroupCount: len(cfg.GroupIDs), GroupPolicyCount: len(cfg.GroupPolicies), RiskRouteAccountCount: len(cfg.RiskRouteAccountIDs),
		CyberFeedbackAccountCount: len(cfg.CyberFeedbackAccountIDs),
		ExcludedUserCount:         len(cfg.ExcludedUserIDs),
		MaxTotalInputChars:        cfg.MaxTotalInputChars, TemplateCount: len(cfg.PromptTemplates),
		CyberSupplementCount: len(cfg.CyberSupplementRules), ActiveTemplateID: cfg.ActivePromptTemplateID,
		NoRouteFallbackMode: normalizeNoRouteFallbackMode(cfg.NoRouteFallbackMode),
		FlagThreshold:       thresholdValue(cfg.FlagThreshold, DefaultFlagThreshold),
		BlockThreshold:      thresholdValue(cfg.BlockThreshold, DefaultBlockThreshold), BlockHTTPStatus: cfg.BlockHTTPStatus,
	}
	rawGroups, _ := json.Marshal(cfg.GroupIDs)
	digest := sha256.Sum256(rawGroups)
	summary.GroupHash = hex.EncodeToString(digest[:])
	rawGroupPolicies, _ := json.Marshal(cfg.GroupPolicies)
	groupPolicyDigest := sha256.Sum256(rawGroupPolicies)
	summary.GroupPolicyHash = hex.EncodeToString(groupPolicyDigest[:])
	rawCyberAccounts, _ := json.Marshal(cfg.CyberFeedbackAccountIDs)
	cyberAccountDigest := sha256.Sum256(rawCyberAccounts)
	summary.CyberFeedbackAccountHash = hex.EncodeToString(cyberAccountDigest[:])
	rawExcludedUsers, _ := json.Marshal(cfg.ExcludedUserIDs)
	excludedUserDigest := sha256.Sum256(rawExcludedUsers)
	summary.ExcludedUserHash = hex.EncodeToString(excludedUserDigest[:])
	raw, _ := json.Marshal(summary)
	return string(raw)
}

func canonicalInt64s(values []int64) []int64 {
	seen := make(map[int64]struct{}, len(values))
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func containsCanonicalInt64(values []int64, target int64) bool {
	i := sort.Search(len(values), func(i int) bool { return values[i] >= target })
	return i < len(values) && values[i] == target
}

func validatePositiveIDs(values []int64, code, message string) error {
	for _, value := range values {
		if value <= 0 {
			return infraerrors.BadRequest(code, message)
		}
	}
	return nil
}

func canonicalScannerIDs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		id := NormalizeCategory(value)
		if _, ok := ScannerCatalog[id]; ok {
			seen[id] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for _, id := range AllScannerIDs {
		if _, ok := seen[id]; ok {
			result = append(result, id)
		}
	}
	return result
}

func validatePromptPolicy(templates []PromptTemplate, activeID string, flagThreshold, blockThreshold *float64, blockHTTPStatus int, blockMessage string) error {
	if len(templates) == 0 || len(templates) > MaxPromptTemplateCount {
		return infraerrors.BadRequest("prompt_audit_invalid_templates", "审核提示词模板数量无效")
	}
	seen := make(map[string]struct{}, len(templates))
	activeFound := false
	for _, template := range templates {
		id := strings.TrimSpace(template.ID)
		name := strings.TrimSpace(template.Name)
		prompt := strings.TrimSpace(template.SystemPrompt)
		if id == "" || len([]rune(id)) > MaxPromptTemplateIDRunes || name == "" || len([]rune(name)) > MaxPromptTemplateNameRunes || prompt == "" || len([]rune(prompt)) > MaxPromptTemplateRunes {
			return infraerrors.BadRequest("prompt_audit_invalid_template", "审核提示词模板无效")
		}
		if _, exists := seen[id]; exists {
			return infraerrors.BadRequest("prompt_audit_duplicate_template", "审核提示词模板 ID 不能重复")
		}
		seen[id] = struct{}{}
		if id == activeID {
			activeFound = true
		}
	}
	if !activeFound {
		return infraerrors.BadRequest("prompt_audit_active_template_not_found", "当前审核提示词模板不存在")
	}
	flag := thresholdValue(flagThreshold, DefaultFlagThreshold)
	block := thresholdValue(blockThreshold, DefaultBlockThreshold)
	if flag < 0 || flag > 1 {
		return infraerrors.BadRequest("prompt_audit_invalid_flag_threshold", "标记阈值必须在 0 到 1 之间")
	}
	if block < 0 || block > 1 {
		return infraerrors.BadRequest("prompt_audit_invalid_block_threshold", "阻断阈值必须在 0 到 1 之间")
	}
	if flag >= block {
		return infraerrors.BadRequest("prompt_audit_invalid_threshold_order", "标记阈值必须小于阻断阈值")
	}
	if blockHTTPStatus < 400 || blockHTTPStatus > 499 {
		return infraerrors.BadRequest("prompt_audit_invalid_block_http_status", "阻断状态码必须在 400 到 499 之间")
	}
	message := strings.TrimSpace(blockMessage)
	if message == "" || len([]rune(message)) > MaxBlockMessageRunes {
		return infraerrors.BadRequest("prompt_audit_invalid_block_message", "阻断提示文案为空或过长")
	}
	return nil
}
