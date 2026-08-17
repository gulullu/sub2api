package securityaudit

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	ErrorCodeCyberFeedbackUnavailable = "prompt_audit_cyber_feedback_unavailable"
	ErrorCodeCyberFeedbackNotFound    = "prompt_audit_cyber_feedback_not_found"
	ErrorCodeCyberFeedbackConflict    = "prompt_audit_cyber_feedback_conflict"
)

type CyberFeedbackPage struct {
	Items         []CyberFeedbackAdminDTO `json:"items"`
	Total         int64                   `json:"total"`
	Page          int                     `json:"page"`
	PageSize      int                     `json:"page_size"`
	ActiveRules   []CyberSupplementRule   `json:"active_rules"`
	Rules         []CyberRuleAdminDTO     `json:"rules"`
	ConfigVersion int64                   `json:"config_version"`
}

// CyberFeedbackAdminDTO is the only feedback shape exposed by P1 handlers.
// It deliberately omits API-key identity, signature bytes/version, and every
// raw prompt field even though the repository model contains internal fields.
type CyberFeedbackAdminDTO struct {
	ID                  int64      `json:"id"`
	RequestID           string     `json:"request_id"`
	TurnNumber          int        `json:"turn_number"`
	GroupID             int64      `json:"group_id"`
	AccountID           int64      `json:"account_id"`
	Model               string     `json:"model"`
	Endpoint            string     `json:"endpoint"`
	Protocol            string     `json:"protocol"`
	Transport           string     `json:"transport"`
	Stage               string     `json:"stage"`
	UpstreamStatus      int        `json:"upstream_status"`
	RedactedPreview     string     `json:"redacted_preview"`
	ConfirmCount        int64      `json:"confirm_count"`
	FirstConfirmedAt    *time.Time `json:"first_confirmed_at"`
	LastConfirmedAt     *time.Time `json:"last_confirmed_at"`
	GenerationStatus    string     `json:"generation_status"`
	GenerationErrorCode string     `json:"generation_error_code"`
	CandidateRuleText   string     `json:"candidate_rule_text"`
	Status              string     `json:"status"`
	ReviewedBy          *int64     `json:"reviewed_by"`
	ReviewedAt          *time.Time `json:"reviewed_at"`
	RuleID              *string    `json:"rule_id"`
	ConfigVersion       int64      `json:"config_version"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// CyberFeedbackAdminDetailDTO is returned only by the administrator detail
// endpoint. Large/raw evidence never appears in list responses or email.
type CyberFeedbackAdminDetailDTO struct {
	CyberFeedbackAdminDTO
	AccountName           string `json:"account_name"`
	CredentialAccountID   int64  `json:"credential_account_id"`
	CredentialAccountName string `json:"credential_account_name"`
	PromptLength          int    `json:"prompt_length"`
	MessageCount          int    `json:"message_count"`
	FullPromptTruncated   bool   `json:"truncated"`
	UpstreamCode          string `json:"upstream_code"`
	UpstreamMessage       string `json:"upstream_message"`
}

type CyberFeedbackEvidenceAdminDTO struct {
	Available                    bool   `json:"available"`
	FullPrompt                   string `json:"full_prompt"`
	PromptLength                 int    `json:"prompt_length"`
	MessageCount                 int    `json:"message_count"`
	Truncated                    bool   `json:"truncated"`
	UserID                       int64  `json:"user_id"`
	Username                     string `json:"username"`
	UserEmail                    string `json:"user_email"`
	APIKeyID                     int64  `json:"api_key_id"`
	APIKeyName                   string `json:"api_key_name"`
	APIKeyPrefix                 string `json:"api_key_prefix"`
	GroupID                      int64  `json:"group_id"`
	GroupName                    string `json:"group_name"`
	SelectedAccountID            int64  `json:"selected_account_id"`
	SelectedAccountName          string `json:"selected_account_name"`
	CredentialAccountID          int64  `json:"credential_account_id"`
	CredentialAccountName        string `json:"credential_account_name"`
	CredentialAccountEmail       string `json:"credential_account_email"`
	CredentialAccountEmailSource string `json:"credential_account_email_source"`
	IdentitySource               string `json:"identity_source"`
	ClientRequestID              string `json:"client_request_id"`
	ClientIP                     string `json:"client_ip"`
	UserAgent                    string `json:"user_agent"`
}

type CyberRulesPage struct {
	Items         []CyberRuleAdminDTO `json:"items"`
	ActiveCount   int                 `json:"active_count"`
	ConfigVersion int64               `json:"config_version"`
	activeRules   []CyberSupplementRule
}

type CyberRuleAdminDTO struct {
	ID                 string     `json:"id"`
	RuleText           string     `json:"rule_text"`
	SourceFeedbackID   int64      `json:"source_feedback_id"`
	Status             string     `json:"status"`
	RuleTextSource     string     `json:"rule_text_source"`
	RecoveredCandidate bool       `json:"recovered_candidate"`
	CreatedAt          time.Time  `json:"created_at"`
	CreatedBy          int64      `json:"created_by"`
	ReviewedAt         *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy         *int64     `json:"reviewed_by,omitempty"`
	StateUpdatedAt     *time.Time `json:"state_updated_at,omitempty"`
	StateUpdatedBy     *int64     `json:"state_updated_by,omitempty"`
	ConfigVersion      int64      `json:"config_version"`
}

type AdoptCyberFeedbackRequest struct {
	RuleText              string `json:"rule_text"`
	ExpectedConfigVersion int64  `json:"expected_config_version" binding:"required"`
}

type RejectCyberFeedbackRequest struct {
	Reason string `json:"reason"`
}

type RevokeCyberRuleRequest struct {
	ExpectedConfigVersion int64 `json:"expected_config_version" binding:"required"`
}

type RestoreCyberRuleRequest struct {
	ExpectedConfigVersion int64 `json:"expected_config_version" binding:"required"`
}

type DeleteCyberRuleRequest struct {
	ExpectedConfigVersion int64  `json:"expected_config_version" binding:"required"`
	ConfirmRuleID         string `json:"confirm_rule_id" binding:"required"`
}

type CyberFeedbackActionResult struct {
	Event         *CyberFeedbackAdminDTO `json:"event,omitempty"`
	Rule          *CyberRuleAdminDTO     `json:"rule,omitempty"`
	ConfigVersion int64                  `json:"config_version"`
}

type CyberSupplementConfigStore interface {
	Public() (PublicConfig, error)
	SaveCyberSupplementRules(context.Context, int64, []CyberSupplementRule, int64) (PublicConfig, error)
	WithCyberSupplementMutationLock(context.Context, func(context.Context) error) error
}

type PromptCyberAdminService interface {
	ListCyberFeedbackAdmin(context.Context, CyberFeedbackFilter, int, int) (*CyberFeedbackPage, error)
	GetCyberFeedbackAdmin(context.Context, int64) (*CyberFeedbackAdminDetailDTO, error)
	GetCyberFeedbackEvidenceAdmin(context.Context, int64) (*CyberFeedbackEvidenceAdminDTO, error)
	ListCyberRulesAdmin(context.Context) (*CyberRulesPage, error)
	AdoptCyberFeedback(context.Context, int64, AdoptCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error)
	RejectCyberFeedback(context.Context, int64, RejectCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error)
	RevokeCyberRule(context.Context, string, RevokeCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
	RestoreCyberRule(context.Context, string, RestoreCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
	DeleteCyberRule(context.Context, string, DeleteCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
	RegenerateCyberRuleDraft(context.Context, int64, int64) (*CyberFeedbackActionResult, error)
}

func (s *PromptService) cyberFeedbackRepo() (CyberFeedbackRepository, error) {
	if s == nil {
		return nil, cyberFeedbackUnavailableError()
	}
	if s.cyberAdminRepo != nil {
		return s.cyberAdminRepo, nil
	}
	if s.repo == nil {
		return nil, cyberFeedbackUnavailableError()
	}
	repo, ok := any(s.repo).(CyberFeedbackRepository)
	if !ok {
		return nil, cyberFeedbackUnavailableError()
	}
	return repo, nil
}

func (s *PromptService) cyberSupplementConfig() (CyberSupplementConfigStore, error) {
	if s == nil {
		return nil, cyberFeedbackUnavailableError()
	}
	if s.cyberAdminConfig != nil {
		return s.cyberAdminConfig, nil
	}
	if s.config == nil {
		return nil, cyberFeedbackUnavailableError()
	}
	store, ok := s.config.(CyberSupplementConfigStore)
	if !ok {
		return nil, cyberFeedbackUnavailableError()
	}
	return store, nil
}

type cyberSupplementMutationLockKey struct{}

func cyberSupplementMutationLockHeld(ctx context.Context) bool {
	value, _ := ctx.Value(cyberSupplementMutationLockKey{}).(bool)
	return value
}

func (s *PromptService) withCyberSupplementMutationLock(
	ctx context.Context,
	operation func(context.Context) (*CyberFeedbackActionResult, error),
) (*CyberFeedbackActionResult, error) {
	s.cyberAdminMu.Lock()
	defer s.cyberAdminMu.Unlock()
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	var result *CyberFeedbackActionResult
	err = store.WithCyberSupplementMutationLock(ctx, func(locked context.Context) error {
		var operationErr error
		result, operationErr = operation(context.WithValue(locked, cyberSupplementMutationLockKey{}, true))
		return operationErr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *PromptService) ListCyberFeedbackAdmin(ctx context.Context, filter CyberFeedbackFilter, page, pageSize int) (*CyberFeedbackPage, error) {
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	filter.ReviewStatus = strings.TrimSpace(filter.ReviewStatus)
	if filter.ReviewStatus == "" {
		filter.ReviewStatus = CyberReviewPending
	}
	if !validCyberReviewStatus(filter.ReviewStatus) {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_status_invalid", "CYB 反馈状态无效")
	}
	filter.GenerationStatus = strings.TrimSpace(filter.GenerationStatus)
	if filter.GenerationStatus != "" && !validCyberGenerationStatus(filter.GenerationStatus) {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_generation_status_invalid", "CYB 规则草案状态无效")
	}
	items, total, err := repo.ListCyberFeedback(ctx, filter, page, pageSize)
	if err != nil {
		return nil, err
	}
	rules, err := s.ListCyberRulesAdmin(ctx)
	if err != nil {
		return nil, err
	}
	return &CyberFeedbackPage{Items: cyberFeedbackAdminDTOs(items), Total: total, Page: page, PageSize: pageSize, ActiveRules: rules.activeRules, Rules: rules.Items, ConfigVersion: rules.ConfigVersion}, nil
}

func (s *PromptService) GetCyberFeedbackAdmin(ctx context.Context, id int64) (*CyberFeedbackAdminDetailDTO, error) {
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	event, err := repo.GetCyberFeedback(ctx, id)
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		return nil, infraerrors.NotFound(ErrorCodeCyberFeedbackNotFound, "CYB 反馈不存在")
	}
	if err != nil {
		return nil, err
	}
	dto := cyberFeedbackAdminDetailDTO(event)
	return &dto, nil
}

func (s *PromptService) GetCyberFeedbackEvidenceAdmin(ctx context.Context, id int64) (*CyberFeedbackEvidenceAdminDTO, error) {
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	evidence, err := repo.GetCyberFeedbackEvidence(ctx, id)
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		return nil, infraerrors.NotFound(ErrorCodeCyberFeedbackNotFound, "CYB 反馈不存在")
	}
	if err != nil {
		return nil, err
	}
	return &CyberFeedbackEvidenceAdminDTO{
		Available: strings.TrimSpace(evidence.FullPrompt) != "", FullPrompt: evidence.FullPrompt,
		PromptLength: evidence.PromptLength, MessageCount: evidence.MessageCount, Truncated: evidence.FullPromptTruncated,
		UserID: evidence.UserID, Username: evidence.Username, UserEmail: evidence.UserEmail,
		APIKeyID: evidence.APIKeyID, APIKeyName: evidence.APIKeyName, APIKeyPrefix: evidence.APIKeyPrefix,
		GroupID: evidence.GroupID, GroupName: evidence.GroupName,
		SelectedAccountID: evidence.SelectedAccountID, SelectedAccountName: evidence.SelectedAccountName,
		CredentialAccountID: evidence.CredentialAccountID, CredentialAccountName: evidence.CredentialAccountName,
		CredentialAccountEmail:       evidence.CredentialAccountEmail,
		CredentialAccountEmailSource: evidence.CredentialAccountEmailSource, IdentitySource: evidence.IdentitySource,
		ClientRequestID: evidence.ClientRequestID, ClientIP: evidence.ClientIP, UserAgent: evidence.UserAgent,
	}, nil
}

func (s *PromptService) ListCyberRulesAdmin(ctx context.Context) (*CyberRulesPage, error) {
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	projections, err := repo.ListCyberRuleProjections(ctx)
	if err != nil {
		return nil, err
	}
	items := mergeCyberRuleAdminDTOs(config.CyberSupplementRules, projections)
	activeCount := 0
	for _, item := range items {
		if item.Status == CyberRuleLifecycleActive {
			activeCount++
		}
	}
	return &CyberRulesPage{Items: items, ActiveCount: activeCount, ConfigVersion: config.ConfigVersion, activeRules: cloneCyberSupplementRules(config.CyberSupplementRules)}, nil
}

func (s *PromptService) AdoptCyberFeedback(ctx context.Context, id int64, request AdoptCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	if s == nil || id <= 0 || request.ExpectedConfigVersion < 1 {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_adopt_invalid", "CYB 反馈采纳请求无效")
	}
	if !cyberSupplementMutationLockHeld(ctx) {
		return s.withCyberSupplementMutationLock(ctx, func(locked context.Context) (*CyberFeedbackActionResult, error) {
			return s.AdoptCyberFeedback(locked, id, request, actorID)
		})
	}
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	feedback, err := repo.GetCyberFeedback(ctx, id)
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		return nil, infraerrors.NotFound(ErrorCodeCyberFeedbackNotFound, "CYB 反馈不存在")
	}
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	ruleID := DeterministicCyberRuleID(id)
	if existing := findCyberRule(config.CyberSupplementRules, ruleID); existing != nil {
		if feedback.ReviewStatus == CyberReviewPending {
			feedback, err = repo.ReviewCyberFeedback(ctx, id, CyberReviewApproved, actorID, ruleID, existing.ConfigVersion)
			if errors.Is(err, ErrCyberFeedbackReviewConflict) {
				feedback, err = repo.GetCyberFeedback(ctx, id)
			}
			if err != nil {
				return nil, err
			}
		}
		if feedback.ReviewStatus != CyberReviewApproved || strings.TrimSpace(feedback.RuleID) != ruleID {
			return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 反馈状态与已保存规则不一致")
		}
		projection, projectionErr := ensureCyberRuleProjection(ctx, repo, *existing, CyberRuleLifecycleActive, actorID, config.ConfigVersion)
		if projectionErr != nil {
			return nil, projectionErr
		}
		copyRule := activeCyberRuleAdminDTO(*existing, &projection)
		dto := cyberFeedbackAdminDTO(feedback)
		return &CyberFeedbackActionResult{Event: &dto, Rule: &copyRule, ConfigVersion: config.ConfigVersion}, nil
	}
	if config.ConfigVersion != request.ExpectedConfigVersion {
		return nil, infraerrors.Conflict(ErrorCodeConfigConflict, "提示词审计配置已被其他管理员更新")
	}
	if feedback.ReviewStatus != CyberReviewPending {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 反馈已被其他管理员处理")
	}
	ruleText := strings.TrimSpace(request.RuleText)
	if ruleText == "" {
		if feedback.GenerationStatus != CyberGenerationGenerated || strings.TrimSpace(feedback.CandidateRuleText) == "" {
			return nil, infraerrors.BadRequest("prompt_audit_cyber_candidate_unavailable", "CYB 规则草案尚不可用，请编辑规则或重新生成")
		}
		ruleText = feedback.CandidateRuleText
	}
	ruleText, err = ValidateCyberRuleDraftCandidate(ruleText, "", feedback.RedactedPreview)
	if err != nil {
		return nil, err
	}
	now := s.now()
	rule := CyberSupplementRule{
		ID: ruleID, RuleText: ruleText, SourceFeedbackID: id, Status: "active",
		CreatedAt: now, CreatedBy: actorID, ReviewedAt: now, ReviewedBy: actorID,
		ConfigVersion: request.ExpectedConfigVersion + 1,
	}
	nextRules := append(cloneCyberSupplementRules(config.CyberSupplementRules), rule)
	saved, err := store.SaveCyberSupplementRules(ctx, request.ExpectedConfigVersion, nextRules, actorID)
	if err != nil {
		return nil, err
	}
	feedback, err = repo.ReviewCyberFeedback(ctx, id, CyberReviewApproved, actorID, ruleID, saved.ConfigVersion)
	if err != nil {
		// The config mutation is durable. A retry finds the deterministic rule and
		// repairs this review projection without creating a duplicate rule.
		if errors.Is(err, ErrCyberFeedbackReviewConflict) {
			return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 反馈已被其他管理员处理；规则已保存，请刷新确认")
		}
		return nil, err
	}
	rule.ConfigVersion = saved.ConfigVersion
	projection, err := ensureCyberRuleProjection(ctx, repo, rule, CyberRuleLifecycleActive, actorID, saved.ConfigVersion)
	if err != nil {
		return nil, err
	}
	adminRule := activeCyberRuleAdminDTO(rule, &projection)
	dto := cyberFeedbackAdminDTO(feedback)
	return &CyberFeedbackActionResult{Event: &dto, Rule: &adminRule, ConfigVersion: saved.ConfigVersion}, nil
}

func (s *PromptService) RejectCyberFeedback(ctx context.Context, id int64, request RejectCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	if s == nil || id <= 0 || len([]rune(strings.TrimSpace(request.Reason))) > 512 {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_reject_invalid", "CYB 反馈拒绝请求无效")
	}
	if !cyberSupplementMutationLockHeld(ctx) {
		return s.withCyberSupplementMutationLock(ctx, func(locked context.Context) (*CyberFeedbackActionResult, error) {
			return s.RejectCyberFeedback(locked, id, request, actorID)
		})
	}
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	feedback, err := repo.GetCyberFeedback(ctx, id)
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		return nil, infraerrors.NotFound(ErrorCodeCyberFeedbackNotFound, "CYB 反馈不存在")
	}
	if err != nil {
		return nil, err
	}
	if feedback.ReviewStatus == CyberReviewRejected {
		dto := cyberFeedbackAdminDTO(feedback)
		return &CyberFeedbackActionResult{Event: &dto, ConfigVersion: feedback.ConfigVersion}, nil
	}
	if feedback.ReviewStatus != CyberReviewPending {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 反馈已被其他管理员处理")
	}
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	if findCyberRule(config.CyberSupplementRules, DeterministicCyberRuleID(id)) != nil {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "该 CYB 反馈的规则已经保存，不能拒绝")
	}
	feedback, err = repo.ReviewCyberFeedback(ctx, id, CyberReviewRejected, actorID, "", feedback.ConfigVersion)
	if errors.Is(err, ErrCyberFeedbackReviewConflict) {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 反馈已被其他管理员处理")
	}
	if err != nil {
		return nil, err
	}
	dto := cyberFeedbackAdminDTO(feedback)
	return &CyberFeedbackActionResult{Event: &dto, ConfigVersion: feedback.ConfigVersion}, nil
}

func (s *PromptService) RevokeCyberRule(ctx context.Context, id string, request RevokeCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	id = strings.TrimSpace(id)
	if s == nil || !validDeterministicCyberRuleID(id) || request.ExpectedConfigVersion < 1 {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_revoke_invalid", "CYB 规则停用请求无效")
	}
	if !cyberSupplementMutationLockHeld(ctx) {
		return s.withCyberSupplementMutationLock(ctx, func(locked context.Context) (*CyberFeedbackActionResult, error) {
			return s.RevokeCyberRule(locked, id, request, actorID)
		})
	}
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	if config.ConfigVersion != request.ExpectedConfigVersion {
		return nil, infraerrors.Conflict(ErrorCodeConfigConflict, "提示词审计配置已被其他管理员更新")
	}
	index := cyberRuleIndex(config.CyberSupplementRules, id)
	if index < 0 {
		projection, getErr := repo.GetCyberRuleProjection(ctx, cyberRuleFeedbackID(id))
		if errors.Is(getErr, ErrCyberFeedbackNotFound) {
			return &CyberFeedbackActionResult{ConfigVersion: config.ConfigVersion}, nil
		}
		if getErr != nil {
			return nil, getErr
		}
		if projection.LifecycleStatus == CyberRuleLifecycleDeleted {
			return &CyberFeedbackActionResult{ConfigVersion: config.ConfigVersion}, nil
		}
		if projection.LifecycleStatus != CyberRuleLifecycleDisabled || projection.LegacyUnprojected {
			if err := repo.SaveCyberRuleProjection(ctx, projection.FeedbackID, id, projection.RuleText, CyberRuleLifecycleDisabled, projection.RuleTextSource, actorID, config.ConfigVersion); err != nil {
				return nil, err
			}
			projection.LifecycleStatus = CyberRuleLifecycleDisabled
			projection.StateConfigVersion = config.ConfigVersion
		}
		disabled := projectedCyberRuleAdminDTO(projection, CyberRuleLifecycleDisabled)
		return &CyberFeedbackActionResult{Rule: &disabled, ConfigVersion: config.ConfigVersion}, nil
	}
	activeRule := config.CyberSupplementRules[index]
	projection, projectionErr := repo.GetCyberRuleProjection(ctx, activeRule.SourceFeedbackID)
	if projectionErr != nil && !errors.Is(projectionErr, ErrCyberFeedbackNotFound) {
		return nil, projectionErr
	}
	terminalDeleted := projectionErr == nil && projection.LifecycleStatus == CyberRuleLifecycleDeleted
	if !terminalDeleted {
		projection, err = ensureCyberRuleProjection(ctx, repo, activeRule, CyberRuleLifecycleDisabled, actorID, request.ExpectedConfigVersion+1)
		if errors.Is(err, ErrCyberRuleLifecycleConflict) {
			// The exact active config is authoritative after a historical partial
			// adoption or reject race. Reconcile the projection so disabling does
			// not make the rule disappear and remains reversible. The earlier
			// administrator action remains in the audit log.
			projection, err = repo.ReconcileActiveCyberRuleProjection(
				ctx, activeRule, CyberRuleLifecycleDisabled, actorID, request.ExpectedConfigVersion+1,
			)
			if errors.Is(err, ErrCyberRuleLifecycleDeleted) {
				terminalDeleted = true
			} else if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	nextRules := cloneCyberSupplementRules(config.CyberSupplementRules)
	nextRules = append(nextRules[:index], nextRules[index+1:]...)
	saved, err := store.SaveCyberSupplementRules(ctx, request.ExpectedConfigVersion, nextRules, actorID)
	if err != nil {
		return nil, err
	}
	if terminalDeleted {
		deleted := projectedCyberRuleAdminDTO(projection, CyberRuleLifecycleDeleted)
		deleted.RuleText = ""
		deleted.RuleTextSource = ""
		deleted.RecoveredCandidate = false
		deleted.ConfigVersion = saved.ConfigVersion
		return &CyberFeedbackActionResult{Rule: &deleted, ConfigVersion: saved.ConfigVersion}, nil
	}
	projection.LifecycleStatus = CyberRuleLifecycleDisabled
	projection.StateConfigVersion = saved.ConfigVersion
	disabled := projectedCyberRuleAdminDTO(projection, CyberRuleLifecycleDisabled)
	disabled.ConfigVersion = saved.ConfigVersion
	return &CyberFeedbackActionResult{Rule: &disabled, ConfigVersion: saved.ConfigVersion}, nil
}

func (s *PromptService) RestoreCyberRule(ctx context.Context, id string, request RestoreCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	id = strings.TrimSpace(id)
	if s == nil || !validDeterministicCyberRuleID(id) || request.ExpectedConfigVersion < 1 {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_restore_invalid", "CYB 规则恢复请求无效")
	}
	if !cyberSupplementMutationLockHeld(ctx) {
		return s.withCyberSupplementMutationLock(ctx, func(locked context.Context) (*CyberFeedbackActionResult, error) {
			return s.RestoreCyberRule(locked, id, request, actorID)
		})
	}
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	if config.ConfigVersion != request.ExpectedConfigVersion {
		return nil, infraerrors.Conflict(ErrorCodeConfigConflict, "提示词审计配置已被其他管理员更新")
	}
	if existing := findCyberRule(config.CyberSupplementRules, id); existing != nil {
		projection, projectionErr := ensureCyberRuleProjection(ctx, repo, *existing, CyberRuleLifecycleActive, actorID, config.ConfigVersion)
		if projectionErr != nil {
			return nil, projectionErr
		}
		active := activeCyberRuleAdminDTO(*existing, &projection)
		return &CyberFeedbackActionResult{Rule: &active, ConfigVersion: config.ConfigVersion}, nil
	}
	projection, err := repo.GetCyberRuleProjection(ctx, cyberRuleFeedbackID(id))
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		return nil, infraerrors.NotFound(ErrorCodeCyberFeedbackNotFound, "CYB 规则不存在")
	}
	if err != nil {
		return nil, err
	}
	if projection.RuleID != id || projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 规则已被永久删除，不能恢复")
	}
	ruleText := strings.TrimSpace(projection.RuleText)
	if ruleText == "" || projection.RuleTextSource == CyberRuleTextSourceUnavailable {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "该历史规则没有可证明的规则文本，无法恢复")
	}
	createdAt := projection.CreatedAt
	createdBy := actorID
	reviewedAt := s.now()
	reviewedBy := actorID
	if projection.ReviewedAt != nil {
		createdAt = *projection.ReviewedAt
		reviewedAt = *projection.ReviewedAt
	}
	if projection.ReviewedBy != nil && *projection.ReviewedBy > 0 {
		createdBy = *projection.ReviewedBy
		reviewedBy = *projection.ReviewedBy
	}
	rule := CyberSupplementRule{
		ID: id, RuleText: ruleText, SourceFeedbackID: projection.FeedbackID, Status: CyberRuleLifecycleActive,
		CreatedAt: createdAt, CreatedBy: createdBy, ReviewedAt: reviewedAt, ReviewedBy: reviewedBy,
		ConfigVersion: request.ExpectedConfigVersion + 1,
	}
	nextRules := append(cloneCyberSupplementRules(config.CyberSupplementRules), rule)
	saved, err := store.SaveCyberSupplementRules(ctx, request.ExpectedConfigVersion, nextRules, actorID)
	if err != nil {
		return nil, err
	}
	rule.ConfigVersion = saved.ConfigVersion
	if err := repo.SaveCyberRuleProjection(ctx, projection.FeedbackID, id, ruleText, CyberRuleLifecycleActive, projection.RuleTextSource, actorID, saved.ConfigVersion); err != nil {
		return nil, err
	}
	projection.LifecycleStatus = CyberRuleLifecycleActive
	projection.StateConfigVersion = saved.ConfigVersion
	active := activeCyberRuleAdminDTO(rule, &projection)
	return &CyberFeedbackActionResult{Rule: &active, ConfigVersion: saved.ConfigVersion}, nil
}

func (s *PromptService) DeleteCyberRule(ctx context.Context, id string, request DeleteCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	id = strings.TrimSpace(id)
	if s == nil || !validDeterministicCyberRuleID(id) || request.ExpectedConfigVersion < 1 || strings.TrimSpace(request.ConfirmRuleID) != id {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_delete_confirmation_invalid", "必须输入完整规则 ID 确认永久删除")
	}
	if !cyberSupplementMutationLockHeld(ctx) {
		return s.withCyberSupplementMutationLock(ctx, func(locked context.Context) (*CyberFeedbackActionResult, error) {
			return s.DeleteCyberRule(locked, id, request, actorID)
		})
	}
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	if config.ConfigVersion != request.ExpectedConfigVersion {
		return nil, infraerrors.Conflict(ErrorCodeConfigConflict, "提示词审计配置已被其他管理员更新")
	}
	if findCyberRule(config.CyberSupplementRules, id) != nil {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "生效中的 CYB 规则必须先停用才能永久删除")
	}
	projection, err := repo.GetCyberRuleProjection(ctx, cyberRuleFeedbackID(id))
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		return &CyberFeedbackActionResult{ConfigVersion: config.ConfigVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	if projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return &CyberFeedbackActionResult{ConfigVersion: config.ConfigVersion}, nil
	}
	if projection.RuleID != id {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 规则状态与来源反馈不一致")
	}
	if projection.LifecycleStatus != CyberRuleLifecycleDisabled || projection.LegacyUnprojected {
		// Config membership is authoritative. Repair a stale non-deleted
		// projection before deletion so a crash after config removal cannot make
		// the visible disabled rule impossible to delete.
		if err := repo.SaveCyberRuleProjection(ctx, projection.FeedbackID, id, projection.RuleText, CyberRuleLifecycleDisabled, projection.RuleTextSource, actorID, config.ConfigVersion); err != nil {
			return nil, err
		}
		projection.LifecycleStatus = CyberRuleLifecycleDisabled
	}
	// Saving the unchanged active set establishes an authoritative config CAS
	// boundary against a concurrent restore on another process.
	saved, err := store.SaveCyberSupplementRules(ctx, request.ExpectedConfigVersion, cloneCyberSupplementRules(config.CyberSupplementRules), actorID)
	if err != nil {
		return nil, err
	}
	if err := repo.DeleteCyberRuleProjection(ctx, projection.FeedbackID, id, actorID, saved.ConfigVersion); err != nil {
		return nil, err
	}
	deleted := projectedCyberRuleAdminDTO(projection, CyberRuleLifecycleDeleted)
	deleted.RuleText = ""
	deleted.RuleTextSource = ""
	deleted.RecoveredCandidate = false
	deleted.ConfigVersion = saved.ConfigVersion
	return &CyberFeedbackActionResult{Rule: &deleted, ConfigVersion: saved.ConfigVersion}, nil
}

func validDeterministicCyberRuleID(value string) bool {
	const prefix = "cyb-feedback-"
	if !strings.HasPrefix(value, prefix) || len(value) > 64 {
		return false
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(value, prefix), 10, 64)
	return err == nil && id > 0 && value == DeterministicCyberRuleID(id)
}

func (s *PromptService) RegenerateCyberRuleDraft(ctx context.Context, id int64, _ int64) (*CyberFeedbackActionResult, error) {
	if id <= 0 || s == nil {
		return nil, cyberFeedbackUnavailableError()
	}
	s.cyberAdminMu.Lock()
	defer s.cyberAdminMu.Unlock()
	repo, err := s.cyberFeedbackRepo()
	if err != nil {
		return nil, err
	}
	feedback, err := repo.GetCyberFeedback(ctx, id)
	if err != nil {
		return nil, err
	}
	if feedback.ReviewStatus != CyberReviewPending {
		return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 反馈已被其他管理员处理")
	}
	evidence, err := repo.GetCyberFeedbackEvidence(ctx, id)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(evidence.FullPrompt) == "" {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_evidence_unavailable", "该历史 CYB 反馈未保存准确触发正文，无法可靠重新生成规则草案")
	}
	if err := repo.ResetCyberRuleGeneration(ctx, id); err != nil {
		if errors.Is(err, ErrCyberFeedbackGenerationConflict) {
			return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 规则草案正在生成或反馈状态已变化")
		}
		return nil, err
	}
	snapshot := PromptSnapshot{
		RequestID: feedback.RequestID, GroupID: &feedback.GroupID, Provider: "openai",
		Endpoint: feedback.Endpoint, Protocol: feedback.Protocol, Model: feedback.Model,
		RedactedPreview: feedback.RedactedPreview, ScanText: evidence.FullPrompt, FullPrompt: evidence.FullPrompt,
	}
	candidate, err := s.GenerateCyberRuleDraft(ctx, snapshot)
	errorCode := ""
	if err != nil {
		errorCode = cyberGenerationErrorCode(err)
		candidate = ""
	}
	if updateErr := repo.CompleteCyberRuleGeneration(ctx, id, candidate, errorCode); updateErr != nil {
		return nil, updateErr
	}
	feedback, err = repo.GetCyberFeedback(ctx, id)
	if err != nil {
		return nil, err
	}
	dto := cyberFeedbackAdminDTO(feedback)
	return &CyberFeedbackActionResult{Event: &dto, ConfigVersion: feedback.ConfigVersion}, nil
}

func findCyberRule(rules []CyberSupplementRule, id string) *CyberSupplementRule {
	for i := range rules {
		if rules[i].ID == id {
			copyRule := rules[i]
			return &copyRule
		}
	}
	return nil
}

func cyberRuleIndex(rules []CyberSupplementRule, id string) int {
	for i := range rules {
		if rules[i].ID == id {
			return i
		}
	}
	return -1
}

func cyberRuleFeedbackID(id string) int64 {
	value, _ := strconv.ParseInt(strings.TrimPrefix(id, "cyb-feedback-"), 10, 64)
	return value
}

func ensureCyberRuleProjection(
	ctx context.Context,
	repo CyberFeedbackRepository,
	rule CyberSupplementRule,
	status string,
	actorID, configVersion int64,
) (CyberRuleProjection, error) {
	projection, err := repo.GetCyberRuleProjection(ctx, rule.SourceFeedbackID)
	if err != nil && !errors.Is(err, ErrCyberFeedbackNotFound) {
		return CyberRuleProjection{}, err
	}
	if errors.Is(err, ErrCyberFeedbackNotFound) {
		feedback, feedbackErr := repo.GetCyberFeedback(ctx, rule.SourceFeedbackID)
		if feedbackErr != nil {
			return CyberRuleProjection{}, feedbackErr
		}
		if feedback.ReviewStatus == CyberReviewPending && strings.TrimSpace(feedback.RuleID) == "" {
			feedback, feedbackErr = repo.ReviewCyberFeedback(
				ctx, rule.SourceFeedbackID, CyberReviewApproved, actorID, rule.ID, configVersion,
			)
			if errors.Is(feedbackErr, ErrCyberFeedbackReviewConflict) {
				feedback, feedbackErr = repo.GetCyberFeedback(ctx, rule.SourceFeedbackID)
			}
			if feedbackErr != nil {
				return CyberRuleProjection{}, feedbackErr
			}
		}
		if feedback.ReviewStatus != CyberReviewApproved || strings.TrimSpace(feedback.RuleID) != rule.ID {
			return CyberRuleProjection{}, ErrCyberRuleLifecycleConflict
		}
		projection, err = repo.GetCyberRuleProjection(ctx, rule.SourceFeedbackID)
		if err != nil {
			return CyberRuleProjection{}, err
		}
	}
	if projection.RuleID != rule.ID || projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return CyberRuleProjection{}, ErrCyberRuleLifecycleConflict
	}
	source := strings.TrimSpace(projection.RuleTextSource)
	if projection.LegacyUnprojected || source == "" || source == CyberRuleTextSourceUnavailable {
		source = CyberRuleTextSourceReviewed
	}
	if err := repo.SaveCyberRuleProjection(ctx, rule.SourceFeedbackID, rule.ID, rule.RuleText, status, source, actorID, configVersion); err != nil {
		return CyberRuleProjection{}, err
	}
	projection.RuleID = rule.ID
	projection.RuleText = rule.RuleText
	projection.LifecycleStatus = status
	projection.RuleTextSource = source
	projection.StateConfigVersion = configVersion
	return projection, nil
}

func mergeCyberRuleAdminDTOs(activeRules []CyberSupplementRule, projections []CyberRuleProjection) []CyberRuleAdminDTO {
	projectionByFeedbackID := make(map[int64]CyberRuleProjection, len(projections))
	for _, projection := range projections {
		projectionByFeedbackID[projection.FeedbackID] = projection
	}
	result := make([]CyberRuleAdminDTO, 0, len(activeRules)+len(projections))
	consumedFeedbackIDs := make(map[int64]struct{}, len(activeRules))
	for _, rule := range activeRules {
		projection, ok := projectionByFeedbackID[rule.SourceFeedbackID]
		if !ok {
			projection = CyberRuleProjection{FeedbackID: rule.SourceFeedbackID, RuleID: rule.ID, RuleTextSource: CyberRuleTextSourceReviewed}
		} else {
			// Source feedback identity is authoritative for an active config rule.
			// Consume even a stale/wrong projection ID so it cannot also appear as
			// an unmanageable disabled ghost rule.
			consumedFeedbackIDs[rule.SourceFeedbackID] = struct{}{}
		}
		result = append(result, activeCyberRuleAdminDTO(rule, &projection))
	}
	for _, projection := range projections {
		if _, consumed := consumedFeedbackIDs[projection.FeedbackID]; consumed || projection.LifecycleStatus == CyberRuleLifecycleDeleted {
			continue
		}
		if projection.RuleID != DeterministicCyberRuleID(projection.FeedbackID) {
			// A non-active projection with a non-canonical ID cannot be addressed
			// safely by the lifecycle endpoints. Hide it until an authoritative
			// active config transition reconciles the row.
			continue
		}
		// Runtime config membership is authoritative. A staged projection left by
		// a failed config CAS is therefore displayed as disabled, never active.
		result = append(result, projectedCyberRuleAdminDTO(projection, CyberRuleLifecycleDisabled))
	}
	return result
}

func activeCyberRuleAdminDTO(rule CyberSupplementRule, projection *CyberRuleProjection) CyberRuleAdminDTO {
	reviewedAt := rule.ReviewedAt
	reviewedBy := rule.ReviewedBy
	result := CyberRuleAdminDTO{
		ID: rule.ID, RuleText: rule.RuleText, SourceFeedbackID: rule.SourceFeedbackID,
		Status: CyberRuleLifecycleActive, RuleTextSource: CyberRuleTextSourceReviewed,
		CreatedAt: rule.CreatedAt, CreatedBy: rule.CreatedBy, ReviewedAt: &reviewedAt, ReviewedBy: &reviewedBy,
		ConfigVersion: rule.ConfigVersion,
	}
	if projection != nil {
		if source := strings.TrimSpace(projection.RuleTextSource); source != "" && !projection.LegacyUnprojected {
			result.RuleTextSource = source
		}
		result.StateUpdatedAt = projection.StateUpdatedAt
		result.StateUpdatedBy = projection.StateUpdatedBy
	}
	result.RecoveredCandidate = result.RuleTextSource == CyberRuleTextSourceRecoveredCandidate
	return result
}

func projectedCyberRuleAdminDTO(projection CyberRuleProjection, status string) CyberRuleAdminDTO {
	createdAt := projection.CreatedAt
	createdBy := int64(0)
	if projection.ReviewedAt != nil {
		createdAt = *projection.ReviewedAt
	}
	if projection.ReviewedBy != nil {
		createdBy = *projection.ReviewedBy
	}
	return CyberRuleAdminDTO{
		ID: projection.RuleID, RuleText: projection.RuleText, SourceFeedbackID: projection.FeedbackID,
		Status: status, RuleTextSource: projection.RuleTextSource,
		RecoveredCandidate: projection.RuleTextSource == CyberRuleTextSourceRecoveredCandidate,
		CreatedAt:          createdAt, CreatedBy: createdBy, ReviewedAt: projection.ReviewedAt, ReviewedBy: projection.ReviewedBy,
		StateUpdatedAt: projection.StateUpdatedAt, StateUpdatedBy: projection.StateUpdatedBy,
		ConfigVersion: projection.StateConfigVersion,
	}
}

func cyberFeedbackAdminDTO(value CyberFeedback) CyberFeedbackAdminDTO {
	var ruleID *string
	if trimmed := strings.TrimSpace(value.RuleID); trimmed != "" {
		ruleID = &trimmed
	}
	return CyberFeedbackAdminDTO{
		ID: value.ID, RequestID: value.RequestID, TurnNumber: value.TurnNumber,
		GroupID: value.GroupID, AccountID: value.AccountID, Model: value.Model,
		Endpoint: value.Endpoint, Protocol: value.Protocol, Transport: value.Transport,
		Stage: value.Stage, UpstreamStatus: value.UpstreamStatus,
		RedactedPreview: value.RedactedPreview, ConfirmCount: value.SignatureConfirmCount,
		FirstConfirmedAt: value.FirstConfirmedAt, LastConfirmedAt: value.LastConfirmedAt,
		GenerationStatus: value.GenerationStatus, GenerationErrorCode: value.GenerationErrorCode,
		CandidateRuleText: value.CandidateRuleText, Status: value.ReviewStatus,
		ReviewedBy: value.ReviewedBy, ReviewedAt: value.ReviewedAt, RuleID: ruleID,
		ConfigVersion: value.ConfigVersion, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}
}

func cyberFeedbackAdminDetailDTO(value CyberFeedback) CyberFeedbackAdminDetailDTO {
	return CyberFeedbackAdminDetailDTO{
		CyberFeedbackAdminDTO: cyberFeedbackAdminDTO(value),
		AccountName:           value.AccountNameSnapshot, CredentialAccountID: value.CredentialAccountID,
		CredentialAccountName: value.CredentialAccountName, PromptLength: value.PromptLength,
		MessageCount: value.MessageCount, FullPromptTruncated: value.FullPromptTruncated,
		UpstreamCode: value.UpstreamCode, UpstreamMessage: value.UpstreamMessage,
	}
}

func cyberFeedbackAdminDTOs(values []CyberFeedback) []CyberFeedbackAdminDTO {
	result := make([]CyberFeedbackAdminDTO, 0, len(values))
	for _, value := range values {
		result = append(result, cyberFeedbackAdminDTO(value))
	}
	return result
}

func validCyberReviewStatus(value string) bool {
	switch value {
	case CyberReviewPending, CyberReviewApproved, CyberReviewRejected:
		return true
	default:
		return false
	}
}

func validCyberGenerationStatus(value string) bool {
	switch value {
	case CyberGenerationPending, CyberGenerationGenerated, CyberGenerationFailed:
		return true
	default:
		return false
	}
}

func cyberFeedbackUnavailableError() error {
	return infraerrors.ServiceUnavailable(ErrorCodeCyberFeedbackUnavailable, "CYB 反馈服务暂不可用")
}

var _ PromptCyberAdminService = (*PromptService)(nil)
