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

type CyberRulesPage struct {
	Items         []CyberSupplementRule `json:"items"`
	ConfigVersion int64                 `json:"config_version"`
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

type CyberFeedbackActionResult struct {
	Event         *CyberFeedbackAdminDTO `json:"event,omitempty"`
	Rule          *CyberSupplementRule   `json:"rule,omitempty"`
	ConfigVersion int64                  `json:"config_version"`
}

type CyberSupplementConfigStore interface {
	Public() (PublicConfig, error)
	SaveCyberSupplementRules(context.Context, int64, []CyberSupplementRule, int64) (PublicConfig, error)
}

type PromptCyberAdminService interface {
	ListCyberFeedbackAdmin(context.Context, CyberFeedbackFilter, int, int) (*CyberFeedbackPage, error)
	GetCyberFeedbackAdmin(context.Context, int64) (*CyberFeedbackAdminDTO, error)
	ListCyberRulesAdmin(context.Context) (*CyberRulesPage, error)
	AdoptCyberFeedback(context.Context, int64, AdoptCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error)
	RejectCyberFeedback(context.Context, int64, RejectCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error)
	RevokeCyberRule(context.Context, string, RevokeCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
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
	return &CyberFeedbackPage{Items: cyberFeedbackAdminDTOs(items), Total: total, Page: page, PageSize: pageSize, ActiveRules: rules.Items, ConfigVersion: rules.ConfigVersion}, nil
}

func (s *PromptService) GetCyberFeedbackAdmin(ctx context.Context, id int64) (*CyberFeedbackAdminDTO, error) {
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
	dto := cyberFeedbackAdminDTO(event)
	return &dto, nil
}

func (s *PromptService) ListCyberRulesAdmin(_ context.Context) (*CyberRulesPage, error) {
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	return &CyberRulesPage{Items: cloneCyberSupplementRules(config.CyberSupplementRules), ConfigVersion: config.ConfigVersion}, nil
}

func (s *PromptService) AdoptCyberFeedback(ctx context.Context, id int64, request AdoptCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	if s == nil || id <= 0 || request.ExpectedConfigVersion < 1 {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_adopt_invalid", "CYB 反馈采纳请求无效")
	}
	s.cyberAdminMu.Lock()
	defer s.cyberAdminMu.Unlock()
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
		copyRule := *existing
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
	dto := cyberFeedbackAdminDTO(feedback)
	return &CyberFeedbackActionResult{Event: &dto, Rule: &rule, ConfigVersion: saved.ConfigVersion}, nil
}

func (s *PromptService) RejectCyberFeedback(ctx context.Context, id int64, request RejectCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	if s == nil || id <= 0 || len([]rune(strings.TrimSpace(request.Reason))) > 512 {
		return nil, infraerrors.BadRequest("prompt_audit_cyber_reject_invalid", "CYB 反馈拒绝请求无效")
	}
	s.cyberAdminMu.Lock()
	defer s.cyberAdminMu.Unlock()
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
		return nil, infraerrors.BadRequest("prompt_audit_cyber_revoke_invalid", "CYB 规则撤销请求无效")
	}
	s.cyberAdminMu.Lock()
	defer s.cyberAdminMu.Unlock()
	store, err := s.cyberSupplementConfig()
	if err != nil {
		return nil, err
	}
	config, err := store.Public()
	if err != nil {
		return nil, err
	}
	index := -1
	for i := range config.CyberSupplementRules {
		if config.CyberSupplementRules[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return &CyberFeedbackActionResult{ConfigVersion: config.ConfigVersion}, nil
	}
	if config.ConfigVersion != request.ExpectedConfigVersion {
		return nil, infraerrors.Conflict(ErrorCodeConfigConflict, "提示词审计配置已被其他管理员更新")
	}
	revoked := config.CyberSupplementRules[index]
	nextRules := cloneCyberSupplementRules(config.CyberSupplementRules)
	nextRules = append(nextRules[:index], nextRules[index+1:]...)
	saved, err := store.SaveCyberSupplementRules(ctx, request.ExpectedConfigVersion, nextRules, actorID)
	if err != nil {
		return nil, err
	}
	revoked.Status = "revoked"
	revoked.ConfigVersion = saved.ConfigVersion
	return &CyberFeedbackActionResult{Rule: &revoked, ConfigVersion: saved.ConfigVersion}, nil
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
	if err := repo.ResetCyberRuleGeneration(ctx, id); err != nil {
		if errors.Is(err, ErrCyberFeedbackGenerationConflict) {
			return nil, infraerrors.Conflict(ErrorCodeCyberFeedbackConflict, "CYB 规则草案正在生成或反馈状态已变化")
		}
		return nil, err
	}
	snapshot := PromptSnapshot{
		RequestID: feedback.RequestID, GroupID: &feedback.GroupID, Provider: "openai",
		Endpoint: feedback.Endpoint, Protocol: feedback.Protocol, Model: feedback.Model,
		RedactedPreview: feedback.RedactedPreview, ScanText: feedback.RedactedPreview,
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
