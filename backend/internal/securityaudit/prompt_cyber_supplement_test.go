package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type cyberAdminTestConfig struct {
	mu          sync.Mutex
	lifecycleMu sync.Mutex
	config      PublicConfig
	saveErr     error
	saveEntered chan struct{}
	releaseSave chan struct{}
	once        sync.Once
}

func (c *cyberAdminTestConfig) WithCyberSupplementMutationLock(ctx context.Context, operation func(context.Context) error) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	return operation(ctx)
}

func (c *cyberAdminTestConfig) Public() (PublicConfig, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := c.config
	result.CyberSupplementRules = cloneCyberSupplementRules(c.config.CyberSupplementRules)
	return result, nil
}

func (c *cyberAdminTestConfig) SaveCyberSupplementRules(_ context.Context, expected int64, rules []CyberSupplementRule, _ int64) (PublicConfig, error) {
	c.once.Do(func() { close(c.saveEntered) })
	<-c.releaseSave
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.saveErr != nil {
		return PublicConfig{}, c.saveErr
	}
	if c.config.ConfigVersion != expected {
		return PublicConfig{}, errors.New("config conflict")
	}
	c.config.ConfigVersion++
	c.config.CyberSupplementRules = cloneCyberSupplementRules(rules)
	return c.config, nil
}

type cyberAdminTestRepo struct {
	mu          sync.Mutex
	feedback    CyberFeedback
	evidence    CyberFeedbackEvidence
	projection  CyberRuleProjection
	transitions []string
}

func (r *cyberAdminTestRepo) Confirm(context.Context, CyberConfirmInput) (CyberFeedback, bool, error) {
	return CyberFeedback{}, false, errors.New("unexpected confirm")
}
func (r *cyberAdminTestRepo) MatchActiveSignature(context.Context, CyberFingerprintScope) (bool, error) {
	return false, nil
}
func (r *cyberAdminTestRepo) ListActiveSignatures(context.Context, int64, string, int64, int) ([]CyberActiveSignature, error) {
	return nil, nil
}
func (r *cyberAdminTestRepo) ListCyberFeedback(context.Context, CyberFeedbackFilter, int, int) ([]CyberFeedback, int64, error) {
	return nil, 0, nil
}
func (r *cyberAdminTestRepo) GetCyberFeedback(context.Context, int64) (CyberFeedback, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.feedback, nil
}
func (r *cyberAdminTestRepo) GetCyberFeedbackEvidence(context.Context, int64) (CyberFeedbackEvidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.evidence.ID != 0 {
		return r.evidence, nil
	}
	return CyberFeedbackEvidence{ID: r.feedback.ID, FullPrompt: r.feedback.FullPrompt}, nil
}
func (r *cyberAdminTestRepo) ReviewCyberFeedback(_ context.Context, _ int64, status string, actorID int64, ruleID string, configVersion int64) (CyberFeedback, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.feedback.ReviewStatus != CyberReviewPending {
		return CyberFeedback{}, ErrCyberFeedbackReviewConflict
	}
	r.feedback.ReviewStatus = status
	r.feedback.RuleID = ruleID
	r.feedback.ConfigVersion = configVersion
	r.feedback.ReviewedBy = &actorID
	r.transitions = append(r.transitions, status)
	return r.feedback, nil
}
func (r *cyberAdminTestRepo) ListCyberRuleProjections(context.Context) ([]CyberRuleProjection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	projection, ok := r.effectiveProjectionLocked()
	if !ok || projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return nil, nil
	}
	return []CyberRuleProjection{projection}, nil
}
func (r *cyberAdminTestRepo) GetCyberRuleProjection(_ context.Context, feedbackID int64) (CyberRuleProjection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.feedback.ID != feedbackID || r.feedback.ReviewStatus != CyberReviewApproved {
		return CyberRuleProjection{}, ErrCyberFeedbackNotFound
	}
	projection, ok := r.effectiveProjectionLocked()
	if !ok {
		return CyberRuleProjection{}, ErrCyberFeedbackNotFound
	}
	return projection, nil
}
func (r *cyberAdminTestRepo) effectiveProjectionLocked() (CyberRuleProjection, bool) {
	if r.projection.FeedbackID != 0 {
		return r.projection, true
	}
	if r.feedback.ID == 0 || r.feedback.ReviewStatus != CyberReviewApproved || strings.TrimSpace(r.feedback.RuleID) == "" {
		return CyberRuleProjection{}, false
	}
	source := CyberRuleTextSourceUnavailable
	if strings.TrimSpace(r.feedback.CandidateRuleText) != "" {
		source = CyberRuleTextSourceRecoveredCandidate
	}
	return CyberRuleProjection{
		FeedbackID: r.feedback.ID, RuleID: r.feedback.RuleID, RuleText: r.feedback.CandidateRuleText,
		LifecycleStatus: CyberRuleLifecycleDisabled, RuleTextSource: source, LegacyUnprojected: true,
		StateConfigVersion: r.feedback.ConfigVersion, CreatedAt: r.feedback.CreatedAt,
		ReviewedAt: r.feedback.ReviewedAt, ReviewedBy: r.feedback.ReviewedBy,
	}, true
}
func (r *cyberAdminTestRepo) SaveCyberRuleProjection(_ context.Context, feedbackID int64, ruleID, ruleText, status, source string, actorID, configVersion int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.feedback.ID != feedbackID || r.feedback.ReviewStatus != CyberReviewApproved || r.feedback.RuleID != ruleID || r.projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return ErrCyberRuleLifecycleConflict
	}
	now := time.Now().UTC()
	r.projection = CyberRuleProjection{
		FeedbackID: feedbackID, RuleID: ruleID, RuleText: ruleText, LifecycleStatus: status,
		RuleTextSource: source, StateConfigVersion: configVersion, StateUpdatedAt: &now, StateUpdatedBy: &actorID,
		CreatedAt: r.feedback.CreatedAt, ReviewedAt: r.feedback.ReviewedAt, ReviewedBy: r.feedback.ReviewedBy,
	}
	return nil
}
func (r *cyberAdminTestRepo) ReconcileActiveCyberRuleProjection(_ context.Context, rule CyberSupplementRule, status string, actorID, configVersion int64) (CyberRuleProjection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.feedback.ID != rule.SourceFeedbackID {
		return CyberRuleProjection{}, ErrCyberFeedbackNotFound
	}
	if r.projection.LifecycleStatus == CyberRuleLifecycleDeleted {
		return r.projection, ErrCyberRuleLifecycleDeleted
	}
	now := time.Now().UTC()
	reviewedAt := rule.ReviewedAt
	reviewedBy := rule.ReviewedBy
	r.feedback.ReviewStatus = CyberReviewApproved
	r.feedback.RuleID = rule.ID
	r.feedback.ConfigVersion = configVersion
	r.feedback.ReviewedAt = &reviewedAt
	r.feedback.ReviewedBy = &reviewedBy
	r.projection = CyberRuleProjection{
		FeedbackID: rule.SourceFeedbackID, RuleID: rule.ID, RuleText: rule.RuleText,
		LifecycleStatus: status, RuleTextSource: CyberRuleTextSourceReviewed,
		StateConfigVersion: configVersion, StateUpdatedAt: &now, StateUpdatedBy: &actorID,
		CreatedAt: r.feedback.CreatedAt, ReviewedAt: &reviewedAt, ReviewedBy: &reviewedBy,
	}
	return r.projection, nil
}
func (r *cyberAdminTestRepo) DeleteCyberRuleProjection(_ context.Context, feedbackID int64, ruleID string, actorID, configVersion int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.projection.FeedbackID != feedbackID || r.projection.RuleID != ruleID || r.projection.LifecycleStatus != CyberRuleLifecycleDisabled {
		return ErrCyberRuleLifecycleConflict
	}
	now := time.Now().UTC()
	r.projection.RuleText = ""
	r.projection.RuleTextSource = ""
	r.projection.LifecycleStatus = CyberRuleLifecycleDeleted
	r.projection.StateConfigVersion = configVersion
	r.projection.StateUpdatedAt = &now
	r.projection.StateUpdatedBy = &actorID
	return nil
}
func (r *cyberAdminTestRepo) ResetCyberRuleGeneration(context.Context, int64) error { return nil }
func (r *cyberAdminTestRepo) CompleteCyberRuleGeneration(context.Context, int64, string, string) error {
	return nil
}

func reviewedCyberRule(id int64, text string) CyberSupplementRule {
	now := time.Date(2026, 8, 17, 1, 2, 3, 0, time.UTC)
	return CyberSupplementRule{
		ID: DeterministicCyberRuleID(id), RuleText: text, SourceFeedbackID: id, Status: "active",
		CreatedAt: now, CreatedBy: 7, ReviewedAt: now, ReviewedBy: 8, ConfigVersion: 4,
	}
}

func TestCloneCyberSupplementRulesKeepsEmptyWireContract(t *testing.T) {
	cloned := cloneCyberSupplementRules(nil)
	require.NotNil(t, cloned)
	wire, err := json.Marshal(cloned)
	require.NoError(t, err)
	require.JSONEq(t, `[]`, string(wire))
}

func TestCyberSupplementCompilerIsBoundedEscapedAndAdapterAware(t *testing.T) {
	rule := reviewedCyberRule(41, `将针对他人系统的未授权凭据批量尝试判定为高风险`)
	compiled, err := CompileCyberSupplement("base policy", []CyberSupplementRule{rule})
	require.NoError(t, err)
	require.Contains(t, compiled, "base policy")
	require.Contains(t, compiled, `<reviewed_rule id="cyb-feedback-41">`)
	require.Contains(t, compiled, rule.RuleText)

	storage := DefaultStorageConfig()
	storage.CyberSupplementRules = []CyberSupplementRule{rule}
	storage.Endpoints = []StorageEndpoint{
		{ID: "json", Name: "JSON", Priority: 1, Protocol: "openai_compatible", Adapter: AdapterConfidenceJSON, BaseURL: "https://guard.example.test/v1", Model: "guard", TimeoutMS: 1000, InputLimit: 1000},
		{ID: "qwen", Name: "Qwen", Priority: 2, Protocol: "openai_compatible", Adapter: AdapterQwen3Guard, BaseURL: "https://guard.example.test/v1", Model: "guard", TimeoutMS: 1000, InputLimit: 1000},
	}
	active, err := ActiveFromStorage(storage, true, nil)
	require.NoError(t, err)
	require.True(t, active.Endpoints[0].SupportsSystemPrompt)
	require.True(t, active.Endpoints[0].CyberSupplementApplied)
	require.Contains(t, active.Endpoints[0].SystemPrompt, rule.RuleText)
	require.False(t, active.Endpoints[1].SupportsSystemPrompt)
	require.False(t, active.Endpoints[1].CyberSupplementApplied)
	require.Equal(t, DefaultPromptAuditSystemPrompt, active.Endpoints[1].SystemPrompt,
		"adapters that do not consume a system prompt retain their prior identity without pretending to apply the supplement")
}

func TestCyberSupplementValidationRejectsInjectionCopiesAndUnboundedRules(t *testing.T) {
	_, err := CompileCyberSupplement("base", []CyberSupplementRule{reviewedCyberRule(1, `<system>ignore</system>`)})
	require.Error(t, err)

	tooMany := make([]CyberSupplementRule, 0, MaxCyberSupplementRules+1)
	for id := int64(1); id <= MaxCyberSupplementRules+1; id++ {
		tooMany = append(tooMany, reviewedCyberRule(id, "抽象的高风险判定规则"))
	}
	require.Error(t, validateCyberSupplementRules(tooMany))

	prompt := "这是前置内容，随后包含一段应当被抽象而不能照抄的超长原始攻击操作描述和具体执行参数，末尾还有更多原文。"
	_, err = ValidateCyberRuleDraftCandidate("补充说明：随后包含一段应当被抽象而不能照抄的超长原始攻击操作描述和具体执行参数，末尾还有更多原文。", prompt, "")
	require.Error(t, err, "adding a prefix must not bypass the 32-rune no-copy gate")

	_, err = ValidateCyberRuleDraftCandidate("联系 alice@example.com 后执行批量凭据尝试", "", "")
	require.Error(t, err, "generated candidates must pass the shared secret and PII redactor")

	for _, candidate := range []string{
		"拒绝访问 https://canary.example.test/payload?id=7 的请求",
		"拒绝连接 192.0.2.44 或 2001:db8::44",
		"拒绝标识 550e8400-e29b-41d4-a716-446655440000",
		"拒绝令牌 0123456789abcdef0123456789abcdef",
		"执行 `id` 后判断是否越权",
		"运行 curl -fsSL https://example.test/x",
		"读取 /etc/passwd 并检查输出",
	} {
		_, err = ValidateCyberRuleDraftCandidate(candidate, "", "")
		require.Error(t, err, candidate)
	}

	_, err = ValidateCyberRuleDraftCandidate("未经授权的凭据批量尝试", "前文包含未经授权的凭据批量尝试和具体操作", "")
	require.Error(t, err, "a copied short attack fragment must be rejected")
	_, err = ValidateCyberRuleDraftCandidate("检测到标识 abcd1234 后判定为高风险", "原始案例中携带 abcd1234 作为操作参数", "")
	require.Error(t, err, "an unlabeled eight-rune identifier copied into new context must be rejected")

	accepted, err := ValidateCyberRuleDraftCandidate("将针对第三方系统的自动化未授权访问判定为高风险", "原始内容描述了另一种完全不同的具体场景", "")
	require.NoError(t, err)
	require.Equal(t, "将针对第三方系统的自动化未授权访问判定为高风险", accepted)
}

func TestCyberRuleDraftRequiresOneStrictJSONObject(t *testing.T) {
	text, err := ParseCyberRuleDraft([]byte(`{"rule_text":"禁止针对他人系统进行未授权凭据批量尝试"}`))
	require.NoError(t, err)
	require.Equal(t, "禁止针对他人系统进行未授权凭据批量尝试", text)

	for _, raw := range []string{
		`{"rule_text":"有效规则","raw_prompt":"secret"}`,
		`{"rule_text":"有效规则"} {"rule_text":"第二条"}`,
		"```json\n{\"rule_text\":\"有效规则\"}\n```",
	} {
		_, err := ParseCyberRuleDraft([]byte(raw))
		require.Error(t, err)
	}
}

func TestCyberRulesRoundTripAndOrdinaryConfigUpdatePreservesThem(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.CyberSupplementRules = []CyberSupplementRule{reviewedCyberRule(9, "禁止对他人账号执行自动化凭据填充")}
	raw, err := json.Marshal(storage)
	require.NoError(t, err)
	parsed, err := ParseStorageConfig(string(raw))
	require.NoError(t, err)
	require.Equal(t, storage.CyberSupplementRules, parsed.CyberSupplementRules)

	request := updateRequestFromStorage(parsed)
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	next, err := manager.buildNextStorage(parsed, request, 77)
	require.NoError(t, err)
	require.Equal(t, parsed.CyberSupplementRules, next.CyberSupplementRules)

	request.cyberSupplementRules = &[]CyberSupplementRule{}
	next, err = manager.buildNextStorage(parsed, request, 77)
	require.NoError(t, err)
	require.Empty(t, next.CyberSupplementRules)
}

func TestLegacyActiveOnlyCyberRuleConfigRemainsParseable(t *testing.T) {
	storage := DefaultStorageConfig()
	storage.CyberSupplementRules = []CyberSupplementRule{reviewedCyberRule(10, "拒绝协助滥用第三方访问凭据")}
	raw, err := json.Marshal(storage)
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"status":"disabled"`)
	require.NotContains(t, string(raw), "recovered_candidate")

	parsed, err := ParseStorageConfig(string(raw))
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleActive, parsed.CyberSupplementRules[0].Status)
}

func TestCyberFeedbackAdminDTOCannotLeakRepositorySecrets(t *testing.T) {
	apiKeyID := int64(991)
	value := CyberFeedback{
		ID: 5, APIKeyID: &apiKeyID, SignatureVersion: "secret-version", PromptSignature: []byte("signature-canary"),
		RequestID: "request-safe", GroupID: 12, AccountID: 34, ReviewStatus: CyberReviewPending,
		GenerationStatus: CyberGenerationGenerated, CandidateRuleText: "抽象规则", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	raw, err := json.Marshal(cyberFeedbackAdminDTO(value))
	require.NoError(t, err)
	payload := string(raw)
	require.NotContains(t, payload, "api_key")
	require.NotContains(t, payload, "signature")
	require.NotContains(t, payload, "991")
	require.NotContains(t, payload, "signature-canary")
	require.Contains(t, payload, "request-safe")
	require.True(t, strings.Contains(payload, "candidate_rule_text"))
}

func TestCyberFeedbackEvidenceIsSeparatedFromOrdinaryDetail(t *testing.T) {
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: 5, RequestID: "req-5", AccountID: 20, AccountNameSnapshot: "shadow", CredentialAccountID: 10, CredentialAccountName: "parent", UpstreamMessage: "blocked"},
		evidence: CyberFeedbackEvidence{ID: 5, FullPrompt: "[user]\nraw canary", UserEmail: "user@example.test", CredentialAccountEmail: "oauth@example.test", IdentitySource: "snapshot"},
	}
	service := &PromptService{cyberAdminRepo: repo}
	detail, err := service.GetCyberFeedbackAdmin(context.Background(), 5)
	require.NoError(t, err)
	rawDetail, err := json.Marshal(detail)
	require.NoError(t, err)
	require.NotContains(t, string(rawDetail), "raw canary")
	require.NotContains(t, string(rawDetail), "user@example.test")

	evidence, err := service.GetCyberFeedbackEvidenceAdmin(context.Background(), 5)
	require.NoError(t, err)
	require.True(t, evidence.Available)
	require.Equal(t, "[user]\nraw canary", evidence.FullPrompt)
	require.Equal(t, "user@example.test", evidence.UserEmail)
	require.Equal(t, "oauth@example.test", evidence.CredentialAccountEmail)
}

func TestCyberAdminMutationMutexSerializesAdoptAgainstReject(t *testing.T) {
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 7},
		saveEntered: make(chan struct{}), releaseSave: make(chan struct{}),
	}
	repo := &cyberAdminTestRepo{feedback: CyberFeedback{
		ID: 51, ReviewStatus: CyberReviewPending, GenerationStatus: CyberGenerationGenerated,
		CandidateRuleText: "禁止针对他人系统执行自动化凭据填充", RedactedPreview: "***…",
	}}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	adoptDone := make(chan error, 1)
	go func() {
		_, err := service.AdoptCyberFeedback(context.Background(), 51, AdoptCyberFeedbackRequest{ExpectedConfigVersion: 7}, 101)
		adoptDone <- err
	}()
	select {
	case <-config.saveEntered:
	case <-time.After(time.Second):
		t.Fatal("adopt did not reach the blocked config save")
	}

	rejectDone := make(chan error, 1)
	go func() {
		_, err := service.RejectCyberFeedback(context.Background(), 51, RejectCyberFeedbackRequest{Reason: "not applicable"}, 202)
		rejectDone <- err
	}()
	select {
	case err := <-rejectDone:
		t.Fatalf("reject escaped the process-local mutation lock before adopt completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(config.releaseSave)
	require.NoError(t, <-adoptDone)
	require.Error(t, <-rejectDone, "the serialized reject must observe the adopted state and conflict")

	repo.mu.Lock()
	defer repo.mu.Unlock()
	require.Equal(t, CyberReviewApproved, repo.feedback.ReviewStatus)
	require.Equal(t, []string{CyberReviewApproved}, repo.transitions)
}

func TestCyberRuleLifecycleDisableRestoreAndConfirmedDelete(t *testing.T) {
	release := make(chan struct{})
	close(release)
	entered := make(chan struct{})
	now := time.Date(2026, 8, 17, 6, 0, 0, 0, time.UTC)
	actor := int64(9)
	rule := reviewedCyberRule(61, "拒绝协助窃取或滥用第三方 OAuth 凭据")
	rule.ConfigVersion = 7
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 7, CyberSupplementRules: []CyberSupplementRule{rule}},
		saveEntered: entered, releaseSave: release,
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: 61, ReviewStatus: CyberReviewApproved, RuleID: rule.ID, ReviewedAt: &now, ReviewedBy: &actor},
		projection: CyberRuleProjection{
			FeedbackID: 61, RuleID: rule.ID, RuleText: rule.RuleText, LifecycleStatus: CyberRuleLifecycleActive,
			RuleTextSource: CyberRuleTextSourceReviewed, StateConfigVersion: 7, CreatedAt: now, ReviewedAt: &now, ReviewedBy: &actor,
		},
	}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	disabled, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 7}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(8), disabled.ConfigVersion)
	require.Equal(t, CyberRuleLifecycleDisabled, disabled.Rule.Status)
	require.Equal(t, rule.RuleText, disabled.Rule.RuleText)
	require.Empty(t, config.config.CyberSupplementRules, "disabled rules must never be persisted in runtime config")
	require.Equal(t, CyberRuleLifecycleDisabled, repo.projection.LifecycleStatus)
	repeatedDisable, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 8}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(8), repeatedDisable.ConfigVersion, "repeating a completed disable is idempotent")

	listed, err := service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Equal(t, 0, listed.ActiveCount)
	require.Len(t, listed.Items, 1)
	require.Equal(t, CyberRuleLifecycleDisabled, listed.Items[0].Status)

	restored, err := service.RestoreCyberRule(context.Background(), rule.ID, RestoreCyberRuleRequest{ExpectedConfigVersion: 8}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(9), restored.ConfigVersion)
	require.Equal(t, CyberRuleLifecycleActive, restored.Rule.Status)
	require.Len(t, config.config.CyberSupplementRules, 1)
	require.Equal(t, CyberRuleLifecycleActive, config.config.CyberSupplementRules[0].Status)
	require.Equal(t, rule.RuleText, config.config.CyberSupplementRules[0].RuleText)
	repeatedRestore, err := service.RestoreCyberRule(context.Background(), rule.ID, RestoreCyberRuleRequest{ExpectedConfigVersion: 9}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(9), repeatedRestore.ConfigVersion, "repeating a completed restore is idempotent")

	_, err = service.DeleteCyberRule(context.Background(), rule.ID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 9, ConfirmRuleID: rule.ID,
	}, actor)
	require.Error(t, err, "active rules must be disabled before permanent deletion")

	_, err = service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 9}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(10), config.config.ConfigVersion)
	_, err = service.DeleteCyberRule(context.Background(), rule.ID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 10, ConfirmRuleID: "wrong-rule-id",
	}, actor)
	require.Error(t, err)
	require.Equal(t, int64(10), config.config.ConfigVersion)

	deleted, err := service.DeleteCyberRule(context.Background(), rule.ID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 10, ConfirmRuleID: rule.ID,
	}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(11), deleted.ConfigVersion, "delete establishes a config CAS boundary against concurrent restore")
	require.Equal(t, CyberRuleLifecycleDeleted, deleted.Rule.Status)
	require.Empty(t, deleted.Rule.RuleText)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus)
	require.Empty(t, repo.projection.RuleText)
	require.Equal(t, CyberReviewApproved, repo.feedback.ReviewStatus, "feedback history must survive rule deletion")
	repeatedDelete, err := service.DeleteCyberRule(context.Background(), rule.ID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 11, ConfirmRuleID: rule.ID,
	}, actor)
	require.NoError(t, err)
	require.Equal(t, int64(11), repeatedDelete.ConfigVersion, "repeating a completed delete is idempotent")

	listed, err = service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Empty(t, listed.Items)
}

func TestCyberRuleRestorePreservesRecoveredCandidateProvenance(t *testing.T) {
	release := make(chan struct{})
	close(release)
	feedbackID := int64(62)
	ruleID := DeterministicCyberRuleID(feedbackID)
	reviewedAt := time.Date(2026, 8, 17, 7, 0, 0, 0, time.UTC)
	reviewer := int64(8)
	config := &cyberAdminTestConfig{
		config: PublicConfig{ConfigVersion: 12}, saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: feedbackID, ReviewStatus: CyberReviewApproved, RuleID: ruleID, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer},
		projection: CyberRuleProjection{
			FeedbackID: feedbackID, RuleID: ruleID, RuleText: "拒绝协助获取或外泄第三方账号凭据",
			// Simulate a crash after config removal but before the lifecycle
			// projection was repaired. Config membership remains authoritative.
			LifecycleStatus: CyberRuleLifecycleActive, RuleTextSource: CyberRuleTextSourceRecoveredCandidate,
			StateConfigVersion: 11, CreatedAt: reviewedAt, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer,
		},
	}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	result, err := service.RestoreCyberRule(context.Background(), ruleID, RestoreCyberRuleRequest{ExpectedConfigVersion: 12}, 99)
	require.NoError(t, err)
	require.True(t, result.Rule.RecoveredCandidate)
	require.Equal(t, CyberRuleTextSourceRecoveredCandidate, result.Rule.RuleTextSource)
	require.Len(t, config.config.CyberSupplementRules, 1)
	require.Equal(t, CyberRuleLifecycleActive, config.config.CyberSupplementRules[0].Status)
}

func TestCyberRuleDeleteRepairsStaleActiveProjectionWhenConfigHasNoMember(t *testing.T) {
	release := make(chan struct{})
	close(release)
	feedbackID := int64(63)
	ruleID := DeterministicCyberRuleID(feedbackID)
	reviewedAt := time.Date(2026, 8, 17, 8, 0, 0, 0, time.UTC)
	reviewer := int64(8)
	config := &cyberAdminTestConfig{
		config: PublicConfig{ConfigVersion: 20}, saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: feedbackID, ReviewStatus: CyberReviewApproved, RuleID: ruleID, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer},
		projection: CyberRuleProjection{
			FeedbackID: feedbackID, RuleID: ruleID, RuleText: "拒绝协助滥用第三方账号凭据",
			LifecycleStatus: CyberRuleLifecycleActive, RuleTextSource: CyberRuleTextSourceReviewed,
			StateConfigVersion: 19, CreatedAt: reviewedAt, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer,
		},
	}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	result, err := service.DeleteCyberRule(context.Background(), ruleID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 20, ConfirmRuleID: ruleID,
	}, 99)
	require.NoError(t, err)
	require.Equal(t, int64(21), result.ConfigVersion)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus)
	require.Empty(t, repo.projection.RuleText)
}

func TestCyberRuleDisableRepairsPendingFeedbackAfterConfigFirstAdoptCrash(t *testing.T) {
	release := make(chan struct{})
	close(release)
	rule := reviewedCyberRule(64, "拒绝协助获取第三方会话凭据")
	rule.ConfigVersion = 30
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 30, CyberSupplementRules: []CyberSupplementRule{rule}},
		saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{feedback: CyberFeedback{
		ID: rule.SourceFeedbackID, ReviewStatus: CyberReviewPending, RuleID: "", CreatedAt: rule.CreatedAt,
	}}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	result, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 30}, 77)
	require.NoError(t, err)
	require.Equal(t, int64(31), result.ConfigVersion)
	require.Empty(t, config.config.CyberSupplementRules)
	require.Equal(t, CyberReviewApproved, repo.feedback.ReviewStatus)
	require.Equal(t, rule.ID, repo.feedback.RuleID)
	require.Equal(t, CyberRuleLifecycleDisabled, repo.projection.LifecycleStatus)
	require.Equal(t, rule.RuleText, repo.projection.RuleText)
}

func TestCyberRuleDistributedLifecycleLockPreventsRestoreInsideDeleteWindow(t *testing.T) {
	feedbackID := int64(65)
	ruleID := DeterministicCyberRuleID(feedbackID)
	reviewedAt := time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	reviewer := int64(8)
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 40},
		saveEntered: make(chan struct{}), releaseSave: make(chan struct{}),
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: feedbackID, ReviewStatus: CyberReviewApproved, RuleID: ruleID, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer},
		projection: CyberRuleProjection{
			FeedbackID: feedbackID, RuleID: ruleID, RuleText: "拒绝协助窃取第三方账号凭据",
			LifecycleStatus: CyberRuleLifecycleDisabled, RuleTextSource: CyberRuleTextSourceReviewed,
			StateConfigVersion: 40, CreatedAt: reviewedAt, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer,
		},
	}
	deleteService := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}
	restoreService := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	deleteDone := make(chan error, 1)
	go func() {
		_, err := deleteService.DeleteCyberRule(context.Background(), ruleID, DeleteCyberRuleRequest{
			ExpectedConfigVersion: 40, ConfirmRuleID: ruleID,
		}, 91)
		deleteDone <- err
	}()
	select {
	case <-config.saveEntered:
	case <-time.After(time.Second):
		t.Fatal("delete did not reach the config CAS window")
	}

	restoreDone := make(chan error, 1)
	go func() {
		_, err := restoreService.RestoreCyberRule(context.Background(), ruleID, RestoreCyberRuleRequest{ExpectedConfigVersion: 40}, 92)
		restoreDone <- err
	}()
	select {
	case err := <-restoreDone:
		t.Fatalf("restore entered the delete CAS-to-tombstone window: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(config.releaseSave)
	require.NoError(t, <-deleteDone)
	require.Error(t, <-restoreDone, "restore with the deleted rule's stale config version must conflict")
	require.Empty(t, config.config.CyberSupplementRules)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus)
}

func TestCyberRuleDisablePreservesDeletedTerminalProjection(t *testing.T) {
	release := make(chan struct{})
	close(release)
	rule := reviewedCyberRule(66, "拒绝协助获取第三方访问令牌")
	rule.ConfigVersion = 50
	reviewedAt := rule.ReviewedAt
	reviewer := rule.ReviewedBy
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 50, CyberSupplementRules: []CyberSupplementRule{rule}},
		saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: rule.SourceFeedbackID, ReviewStatus: CyberReviewApproved, RuleID: rule.ID, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer},
		projection: CyberRuleProjection{
			FeedbackID: rule.SourceFeedbackID, RuleID: rule.ID, LifecycleStatus: CyberRuleLifecycleDeleted,
			StateConfigVersion: 49, CreatedAt: reviewedAt, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer,
		},
	}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	result, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 50}, 77)
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleDeleted, result.Rule.Status)
	require.Empty(t, config.config.CyberSupplementRules)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus, "permanent deletion must remain terminal")
	_, err = service.RestoreCyberRule(context.Background(), rule.ID, RestoreCyberRuleRequest{ExpectedConfigVersion: 51}, 77)
	require.Error(t, err)
}

func TestCyberRuleDisableReconcilesRejectedMetadataAndRemainsReversible(t *testing.T) {
	release := make(chan struct{})
	close(release)
	rule := reviewedCyberRule(67, "拒绝协助窃取第三方会话")
	rule.ConfigVersion = 60
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 60, CyberSupplementRules: []CyberSupplementRule{rule}},
		saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{feedback: CyberFeedback{
		ID: rule.SourceFeedbackID, ReviewStatus: CyberReviewRejected, RuleID: "", CreatedAt: rule.CreatedAt,
	}}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	result, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 60}, 77)
	require.NoError(t, err)
	require.Equal(t, int64(61), result.ConfigVersion)
	require.Empty(t, config.config.CyberSupplementRules, "metadata inconsistency must never prevent a safety disable")
	require.Equal(t, CyberReviewApproved, repo.feedback.ReviewStatus, "the exact active config is the authoritative adoption fact")
	require.Equal(t, rule.ID, repo.feedback.RuleID)
	require.Equal(t, CyberRuleLifecycleDisabled, repo.projection.LifecycleStatus)
	require.Equal(t, rule.RuleText, repo.projection.RuleText)
	require.Equal(t, CyberRuleTextSourceReviewed, result.Rule.RuleTextSource)

	listed, err := service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Len(t, listed.Items, 1, "a repaired disable must remain visible")
	require.Equal(t, CyberRuleLifecycleDisabled, listed.Items[0].Status)

	_, err = service.RestoreCyberRule(context.Background(), rule.ID, RestoreCyberRuleRequest{ExpectedConfigVersion: 61}, 77)
	require.NoError(t, err)
	_, err = service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 62}, 77)
	require.NoError(t, err)
	_, err = service.DeleteCyberRule(context.Background(), rule.ID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 63, ConfirmRuleID: rule.ID,
	}, 77)
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus)
}

func TestCyberRuleDisableReconcilesWrongRuleProjection(t *testing.T) {
	release := make(chan struct{})
	close(release)
	rule := reviewedCyberRule(68, "拒绝协助滥用第三方 OAuth 会话")
	rule.ConfigVersion = 70
	wrongID := DeterministicCyberRuleID(999)
	reviewedAt := rule.ReviewedAt
	reviewer := rule.ReviewedBy
	config := &cyberAdminTestConfig{
		config:      PublicConfig{ConfigVersion: 70, CyberSupplementRules: []CyberSupplementRule{rule}},
		saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: rule.SourceFeedbackID, ReviewStatus: CyberReviewApproved, RuleID: wrongID, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer},
		projection: CyberRuleProjection{
			FeedbackID: rule.SourceFeedbackID, RuleID: wrongID, RuleText: "错误历史规则",
			LifecycleStatus: CyberRuleLifecycleDisabled, RuleTextSource: CyberRuleTextSourceReviewed,
		},
	}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	listed, err := service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Len(t, listed.Items, 1, "wrong projection ID must not create a disabled ghost beside the active rule")
	require.Equal(t, rule.ID, listed.Items[0].ID)
	require.Equal(t, CyberRuleLifecycleActive, listed.Items[0].Status)
	require.NotEqual(t, wrongID, listed.Items[0].ID)

	result, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 70}, 77)
	require.NoError(t, err)
	require.Equal(t, rule.ID, result.Rule.ID)
	require.Equal(t, rule.RuleText, result.Rule.RuleText)
	require.Equal(t, rule.ID, repo.feedback.RuleID)
	require.Equal(t, rule.ID, repo.projection.RuleID)
	require.Equal(t, CyberRuleLifecycleDisabled, repo.projection.LifecycleStatus)

	listed, err = service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Len(t, listed.Items, 1)
	require.Equal(t, rule.ID, listed.Items[0].ID)
	require.Equal(t, CyberRuleLifecycleDisabled, listed.Items[0].Status)
	_, err = service.RestoreCyberRule(context.Background(), rule.ID, RestoreCyberRuleRequest{ExpectedConfigVersion: 71}, 77)
	require.NoError(t, err)
	_, err = service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 72}, 77)
	require.NoError(t, err)
	_, err = service.DeleteCyberRule(context.Background(), rule.ID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 73, ConfirmRuleID: rule.ID,
	}, 77)
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus)
}

func TestCyberRuleConfigSaveFailureLeavesRepairableProjection(t *testing.T) {
	release := make(chan struct{})
	close(release)
	rule := reviewedCyberRule(69, "拒绝协助外泄第三方访问令牌")
	rule.ConfigVersion = 80
	reviewedAt := rule.ReviewedAt
	reviewer := rule.ReviewedBy
	config := &cyberAdminTestConfig{
		config:  PublicConfig{ConfigVersion: 80, CyberSupplementRules: []CyberSupplementRule{rule}},
		saveErr: errors.New("injected config CAS failure"), saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{
		feedback: CyberFeedback{ID: rule.SourceFeedbackID, ReviewStatus: CyberReviewApproved, RuleID: rule.ID, ReviewedAt: &reviewedAt, ReviewedBy: &reviewer},
		projection: CyberRuleProjection{
			FeedbackID: rule.SourceFeedbackID, RuleID: rule.ID, RuleText: rule.RuleText,
			LifecycleStatus: CyberRuleLifecycleActive, RuleTextSource: CyberRuleTextSourceReviewed,
		},
	}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	_, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 80}, 77)
	require.Error(t, err)
	require.Len(t, config.config.CyberSupplementRules, 1)
	require.Equal(t, CyberRuleLifecycleDisabled, repo.projection.LifecycleStatus, "projection-first failure is intentionally repairable")
	listed, err := service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleActive, listed.Items[0].Status, "config membership stays authoritative")

	config.mu.Lock()
	config.saveErr = nil
	config.mu.Unlock()
	result, err := service.RevokeCyberRule(context.Background(), rule.ID, RevokeCyberRuleRequest{ExpectedConfigVersion: 80}, 77)
	require.NoError(t, err)
	require.Equal(t, int64(81), result.ConfigVersion)
	require.Empty(t, config.config.CyberSupplementRules)
}

func TestLegacyRollbackAdoptRevokeProjectionCanListRestoreAndDelete(t *testing.T) {
	release := make(chan struct{})
	close(release)
	feedbackID := int64(70)
	ruleID := DeterministicCyberRuleID(feedbackID)
	reviewedAt := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	reviewer := int64(8)
	config := &cyberAdminTestConfig{
		config: PublicConfig{ConfigVersion: 90}, saveEntered: make(chan struct{}), releaseSave: release,
	}
	repo := &cyberAdminTestRepo{feedback: CyberFeedback{
		ID: feedbackID, ReviewStatus: CyberReviewApproved, RuleID: ruleID,
		CandidateRuleText: "拒绝协助获取第三方账号凭据", ConfigVersion: 89,
		ReviewedAt: &reviewedAt, ReviewedBy: &reviewer, CreatedAt: reviewedAt,
	}}
	service := &PromptService{clock: realClock{}, cyberAdminRepo: repo, cyberAdminConfig: config}

	listed, err := service.ListCyberRulesAdmin(context.Background())
	require.NoError(t, err)
	require.Len(t, listed.Items, 1)
	require.Equal(t, CyberRuleLifecycleDisabled, listed.Items[0].Status)
	require.Equal(t, CyberRuleTextSourceRecoveredCandidate, listed.Items[0].RuleTextSource)
	require.True(t, listed.Items[0].RecoveredCandidate)

	_, err = service.RestoreCyberRule(context.Background(), ruleID, RestoreCyberRuleRequest{ExpectedConfigVersion: 90}, 99)
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleActive, repo.projection.LifecycleStatus, "first mutation persists the lazy legacy projection")
	_, err = service.RevokeCyberRule(context.Background(), ruleID, RevokeCyberRuleRequest{ExpectedConfigVersion: 91}, 99)
	require.NoError(t, err)
	_, err = service.DeleteCyberRule(context.Background(), ruleID, DeleteCyberRuleRequest{
		ExpectedConfigVersion: 92, ConfirmRuleID: ruleID,
	}, 99)
	require.NoError(t, err)
	require.Equal(t, CyberRuleLifecycleDeleted, repo.projection.LifecycleStatus)
}
