//go:build unit

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

type handlerCyberFeedbackRepo struct {
	mu        sync.Mutex
	active    []securityaudit.CyberActiveSignature
	confirmed chan securityaudit.CyberConfirmInput
}

type handlerCyberScopeProvider struct{ cfg securityaudit.ActiveConfig }

func (p handlerCyberScopeProvider) IncludesCyberFeedbackSource(accountID int64, platform, accountType string) bool {
	return p.cfg.IncludesCyberFeedbackSource(accountID, platform, accountType)
}

func (handlerCyberScopeProvider) GenerateCyberRuleDraft(context.Context, securityaudit.PromptSnapshot) (string, error) {
	return "", nil
}

func (r *handlerCyberFeedbackRepo) Confirm(_ context.Context, input securityaudit.CyberConfirmInput) (securityaudit.CyberFeedback, bool, error) {
	if r.confirmed != nil {
		r.confirmed <- input
	}
	apiKeyID := input.APIKeyID
	return securityaudit.CyberFeedback{
		ID: 1, RequestID: input.RequestID, APIKeyID: &apiKeyID, GroupID: input.GroupID,
		AccountID: input.AccountID, Model: input.Model, Endpoint: input.Endpoint,
		Protocol: input.Protocol, Transport: input.Transport, Stage: input.Stage,
		UpstreamStatus: input.UpstreamStatus, CreatedAt: time.Now().UTC(),
	}, true, nil
}

func (*handlerCyberFeedbackRepo) MatchActiveSignature(context.Context, securityaudit.CyberFingerprintScope) (bool, error) {
	return false, nil
}

func (r *handlerCyberFeedbackRepo) ListActiveSignatures(_ context.Context, groupID int64, version string, afterID int64, limit int) ([]securityaudit.CyberActiveSignature, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]securityaudit.CyberActiveSignature, 0, limit)
	for _, item := range r.active {
		if item.GroupID != groupID || item.SignatureVersion != version || item.ID <= afterID {
			continue
		}
		result = append(result, item)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (*handlerCyberFeedbackRepo) ListCyberFeedback(context.Context, securityaudit.CyberFeedbackFilter, int, int) ([]securityaudit.CyberFeedback, int64, error) {
	return nil, 0, nil
}

func (*handlerCyberFeedbackRepo) GetCyberFeedback(context.Context, int64) (securityaudit.CyberFeedback, error) {
	return securityaudit.CyberFeedback{}, securityaudit.ErrCyberFeedbackNotFound
}

func (*handlerCyberFeedbackRepo) GetCyberFeedbackEvidence(context.Context, int64) (securityaudit.CyberFeedbackEvidence, error) {
	return securityaudit.CyberFeedbackEvidence{}, securityaudit.ErrCyberFeedbackNotFound
}

func (*handlerCyberFeedbackRepo) ReviewCyberFeedback(context.Context, int64, string, int64, string, int64) (securityaudit.CyberFeedback, error) {
	return securityaudit.CyberFeedback{}, nil
}

func (*handlerCyberFeedbackRepo) ListCyberRuleProjections(context.Context) ([]securityaudit.CyberRuleProjection, error) {
	return nil, nil
}

func (*handlerCyberFeedbackRepo) GetCyberRuleProjection(context.Context, int64) (securityaudit.CyberRuleProjection, error) {
	return securityaudit.CyberRuleProjection{}, securityaudit.ErrCyberFeedbackNotFound
}

func (*handlerCyberFeedbackRepo) SaveCyberRuleProjection(context.Context, int64, string, string, string, string, int64, int64) error {
	return nil
}

func (*handlerCyberFeedbackRepo) ReconcileActiveCyberRuleProjection(context.Context, securityaudit.CyberSupplementRule, string, int64, int64) (securityaudit.CyberRuleProjection, error) {
	return securityaudit.CyberRuleProjection{}, nil
}

func (*handlerCyberFeedbackRepo) DeleteCyberRuleProjection(context.Context, int64, string, int64, int64) error {
	return nil
}

func (*handlerCyberFeedbackRepo) ResetCyberRuleGeneration(context.Context, int64) error { return nil }

func (*handlerCyberFeedbackRepo) CompleteCyberRuleGeneration(context.Context, int64, string, string) error {
	return nil
}

func newHandlerCyberService(t *testing.T, repo *handlerCyberFeedbackRepo, withRedis bool, scopes ...securityaudit.ActiveConfig) *securityaudit.CyberFeedbackService {
	t.Helper()
	var client *redis.Client
	if withRedis {
		mr := miniredis.RunT(t)
		client = redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
		t.Cleanup(func() { _ = client.Close() })
	}
	var generator securityaudit.CyberRuleDraftGenerator
	var scope securityaudit.CyberFeedbackScopeProvider
	if len(scopes) > 0 {
		provider := handlerCyberScopeProvider{cfg: scopes[0]}
		generator = provider
		scope = provider
	}
	return securityaudit.NewCyberFeedbackService(
		repo, client, &config.Config{JWT: config.JWTConfig{Secret: "handler-test-stable-key"}}, nil, nil, generator, scope,
	)
}

func newHandlerCyberContext(path string) *gin.Context {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, path, nil)
	return c
}

func TestOpenAICyberReplayBlocksBeforeAuditAcrossHTTPCompatProtocols(t *testing.T) {
	groupID := int64(12)
	apiKey := &service.APIKey{ID: 7, GroupID: &groupID, Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI}}
	subject := middleware2.AuthSubject{UserID: 8}
	for _, test := range []struct {
		name, path, protocol, body string
	}{
		{"responses", "/v1/responses", service.ContentModerationProtocolOpenAIResponses, `{"input":"confirmed response prompt"}`},
		{"chat", "/v1/chat/completions", service.ContentModerationProtocolOpenAIChat, `{"messages":[{"role":"user","content":"confirmed chat prompt"}]}`},
		{"messages", "/v1/messages", service.ContentModerationProtocolAnthropicMessages, `{"messages":[{"role":"user","content":"confirmed messages prompt"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &handlerCyberFeedbackRepo{}
			cyberService := newHandlerCyberService(t, repo, true)
			evidence, ok := cyberService.PrepareTurn(securityaudit.Request{
				GroupID: &groupID, Provider: service.PlatformOpenAI, Protocol: test.protocol,
				Body: []byte(test.body), Stage: "http",
			}, 0)
			require.True(t, ok)
			repo.active = []securityaudit.CyberActiveSignature{{
				ID: 1, GroupID: groupID, SignatureVersion: evidence.Scope.SignatureVersion,
				PromptSignature: evidence.Scope.PromptSignature, ExpiresAt: time.Now().Add(time.Hour),
			}}
			h := &OpenAIGatewayHandler{cyberFeedbackService: cyberService}
			c := newHandlerCyberContext(test.path)
			decision := h.checkSecurityAudit(c, nil, apiKey, subject, test.protocol, "gpt-test", []byte(test.body))
			require.NotNil(t, decision)
			require.Equal(t, securityaudit.DecisionBlock, decision.Kind)
			require.Equal(t, http.StatusForbidden, decision.HTTPStatus)
			require.False(t, decision.AllowNextStage)
			require.NotNil(t, decision.Prompt)
			require.False(t, decision.Prompt.AllowNextStage)
			require.True(t, service.HasOpsClientBusinessLimited(c))
			require.Equal(t, service.OpsClientBusinessLimitedReasonLocalPolicyDenied, c.GetString(service.OpsClientBusinessLimitedReasonKey))
		})
	}
}

func TestOpenAICyberReplayTracksEveryWebSocketTurnAndClearsEvidence(t *testing.T) {
	groupID := int64(12)
	apiKey := &service.APIKey{ID: 7, GroupID: &groupID, Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI}}
	repo := &handlerCyberFeedbackRepo{}
	cyberService := newHandlerCyberService(t, repo, true)
	h := &OpenAIGatewayHandler{cyberFeedbackService: cyberService}
	c := newHandlerCyberContext("/v1/responses")
	c.Set(securityAuditWSTurnContextKey, 1)
	firstBody := []byte(`{"type":"response.create","input":"first turn"}`)
	require.Nil(t, h.checkSecurityAuditStage(c, nil, apiKey, middleware2.AuthSubject{UserID: 8}, "responses_websocket", "gpt-test", firstBody, "first_turn"))
	first, ok := currentCyberTurnEvidence(c)
	require.True(t, ok)
	require.Equal(t, 1, first.TurnNumber)
	require.Equal(t, "first_turn", first.Stage)
	require.Equal(t, "websocket", first.Transport)

	c.Set(securityAuditWSTurnContextKey, 4)
	secondBody := []byte(`{"type":"response.create","input":"later turn"}`)
	require.Nil(t, h.checkSecurityAuditStage(c, nil, apiKey, middleware2.AuthSubject{UserID: 8}, "responses_websocket", "gpt-test", secondBody, "subsequent_turn"))
	second, ok := currentCyberTurnEvidence(c)
	require.True(t, ok)
	require.Equal(t, 4, second.TurnNumber)
	require.Equal(t, "subsequent_turn", second.Stage)
	require.NotEqual(t, first.Scope.PromptSignature, second.Scope.PromptSignature)

	clearCyberPolicyTurnState(c)
	_, ok = currentCyberTurnEvidence(c)
	require.False(t, ok)
}

func TestRecordCyberPolicyDefaultScopeConfirmsOnlyRealOpenAIOAuthMark(t *testing.T) {
	groupID := int64(12)
	apiKey := &service.APIKey{ID: 7, Key: "sk-safe-prefix-value", Name: "test-key", GroupID: &groupID, Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI}}
	openAIOAuth := &service.Account{ID: 90, Name: "oauth-account", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Credentials: map[string]any{"email": "oauth@example.test"}}

	repo := &handlerCyberFeedbackRepo{confirmed: make(chan securityaudit.CyberConfirmInput, 2)}
	h := &OpenAIGatewayHandler{cyberFeedbackService: newHandlerCyberService(t, repo, false)}
	c := newHandlerCyberContext("/v1/responses")
	c.Set(securityAuditCyberTurnEvidenceContextKey, securityaudit.CyberTurnEvidence{
		Scope:     securityaudit.CyberFingerprintScope{GroupID: groupID, Protocol: service.ContentModerationProtocolOpenAIResponses, Stage: "http"},
		RequestID: "request-1", Model: "gpt-test", Endpoint: "/v1/responses", Transport: "http", Stage: "http",
	})
	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{Message: "rejected", UpstreamStatus: 400})
	h.recordCyberPolicyIfMarked(c, apiKey, openAIOAuth, nil, "gpt-test", true, nil, service.ChannelUsageFields{}, "")
	select {
	case confirmed := <-repo.confirmed:
		require.Equal(t, openAIOAuth.ID, confirmed.AccountID)
		require.Equal(t, groupID, confirmed.GroupID)
		require.Equal(t, "oauth-account", confirmed.AccountName)
		require.Equal(t, openAIOAuth.ID, confirmed.CredentialAccountID)
		require.Equal(t, "oauth@example.test", confirmed.CredentialAccountEmail)
		require.Equal(t, "cyber_policy", confirmed.UpstreamCode)
		require.Equal(t, "rejected", confirmed.UpstreamMessage)
	case <-time.After(time.Second):
		t.Fatal("expected OpenAI OAuth confirmation")
	}
	h.recordCyberPolicyIfMarked(c, apiKey, openAIOAuth, nil, "gpt-test", true, nil, service.ChannelUsageFields{}, "")
	select {
	case <-repo.confirmed:
		t.Fatal("duplicate recorder call must be idempotent")
	case <-time.After(30 * time.Millisecond):
	}

	for _, account := range []*service.Account{
		{ID: 91, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey},
		{ID: 92, Platform: service.PlatformGrok, Type: service.AccountTypeOAuth},
	} {
		caseRepo := &handlerCyberFeedbackRepo{confirmed: make(chan securityaudit.CyberConfirmInput, 1)}
		caseHandler := &OpenAIGatewayHandler{cyberFeedbackService: newHandlerCyberService(t, caseRepo, false)}
		caseContext := newHandlerCyberContext("/v1/responses")
		caseContext.Set(securityAuditCyberTurnEvidenceContextKey, securityaudit.CyberTurnEvidence{Scope: securityaudit.CyberFingerprintScope{GroupID: groupID}})
		service.MarkOpsCyberPolicy(caseContext, service.CyberPolicyMark{UpstreamStatus: 400})
		caseHandler.recordCyberPolicyIfMarked(caseContext, apiKey, account, nil, "gpt-test", true, nil, service.ChannelUsageFields{}, "")
		select {
		case <-caseRepo.confirmed:
			t.Fatalf("account %+v must not confirm OpenAI OAuth feedback", account)
		case <-time.After(30 * time.Millisecond):
		}
	}

	noMarkRepo := &handlerCyberFeedbackRepo{confirmed: make(chan securityaudit.CyberConfirmInput, 1)}
	noMarkHandler := &OpenAIGatewayHandler{cyberFeedbackService: newHandlerCyberService(t, noMarkRepo, false)}
	noMarkHandler.recordCyberPolicyIfMarked(newHandlerCyberContext("/v1/responses"), apiKey, openAIOAuth, nil, "gpt-test", true, nil, service.ChannelUsageFields{}, "")
	select {
	case <-noMarkRepo.confirmed:
		t.Fatal("missing upstream mark must not confirm feedback")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestRecordCyberPolicyConfiguredScopeCapturesNonOAuthOutsideAuditGroups(t *testing.T) {
	requestGroupID := int64(44)
	apiKey := &service.APIKey{ID: 7, Key: "sk-safe-prefix-value", Name: "test-key", GroupID: &requestGroupID, Group: &service.Group{ID: requestGroupID, Platform: service.PlatformOpenAI}}
	apiKeyAccount := &service.Account{ID: 91, Name: "api-account", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey}
	repo := &handlerCyberFeedbackRepo{confirmed: make(chan securityaudit.CyberConfirmInput, 1)}
	scope := securityaudit.ActiveConfig{
		Enabled: false, AllGroups: false, GroupIDs: []int64{12},
		CyberFeedbackAccountIDs: []int64{91},
	}
	cyberService := newHandlerCyberService(t, repo, false, scope)
	h := &OpenAIGatewayHandler{cyberFeedbackService: cyberService}
	c := newHandlerCyberContext("/v1/responses")
	evidence, ok := cyberService.PrepareTurn(securityaudit.Request{
		RequestID: "request-non-oauth", APIKeyID: apiKey.ID, GroupID: &requestGroupID, Provider: service.PlatformOpenAI,
		Protocol: service.ContentModerationProtocolOpenAIResponses, Model: "gpt-test", Endpoint: "/v1/responses",
		Body: []byte(`{"input":[{"role":"user","content":"complete evidence outside audit scope"}]}`), Stage: "http",
	}, 0)
	require.True(t, ok)
	c.Set(securityAuditCyberTurnEvidenceContextKey, evidence)
	service.MarkOpsCyberPolicy(c, service.CyberPolicyMark{Message: "rejected", UpstreamStatus: 400})
	h.recordCyberPolicyIfMarked(c, apiKey, apiKeyAccount, nil, "gpt-test", true, nil, service.ChannelUsageFields{}, "")
	select {
	case confirmed := <-repo.confirmed:
		require.Equal(t, apiKeyAccount.ID, confirmed.AccountID)
		require.Equal(t, requestGroupID, confirmed.GroupID)
		require.Contains(t, confirmed.FullPrompt, "complete evidence outside audit scope")
		require.Positive(t, confirmed.PromptLength)
	case <-time.After(time.Second):
		t.Fatal("expected configured non-OAuth CYB confirmation")
	}
}

func TestCyberEvidenceKeyPrefixNeverExposesAnEntireShortKey(t *testing.T) {
	groupID := int64(12)
	c := newHandlerCyberContext("/v1/responses")
	short := buildSecurityAuditRequest(c, &service.APIKey{
		ID: 7, Key: "short", GroupID: &groupID,
	}, middleware2.AuthSubject{UserID: 8}, service.ContentModerationProtocolOpenAIResponses,
		"gpt-test", []byte(`{"input":"test"}`), "http")
	require.Empty(t, short.APIKeyPrefix)

	long := buildSecurityAuditRequest(c, &service.APIKey{
		ID: 7, Key: "sk-long-secret-value", GroupID: &groupID,
	}, middleware2.AuthSubject{UserID: 8}, service.ContentModerationProtocolOpenAIResponses,
		"gpt-test", []byte(`{"input":"test"}`), "http")
	require.Equal(t, "sk-long-", long.APIKeyPrefix)
}
