//go:build unit

package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type responsesModelPreflightRepo struct {
	service.AccountRepository
	accounts []service.Account
	err      error
}

func (r *responsesModelPreflightRepo) ListModelAvailabilityCandidates(
	context.Context,
	*int64,
	[]string,
	bool,
) ([]service.Account, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]service.Account(nil), r.accounts...), nil
}

func newResponsesModelPreflightHandler(t *testing.T, accounts []service.Account, engine *handlerPromptEngine) *OpenAIGatewayHandler {
	t.Helper()
	return newResponsesModelPreflightHandlerWithRepo(t, &responsesModelPreflightRepo{accounts: accounts}, engine)
}

func newResponsesModelPreflightHandlerWithRepo(t *testing.T, repo service.AccountRepository, engine *handlerPromptEngine) *OpenAIGatewayHandler {
	t.Helper()
	cfg := &config.Config{RunMode: config.RunModeStandard}
	gateway := service.NewOpenAIGatewayService(
		repo,
		nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)
	billingCfg := &config.Config{RunMode: config.RunModeSimple}
	billingCache := service.NewBillingCacheService(nil, nil, nil, nil, nil, nil, billingCfg, nil)
	t.Cleanup(billingCache.Stop)
	h := NewOpenAIGatewayHandler(
		gateway,
		service.NewConcurrencyService(nil),
		billingCache,
		&service.APIKeyService{},
		nil, nil, nil, nil, cfg,
	)
	h.securityAuditCoordinator = securityaudit.NewCoordinator(nil, engine)
	return h
}

func responsesModelPreflightContext(t *testing.T, path, model string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"`+model+`","input":"hello","stream":false}`))
	c.Request.Header.Set("Content-Type", "application/json")
	groupID := int64(12)
	user := &service.User{ID: 100, Status: service.StatusActive}
	c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
		ID: 101, UserID: user.ID, User: user, GroupID: &groupID,
		Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI, Status: service.StatusActive},
	})
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
	return c, recorder
}

func TestOpenAIResponsesUnsupportedModelSkipsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range []string{"/openai/v1/responses", "/openai/v1/responses/compact"} {
		t.Run(path, func(t *testing.T) {
			engine := blockingHandlerPromptEngine()
			account := service.Account{
				ID: 1, Platform: service.PlatformOpenAI, Status: service.StatusActive, Schedulable: true,
				Credentials: map[string]any{"model_mapping": map[string]any{"gpt-supported": "gpt-supported"}},
			}
			h := newResponsesModelPreflightHandler(t, []service.Account{account}, engine)
			c, recorder := responsesModelPreflightContext(t, path, "gpt-unsupported")

			h.Responses(c)

			require.Equal(t, http.StatusNotFound, recorder.Code)
			require.Equal(t, "model_not_found", gjson.GetBytes(recorder.Body.Bytes(), "error.type").String())
			require.Contains(t, gjson.GetBytes(recorder.Body.Bytes(), "error.message").String(), "gpt-unsupported")
			evaluated, _, _ := engine.snapshot()
			require.Zero(t, evaluated, "a structurally unsupported model must not spend an external prompt-audit call")
			require.True(t, service.HasOpsClientBusinessLimited(c))
			require.Equal(t, opsClientBusinessLimitedReasonLocalModelUnsupported, c.GetString(service.OpsClientBusinessLimitedReasonKey))
		})
	}
}

func TestOpenAIResponsesSupportedModelStillRunsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	account := service.Account{
		ID: 1, Platform: service.PlatformOpenAI, Status: service.StatusActive, Schedulable: true,
		Credentials: map[string]any{"model_mapping": map[string]any{"gpt-supported": "gpt-supported"}},
	}
	h := newResponsesModelPreflightHandler(t, []service.Account{account}, engine)
	c, recorder := responsesModelPreflightContext(t, "/openai/v1/responses", "gpt-supported")

	h.Responses(c)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Equal(t, 1, evaluated, "supported models must retain the configured prompt-audit gate")
}

func TestOpenAIResponsesEmptyPersistentPoolSkipsPromptAuditWith503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	h := newResponsesModelPreflightHandlerWithRepo(t, &responsesModelPreflightRepo{}, engine)
	c, recorder := responsesModelPreflightContext(t, "/openai/v1/responses", "gpt-any")

	h.Responses(c)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated, "a conclusively empty persistent pool must not spend an external prompt-audit call")
	require.True(t, isOpsRoutingCapacityLimited(c))
}

func TestOpenAIResponsesRepositoryErrorStillRunsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	h := newResponsesModelPreflightHandlerWithRepo(t, &responsesModelPreflightRepo{err: errors.New("temporary database failure")}, engine)
	c, recorder := responsesModelPreflightContext(t, "/openai/v1/responses", "gpt-any")

	h.Responses(c)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Equal(t, 1, evaluated, "an operationally inconclusive preflight must preserve the configured prompt-audit gate")
}

func TestOpenAIResponsesUnsupportedCompositeModelDoesNotLeakUpstreamAlias(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	account := service.Account{
		ID: 1, Platform: service.PlatformOpenAI, Status: service.StatusActive, Schedulable: true,
		Credentials: map[string]any{"model_mapping": map[string]any{"gpt-supported": "gpt-supported"}},
	}
	h := newResponsesModelPreflightHandler(t, []service.Account{account}, engine)
	c, recorder := responsesModelPreflightContext(t, "/openai/v1/responses", "internal-upstream-model")
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	require.True(t, ok)
	apiKey.Group.Platform = service.PlatformComposite
	c.Request = c.Request.WithContext(service.WithCompositeRouteDecision(c.Request.Context(), service.CompositeRouteDecision{
		Matched:        true,
		PublicModel:    "public-model-alias",
		UpstreamModel:  "internal-upstream-model",
		TargetPlatform: service.PlatformOpenAI,
	}))

	h.Responses(c)

	require.Equal(t, http.StatusNotFound, recorder.Code)
	message := gjson.GetBytes(recorder.Body.Bytes(), "error.message").String()
	require.Contains(t, message, "public-model-alias")
	require.NotContains(t, message, "internal-upstream-model")
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}

func TestOpenAICompatibleAuditedHTTPEntrypointsUnsupportedModelSkipPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name     string
		platform string
		path     string
		body     string
		invoke   func(*OpenAIGatewayHandler, *gin.Context)
	}{
		{
			name: "chat_completions", platform: service.PlatformOpenAI, path: "/v1/chat/completions",
			body:   `{"model":"unsupported-model","messages":[{"role":"user","content":"hello"}]}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.ChatCompletions(c) },
		},
		{
			name: "messages", platform: service.PlatformOpenAI, path: "/v1/messages",
			body:   `{"model":"unsupported-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.Messages(c) },
		},
		{
			name: "embeddings", platform: service.PlatformOpenAI, path: "/v1/embeddings",
			body:   `{"model":"unsupported-model","input":"hello"}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.Embeddings(c) },
		},
		{
			name: "alpha_search", platform: service.PlatformOpenAI, path: "/v1/alpha/search",
			body:   `{"model":"unsupported-model","query":"hello"}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.AlphaSearch(c) },
		},
		{
			name: "images", platform: service.PlatformOpenAI, path: "/v1/images/generations",
			body:   `{"model":"gpt-image-1","prompt":"hello"}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.Images(c) },
		},
		{
			name: "grok_images", platform: service.PlatformGrok, path: "/v1/images/generations",
			body:   `{"model":"unsupported-model","prompt":"hello"}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.GrokImages(c) },
		},
		{
			name: "grok_video", platform: service.PlatformGrok, path: "/v1/videos/generations",
			body:   `{"model":"unsupported-model","prompt":"hello"}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.GrokVideoGeneration(c) },
		},
		{
			name: "grok_tts", platform: service.PlatformGrok, path: "/v1/tts",
			body:   `{"input":"hello"}`,
			invoke: func(h *OpenAIGatewayHandler, c *gin.Context) { h.GrokVoice(c, "tts") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := blockingHandlerPromptEngine()
			account := service.Account{
				ID: 1, Platform: tt.platform, Status: service.StatusActive, Schedulable: true,
				Credentials: map[string]any{"model_mapping": map[string]any{"supported-model": "supported-model"}},
			}
			h := newResponsesModelPreflightHandler(t, []service.Account{account}, engine)
			c, recorder := responsesModelPreflightContext(t, tt.path, "placeholder")
			c.Request = httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			apiKey, ok := middleware2.GetAPIKeyFromContext(c)
			require.True(t, ok)
			apiKey.Group.Platform = tt.platform
			apiKey.Group.AllowImageGeneration = true
			apiKey.Group.AllowMessagesDispatch = true

			tt.invoke(h, c)

			require.Equal(t, http.StatusNotFound, recorder.Code)
			evaluated, _, _ := engine.snapshot()
			require.Zero(t, evaluated)
			require.True(t, service.HasOpsClientBusinessLimited(c))
		})
	}
}

func TestGrokTTSMalformedRequestPrecedesModelPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		body string
	}{
		{name: "empty_body", body: ``},
		{name: "invalid_json", body: `{"input":`},
		{name: "non_object", body: `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := blockingHandlerPromptEngine()
			h := newResponsesModelPreflightHandler(t, nil, engine)
			c, recorder := responsesModelPreflightContext(t, "/v1/tts", "placeholder")
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/tts", strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")
			apiKey, ok := middleware2.GetAPIKeyFromContext(c)
			require.True(t, ok)
			apiKey.Group.Platform = service.PlatformGrok

			h.GrokVoice(c, "tts")

			require.Equal(t, http.StatusBadRequest, recorder.Code)
			evaluated, _, _ := engine.snapshot()
			require.Zero(t, evaluated)
			require.False(t, isOpsRoutingCapacityLimited(c))
		})
	}
}

func TestGrokTTSUnknownJSONObjectFieldsProceedToModelPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	h := newResponsesModelPreflightHandler(t, nil, engine)
	c, recorder := responsesModelPreflightContext(t, "/v1/tts", "placeholder")
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/tts", strings.NewReader(`{"future_tts_field":true}`))
	c.Request.Header.Set("Content-Type", "application/json")
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	require.True(t, ok)
	apiKey.Group.Platform = service.PlatformGrok

	h.GrokVoice(c, "tts")

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.True(t, isOpsRoutingCapacityLimited(c))
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}
