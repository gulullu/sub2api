//go:build unit

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type blockingModelScopeGroupRepo struct {
	service.GroupRepository
}

func (r *blockingModelScopeGroupRepo) GetByIDLite(ctx context.Context, _ int64) (*service.Group, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type panickingHandlerModelScopeGroupRepo struct {
	service.GroupRepository
}

func (r *panickingHandlerModelScopeGroupRepo) GetByIDLite(context.Context, int64) (*service.Group, error) {
	panic("handler model scope group lookup panic")
}

func newGenericModelPreflightHandler(
	t *testing.T,
	group *service.Group,
	accounts []service.Account,
	engine *handlerPromptEngine,
) *GatewayHandler {
	t.Helper()
	return newGenericModelPreflightHandlerWithGroupRepo(
		t,
		group,
		&fakeGroupRepo{group: group},
		accounts,
		engine,
	)
}

func newGenericModelPreflightHandlerWithGroupRepo(
	t *testing.T,
	group *service.Group,
	groupRepo service.GroupRepository,
	accounts []service.Account,
	engine *handlerPromptEngine,
) *GatewayHandler {
	t.Helper()
	cfg := &config.Config{RunMode: config.RunModeStandard}
	accountRepo := &responsesModelPreflightRepo{accounts: accounts}
	gateway := service.NewGatewayService(
		accountRepo,
		groupRepo,
		nil, nil, nil, nil, nil, nil, cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	)
	h := &GatewayHandler{gatewayService: gateway, cfg: cfg}
	h.securityAuditCoordinator = securityaudit.NewCoordinator(nil, engine)
	return h
}

func genericModelPreflightContext(
	t *testing.T,
	group *service.Group,
	path string,
	body string,
) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	user := &service.User{ID: 100, Status: service.StatusActive}
	c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
		ID: 101, UserID: user.ID, User: user, GroupID: &group.ID, Group: group,
	})
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
	return c, recorder
}

func genericPreflightAccount(groupID int64, platform, supportedModel string) service.Account {
	return service.Account{
		ID: 1, Platform: platform, Status: service.StatusActive, Schedulable: true,
		AccountGroups: []service.AccountGroup{{GroupID: groupID}},
		Credentials:   map[string]any{"model_mapping": map[string]any{supportedModel: supportedModel}},
	}
}

func TestGenericAuditedHTTPEntrypointsUnsupportedModelSkipPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name      string
		platform  string
		path      string
		body      string
		configure func(*gin.Context)
		invoke    func(*GatewayHandler, *gin.Context)
	}{
		{
			name: "responses", platform: service.PlatformAnthropic, path: "/v1/responses",
			body:   `{"model":"unsupported-model","input":"hello","stream":false}`,
			invoke: func(h *GatewayHandler, c *gin.Context) { h.Responses(c) },
		},
		{
			name: "chat_completions", platform: service.PlatformAnthropic, path: "/v1/chat/completions",
			body:   `{"model":"unsupported-model","messages":[{"role":"user","content":"hello"}]}`,
			invoke: func(h *GatewayHandler, c *gin.Context) { h.ChatCompletions(c) },
		},
		{
			name: "messages", platform: service.PlatformAnthropic, path: "/v1/messages",
			body:   `{"model":"unsupported-model","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`,
			invoke: func(h *GatewayHandler, c *gin.Context) { h.Messages(c) },
		},
		{
			name: "gemini_native", platform: service.PlatformGemini, path: "/v1beta/models/unsupported-model:generateContent",
			body: `{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`,
			configure: func(c *gin.Context) {
				c.Params = gin.Params{{Key: "modelAction", Value: "unsupported-model:generateContent"}}
			},
			invoke: func(h *GatewayHandler, c *gin.Context) { h.GeminiV1BetaModels(c) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &service.Group{ID: 12, Platform: tt.platform, Status: service.StatusActive}
			engine := blockingHandlerPromptEngine()
			h := newGenericModelPreflightHandler(t, group, []service.Account{
				genericPreflightAccount(group.ID, tt.platform, "supported-model"),
			}, engine)
			c, recorder := genericModelPreflightContext(t, group, tt.path, tt.body)
			if tt.configure != nil {
				tt.configure(c)
			}

			tt.invoke(h, c)

			require.Equal(t, http.StatusNotFound, recorder.Code)
			evaluated, _, _ := engine.snapshot()
			require.Zero(t, evaluated)
			require.True(t, service.HasOpsClientBusinessLimited(c))
		})
	}
}

func TestGenericResponsesSupportedModelRunsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	group := &service.Group{ID: 12, Platform: service.PlatformAnthropic, Status: service.StatusActive}
	engine := blockingHandlerPromptEngine()
	h := newGenericModelPreflightHandler(t, group, []service.Account{
		genericPreflightAccount(12, service.PlatformAnthropic, "supported-model"),
	}, engine)
	c, recorder := genericModelPreflightContext(
		t, group, "/v1/responses", `{"model":"supported-model","input":"hello","stream":false}`,
	)

	h.Responses(c)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Equal(t, 1, evaluated)
}

func TestGenericResponsesEmptyPersistentPoolSkipsPromptAuditWith503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	group := &service.Group{ID: 12, Platform: service.PlatformAnthropic, Status: service.StatusActive}
	engine := blockingHandlerPromptEngine()
	h := newGenericModelPreflightHandler(t, group, nil, engine)
	c, recorder := genericModelPreflightContext(
		t, group, "/v1/responses", `{"model":"any-model","input":"hello","stream":false}`,
	)

	h.Responses(c)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
	require.True(t, isOpsRoutingCapacityLimited(c))
}

func TestGenericResponsesScopeTimeoutFailsOpenIntoPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	group := &service.Group{ID: 12, Platform: service.PlatformAnthropic, Status: service.StatusActive}
	engine := blockingHandlerPromptEngine()
	h := newGenericModelPreflightHandlerWithGroupRepo(
		t,
		group,
		&blockingModelScopeGroupRepo{},
		nil,
		engine,
	)
	c, recorder := genericModelPreflightContext(
		t, group, "/v1/responses", `{"model":"any-model","input":"hello","stream":false}`,
	)
	started := time.Now()

	h.Responses(c)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Less(t, time.Since(started), 800*time.Millisecond)
	evaluated, _, _ := engine.snapshot()
	require.Equal(t, 1, evaluated)
}

func TestGenericResponsesScopeFailuresFailOpenIntoPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name      string
		group     *service.Group
		groupRepo service.GroupRepository
	}{
		{
			name:      "group_repository_panic",
			group:     &service.Group{ID: 12, Platform: service.PlatformAnthropic, Status: service.StatusActive},
			groupRepo: &panickingHandlerModelScopeGroupRepo{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			engine := blockingHandlerPromptEngine()
			h := newGenericModelPreflightHandlerWithGroupRepo(t, tt.group, tt.groupRepo, nil, engine)
			c, recorder := genericModelPreflightContext(
				t, tt.group, "/v1/responses", `{"model":"any-model","input":"hello","stream":false}`,
			)

			require.NotPanics(t, func() { h.Responses(c) })

			require.Equal(t, http.StatusForbidden, recorder.Code)
			evaluated, _, _ := engine.snapshot()
			require.Equal(t, 1, evaluated)
		})
	}
}

func TestGrokStandaloneSearchUnsupportedFixedModelSkipsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	group := &service.Group{ID: 12, Platform: service.PlatformGrok, Status: service.StatusActive}
	engine := blockingHandlerPromptEngine()
	h := newGenericModelPreflightHandler(t, group, []service.Account{
		genericPreflightAccount(group.ID, service.PlatformGrok, "some-other-model"),
	}, engine)
	c, recorder := genericModelPreflightContext(t, group, "/v1/web_search", `{"query":"hello"}`)

	h.WebSearch(c)

	require.Equal(t, http.StatusNotFound, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
	require.True(t, service.HasOpsClientBusinessLimited(c))
}

func TestGrokStandaloneSearchMissingGroupPrecedesModelPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	group := &service.Group{ID: 12, Platform: service.PlatformGrok, Status: service.StatusActive}
	engine := blockingHandlerPromptEngine()
	h := newGenericModelPreflightHandler(t, group, nil, engine)
	c, recorder := genericModelPreflightContext(t, group, "/v1/web_search", `{"query":"hello"}`)
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	require.True(t, ok)
	apiKey.GroupID = nil

	h.WebSearch(c)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "group required")
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
	require.False(t, isOpsRoutingCapacityLimited(c))
}
