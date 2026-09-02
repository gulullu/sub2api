//go:build unit

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type handlerPromptEngine struct {
	mu sync.Mutex

	mode      securityaudit.Mode
	decision  *securityaudit.PromptDecision
	err       error
	evaluated int
	enqueued  int
	requests  []securityaudit.Request
}

func (e *handlerPromptEngine) EffectiveMode() securityaudit.Mode { return e.mode }
func (e *handlerPromptEngine) Enqueue(_ context.Context, req securityaudit.Request) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enqueued++
	e.requests = append(e.requests, req.Clone())
	return e.err
}
func (e *handlerPromptEngine) Evaluate(_ context.Context, req securityaudit.Request) (*securityaudit.PromptDecision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evaluated++
	e.requests = append(e.requests, req.Clone())
	return e.decision, e.err
}
func (e *handlerPromptEngine) snapshot() (evaluated, enqueued int, requests []securityaudit.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	requests = make([]securityaudit.Request, len(e.requests))
	copy(requests, e.requests)
	return e.evaluated, e.enqueued, requests
}

func securityAuditMediaTestMiddleware(c *gin.Context) {
	groupID := int64(3)
	user := &service.User{ID: 7, Username: "media-user", Email: "media@example.test"}
	c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
		ID: 9, UserID: 7, User: user, Name: "media-key", GroupID: &groupID,
		Group: &service.Group{ID: groupID, Name: "media-group", Platform: service.PlatformOpenAI, AllowImageGeneration: true},
	})
	c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: 7, Concurrency: 2})
	c.Next()
}

func blockingHandlerPromptEngine() *handlerPromptEngine {
	return &handlerPromptEngine{mode: securityaudit.ModeBlocking, decision: &securityaudit.PromptDecision{
		Kind: securityaudit.DecisionBlock, ErrorCode: securityaudit.ErrorCodeBlocked, AllowNextStage: false,
	}}
}

type batchImageModelPreflightRepo struct {
	service.AccountRepository
	accounts []service.Account
}

type batchImageNoopPublicRepo struct {
	service.BatchImageRepository
}

func (r *batchImageModelPreflightRepo) ListModelAvailabilityCandidates(
	context.Context,
	*int64,
	[]string,
	bool,
) ([]service.Account, error) {
	return append([]service.Account(nil), r.accounts...), nil
}

func TestAsyncImagePromptGuardRunsBeforeTaskCreation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &asyncImageMemoryStore{tasks: map[string]*service.ImageTaskRecord{}}
	tasks := service.NewImageTaskServiceWithUploader(store, nil, time.Hour, time.Minute)
	engine := blockingHandlerPromptEngine()
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	h := &AsyncImageHandler{tasks: tasks, openAI: openAI}
	executions := 0
	h.execute = func(string, *gin.Context) { executions++ }

	router := gin.New()
	router.Use(securityAuditMediaTestMiddleware)
	router.POST("/v1/images/generations/async", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/generations/async", strings.NewReader(`{"model":"gpt-image-2","prompt":"blocked async prompt"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Contains(t, recorder.Body.String(), securityaudit.ErrorCodeBlocked)
	require.Empty(t, store.tasks, "no asynchronous task may exist after a blocking decision")
	require.Zero(t, executions)
	evaluated, _, requests := engine.snapshot()
	require.Equal(t, 1, evaluated)
	require.Len(t, requests, 1)
	require.Contains(t, string(requests[0].Body), "blocked async prompt")
}

func TestAsyncImageUnsupportedModelSkipsPromptAuditAndTaskCreation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &asyncImageMemoryStore{tasks: map[string]*service.ImageTaskRecord{}}
	tasks := service.NewImageTaskServiceWithUploader(store, nil, time.Hour, time.Minute)
	engine := blockingHandlerPromptEngine()
	openAI := newResponsesModelPreflightHandler(t, []service.Account{{
		ID: 1, Platform: service.PlatformOpenAI, Status: service.StatusActive, Schedulable: true,
		Credentials: map[string]any{"model_mapping": map[string]any{"gpt-image-supported": "gpt-image-supported"}},
	}}, engine)
	h := &AsyncImageHandler{tasks: tasks, openAI: openAI}
	h.execute = func(string, *gin.Context) { t.Error("unsupported request must not start detached execution") }

	router := gin.New()
	router.Use(securityAuditMediaTestMiddleware)
	router.POST("/v1/images/generations/async", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/generations/async", strings.NewReader(`{"model":"gpt-image-unsupported","prompt":"must not be audited"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.Empty(t, store.tasks)
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}

func TestAsyncImageSuccessfulPrecheckIsNotRepeatedByDetachedExecution(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := &asyncImageMemoryStore{tasks: map[string]*service.ImageTaskRecord{}}
	tasks := service.NewImageTaskServiceWithUploader(store, nil, time.Hour, time.Minute)
	engine := &handlerPromptEngine{mode: securityaudit.ModeBlocking, decision: &securityaudit.PromptDecision{Kind: securityaudit.DecisionAllow, AllowNextStage: true}}
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	h := &AsyncImageHandler{tasks: tasks, openAI: openAI}
	var executionMu sync.Mutex
	repeatedDecision := false
	h.execute = func(_ string, c *gin.Context) {
		apiKey, _ := middleware2.GetAPIKeyFromContext(c)
		subject, _ := middleware2.GetAuthSubjectFromContext(c)
		decision := openAI.checkSecurityAudit(c, nil, apiKey, subject, service.ContentModerationProtocolOpenAIImages, "gpt-image-2", []byte(`{"prompt":"must not rescan"}`))
		executionMu.Lock()
		repeatedDecision = decision != nil
		executionMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"created": 1, "data": []any{}})
	}

	router := gin.New()
	router.Use(securityAuditMediaTestMiddleware)
	router.POST("/v1/images/generations/async", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/generations/async", strings.NewReader(`{"model":"gpt-image-2","prompt":"allowed async prompt"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusAccepted, recorder.Code)
	require.Eventually(t, func() bool {
		store.mu.RLock()
		defer store.mu.RUnlock()
		for _, task := range store.tasks {
			if task.Status == service.ImageTaskStatusCompleted {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
	evaluated, _, _ := engine.snapshot()
	require.Equal(t, 1, evaluated)
	executionMu.Lock()
	require.False(t, repeatedDecision)
	executionMu.Unlock()
}

func TestBatchImagePromptGuardRunsBeforePersistenceOrBilling(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	h := &BatchImageHandler{openAI: openAI}
	router := gin.New()
	router.Use(securityAuditMediaTestMiddleware)
	router.POST("/v1/images/batches", h.Submit)
	body := map[string]any{
		"model": "gemini-image-test",
		"items": []map[string]any{{
			"custom_id": "one", "prompt": "blocked batch prompt",
			"reference_images": []map[string]any{{"mime_type": "image/png", "data": []byte("BINARY_CANARY")}},
		}},
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/batches", strings.NewReader(string(raw)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	require.NotPanics(t, func() { router.ServeHTTP(recorder, request) }, "nil service would panic if Submit were reached")
	require.Equal(t, http.StatusForbidden, recorder.Code)
	evaluated, _, requests := engine.snapshot()
	require.Equal(t, 1, evaluated)
	require.Len(t, requests, 1)
	require.Contains(t, string(requests[0].Body), "blocked batch prompt")
	require.NotContains(t, string(requests[0].Body), "BINARY_CANARY")
	require.NotContains(t, string(requests[0].Body), "QklOQVJZX0NBTkFSWQ==")
}

func TestBatchImageUnsupportedModelSkipsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	batchService := &service.BatchImagePublicService{
		Repo: &batchImageNoopPublicRepo{},
		AccountRepo: &batchImageModelPreflightRepo{accounts: []service.Account{{
			ID: 1, Platform: service.PlatformGemini, Status: service.StatusActive, Schedulable: true,
			Credentials: map[string]any{"model_mapping": map[string]any{"gemini-supported": "gemini-supported"}},
		}}},
		Config: &config.Config{BatchImage: config.BatchImageConfig{Enabled: true}},
	}
	h := &BatchImageHandler{service: batchService, openAI: openAI}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		groupID := int64(3)
		user := &service.User{ID: 7}
		c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
			ID: 9, UserID: user.ID, User: user, GroupID: &groupID,
			Group: &service.Group{ID: groupID, Platform: service.PlatformGemini, AllowBatchImageGeneration: true},
		})
		c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
		c.Next()
	})
	router.POST("/v1/images/batches", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/batches", strings.NewReader(`{
		"model":"gemini-unsupported",
		"items":[{"custom_id":"one","prompt":"must not be audited"}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.Contains(t, recorder.Body.String(), "MODEL_NOT_FOUND")
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}

func TestBatchImageEmptyPersistentPoolSkipsPromptAuditWithCapacityError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	batchService := &service.BatchImagePublicService{
		Repo:        &batchImageNoopPublicRepo{},
		AccountRepo: &batchImageModelPreflightRepo{},
		Config:      &config.Config{BatchImage: config.BatchImageConfig{Enabled: true}},
	}
	h := &BatchImageHandler{service: batchService, openAI: openAI}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		groupID := int64(3)
		user := &service.User{ID: 7}
		c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
			ID: 9, UserID: user.ID, User: user, GroupID: &groupID,
			Group: &service.Group{ID: groupID, Platform: service.PlatformGemini, AllowBatchImageGeneration: true},
		})
		c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
		c.Next()
	})
	router.POST("/v1/images/batches", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/batches", strings.NewReader(`{
		"model":"gemini-any",
		"items":[{"custom_id":"one","prompt":"must not be audited"}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.Contains(t, recorder.Body.String(), "BATCH_IMAGE_NO_ACCOUNT_AVAILABLE")
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}

func TestBatchImageGroupGatePrecedesModelPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, group := range []*service.Group{
		{ID: 3, Platform: service.PlatformGemini, AllowBatchImageGeneration: false},
		{ID: 3, Platform: service.PlatformOpenAI, AllowBatchImageGeneration: true},
	} {
		t.Run(group.Platform, func(t *testing.T) {
			engine := blockingHandlerPromptEngine()
			openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
			batchService := &service.BatchImagePublicService{
				Repo:        &batchImageNoopPublicRepo{},
				AccountRepo: &batchImageModelPreflightRepo{},
				Config:      &config.Config{BatchImage: config.BatchImageConfig{Enabled: true}},
			}
			h := &BatchImageHandler{service: batchService, openAI: openAI}
			router := gin.New()
			router.Use(func(c *gin.Context) {
				user := &service.User{ID: 7}
				c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
					ID: 9, UserID: user.ID, User: user, GroupID: &group.ID, Group: group,
				})
				c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
				c.Next()
			})
			router.POST("/v1/images/batches", h.Submit)
			request := httptest.NewRequest(http.MethodPost, "/v1/images/batches", strings.NewReader(`{
				"model":"gemini-any",
				"items":[{"custom_id":"one","prompt":"must not be audited"}]
			}`))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			require.Equal(t, http.StatusForbidden, recorder.Code)
			require.Contains(t, recorder.Body.String(), "BATCH_IMAGE_GROUP_DISABLED")
			evaluated, _, _ := engine.snapshot()
			require.Zero(t, evaluated)
		})
	}
}

func TestBatchImageDisabledFeaturePrecedesModelPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := &handlerPromptEngine{mode: securityaudit.ModeBlocking, decision: &securityaudit.PromptDecision{
		Kind: securityaudit.DecisionAllow, AllowNextStage: true,
	}}
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	batchService := &service.BatchImagePublicService{
		Repo:        &batchImageNoopPublicRepo{},
		AccountRepo: &batchImageModelPreflightRepo{},
		Config:      &config.Config{BatchImage: config.BatchImageConfig{Enabled: false}},
	}
	h := &BatchImageHandler{service: batchService, openAI: openAI}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		groupID := int64(3)
		user := &service.User{ID: 7}
		c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
			ID: 9, UserID: user.ID, User: user, GroupID: &groupID,
			Group: &service.Group{ID: groupID, Platform: service.PlatformGemini, AllowBatchImageGeneration: true},
		})
		c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
		c.Next()
	})
	router.POST("/v1/images/batches", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/batches", strings.NewReader(`{
		"model":"gemini-any",
		"items":[{"custom_id":"one","prompt":"allowed audit"}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusNotFound, recorder.Code)
	require.Contains(t, recorder.Body.String(), "BATCH_IMAGE_DISABLED")
	require.NotContains(t, recorder.Body.String(), "MODEL_NOT_FOUND")
	require.NotContains(t, recorder.Body.String(), "BATCH_IMAGE_NO_ACCOUNT_AVAILABLE")
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}

func TestBatchImageEmptyPromptValidationPrecedesModelPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	openAI := &OpenAIGatewayHandler{securityAuditCoordinator: securityaudit.NewCoordinator(nil, engine)}
	batchService := &service.BatchImagePublicService{
		Repo:        &batchImageNoopPublicRepo{},
		AccountRepo: &batchImageModelPreflightRepo{},
		Config:      &config.Config{BatchImage: config.BatchImageConfig{Enabled: true}},
	}
	h := &BatchImageHandler{service: batchService, openAI: openAI}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		groupID := int64(3)
		user := &service.User{ID: 7}
		c.Set(string(middleware2.ContextKeyAPIKey), &service.APIKey{
			ID: 9, UserID: user.ID, User: user, GroupID: &groupID,
			Group: &service.Group{ID: groupID, Platform: service.PlatformGemini, AllowBatchImageGeneration: true},
		})
		c.Set(string(middleware2.ContextKeyUser), middleware2.AuthSubject{UserID: user.ID, Concurrency: 1})
		c.Next()
	})
	router.POST("/v1/images/batches", h.Submit)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/batches", strings.NewReader(`{
		"model":"gemini-any",
		"items":[{"custom_id":"one","prompt":"   "}]
	}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "BATCH_IMAGE_INVALID_ITEMS")
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
}

func TestSecurityAuditBlockingFailuresLeaveAllDownstreamCountersAtZero(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, kind := range []securityaudit.DecisionKind{securityaudit.DecisionBlock, securityaudit.DecisionUnavailable, securityaudit.DecisionInvalid} {
		t.Run(string(kind), func(t *testing.T) {
			promptDecision := promptGuardDecision(kind)
			engine := &handlerPromptEngine{mode: securityaudit.ModeBlocking, decision: &securityaudit.PromptDecision{
				Kind: kind, ErrorCode: promptDecision.ErrorCode, AllowNextStage: false,
			}}
			coordinator := securityaudit.NewCoordinator(nil, engine)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-test","messages":[{"role":"user","content":"guard me"}]}`))
			groupID := int64(3)
			apiKey := &service.APIKey{ID: 9, UserID: 7, GroupID: &groupID, Group: &service.Group{ID: groupID, Platform: service.PlatformOpenAI}}
			subject := middleware2.AuthSubject{UserID: 7, Concurrency: 2}
			decision := runSecurityAudit(c, nil, coordinator, nil, apiKey, subject, service.ContentModerationProtocolOpenAIChat, "gpt-test", []byte(`{"messages":[{"role":"user","content":"guard me"}]}`), "http")
			require.NotNil(t, decision)
			require.False(t, decision.AllowNextStage)
			require.False(t, recorder.Result().Header.Get("Content-Type") != "", "Guard evaluation itself must not start SSE/HTTP output")

			accountSelections, billingChecks, billingPreconsumes, upstreamDispatches := 0, 0, 0, 0
			if decision.AllowNextStage {
				accountSelections++
				billingChecks++
				billingPreconsumes++
				upstreamDispatches++
			}
			require.Zero(t, accountSelections)
			require.Zero(t, billingChecks)
			require.Zero(t, billingPreconsumes)
			require.Zero(t, upstreamDispatches)
			(&OpenAIGatewayHandler{}).openAISecurityAuditError(c, decision)
			require.Equal(t, promptDecision.HTTPStatus, recorder.Code)
		})
	}
}
