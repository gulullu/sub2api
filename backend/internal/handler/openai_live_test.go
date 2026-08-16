package handler

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestParseLiveCallRequestMultipartPreservesSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	session := `{"model":"gpt-live-test","delegation":{"type":"client"},"instructions":"你好"}`
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	require.NoError(t, writer.WriteField("sdp", "v=0\r\n"))
	require.NoError(t, writer.WriteField("session", session))
	require.NoError(t, writer.Close())

	request := httptest.NewRequest("POST", "/v1/live", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = request

	parsed, err := parseLiveCallRequest(context)
	require.NoError(t, err)
	require.Equal(t, "v=0\r\n", parsed.SDP)
	require.JSONEq(t, session, string(parsed.Session))
	require.Equal(t, "client", jsonPathString(t, parsed.Session, "delegation", "type"))
}

func TestParseLiveCallRequestJSONPreservesSessionWithoutDelegation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := `{"sdp":"v=0\\r\\n","session":{"model":"gpt-live-test","instructions":"standalone"}}`
	request := httptest.NewRequest("POST", "/backend-api/codex/realtime/calls", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = request

	parsed, err := parseLiveCallRequest(context)
	require.NoError(t, err)
	require.NotContains(t, string(parsed.Session), "delegation")
	require.Equal(t, "standalone", jsonPathString(t, parsed.Session, "instructions"))
}

func TestParseLiveCallRequestRejectsInvalidJSONShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	testCases := []string{
		`{"session":{"type":"quicksilver"}}`,
		`{"sdp":"v=0\\r\\n","session":[]}`,
		`{"sdp":"v=0\\r\\n","session":null}`,
		`{"sdp":"v=0\\r\\n","session":{"type":"quicksilver"}} {}`,
	}
	for _, body := range testCases {
		request := httptest.NewRequest("POST", "/backend-api/codex/realtime/calls", bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = request
		_, err := parseLiveCallRequest(context)
		require.Error(t, err)
	}
}

func TestLiveSidebandLocationMatchesCreateRoute(t *testing.T) {
	require.Equal(t, "/v1/live/call_123", liveSidebandLocation("/v1/live", "call_123"))
	require.Equal(
		t,
		"/backend-api/codex/call_123",
		liveSidebandLocation("/backend-api/codex/realtime/calls", "call_123"),
	)
}

func TestLiveEnabledForAPIKey(t *testing.T) {
	require.False(t, liveEnabledForAPIKey(nil))
	require.False(t, liveEnabledForAPIKey(&service.APIKey{}))
	require.False(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformOpenAI},
	}))
	require.False(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformAnthropic, AllowLive: true},
	}))
	require.True(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformOpenAI, AllowLive: true},
	}))
}

func TestLiveExplicitUnsupportedModelSkipsPromptAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	h := newResponsesModelPreflightHandler(t, []service.Account{{
		ID: 1, Platform: service.PlatformOpenAI, Status: service.StatusActive, Schedulable: true,
		Credentials: map[string]any{"model_mapping": map[string]any{"gpt-live-supported": "gpt-live-supported"}},
	}}, engine)
	c, recorder := responsesModelPreflightContext(t, "/v1/live", "ignored")
	c.Request = httptest.NewRequest(
		http.MethodPost,
		"/v1/live",
		bytes.NewBufferString(`{"sdp":"v=0\\r\\n","session":{"model":"gpt-live-unsupported","instructions":"hello"}}`),
	)
	c.Request.Header.Set("Content-Type", "application/json")
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	require.True(t, ok)
	apiKey.Group.AllowLive = true

	h.Live(c)

	require.Equal(t, http.StatusNotFound, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Zero(t, evaluated)
	require.True(t, service.HasOpsClientBusinessLimited(c))
}

func TestLiveOmittedModelPreservesPromptAuditPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := blockingHandlerPromptEngine()
	h := newResponsesModelPreflightHandler(t, nil, engine)
	c, recorder := responsesModelPreflightContext(t, "/v1/live", "ignored")
	c.Request = httptest.NewRequest(
		http.MethodPost,
		"/v1/live",
		bytes.NewBufferString(`{"sdp":"v=0\\r\\n","session":{"instructions":"hello"}}`),
	)
	c.Request.Header.Set("Content-Type", "application/json")
	apiKey, ok := middleware2.GetAPIKeyFromContext(c)
	require.True(t, ok)
	apiKey.Group.AllowLive = true

	h.Live(c)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	evaluated, _, _ := engine.snapshot()
	require.Equal(t, 1, evaluated)
}

func TestLiveNonStringModelPreservesPromptAuditPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, model := range []string{`123`, `true`, `{"name":"gpt-live-unsupported"}`, `null`} {
		t.Run(model, func(t *testing.T) {
			engine := blockingHandlerPromptEngine()
			h := newResponsesModelPreflightHandler(t, nil, engine)
			c, recorder := responsesModelPreflightContext(t, "/v1/live", "ignored")
			c.Request = httptest.NewRequest(
				http.MethodPost,
				"/v1/live",
				bytes.NewBufferString(`{"sdp":"v=0\\r\\n","session":{"model":`+model+`,"instructions":"hello"}}`),
			)
			c.Request.Header.Set("Content-Type", "application/json")
			apiKey, ok := middleware2.GetAPIKeyFromContext(c)
			require.True(t, ok)
			apiKey.Group.AllowLive = true

			h.Live(c)

			require.Equal(t, http.StatusForbidden, recorder.Code)
			evaluated, _, _ := engine.snapshot()
			require.Equal(t, 1, evaluated)
		})
	}
}

func TestLiveAttestationErrorIsExplicit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)

	(&OpenAIGatewayHandler{}).writeLiveCreateError(context, &service.LiveAttestationUnavailableError{
		Reason: "Live attestation is only supported when Sub2API runs on macOS",
	})

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.Contains(t, recorder.Body.String(), "Sub2API runs on macOS")
}

func TestLivePromptRiskRouteErrorsAreSafe503(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, routeErr := range []error{
		service.ErrPromptRiskRouteUnavailable,
		service.ErrPromptRiskRouteStateConflict,
	} {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)

		(&OpenAIGatewayHandler{}).writeLiveCreateError(context, routeErr)

		require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
		require.Contains(t, recorder.Body.String(), "Service temporarily unavailable")
		require.NotContains(t, recorder.Body.String(), "prompt risk route")
	}
}

func jsonPathString(t *testing.T, raw json.RawMessage, keys ...string) string {
	t.Helper()
	var value any
	require.NoError(t, json.Unmarshal(raw, &value))
	current := value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		require.True(t, ok)
		current = object[key]
	}
	result, ok := current.(string)
	require.True(t, ok)
	return result
}
