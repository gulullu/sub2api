package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestIsKnownOpenAIOAuthModelWithoutResponsesLiteUsesFinalCanonicalModel(t *testing.T) {
	for _, model := range []string{
		"gpt-5.3-codex-spark",
		"openai/gpt-5.3-codex-spark-xhigh",
		"gpt-5.4",
		"gpt-5.4-high",
		"gpt-5.4-mini",
		"gpt-5.5",
		"gpt-5.5-xhigh",
		"codex-auto-review",
	} {
		require.True(t, isKnownOpenAIOAuthModelWithoutResponsesLite(model), model)
	}
	for _, model := range []string{
		"",
		"gpt-5.3-codex",
		"gpt-5.4-nano",
		"gpt-5.5-pro",
		"gpt-5.6-sol",
		"gpt-5.6-terra",
		"gpt-5.6-luna",
		"codex-auto-review-preview",
		"unknown-model",
	} {
		require.False(t, isKnownOpenAIOAuthModelWithoutResponsesLite(model), model)
	}
}

func TestIsKnownOpenAIAccountModelWithoutResponsesLiteUsesAccountSpecificExactSets(t *testing.T) {
	oauth := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	apiKey := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	for _, model := range []string{"gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "codex-auto-review"} {
		require.True(t, isKnownOpenAIAccountModelWithoutResponsesLite(oauth, model), model)
	}
	require.False(t, isKnownOpenAIAccountModelWithoutResponsesLite(oauth, "codex-auto-review-preview"))
	require.False(t, isKnownOpenAIAccountModelWithoutResponsesLite(oauth, "gpt-5.6-terra"))
	for _, model := range []string{"gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"} {
		require.True(t, isKnownOpenAIAccountModelWithoutResponsesLite(apiKey, model), model)
	}
	require.False(t, isKnownOpenAIAccountModelWithoutResponsesLite(apiKey, "gpt-5.5-pro"))
	require.False(t, isKnownOpenAIAccountModelWithoutResponsesLite(apiKey, "codex-auto-review"))
	require.False(t, isKnownOpenAIAccountModelWithoutResponsesLite(&Account{Platform: PlatformGrok, Type: AccountTypeAPIKey}, "gpt-5.5"))
}

func TestNormalizeOpenAIRequiredClientToolSearchChoiceIsExact(t *testing.T) {
	openAIAPIKey := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	grokOAuth := &Account{Platform: PlatformGrok, Type: AccountTypeOAuth}
	tests := []struct {
		name        string
		account     *Account
		body        string
		wantChanged bool
		wantChoice  string
	}{
		{
			name:        "single client tool search",
			account:     openAIAPIKey,
			body:        `{"tools":[{"type":"tool_search","execution":"client"}],"tool_choice":"required"}`,
			wantChanged: true,
			wantChoice:  "auto",
		},
		{
			name:        "multiple client tool searches",
			account:     openAIAPIKey,
			body:        `{"tools":[{"type":"tool_search","execution":"client"},{"type":"tool_search","execution":"client","name":"other"}],"tool_choice":"required"}`,
			wantChanged: true,
			wantChoice:  "auto",
		},
		{
			name:       "mixed function preserves required",
			account:    openAIAPIKey,
			body:       `{"tools":[{"type":"tool_search","execution":"client"},{"type":"function","name":"run"}],"tool_choice":"required"}`,
			wantChoice: "required",
		},
		{
			name:       "server tool search preserves required",
			account:    openAIAPIKey,
			body:       `{"tools":[{"type":"tool_search","execution":"server"}],"tool_choice":"required"}`,
			wantChoice: "required",
		},
		{
			name:       "missing execution preserves required",
			account:    openAIAPIKey,
			body:       `{"tools":[{"type":"tool_search"}],"tool_choice":"required"}`,
			wantChoice: "required",
		},
		{
			name:       "empty tools preserves required",
			account:    openAIAPIKey,
			body:       `{"tools":[],"tool_choice":"required"}`,
			wantChoice: "required",
		},
		{
			name:       "object choice is untouched",
			account:    openAIAPIKey,
			body:       `{"tools":[{"type":"tool_search","execution":"client"}],"tool_choice":{"type":"tool_search"}}`,
			wantChoice: "",
		},
		{
			name:       "non OpenAI account is untouched",
			account:    grokOAuth,
			body:       `{"tools":[{"type":"tool_search","execution":"client"}],"tool_choice":"required"}`,
			wantChoice: "required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed, err := normalizeOpenAIRequiredClientToolSearchChoice(tt.account, []byte(tt.body))
			require.NoError(t, err)
			require.Equal(t, tt.wantChanged, changed)
			if tt.wantChoice == "" {
				require.True(t, gjson.GetBytes(got, "tool_choice").IsObject())
			} else {
				require.Equal(t, tt.wantChoice, gjson.GetBytes(got, "tool_choice").String())
			}
		})
	}
}

func TestNormalizeOpenAIResponsesLiteWSPayloadForFinalModel(t *testing.T) {
	markerPath := "client_metadata." + responsesLiteWSMetadataKey
	basePayload := []byte(`{
		"type":"response.create",
		"model":"client-model",
		"client_metadata":{"trace":"keep","ws_request_header_x_openai_internal_codex_responses_lite":"true"},
		"tools":[{"type":"namespace","name":"collaboration"}],
		"input":"hello"
	}`)
	oauth := &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	apiKey := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}

	spark, changed, err := normalizeOpenAIResponsesLiteWSPayloadForModel(oauth, basePayload, "gpt-5.3-codex-spark")
	require.NoError(t, err)
	require.True(t, changed)
	require.False(t, gjson.GetBytes(spark, markerPath).Exists())
	require.Equal(t, "keep", gjson.GetBytes(spark, "client_metadata.trace").String())
	require.Equal(t, "collaboration", gjson.GetBytes(spark, `tools.#(type=="namespace").name`).String())
	require.False(t, gjson.GetBytes(spark, `input.#(type=="additional_tools")`).Exists())
	require.False(t, gjson.GetBytes(spark, "reasoning.context").Exists())

	terra, changed, err := normalizeOpenAIResponsesLiteWSPayloadForModel(oauth, basePayload, "gpt-5.6-terra")
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, "true", gjson.GetBytes(terra, markerPath).String())
	require.False(t, gjson.GetBytes(terra, `tools.#(type=="namespace")`).Exists())
	require.Equal(t, "collaboration", gjson.GetBytes(terra, `input.#(type=="additional_tools").tools.0.name`).String())
	require.Equal(t, "all_turns", gjson.GetBytes(terra, "reasoning.context").String())

	apiKeySpark, changed, err := normalizeOpenAIResponsesLiteWSPayloadForModel(apiKey, basePayload, "gpt-5.3-codex-spark")
	require.NoError(t, err)
	require.True(t, changed)
	require.False(t, gjson.GetBytes(apiKeySpark, markerPath).Exists())
	require.Equal(t, "keep", gjson.GetBytes(apiKeySpark, "client_metadata.trace").String())
	require.Equal(t, "collaboration", gjson.GetBytes(apiKeySpark, `tools.#(type=="namespace").name`).String())
	require.False(t, gjson.GetBytes(apiKeySpark, `input.#(type=="additional_tools")`).Exists())

	apiKeyUnknown, changed, err := normalizeOpenAIResponsesLiteWSPayloadForModel(apiKey, basePayload, "custom-model")
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, string(basePayload), string(apiKeyUnknown))
}

func TestOpenAIHTTPBuildersNormalizeRequiredClientToolSearchAndStripKnownNonLiteAPIKeyHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(responsesLiteHeader, "true")
	account := &Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":  "sk-test",
			"base_url": "https://upstream.example",
		},
	}
	svc := &OpenAIGatewayService{cfg: &config.Config{}}
	body := []byte(`{"model":"gpt-5.5","tools":[{"type":"tool_search","execution":"client"}],"tool_choice":"required"}`)

	builders := []struct {
		name  string
		build func() (*http.Request, error)
	}{
		{
			name: "managed",
			build: func() (*http.Request, error) {
				return svc.buildUpstreamRequest(context.Background(), c, account, body, "sk-test", false, "", false)
			},
		},
		{
			name: "passthrough",
			build: func() (*http.Request, error) {
				return svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, account, body, "sk-test")
			},
		},
	}
	for _, tt := range builders {
		t.Run(tt.name, func(t *testing.T) {
			req, err := tt.build()
			require.NoError(t, err)
			requestBody, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, "auto", gjson.GetBytes(requestBody, "tool_choice").String())
			require.Empty(t, req.Header.Get(responsesLiteHeader))
			require.Equal(t, "true", c.Request.Header.Get(responsesLiteHeader))
		})
	}
}

func TestOpenAIGatewayResponsesLiteAttemptStateDoesNotLeakAcrossMappedOAuthFailover(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, order := range []struct {
		name   string
		models []string
	}{
		{name: "nonlite then lite", models: []string{"gpt-5.3-codex-spark", "gpt-5.6-terra"}},
		{name: "lite then nonlite", models: []string{"gpt-5.6-terra", "gpt-5.3-codex-spark"}},
	} {
		t.Run(order.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Request.Header.Set("User-Agent", "codex_cli_rs/0.147.0")
			c.Request.Header.Set(responsesLiteHeader, "true")
			upstream := &httpUpstreamRecorder{responses: []*http.Response{
				openAICompatCaptureErrorResponse(), openAICompatCaptureErrorResponse(),
			}}
			svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			canonicalBody := []byte(`{
				"model":"client-model","stream":false,"instructions":"test",
				"tools":[{"type":"namespace","name":"collaboration"}],
				"input":[{"type":"message","role":"user","content":"hello"}]
			}`)

			for index, model := range order.models {
				account := openAICompatOAuthAccount(int64(index+1), "client-model", model, false)
				_, err := svc.Forward(context.Background(), c, account, canonicalBody)
				require.Error(t, err)
			}

			require.Len(t, upstream.requests, 2)
			require.Len(t, upstream.bodies, 2)
			for index, model := range order.models {
				require.Equal(t, model, gjson.GetBytes(upstream.bodies[index], "model").String())
				if isKnownOpenAIOAuthModelWithoutResponsesLite(model) {
					require.Empty(t, upstream.requests[index].Header.Get(responsesLiteHeader))
					require.Equal(t, "collaboration", gjson.GetBytes(upstream.bodies[index], `tools.#(type=="namespace").name`).String())
					require.False(t, gjson.GetBytes(upstream.bodies[index], `input.#(type=="additional_tools")`).Exists())
				} else {
					require.Equal(t, "true", upstream.requests[index].Header.Get(responsesLiteHeader))
					require.False(t, gjson.GetBytes(upstream.bodies[index], `tools.#(type=="namespace")`).Exists())
					require.Equal(t, "collaboration", gjson.GetBytes(upstream.bodies[index], `input.#(type=="additional_tools").tools.0.name`).String())
				}
			}
			require.Equal(t, "client-model", gjson.GetBytes(canonicalBody, "model").String())
			require.Equal(t, "true", c.Request.Header.Get(responsesLiteHeader))
		})
	}
}

func TestOpenAIGatewayResponsesLiteAttemptStateDoesNotLeakBetweenOAuthAndAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, reverse := range []bool{false, true} {
		name := "apikey nonlite then oauth lite"
		accounts := []*Account{
			openAICompatAPIKeyAccount(31, "client-model", "gpt-5.5"),
			openAICompatOAuthAccount(32, "client-model", "gpt-5.6-terra", false),
		}
		if reverse {
			name = "oauth lite then apikey nonlite"
			accounts[0], accounts[1] = accounts[1], accounts[0]
		}
		t.Run(name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Request.Header.Set(responsesLiteHeader, "true")
			upstream := &httpUpstreamRecorder{responses: []*http.Response{
				openAICompatCaptureErrorResponse(), openAICompatCaptureErrorResponse(),
			}}
			svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			canonicalBody := []byte(`{"model":"client-model","stream":false,"instructions":"test","input":"hi"}`)

			for _, account := range accounts {
				_, err := svc.Forward(context.Background(), c, account, canonicalBody)
				require.Error(t, err)
			}

			require.Len(t, upstream.requests, 2)
			for index, account := range accounts {
				model := gjson.GetBytes(upstream.bodies[index], "model").String()
				if account.Type == AccountTypeAPIKey {
					require.Equal(t, "gpt-5.5", model)
					require.Empty(t, upstream.requests[index].Header.Get(responsesLiteHeader))
				} else {
					require.Equal(t, "gpt-5.6-terra", model)
					require.Equal(t, "true", upstream.requests[index].Header.Get(responsesLiteHeader))
				}
			}
			require.Equal(t, "client-model", gjson.GetBytes(canonicalBody, "model").String())
			require.Equal(t, "true", c.Request.Header.Get(responsesLiteHeader))
		})
	}
}

func TestOpenAIGatewayResponsesLiteKnownNonLitePassthroughStripsOnlyOutboundHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set(responsesLiteHeader, "true")
	upstream := &httpUpstreamRecorder{resp: openAICompatCaptureErrorResponse()}
	svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
	account := openAICompatOAuthAccount(11, "", "", true)
	body := []byte(`{"model":"gpt-5.5","stream":false,"instructions":"test","tools":[{"type":"namespace","name":"collaboration"}],"input":"hi"}`)

	_, err := svc.Forward(context.Background(), c, account, body)
	require.Error(t, err)
	require.Empty(t, upstream.lastReq.Header.Get(responsesLiteHeader))
	require.Equal(t, "true", c.Request.Header.Get(responsesLiteHeader))
	require.Equal(t, "collaboration", gjson.GetBytes(upstream.lastBody, `tools.#(type=="namespace").name`).String())
	require.False(t, gjson.GetBytes(upstream.lastBody, `input.#(type=="additional_tools")`).Exists())
}

func TestOpenAIWSPassthroughNormalizesRequiredClientToolSearchForAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	upstream := newStagedPassthroughConn()
	controlCtx, cancelControl := context.WithCancel(context.Background())
	defer cancelControl()
	server, serverErr := startPassthroughLifecycleServer(
		t,
		controlCtx,
		newPassthroughLifecycleService(passthroughLifecycleConfig(), upstream),
		passthroughLifecycleAccount(),
	)
	defer server.Close()

	dialCtx, cancelDial := context.WithTimeout(context.Background(), 3*time.Second)
	clientConn, _, err := coderws.Dial(dialCtx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	cancelDial()
	require.NoError(t, err)
	defer func() { _ = clientConn.CloseNow() }()

	payload := []byte(`{
		"type":"response.create","model":"gpt-5.5","stream":false,
		"client_metadata":{"ws_request_header_x_openai_internal_codex_responses_lite":"true"},
		"tools":[{"type":"tool_search","execution":"client"}],
		"tool_choice":"required"
	}`)
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 3*time.Second)
	err = clientConn.Write(writeCtx, coderws.MessageText, payload)
	cancelWrite()
	require.NoError(t, err)

	forwarded := requirePassthroughUpstreamWrite(t, upstream, time.Second)
	require.Equal(t, "auto", gjson.GetBytes(forwarded, "tool_choice").String())
	require.False(t, gjson.GetBytes(forwarded, "client_metadata."+responsesLiteWSMetadataKey).Exists())

	upstream.Send(`{"type":"response.completed","response":{"id":"resp_apikey_required","model":"gpt-5.5","usage":{"input_tokens":1,"output_tokens":1}}}`)
	response, err := readPassthroughLifecycleFrame(t, clientConn, 3*time.Second)
	require.NoError(t, err)
	require.Equal(t, "resp_apikey_required", gjson.GetBytes(response, "response.id").String())
	_ = clientConn.Close(coderws.StatusNormalClosure, "done")

	select {
	case err := <-serverErr:
		if err != nil {
			require.Contains(t, err.Error(), "StatusNormalClosure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiting for API key passthrough websocket shutdown timed out")
	}
}

func TestOpenAIWSHTTPBridgeFinalLiteHeaderGuard(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		model      string
		wantHeader string
	}{
		{model: "gpt-5.3-codex-spark"},
		{model: "gpt-5.5"},
		{model: "gpt-5.6-terra", wantHeader: "true"},
	} {
		t.Run(tt.model, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
			upstream := &httpUpstreamRecorder{resp: openAICompatCaptureErrorResponse()}
			svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			account := openAICompatOAuthAccount(20, "", "", false)
			payload := []byte(`{"type":"response.create","model":"` + tt.model + `","stream":true,"instructions":"test","client_metadata":{"ws_request_header_x_openai_internal_codex_responses_lite":"true"},"input":"hi"}`)

			_, err := svc.proxyOpenAIWSHTTPBridgeTurn(
				context.Background(), c, account, "oauth-token", payload, len(payload),
				tt.model, "", "", "", "", 2, func([]byte) error { return nil },
			)
			require.Error(t, err)
			require.Equal(t, tt.wantHeader, upstream.lastReq.Header.Get(responsesLiteHeader))
		})
	}
}

func TestOpenAIWSHTTPBridgeFinalLiteHeaderGuardForAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		model      string
		wantHeader string
	}{
		{model: "gpt-5.5"},
		{model: "gpt-5.6-sol"},
		{model: "custom-model", wantHeader: "true"},
	} {
		t.Run(tt.model, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil)
			upstream := &httpUpstreamRecorder{resp: openAICompatCaptureErrorResponse()}
			svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			account := &Account{
				ID: 21, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Concurrency: 1,
				Credentials: map[string]any{"api_key": "sk-test"},
			}
			payload := []byte(`{"type":"response.create","model":"` + tt.model + `","stream":true,"client_metadata":{"ws_request_header_x_openai_internal_codex_responses_lite":"true"},"input":"hi"}`)

			_, err := svc.proxyOpenAIWSHTTPBridgeTurn(
				context.Background(), c, account, "sk-test", payload, len(payload),
				tt.model, "", "", "", "", 2, func([]byte) error { return nil },
			)
			require.Error(t, err)
			require.Equal(t, tt.wantHeader, upstream.lastReq.Header.Get(responsesLiteHeader))
		})
	}
}

func openAICompatOAuthAccount(id int64, requestedModel, mappedModel string, passthrough bool) *Account {
	credentials := map[string]any{
		"access_token":       "oauth-token",
		"chatgpt_account_id": "chatgpt-account",
	}
	if requestedModel != "" {
		credentials["model_mapping"] = map[string]any{requestedModel: mappedModel}
	}
	return &Account{
		ID:          id,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Concurrency: 1,
		Status:      StatusActive,
		Schedulable: true,
		Credentials: credentials,
		Extra:       map[string]any{"openai_passthrough": passthrough},
	}
}

func openAICompatAPIKeyAccount(id int64, requestedModel, mappedModel string) *Account {
	return &Account{
		ID:          id,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Concurrency: 1,
		Status:      StatusActive,
		Schedulable: true,
		Credentials: map[string]any{
			"api_key":       "sk-test",
			"base_url":      "https://upstream.example",
			"model_mapping": map[string]any{requestedModel: mappedModel},
		},
		Extra: map[string]any{"openai_responses_supported": true},
	}
}

func openAICompatCaptureErrorResponse() *http.Response {
	return &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"type":"invalid_request_error","message":"captured"}}`)),
	}
}
