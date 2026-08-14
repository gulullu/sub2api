package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestNormalizeCodexSparkReasoningContextForUpstream(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		body        string
		wantChanged bool
		wantContext string
	}{
		{
			name:        "Spark all turns",
			model:       "gpt-5.3-codex-spark",
			body:        `{"reasoning":{"effort":"high","context":"all_turns"}}`,
			wantChanged: true,
			wantContext: "current_turn",
		},
		{
			name:        "Spark mapped model with payload model omitted",
			model:       "gpt-5.3-codex-spark",
			body:        `{"type":"response.create","reasoning":{"context":"all_turns"}}`,
			wantChanged: true,
			wantContext: "current_turn",
		},
		{
			name:        "Spark auto",
			model:       "gpt-5.3-codex-spark",
			body:        `{"reasoning":{"context":"auto"}}`,
			wantContext: "auto",
		},
		{
			name:        "Spark current turn",
			model:       "gpt-5.3-codex-spark",
			body:        `{"reasoning":{"context":"current_turn"}}`,
			wantContext: "current_turn",
		},
		{
			name:  "Spark missing context",
			model: "gpt-5.3-codex-spark",
			body:  `{"reasoning":{"effort":"high"}}`,
		},
		{
			name:        "non Spark all turns",
			model:       "gpt-5.6-sol",
			body:        `{"reasoning":{"context":"all_turns"}}`,
			wantContext: "all_turns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updated, changed, err := normalizeCodexSparkReasoningContextForUpstream([]byte(tt.body), tt.model)

			require.NoError(t, err)
			require.Equal(t, tt.wantChanged, changed)
			require.Equal(t, tt.wantContext, gjson.GetBytes(updated, "reasoning.context").String())
			if strings.Contains(tt.body, `"effort":"high"`) {
				require.Equal(t, "high", gjson.GetBytes(updated, "reasoning.effort").String())
			}
		})
	}
}

func TestOpenAIGatewayServiceForward_NormalizesResponsesLiteReasoningForSpark(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		passthrough  bool
		requestModel string
		modelMapping map[string]any
		wantModel    string
		wantContext  string
	}{
		{
			name:         "managed Spark",
			requestModel: "gpt-5.3-codex-spark",
			wantModel:    "gpt-5.3-codex-spark",
			wantContext:  "current_turn",
		},
		{
			name:         "passthrough Spark",
			passthrough:  true,
			requestModel: "gpt-5.3-codex-spark",
			wantModel:    "gpt-5.3-codex-spark",
			wantContext:  "current_turn",
		},
		{
			name:         "managed alias mapped to Spark",
			requestModel: "spark-alias",
			modelMapping: map[string]any{"spark-alias": "gpt-5.3-codex-spark"},
			wantModel:    "gpt-5.3-codex-spark",
			wantContext:  "current_turn",
		},
		{
			name:         "managed non Spark keeps Lite context",
			requestModel: "gpt-5.6-sol",
			wantModel:    "gpt-5.6-sol",
			wantContext:  "all_turns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(nil))
			c.Request.Header.Set("User-Agent", "codex_cli_rs/0.144.1")
			c.Request.Header.Set(responsesLiteHeader, "true")
			upstream := &httpUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body: io.NopCloser(strings.NewReader(
					"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_spark_context\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n" +
						"data: [DONE]\n\n",
				)),
			}}
			svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			credentials := map[string]any{
				"access_token":       "oauth-token",
				"chatgpt_account_id": "chatgpt-account",
			}
			if tt.modelMapping != nil {
				credentials["model_mapping"] = tt.modelMapping
			}
			account := &Account{
				ID: 502, Name: "spark-context", Platform: PlatformOpenAI, Type: AccountTypeOAuth,
				Concurrency: 1, Status: StatusActive, Schedulable: true, RateMultiplier: f64p(1),
				Credentials: credentials,
				Extra:       map[string]any{"openai_passthrough": tt.passthrough},
			}
			body := []byte(`{
				"model":"` + tt.requestModel + `","stream":true,"instructions":"test",
				"reasoning":{"effort":"high","context":"auto"},
				"input":[{"type":"message","role":"user","content":"hello"}]
			}`)

			result, err := svc.Forward(context.Background(), c, account, body)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.Equal(t, tt.wantModel, gjson.GetBytes(upstream.lastBody, "model").String())
			require.Equal(t, tt.wantContext, gjson.GetBytes(upstream.lastBody, "reasoning.context").String())
			require.Equal(t, "high", gjson.GetBytes(upstream.lastBody, "reasoning.effort").String())
		})
	}
}
