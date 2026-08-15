package service

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestIsOpenAILegacyCompactRouteNotFound(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "bare route json", status: http.StatusNotFound, body: `{"detail":"Not Found"}`, want: true},
		{name: "wrong status", status: http.StatusBadRequest, body: `{"detail":"Not Found"}`},
		{name: "plain text remains narrow", status: http.StatusNotFound, body: `Not Found`},
		{name: "model error envelope", status: http.StatusNotFound, body: `{"error":{"code":"model_not_found","message":"Not Found"}}`},
		{name: "detail plus model code", status: http.StatusNotFound, body: `{"detail":"Not Found","error":{"code":"model_not_found"}}`},
		{name: "top level model code", status: http.StatusNotFound, body: `{"detail":"Not Found","code":"model_not_found"}`},
		{name: "different detail", status: http.StatusNotFound, body: `{"detail":"model not found"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isOpenAILegacyCompactRouteNotFound(tt.status, []byte(tt.body)))
		})
	}
}

func newOpenAICompactRouteNotFoundTestAccount(passthrough bool) *Account {
	return &Account{
		ID:          17001,
		Name:        "compact-route-test",
		Platform:    PlatformOpenAI,
		Type:        AccountTypeAPIKey,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 1,
		Credentials: map[string]any{
			"api_key":  "sk-test",
			"base_url": "https://api.example.test",
		},
		Extra: map[string]any{
			"openai_passthrough":         passthrough,
			"openai_responses_supported": true,
		},
	}
}

func TestOpenAIGatewayService_Forward_LegacyCompactBareRoute404FailsOverWithoutHealthPenalty(t *testing.T) {
	for _, passthrough := range []bool{false, true} {
		name := "transformed"
		if passthrough {
			name = "passthrough"
		}
		t.Run(name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			requestBody := []byte(`{"model":"gpt-5.5","stream":false,"input":"compact me"}`)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/compact", bytes.NewReader(nil))

			const upstreamBody = `{"detail":"Not Found"}`
			body := &passthroughCloseTrackingReadCloser{Reader: strings.NewReader(upstreamBody)}
			responseHeader := http.Header{
				"Content-Type": []string{"application/json"},
				"X-Request-Id": []string{"rid-compact-route-missing"},
			}
			svc := &OpenAIGatewayService{
				cfg: &config.Config{Gateway: config.GatewayConfig{
					ForceCodexCLI:                false,
					LogUpstreamErrorBody:         true,
					LogUpstreamErrorBodyMaxBytes: 2048,
				}},
				httpUpstream: &httpUpstreamRecorder{resp: &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     responseHeader,
					Body:       body,
				}},
			}

			result, err := svc.Forward(context.Background(), c, newOpenAICompactRouteNotFoundTestAccount(passthrough), requestBody)

			require.Nil(t, result)
			var failoverErr *UpstreamFailoverError
			require.ErrorAs(t, err, &failoverErr)
			require.Equal(t, http.StatusNotFound, failoverErr.StatusCode)
			require.Equal(t, []byte(upstreamBody), failoverErr.ResponseBody)
			require.Equal(t, "rid-compact-route-missing", failoverErr.ResponseHeaders.Get("x-request-id"))
			require.Equal(t, GatewayFailureScopeAccount, failoverErr.Scope)
			require.Equal(t, openAILegacyCompactRouteNotFoundReason, failoverErr.Reason)
			require.Equal(t, NextAccountRetry, failoverErr.NextAccountAction)
			require.False(t, failoverErr.RetryableOnSameAccount)
			require.True(t, failoverErr.ShouldRetryNextAccount())
			require.False(t, failoverErr.ShouldReportAccountScheduleFailure())
			require.False(t, c.Writer.Written())
			require.Empty(t, rec.Body.String())
			require.True(t, body.closed)
		})
	}
}

func TestOpenAIGatewayService_Forward_CompactRoute404FailoverIsNarrow(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
	}{
		{
			name: "ordinary responses bare route 404",
			path: "/v1/responses",
			body: `{"detail":"Not Found"}`,
		},
		{
			name: "compact model not found",
			path: "/v1/responses/compact",
			body: `{"error":{"code":"model_not_found","type":"invalid_request_error","message":"The model was not found"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(nil))
			responseBody := &passthroughCloseTrackingReadCloser{Reader: strings.NewReader(tt.body)}
			svc := &OpenAIGatewayService{
				cfg: &config.Config{Gateway: config.GatewayConfig{ForceCodexCLI: false}},
				httpUpstream: &httpUpstreamRecorder{resp: &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       responseBody,
				}},
			}

			result, err := svc.Forward(
				context.Background(),
				c,
				newOpenAICompactRouteNotFoundTestAccount(true),
				[]byte(`{"model":"gpt-5.5","stream":false,"input":"hello"}`),
			)

			require.Nil(t, result)
			require.Error(t, err)
			var failoverErr *UpstreamFailoverError
			require.False(t, errors.As(err, &failoverErr))
			require.True(t, c.Writer.Written())
			require.NotEmpty(t, rec.Body.String())
			require.True(t, responseBody.closed)
		})
	}
}
