package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type probeFailWriteResponseWriter struct{ gin.ResponseWriter }

func (w *probeFailWriteResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("client disconnected")
}

func (w *probeFailWriteResponseWriter) WriteString(string) (int, error) {
	return 0, errors.New("client disconnected")
}

func TestProbeLocalResponsesAreProtocolValidHTTP200WithoutGovernanceFingerprint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	protocols := []string{
		service.ContentModerationProtocolOpenAIChat,
		service.ContentModerationProtocolOpenAIResponses,
		service.ContentModerationProtocolAnthropicMessages,
	}
	for _, protocol := range protocols {
		for _, stream := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "_nonstream", true: "_stream"}[stream], func(t *testing.T) {
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
				writeProbeLocalResponse(c, &securityaudit.ProbeLocalResponse{
					Protocol: protocol, Model: "test-model", Stream: stream, Message: "service healthy", Kind: "healthy",
				})

				require.Equal(t, http.StatusOK, recorder.Code)
				require.Empty(t, recorder.Header().Get("X-Sub2-Probe-Governance"))
				require.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
				body := recorder.Body.String()
				require.Contains(t, body, "service healthy")
				if stream {
					require.Contains(t, recorder.Header().Get("Content-Type"), "text/event-stream")
					switch protocol {
					case service.ContentModerationProtocolOpenAIChat:
						require.Contains(t, body, `"total_tokens":0`)
						require.Contains(t, body, "data: [DONE]")
					case service.ContentModerationProtocolOpenAIResponses:
						assertProbeResponsesSSELifecycle(t, body)
					case service.ContentModerationProtocolAnthropicMessages:
						require.Contains(t, body, `"output_tokens":0`)
						require.Contains(t, body, "event: message_stop")
					}
					return
				}
				var payload map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
				if protocol == service.ContentModerationProtocolOpenAIResponses {
					assertProbeResponsesOutputPartWire(t, payload)
				}
				usage, ok := payload["usage"].(map[string]any)
				require.True(t, ok)
				for key, value := range usage {
					if number, numeric := value.(float64); numeric {
						require.Zero(t, number, key)
					}
				}
			})
		}
	}
}

func assertProbeResponsesSSELifecycle(t *testing.T, body string) {
	t.Helper()
	want := []string{
		"response.created", "response.output_item.added", "response.content_part.added",
		"response.output_text.delta", "response.output_text.done", "response.content_part.done",
		"response.output_item.done", "response.completed",
	}
	last := -1
	for _, event := range want {
		index := strings.Index(body, "event: "+event)
		require.Greater(t, index, last, event)
		last = index
	}
	frames := strings.Split(strings.TrimSpace(body), "\n\n")
	require.Len(t, frames, len(want))
	var created, completed map[string]any
	for index, frame := range frames {
		lines := strings.Split(frame, "\n")
		require.Len(t, lines, 2)
		require.Equal(t, "event: "+want[index], lines[0])
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(lines[1], "data: ")), &event))
		require.Equal(t, float64(index), event["sequence_number"])
		if index == 0 {
			created = event["response"].(map[string]any)
		}
		if want[index] == "response.content_part.added" || want[index] == "response.content_part.done" {
			part, ok := event["part"].(map[string]any)
			require.True(t, ok)
			require.Contains(t, part, "text")
			require.Contains(t, part, "annotations")
			require.Contains(t, part, "logprobs")
		}
		if index == len(frames)-1 {
			completed = event["response"].(map[string]any)
		}
	}
	require.Equal(t, "in_progress", created["status"])
	require.Empty(t, created["output"])
	require.Equal(t, "", created["output_text"])
	require.Equal(t, "completed", completed["status"])
	require.NotEmpty(t, completed["output"])
	require.Equal(t, "service healthy", completed["output_text"])
	require.Equal(t, created["id"], completed["id"])
	assertProbeResponsesOutputPartWire(t, completed)
}

func assertProbeResponsesOutputPartWire(t *testing.T, response map[string]any) {
	t.Helper()
	outputs, ok := response["output"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, outputs)
	item, ok := outputs[0].(map[string]any)
	require.True(t, ok)
	content, ok := item["content"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, content)
	part, ok := content[0].(map[string]any)
	require.True(t, ok)
	require.Contains(t, part, "text")
	require.Contains(t, part, "annotations")
	require.Contains(t, part, "logprobs")
}

type probeFinalizeEngine struct {
	finalizeCalls atomic.Int64
	attempted     bool
	succeeded     bool
}

func (f *probeFinalizeEngine) EffectiveMode() securityaudit.Mode                    { return securityaudit.ModeOff }
func (f *probeFinalizeEngine) Enqueue(context.Context, securityaudit.Request) error { return nil }
func (f *probeFinalizeEngine) Evaluate(context.Context, securityaudit.Request) (*securityaudit.PromptDecision, error) {
	return nil, nil
}
func (f *probeFinalizeEngine) ProbeGovernanceEnabled(context.Context, securityaudit.Request) bool {
	return true
}
func (f *probeFinalizeEngine) GovernProbe(context.Context, securityaudit.Request) securityaudit.ProbeGovernanceResult {
	return securityaudit.ProbeGovernanceResult{}
}
func (f *probeFinalizeEngine) GovernConfirmedProbe(context.Context, securityaudit.Request) securityaudit.ProbeGovernanceResult {
	return securityaudit.ProbeGovernanceResult{}
}
func (f *probeFinalizeEngine) FinalizeProbeForward(_ *securityaudit.ProbeForwardClaim, attempted, succeeded bool) {
	f.finalizeCalls.Add(1)
	f.attempted = attempted
	f.succeeded = succeeded
}
func (f *probeFinalizeEngine) ReleaseProbeForwardClaim(*securityaudit.ProbeForwardClaim) {}
func (f *probeFinalizeEngine) RejectProbeForwardClaim(*securityaudit.ProbeForwardClaim, string) *securityaudit.ProbeLocalResponse {
	return nil
}

func TestProbeFinalizeRequiresExplicitCompletedForwardMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := &probeFinalizeEngine{}
	coordinator := securityaudit.NewCoordinator(nil, engine)

	partial := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(partial)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
	markProbeUpstreamAttempted(c)
	c.Status(http.StatusOK)
	_, _ = c.Writer.WriteString("event: response.output_text.delta\n\n")
	finalizeProbeGovernance(c, coordinator)
	require.Equal(t, int64(1), engine.finalizeCalls.Load())
	require.True(t, engine.attempted)
	require.False(t, engine.succeeded, "a committed 200 followed by a stream error must not mark health")

	success := httptest.NewRecorder()
	c, _ = gin.CreateTestContext(success)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
	markProbeUpstreamAttempted(c)
	markProbeUpstreamSuccess(c)
	finalizeProbeGovernance(c, coordinator)
	require.Equal(t, int64(2), engine.finalizeCalls.Load())
	require.True(t, engine.attempted)
	require.True(t, engine.succeeded)

	preDispatch := httptest.NewRecorder()
	c, _ = gin.CreateTestContext(preDispatch)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
	finalizeProbeGovernance(c, coordinator)
	require.Equal(t, int64(3), engine.finalizeCalls.Load())
	require.False(t, engine.attempted)
	require.False(t, engine.succeeded)
}

func TestProbeOpenAIUpstreamTerminalFailureDoesNotSetSuccessMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, terminal := range []string{"response.failed", "response.incomplete", "response.cancelled"} {
		t.Run(terminal, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
			markProbeOpenAIUpstreamSuccess(c, &service.OpenAIForwardResult{
				OpenAIWSMode: true, UpstreamTerminalEvent: terminal,
			})
			_, exists := c.Get(probeGovernanceSuccessContextKey)
			require.False(t, exists)
		})
	}
}

func TestProbeOpenAINilForwardResultDoesNotSetSuccessMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
	markProbeOpenAIUpstreamSuccess(c, nil)
	_, exists := c.Get(probeGovernanceSuccessContextKey)
	require.False(t, exists)
}

func TestProbeOpenAIClientDisconnectDoesNotSetSuccessMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
	markProbeOpenAIUpstreamSuccess(c, &service.OpenAIForwardResult{ClientDisconnect: true})
	_, exists := c.Get(probeGovernanceSuccessContextKey)
	require.False(t, exists)
}

func TestOpenAIProbeForwardCompletionIsFailClosed(t *testing.T) {
	require.False(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{Stream: false}))
	require.True(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{Stream: false, UpstreamCompleted: true}))
	require.False(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{Stream: true}))
	require.False(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{Stream: true, OpenAIWSMode: true}))
	require.True(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{
		Stream: true, OpenAIWSMode: true, UpstreamCompleted: true, UpstreamTerminalEvent: "response.completed",
	}))
	require.False(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{
		Stream: true, OpenAIWSMode: true, UpstreamCompleted: false, UpstreamTerminalEvent: "response.failed",
	}))
	require.False(t, openAIProbeForwardCompleted(&service.OpenAIForwardResult{UpstreamCompleted: true, ClientDisconnect: true}))
}

func TestProbeCompletedEnvelopeWithDownstreamWriteFailureDoesNotSetSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	c.Writer = &probeFailWriteResponseWriter{ResponseWriter: c.Writer}
	c.Set(probeGovernanceClaimContextKey, &securityaudit.ProbeForwardClaim{})
	c.Data(http.StatusOK, "application/json", []byte(`{"type":"message"}`))
	require.True(t, c.IsAborted())
	require.NotEmpty(t, c.Errors)
	markProbeGatewayUpstreamSuccess(c, &service.ForwardResult{UpstreamCompleted: true})
	_, exists := c.Get(probeGovernanceSuccessContextKey)
	require.False(t, exists)
}

func TestProbeChecksPrecedeModelAvailabilityPreflightInAllHTTPHandlers(t *testing.T) {
	files := []string{
		"gateway_handler.go", "gateway_handler_chat_completions.go", "gateway_handler_responses.go",
		"openai_chat_completions.go", "openai_gateway_handler.go",
	}
	for _, filename := range files {
		raw, err := os.ReadFile(filename)
		require.NoError(t, err)
		source := string(raw)
		require.Contains(t, source, "checkProbeGovernance")
		require.Contains(t, source, "preflightModelAvailability")
		// Every handler file must have at least one early probe check before its
		// first model-availability preflight. The two multi-protocol files have
		// dedicated runtime tests elsewhere for each dispatch branch.
		require.Less(t, strings.Index(source, "checkProbeGovernance"), strings.Index(source, "preflightModelAvailability"), filename)
	}
}
