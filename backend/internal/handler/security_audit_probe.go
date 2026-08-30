package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	probeGovernanceClaimContextKey   = "sub2api.prompt_probe.claim"
	probeGovernanceSuccessContextKey = "sub2api.prompt_probe.upstream_succeeded"
)

func (h *GatewayHandler) checkProbeGovernance(c *gin.Context, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte) bool {
	if h == nil {
		return false
	}
	return applyProbeGovernance(c, h.securityAuditCoordinator, buildSecurityAuditRequest(c, apiKey, subject, protocol, model, body, "http"))
}

func (h *OpenAIGatewayHandler) checkProbeGovernance(c *gin.Context, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte) bool {
	if h == nil {
		return false
	}
	request := buildSecurityAuditRequest(c, apiKey, subject, protocol, model, body, "http")
	if c == nil || c.Request == nil || h.securityAuditCoordinator == nil {
		return false
	}
	enabled := h.securityAuditCoordinator.ProbeGovernanceEnabled(c.Request.Context(), request)
	if enabled && !c.IsAborted() && h.cyberFeedbackService != nil {
		evidence, ok := h.cyberFeedbackService.PrepareTurn(request, 0)
		if ok {
			c.Set(securityAuditCyberTurnEvidenceContextKey, evidence)
			if h.cyberFeedbackService.IsReplay(c.Request.Context(), evidence) {
				confirmed := h.securityAuditCoordinator.GovernConfirmedProbe(c.Request.Context(), request)
				return applyProbeGovernanceResult(c, confirmed)
			}
		}
		c.Set(securityAuditCyberReplayCheckedContextKey, true)
	}
	result := h.securityAuditCoordinator.GovernProbe(c.Request.Context(), request)
	if applyProbeGovernanceResult(c, result) {
		return true
	}
	if result.Applied {
		return false
	}
	if c == nil || c.IsAborted() || h.securityAuditCoordinator == nil || h.cyberFeedbackService == nil {
		return false
	}
	// Only consult the durable CYB replay index before model availability when
	// governance is enabled. With the switch off, the historical preflight then
	// direct-403 ordering remains byte-for-byte unchanged.
	return false
}

func applyProbeGovernance(c *gin.Context, coordinator *securityaudit.Coordinator, request securityaudit.Request) bool {
	if c == nil || c.Request == nil || coordinator == nil {
		return false
	}
	return applyProbeGovernanceResult(c, coordinator.GovernProbe(c.Request.Context(), request))
}

func applyProbeGovernanceResult(c *gin.Context, result securityaudit.ProbeGovernanceResult) bool {
	if c == nil || !result.Applied {
		return false
	}
	if result.Local != nil {
		c.Set(securityAuditCompletedContextKey, true)
		writeProbeLocalResponse(c, result.Local)
		return true
	}
	if result.Claim != nil {
		// Candidate Prompt Audit and legacy moderation have both already run.
		// Apply the combined decision so flag routing is preserved, then prevent
		// the later normal Coordinator call from performing either check twice.
		if result.AuditDecision != nil {
			applySecurityAuditDecisionContext(c, *result.AuditDecision)
		}
		c.Set(securityAuditCompletedContextKey, true)
		c.Set(probeGovernanceClaimContextKey, result.Claim)
		return false
	}
	return false
}

func finalizeProbeGovernance(c *gin.Context, coordinator *securityaudit.Coordinator) {
	if c == nil || coordinator == nil {
		return
	}
	value, exists := c.Get(probeGovernanceClaimContextKey)
	claim, ok := value.(*securityaudit.ProbeForwardClaim)
	if !exists || !ok || claim == nil {
		return
	}
	c.Set(probeGovernanceClaimContextKey, (*securityaudit.ProbeForwardClaim)(nil))
	succeeded, _ := c.Get(probeGovernanceSuccessContextKey)
	upstreamSucceeded, _ := succeeded.(bool)
	upstreamAttempted := service.GatewayUpstreamDispatchAttempted(c)
	coordinator.FinalizeProbeForward(claim, upstreamAttempted, upstreamSucceeded)
}

func markProbeUpstreamAttempted(c *gin.Context) {
	if c == nil {
		return
	}
	if claim, exists := c.Get(probeGovernanceClaimContextKey); !exists || claim == nil {
		return
	}
	service.MarkGatewayUpstreamDispatchAttempted(c)
}

func hasProbeForwardClaim(c *gin.Context) bool {
	if c == nil {
		return false
	}
	claim, exists := c.Get(probeGovernanceClaimContextKey)
	return exists && claim != nil
}

// markProbeUpstreamSuccess is deliberately called only after a forwarder has
// returned without an error. HTTP 200 alone is not sufficient: streaming
// forwarders may already have committed 200 before reporting a terminal SSE
// read error or client disconnect.
func markProbeUpstreamSuccess(c *gin.Context) {
	if c == nil {
		return
	}
	if claim, exists := c.Get(probeGovernanceClaimContextKey); !exists || claim == nil {
		return
	}
	c.Set(probeGovernanceSuccessContextKey, true)
}

func markProbeOpenAIUpstreamSuccess(c *gin.Context, result *service.OpenAIForwardResult) {
	if probeRequestContextActive(c) && openAIProbeForwardCompleted(result) {
		markProbeUpstreamSuccess(c)
	}
}

func openAIProbeForwardCompleted(result *service.OpenAIForwardResult) bool {
	return result != nil && result.UpstreamCompleted && !result.ClientDisconnect
}

func markProbeGatewayUpstreamSuccess(c *gin.Context, result *service.ForwardResult) {
	if probeRequestContextActive(c) && result != nil && result.UpstreamCompleted && !result.ClientDisconnect {
		markProbeUpstreamSuccess(c)
	}
}

func probeRequestContextActive(c *gin.Context) bool {
	return c != nil && !c.IsAborted() && len(c.Errors) == 0 &&
		(c.Request == nil || c.Request.Context().Err() == nil)
}

func writeProbeLocalResponse(c *gin.Context, local *securityaudit.ProbeLocalResponse) {
	if c == nil || local == nil {
		return
	}
	c.Header("Cache-Control", "no-store")
	if local.Stream {
		writeProbeLocalStream(c, local)
		return
	}
	switch local.Protocol {
	case service.ContentModerationProtocolAnthropicMessages:
		c.JSON(http.StatusOK, gin.H{
			"id": probeResponseID("msg"), "type": "message", "role": "assistant", "model": local.Model,
			"content": []gin.H{{"type": "text", "text": local.Message}}, "stop_reason": "end_turn", "stop_sequence": nil,
			"usage": gin.H{"input_tokens": 0, "output_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
		})
	case service.ContentModerationProtocolOpenAIResponses:
		c.JSON(http.StatusOK, probeResponsesBody(local, "completed"))
	default:
		c.JSON(http.StatusOK, gin.H{
			"id": probeResponseID("chatcmpl"), "object": "chat.completion", "created": time.Now().Unix(), "model": local.Model,
			"choices": []gin.H{{"index": 0, "message": gin.H{"role": "assistant", "content": local.Message}, "finish_reason": "stop"}},
			"usage":   gin.H{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		})
	}
}

func writeProbeLocalStream(c *gin.Context, local *securityaudit.ProbeLocalResponse) {
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Connection", "keep-alive")
	c.Status(http.StatusOK)
	switch local.Protocol {
	case service.ContentModerationProtocolAnthropicMessages:
		id := probeResponseID("msg")
		writeProbeSSE(c, "message_start", gin.H{"type": "message_start", "message": gin.H{"id": id, "type": "message", "role": "assistant", "model": local.Model, "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": gin.H{"input_tokens": 0, "output_tokens": 0}}})
		writeProbeSSE(c, "content_block_start", gin.H{"type": "content_block_start", "index": 0, "content_block": gin.H{"type": "text", "text": ""}})
		writeProbeSSE(c, "content_block_delta", gin.H{"type": "content_block_delta", "index": 0, "delta": gin.H{"type": "text_delta", "text": local.Message}})
		writeProbeSSE(c, "content_block_stop", gin.H{"type": "content_block_stop", "index": 0})
		writeProbeSSE(c, "message_delta", gin.H{"type": "message_delta", "delta": gin.H{"stop_reason": "end_turn", "stop_sequence": nil}, "usage": gin.H{"output_tokens": 0}})
		writeProbeSSE(c, "message_stop", gin.H{"type": "message_stop"})
	case service.ContentModerationProtocolOpenAIResponses:
		id := probeResponseID("resp")
		itemID := id + "_message"
		created := probeResponsesBodyWithID(local, id, "in_progress")
		created["output"] = []any{}
		created["output_text"] = ""
		writeProbeSSE(c, "response.created", gin.H{"type": "response.created", "sequence_number": 0, "response": created})
		writeProbeSSE(c, "response.output_item.added", gin.H{"type": "response.output_item.added", "sequence_number": 1, "output_index": 0, "item": gin.H{"id": itemID, "type": "message", "status": "in_progress", "role": "assistant", "content": []any{}}})
		writeProbeSSE(c, "response.content_part.added", gin.H{"type": "response.content_part.added", "sequence_number": 2, "item_id": itemID, "output_index": 0, "content_index": 0, "part": gin.H{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}}})
		writeProbeSSE(c, "response.output_text.delta", gin.H{"type": "response.output_text.delta", "sequence_number": 3, "item_id": itemID, "output_index": 0, "content_index": 0, "delta": local.Message})
		writeProbeSSE(c, "response.output_text.done", gin.H{"type": "response.output_text.done", "sequence_number": 4, "item_id": itemID, "output_index": 0, "content_index": 0, "text": local.Message})
		part := gin.H{"type": "output_text", "text": local.Message, "annotations": []any{}, "logprobs": []any{}}
		writeProbeSSE(c, "response.content_part.done", gin.H{"type": "response.content_part.done", "sequence_number": 5, "item_id": itemID, "output_index": 0, "content_index": 0, "part": part})
		writeProbeSSE(c, "response.output_item.done", gin.H{"type": "response.output_item.done", "sequence_number": 6, "output_index": 0, "item": gin.H{"id": itemID, "type": "message", "status": "completed", "role": "assistant", "content": []gin.H{part}}})
		completed := probeResponsesBodyWithID(local, id, "completed")
		writeProbeSSE(c, "response.completed", gin.H{"type": "response.completed", "sequence_number": 7, "response": completed})
	default:
		payload := gin.H{"id": probeResponseID("chatcmpl"), "object": "chat.completion.chunk", "created": time.Now().Unix(), "model": local.Model, "choices": []gin.H{{"index": 0, "delta": gin.H{"role": "assistant", "content": local.Message}, "finish_reason": "stop"}}, "usage": gin.H{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
		raw, _ := json.Marshal(payload)
		_, _ = fmt.Fprintf(c.Writer, "data: %s\n\n", raw)
		_, _ = fmt.Fprint(c.Writer, "data: [DONE]\n\n")
	}
	c.Writer.Flush()
}

func probeResponsesBody(local *securityaudit.ProbeLocalResponse, status string) gin.H {
	return probeResponsesBodyWithID(local, probeResponseID("resp"), status)
}
func probeResponsesBodyWithID(local *securityaudit.ProbeLocalResponse, id, status string) gin.H {
	return gin.H{"id": id, "object": "response", "created_at": time.Now().Unix(), "status": status, "model": local.Model,
		"output":      []gin.H{{"id": id + "_message", "type": "message", "status": "completed", "role": "assistant", "content": []gin.H{{"type": "output_text", "text": local.Message, "annotations": []any{}, "logprobs": []any{}}}}},
		"output_text": local.Message, "usage": gin.H{"input_tokens": 0, "input_tokens_details": gin.H{"cached_tokens": 0}, "output_tokens": 0, "output_tokens_details": gin.H{"reasoning_tokens": 0}, "total_tokens": 0}, "error": nil, "incomplete_details": nil}
}

func writeProbeSSE(c *gin.Context, event string, payload any) {
	raw, _ := json.Marshal(payload)
	_, _ = fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, raw)
}
func probeResponseID(prefix string) string {
	return prefix + "_probe_" + strings.ToLower(strconvBase36(time.Now().UnixNano()))
}
func strconvBase36(value int64) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	if value <= 0 {
		return "0"
	}
	var out [16]byte
	i := len(out)
	for value > 0 {
		i--
		out[i] = alphabet[value%36]
		value /= 36
	}
	return string(out[i:])
}
