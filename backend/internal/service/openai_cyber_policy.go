package service

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// opsCyberPolicyKey 在 gin context 中携带 cyber_policy 命中标记。
// 由 gateway 服务层在检测到上游 error.code=="cyber_policy" 时设置，
// handler 在 Forward 返回后读取以触发风控记录、邮件与 tokens=0 用量行。
const opsCyberPolicyKey = "ops_cyber_policy"

// errOpenAICyberPolicyForwarded 表示 cyber_policy 已按当前端点格式透传给客户端
// （error 已写出/下发）。compat 路径 ForwardAsChatCompletions / ForwardAsAnthropic 出口
// 据此丢弃 result 并返回该哨兵，使 handler 落入 tokens=0 免费用量行（对齐 /v1/responses），
// 既不计费、也不 failover、不重复写响应。
var errOpenAICyberPolicyForwarded = errors.New("openai cyber_policy forwarded to client")

var openAICyberPolicyCodePaths = [...]string{
	"error.code",
	"response.error.code",
	"response.status_details.error.code",
	"error.codex_error_info",
	"response.error.codex_error_info",
	"response.status_details.error.codex_error_info",
	"error.type",
	"response.error.type",
	"response.status_details.error.type",
	"codex_error_info",
	"code",
	"type",
}

var openAICyberPolicyMessagePaths = [...]string{
	"error.message",
	"response.error.message",
	"response.status_details.error.message",
	"message",
	"response.status_details.message",
}

// CyberPolicyMark 记录一次 cyber_policy 硬阻断的上游证据。
type CyberPolicyMark struct {
	Code           string // 固定 "cyber_policy"
	Message        string // 上游 error.message
	Body           string // 上游 response.failed / 400 原始 body（已截断；未脱敏，ops_error 落库由 sanitizeErrorBodyForStorage、风控日志由 redactContentModerationSecrets 统一脱敏）
	UpstreamStatus int    // 上游 HTTP 状态（流式=200，非流式=400）
	UpstreamInTok  int    // 上游已报 input tokens（如有）
	UpstreamOutTok int    // 上游已报 output tokens（如有）
}

// MarkOpsCyberPolicy 记录 cyber 标记；首个写入生效，后续忽略（同一 turn 只记一次）。
// WS 多轮场景由 handler 在每个 turn 结束后调用 ClearOpsCyberPolicy 重置。
func MarkOpsCyberPolicy(c *gin.Context, mark CyberPolicyMark) {
	if c == nil {
		return
	}
	if GetOpsCyberPolicy(c) != nil {
		return
	}
	mark.Code = "cyber_policy"
	mark.Message = strings.TrimSpace(mark.Message)
	mark.Body = strings.TrimSpace(mark.Body)
	c.Set(opsCyberPolicyKey, &mark)
}

// GetOpsCyberPolicy 返回 cyber 标记，未命中（或已被 Clear）返回 nil。
func GetOpsCyberPolicy(c *gin.Context) *CyberPolicyMark {
	if c == nil {
		return nil
	}
	if v, ok := c.Get(opsCyberPolicyKey); ok {
		if m, ok := v.(*CyberPolicyMark); ok && m != nil {
			return m
		}
	}
	return nil
}

// ClearOpsCyberPolicy 清除 cyber 标记（typed-nil 覆盖；gin context 无并发安全的
// 删除原语，Set 走内部锁，与异步 GetOpsCyberPolicy 不构成 data race）。
// 仅 WS 多轮路径在 turn 收尾调用；HTTP 单请求路径不调用（context 随请求销毁，
// 且中间件 shouldSkipOpsErrorLogForCyber 依赖标记防双写）。
// WS 路径 clear 发生在中间件收尾之前，连接响应状态为 101，不触发中间件 status>=400
// 落库分支，故无双写/漏写。
func ClearOpsCyberPolicy(c *gin.Context) {
	if c == nil {
		return
	}
	c.Set(opsCyberPolicyKey, (*CyberPolicyMark)(nil))
}

// detectOpenAICyberPolicy 精确识别 cyber_policy（对齐 codex2api 的
// response.failed/HTTP 错误兼容形态）。命中返回 (true, "cyber_policy", message)。
//
// codex2api 会原样转发部分 Responses 错误，其中官方上游可能把标记放在
// codex_error_info，而不是 error.code；response.failed 还可能把 error 再包在
// response 或 response.status_details 下。这里仅接受字段值精确等于
// cyber_policy（大小写不敏感），不依据 message 猜测，避免把普通安全/上游错误
// 误记成 CYB。
func detectOpenAICyberPolicy(payload []byte) (bool, string, string) {
	for _, path := range openAICyberPolicyCodePaths {
		if code := strings.TrimSpace(gjson.GetBytes(payload, path).String()); strings.EqualFold(code, "cyber_policy") {
			return true, "cyber_policy", openAICyberPolicyMessage(payload)
		}
	}
	return false, "", ""
}

func openAICyberPolicyMessage(payload []byte) string {
	for _, path := range openAICyberPolicyMessagePaths {
		if message := strings.TrimSpace(gjson.GetBytes(payload, path).String()); message != "" {
			return message
		}
	}
	return ""
}

func markOpenAICyberPolicyEvent(c *gin.Context, payload []byte, upstreamStatus int, usage *OpenAIUsage) bool {
	hit, code, message := detectOpenAICyberPolicy(payload)
	if !hit {
		return false
	}
	mark := CyberPolicyMark{
		Code:           code,
		Message:        message,
		Body:           truncateString(string(payload), 4096),
		UpstreamStatus: upstreamStatus,
	}
	if usage != nil {
		mark.UpstreamInTok = usage.InputTokens
		mark.UpstreamOutTok = usage.OutputTokens
	}
	MarkOpsCyberPolicy(c, mark)
	return true
}
