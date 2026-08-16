package service

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// openAIOAuthModelsWithoutResponsesLite is deliberately an exact canonical
// allowlist derived from the final model sent by failed production OAuth
// attempts. Do not turn this into a family-prefix match: siblings such as
// gpt-5.4-nano or gpt-5.5-pro may have different protocol capabilities.
var openAIOAuthModelsWithoutResponsesLite = map[string]struct{}{
	"gpt-5.3-codex-spark": {},
	"gpt-5.4":             {},
	"gpt-5.4-mini":        {},
	"gpt-5.5":             {},
	"codex-auto-review":   {},
}

func isKnownOpenAIOAuthModelWithoutResponsesLite(model string) bool {
	if strings.TrimSpace(model) == "" {
		return false
	}
	canonical := normalizeCodexModel(model)
	_, ok := openAIOAuthModelsWithoutResponsesLite[canonical]
	return ok
}

func isKnownOpenAIAccountModelWithoutResponsesLite(account *Account, model string) bool {
	if account == nil || account.Platform != PlatformOpenAI || strings.TrimSpace(model) == "" {
		return false
	}
	canonical := normalizeCodexModel(model)
	if account.Type == AccountTypeAPIKey {
		_, ok := apiKeyCodexModelsWithoutResponsesLite[canonical]
		return ok
	}
	if account.Type == AccountTypeOAuth {
		_, ok := openAIOAuthModelsWithoutResponsesLite[canonical]
		return ok
	}
	return false
}

// openAIResponsesLiteHTTPAttemptModel resolves the model that this concrete
// account attempt will actually send upstream. Managed forwarding applies the
// account mapping and OAuth canonicalization. HTTP passthrough intentionally
// uses the model present in its outbound body (apart from compact-only mapping),
// matching forwardOpenAIPassthrough rather than an unused account mapping.
func openAIResponsesLiteHTTPAttemptModel(account *Account, body []byte, passthrough, compact bool) string {
	model := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if account == nil {
		return model
	}
	if passthrough {
		if compact {
			model = resolveOpenAICompactForwardModel(account, model)
		}
		return model
	}
	model = account.GetMappedModel(model)
	if compact {
		model = resolveOpenAICompactForwardModel(account, model)
	}
	return normalizeOpenAIModelForUpstream(account, model)
}

// isOpenAIResponsesLiteHTTPAttemptEnabled resolves the effective protocol for
// this account attempt. It is intentionally broader than OAuth payload
// normalization: API-key attempts also need the effective value so downstream
// full-Responses features are not disabled after a stale Lite signal is
// stripped.
func isOpenAIResponsesLiteHTTPAttemptEnabled(
	account *Account,
	body []byte,
	passthrough bool,
	compact bool,
	clientRequestedLite bool,
) bool {
	if account == nil || account.Platform != PlatformOpenAI || !clientRequestedLite {
		return false
	}
	model := openAIResponsesLiteHTTPAttemptModel(account, body, passthrough, compact)
	return !isKnownOpenAIAccountModelWithoutResponsesLite(account, model)
}

// guardOpenAIResponsesLiteHTTPHeader is a final, attempt-local outbound guard.
// It mutates only the newly-created upstream request, never the shared Gin
// request headers that are reused by later account failover attempts.
func guardOpenAIResponsesLiteHTTPHeader(req *http.Request, account *Account, body []byte) {
	if req == nil || account == nil || account.Platform != PlatformOpenAI {
		return
	}
	model := strings.TrimSpace(gjson.GetBytes(body, "model").String())
	if isKnownOpenAIAccountModelWithoutResponsesLite(account, model) {
		req.Header.Del(responsesLiteHeader)
	}
}

// normalizeOpenAIResponsesLiteWSPayloadForModel applies the Lite contract only
// after the current WS frame has reached its final upstream model. Known
// non-Lite models keep the full Responses body and lose only the private Lite
// marker; all other client_metadata fields remain intact.
func normalizeOpenAIResponsesLiteWSPayloadForModel(account *Account, payload []byte, upstreamModel string) ([]byte, bool, error) {
	if account == nil || account.Platform != PlatformOpenAI || !isOpenAIResponsesLiteWebSocketPayload(payload) {
		return payload, false, nil
	}
	if isKnownOpenAIAccountModelWithoutResponsesLite(account, upstreamModel) {
		stripped, err := sjson.DeleteBytes(payload, "client_metadata."+responsesLiteWSMetadataKey)
		if err != nil {
			return payload, false, fmt.Errorf("strip responses Lite websocket marker: %w", err)
		}
		return stripped, true, nil
	}
	if account.IsOpenAIOAuth() {
		return normalizeOpenAIResponsesLiteToolsPayload(payload)
	}
	return payload, false, nil
}

// normalizeOpenAIRequiredClientToolSearchChoice handles an upstream validation
// incompatibility shared by full Responses and Responses Lite: a top-level
// client-executed tool_search entry is a discovery mechanism and does not
// satisfy tool_choice="required". Keep this raw rewrite deliberately narrow so
// ordinary function/custom tools and mixed tool sets retain required semantics.
func normalizeOpenAIRequiredClientToolSearchChoice(account *Account, payload []byte) ([]byte, bool, error) {
	if account == nil || account.Platform != PlatformOpenAI || len(payload) == 0 || !gjson.ValidBytes(payload) {
		return payload, false, nil
	}
	choice := gjson.GetBytes(payload, "tool_choice")
	if choice.Type != gjson.String || strings.TrimSpace(choice.String()) != "required" {
		return payload, false, nil
	}
	tools := gjson.GetBytes(payload, "tools")
	if !tools.Exists() || !tools.IsArray() {
		return payload, false, nil
	}
	toolCount := 0
	allClientToolSearch := true
	tools.ForEach(func(_, tool gjson.Result) bool {
		toolCount++
		if !tool.IsObject() {
			allClientToolSearch = false
			return false
		}
		toolType := tool.Get("type")
		execution := tool.Get("execution")
		if toolType.Type != gjson.String || strings.TrimSpace(toolType.String()) != "tool_search" ||
			execution.Type != gjson.String || strings.TrimSpace(execution.String()) != "client" {
			allClientToolSearch = false
			return false
		}
		return true
	})
	if toolCount == 0 || !allClientToolSearch {
		return payload, false, nil
	}
	normalized, err := sjson.SetBytes(payload, "tool_choice", "auto")
	if err != nil {
		return payload, false, fmt.Errorf("normalize client tool_search required choice: %w", err)
	}
	return normalized, true, nil
}
