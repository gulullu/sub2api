package handler

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type promptAuditOrderCase struct {
	file       string
	function   string
	auditToken string
}

func TestPromptAuditGatePrecedesAccountBillingAndUpstreamSideEffects(t *testing.T) {
	tests := []promptAuditOrderCase{
		{file: "gateway_handler.go", function: "Messages", auditToken: "checkSecurityAudit"},
		{file: "gateway_handler_chat_completions.go", function: "ChatCompletions", auditToken: "checkSecurityAudit"},
		{file: "gateway_handler_responses.go", function: "Responses", auditToken: "checkSecurityAudit"},
		{file: "gemini_v1beta_handler.go", function: "GeminiV1BetaModels", auditToken: "checkSecurityAudit"},
		{file: "openai_gateway_handler.go", function: "Responses", auditToken: "checkSecurityAudit"},
		{file: "openai_gateway_handler.go", function: "Messages", auditToken: "checkSecurityAudit"},
		{file: "openai_chat_completions.go", function: "ChatCompletions", auditToken: "checkSecurityAudit"},
		{file: "openai_images.go", function: "Images", auditToken: "checkSecurityAudit"},
		{file: "grok_media.go", function: "handleGrokMedia", auditToken: "checkSecurityAudit"},
		{file: "openai_embeddings.go", function: "Embeddings", auditToken: "checkSecurityAudit"},
		{file: "openai_alpha_search.go", function: "AlphaSearch", auditToken: "checkSecurityAudit"},
		{file: "openai_live.go", function: "Live", auditToken: "checkSecurityAudit"},
		{file: "image_task_handler.go", function: "Submit", auditToken: "checkSecurityAuditBeforeSubmit"},
		{file: "batch_image_handler.go", function: "Submit", auditToken: "checkSecurityAuditBeforeSubmit"},
	}
	sideEffectTokens := []string{
		"CheckBillingEligibility(", "SelectAccount", ".Forward", "acquireResponsesUserSlot(",
		"AcquireUserSlot", "TryAcquireUserSlot", "acquireImageGenerationSlot(",
		"h.tasks.Create(", "h.service.Submit(",
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.function, func(t *testing.T) {
			functionSource := stripGoComments(goFunctionSource(t, tt.file, tt.function))
			auditIndex := strings.Index(functionSource, tt.auditToken)
			require.NotEqual(t, -1, auditIndex, "missing Prompt Audit gate")
			foundSideEffect := false
			for _, sideEffect := range sideEffectTokens {
				index := strings.Index(functionSource, sideEffect)
				if index < 0 {
					continue
				}
				foundSideEffect = true
				require.Lessf(t, auditIndex, index, "%s must run before %s", tt.auditToken, sideEffect)
			}
			require.True(t, foundSideEffect, "coverage case must contain a downstream side effect")
		})
	}
}

func TestModelAvailabilityPreflightPrecedesPromptAuditAcrossHTTPModelEntrypoints(t *testing.T) {
	tests := []struct {
		file           string
		function       string
		auditToken     string
		preflightToken string
	}{
		{file: "gateway_handler.go", function: "Messages", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "gateway_handler_chat_completions.go", function: "ChatCompletions", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "gateway_handler_responses.go", function: "Responses", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "gemini_v1beta_handler.go", function: "GeminiV1BetaModels", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_gateway_handler.go", function: "Responses", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_gateway_handler.go", function: "Messages", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_chat_completions.go", function: "ChatCompletions", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_images.go", function: "Images", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "grok_media.go", function: "handleGrokMedia", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_embeddings.go", function: "Embeddings", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_alpha_search.go", function: "AlphaSearch", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "openai_live.go", function: "Live", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "image_task_handler.go", function: "checkSecurityAuditBeforeSubmit", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "batch_image_handler.go", function: "checkSecurityAuditBeforeSubmit", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "gateway_web_search.go", function: "WebSearch", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
		{file: "grok_audio.go", function: "GrokVoice", auditToken: "checkSecurityAudit(", preflightToken: "preflightModelAvailabilityFromGin("},
	}
	for _, tt := range tests {
		t.Run(tt.file+"/"+tt.function, func(t *testing.T) {
			functionSource := stripGoComments(goFunctionSource(t, tt.file, tt.function))
			preflightIndex := strings.Index(functionSource, tt.preflightToken)
			auditIndex := strings.Index(functionSource, tt.auditToken)
			require.NotEqual(t, -1, preflightIndex, "missing structural model-availability preflight")
			require.NotEqual(t, -1, auditIndex, "missing Prompt Audit gate")
			require.Less(t, preflightIndex, auditIndex, "unsupported models must be rejected before external Prompt Audit")
		})
	}
}

func TestGrokMediaNoAccountClassifierUsesRoutingModelAndPublicDisplayModel(t *testing.T) {
	functionSource := stripGoComments(goFunctionSource(t, "grok_media.go", "handleGrokMedia"))
	want := "classifyNoAccountErrorFromGin(c, h.gatewayService, apiKey, routingModel, clientRequestedModel(c, requestModel), service.PlatformGrok)"
	require.Equal(t, 2, strings.Count(functionSource, want), "both Grok media selection-failure branches must diagnose the scheduler model without leaking its normalized alias")
}

func TestGrokTTSKeepsBillingAndValidationErrorPriorityBeforeModelPreflight(t *testing.T) {
	functionSource := stripGoComments(goFunctionSource(t, "grok_audio.go", "GrokVoice"))
	billingIndex := strings.Index(functionSource, "CheckBillingEligibility(")
	bodyIndex := strings.Index(functionSource, "readGrokVoiceGatewayBody(")
	validationIndex := strings.Index(functionSource, "validateGrokTTSRequestBody(")
	preflightIndex := strings.Index(functionSource, "preflightModelAvailabilityFromGin(")
	auditIndex := strings.Index(functionSource, "checkSecurityAudit(")
	for name, index := range map[string]int{
		"billing": billingIndex, "body": bodyIndex, "validation": validationIndex,
		"preflight": preflightIndex, "audit": auditIndex,
	} {
		require.NotEqualf(t, -1, index, "missing %s stage", name)
	}
	require.Less(t, billingIndex, bodyIndex)
	require.Less(t, bodyIndex, validationIndex)
	require.Less(t, validationIndex, preflightIndex)
	require.Less(t, preflightIndex, auditIndex)
}

func stripGoComments(source string) string {
	source = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(source, "")
	return regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(source, "")
}

func goFunctionSource(t *testing.T, filename, functionName string) string {
	t.Helper()
	raw, err := os.ReadFile(filename)
	require.NoError(t, err)
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, raw, 0)
	require.NoError(t, err)
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != functionName || function.Body == nil {
			continue
		}
		start := files.Position(function.Pos()).Offset
		end := files.Position(function.End()).Offset
		require.Greater(t, end, start)
		return string(raw[start:end])
	}
	t.Fatalf("function %s not found in %s", functionName, filename)
	return ""
}
