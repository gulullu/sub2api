package securityaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type ScannerDefinition struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	LabelZH     string `json:"label_zh"`
	Description string `json:"description"`
}

var AllScannerIDs = []string{
	"violent",
	"non_violent_illegal_acts",
	"sexual_content_or_sexual_acts",
	"pii",
	"suicide_and_self_harm",
	"unethical_acts",
	"politically_sensitive_topics",
	"copyright_violation",
	"jailbreak",
}

var ScannerCatalog = map[string]ScannerDefinition{
	"violent":                       {ID: "violent", Label: "Violent", LabelZH: "暴力", Description: "Violence or threats of violence"},
	"non_violent_illegal_acts":      {ID: "non_violent_illegal_acts", Label: "Non-violent Illegal Acts", LabelZH: "非暴力违法行为", Description: "Non-violent illegal activity"},
	"sexual_content_or_sexual_acts": {ID: "sexual_content_or_sexual_acts", Label: "Sexual Content or Sexual Acts", LabelZH: "性内容或性行为", Description: "Sexual content or sexual acts"},
	"pii":                           {ID: "pii", Label: "PII", LabelZH: "个人敏感信息", Description: "Personal identifying information"},
	"suicide_and_self_harm":         {ID: "suicide_and_self_harm", Label: "Suicide & Self-Harm", LabelZH: "自杀与自残", Description: "Suicide or self-harm"},
	"unethical_acts":                {ID: "unethical_acts", Label: "Unethical Acts", LabelZH: "不道德行为", Description: "Unethical behavior"},
	"politically_sensitive_topics":  {ID: "politically_sensitive_topics", Label: "Politically Sensitive Topics", LabelZH: "政治敏感话题", Description: "Politically sensitive topics"},
	"copyright_violation":           {ID: "copyright_violation", Label: "Copyright Violation", LabelZH: "版权侵权", Description: "Copyright infringement"},
	"jailbreak":                     {ID: "jailbreak", Label: "Jailbreak", LabelZH: "越狱攻击", Description: "Prompt injection or jailbreak attempt"},
}

var categoryAliases = map[string]string{
	"violent": "violent", "violence": "violent",
	"non violent illegal acts": "non_violent_illegal_acts", "non-violent illegal acts": "non_violent_illegal_acts",
	"sexual content or sexual acts": "sexual_content_or_sexual_acts", "sexual": "sexual_content_or_sexual_acts",
	"pii": "pii", "personal identifying information": "pii", "personal identifiable information": "pii",
	"suicide self harm": "suicide_and_self_harm", "suicide and self harm": "suicide_and_self_harm", "suicide & self-harm": "suicide_and_self_harm",
	"unethical acts": "unethical_acts", "unethical": "unethical_acts",
	"politically sensitive topics": "politically_sensitive_topics", "political": "politically_sensitive_topics",
	"copyright violation": "copyright_violation", "copyright": "copyright_violation",
	"jailbreak": "jailbreak", "prompt injection": "jailbreak",
}

type GuardError struct {
	Code       string
	HTTPStatus int
	Retryable  bool
	Timeout    bool
	Cause      error
}

func (e *GuardError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code
}

func (e *GuardError) Unwrap() error { return e.Cause }

func NormalizeCategory(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.NewReplacer("_", " ", "&", " and ", "/", " ", "-", " ", "–", " ", "—", " ").Replace(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	if canonical, ok := categoryAliases[normalized]; ok {
		return canonical
	}
	return strings.ReplaceAll(normalized, " ", "_")
}

func ParseQwen3Guard(content string, enabledScanners []string) (*NormalizedResult, error) {
	var safety string
	var categoryLine string
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "safety:"):
			if safety != "" {
				return nil, &GuardError{Code: ErrorCodeInvalidResponse}
			}
			safety = strings.TrimSpace(line[len("safety:"):])
		case strings.HasPrefix(lower, "categories:"):
			if categoryLine != "" {
				return nil, &GuardError{Code: ErrorCodeInvalidResponse}
			}
			categoryLine = strings.TrimSpace(line[len("categories:"):])
		default:
			// Auxiliary Guard fields, such as Refusal, do not affect audit decisions.
		}
	}
	switch strings.ToLower(safety) {
	case "safe":
		safety = "Safe"
	case "controversial":
		safety = "Controversial"
	case "unsafe":
		safety = "Unsafe"
	default:
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	if categoryLine == "" {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	enabled := make(map[string]struct{}, len(enabledScanners))
	for _, scanner := range enabledScanners {
		enabled[NormalizeCategory(scanner)] = struct{}{}
	}
	known := map[string]struct{}{}
	unknown := map[string]struct{}{}
	for _, raw := range strings.Split(categoryLine, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.EqualFold(raw, "none") || strings.EqualFold(raw, "n/a") {
			continue
		}
		category := NormalizeCategory(raw)
		if _, ok := ScannerCatalog[category]; ok {
			known[category] = struct{}{}
		} else {
			unknown[unknownCategoryID(category)] = struct{}{}
		}
	}
	knownList := orderedScannerKeys(known)
	unknownList := sortedKeys(unknown)
	matched := make([]string, 0, len(knownList))
	for _, category := range knownList {
		if _, ok := enabled[category]; ok {
			matched = append(matched, category)
		}
	}
	result := &NormalizedResult{
		Safety: safety, Categories: knownList, MatchedScanners: matched, UnknownCategories: unknownList,
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{},
		ScannerBackend: "qwen3guard-openai", ScannerVersion: "qwen3guard",
		PolicyID: "priority", PolicyVersion: 1,
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow,
	}
	score := 0.0
	if safety == "Controversial" {
		score = 0.5
		result.Decision, result.RiskLevel, result.Action = EventFlag, RiskMedium, ActionWarn
	}
	if safety == "Unsafe" {
		score = 1
		if len(matched) > 0 || len(unknownList) > 0 || len(knownList) == 0 {
			result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
		} else {
			result.Decision, result.RiskLevel, result.Action = EventFlag, RiskHigh, ActionWarn
		}
	}
	for _, category := range matched {
		result.ScannerScores[category] = score
		result.ScannerEvidence[category] = ScannerCatalog[category].Label
		if safety == "Controversial" && isElevatedControversial(category) {
			result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
		}
	}
	return result, nil
}

func unknownCategoryID(value string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(strings.ToLower(value))))
	return fmt.Sprintf("unknown:%x", digest[:8])
}

func isElevatedControversial(category string) bool {
	return category == "jailbreak" || category == "pii" || category == "suicide_and_self_harm"
}

type OpenAICompatibleScanner struct {
	clients sync.Map
}

func NewOpenAICompatibleScanner() *OpenAICompatibleScanner { return &OpenAICompatibleScanner{} }

func (s *OpenAICompatibleScanner) Scan(ctx context.Context, endpoint ActiveEndpoint, chunk string, enabledScanners []string) (*NormalizedResult, error) {
	client, err := s.clientFor(endpoint)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: err}
	}
	adapter := strings.TrimSpace(endpoint.Adapter)
	if adapter == "" {
		adapter = AdapterQwen3Guard
	}
	requestURL := ""
	if adapter == AdapterOpenAIModeration {
		requestURL, err = ModerationsURL(endpoint.BaseURL)
	} else {
		requestURL, err = ChatCompletionsURL(endpoint.BaseURL)
	}
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: err}
	}
	var payload map[string]any
	switch adapter {
	case AdapterQwen3Guard:
		payload = map[string]any{
			"model":       endpoint.Model,
			"messages":    []map[string]string{{"role": "user", "content": chunk}},
			"temperature": 0,
			"max_tokens":  64,
			"seed":        42,
		}
	case AdapterConfidenceJSON:
		systemPrompt := confidenceJSONSystemPrompt(endpoint.SystemPrompt)
		payload = map[string]any{
			"model": endpoint.Model,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": WrapPromptAuditInput(chunk)},
			},
			"temperature": 0,
		}
	case AdapterOpenAIModeration:
		payload = map[string]any{"model": endpoint.Model, "input": chunk}
	default:
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	if endpoint.Token != "" {
		req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		timeout := errors.Is(err, context.DeadlineExceeded)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			timeout = true
		}
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: timeout, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: resp.StatusCode, Retryable: retryable}
	}
	limited := io.LimitReader(resp.Body, maxGuardResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: err}
	}
	if int64(len(responseBody)) > maxGuardResponseBytes {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	var result *NormalizedResult
	switch adapter {
	case AdapterQwen3Guard:
		content, extractErr := extractOpenAIContent(responseBody)
		if extractErr != nil {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: extractErr}
		}
		result, err = ParseQwen3Guard(content, enabledScanners)
	case AdapterConfidenceJSON:
		content, extractErr := extractOpenAIContent(responseBody)
		if extractErr != nil {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: extractErr}
		}
		result, err = ParseConfidenceJSON(content, endpoint)
	case AdapterOpenAIModeration:
		result, err = ParseOpenAIModeration(responseBody, endpoint, enabledScanners)
	}
	if err != nil {
		return nil, err
	}
	result.GuardEndpointID = endpoint.ID
	result.ScannerVersion = endpoint.Model
	return result, nil
}

var openAIModerationCategoryOrder = []string{
	"violence", "violence/graphic", "illicit/violent", "illicit",
	"sexual", "sexual/minors",
	"self-harm", "self-harm/intent", "self-harm/instructions",
	"harassment", "harassment/threatening", "hate", "hate/threatening",
}

var openAIModerationReasonLabels = map[string]string{
	"violent":                       "暴力或暴力型违法风险",
	"non_violent_illegal_acts":      "非暴力违法风险",
	"sexual_content_or_sexual_acts": "性内容风险",
	"suicide_and_self_harm":         "自杀与自残风险",
	"unethical_acts":                "骚扰或仇恨风险",
}

// ParseOpenAIModeration normalizes the official /v1/moderations response. The
// provider's flagged boolean is authoritative for Safe vs Unsafe; category
// scores are evidence only and never compared with Prompt Audit confidence
// thresholds. As with Qwen3Guard, disabled known scanners downgrade an Unsafe
// result to a warning instead of silently overriding the administrator policy.
func ParseOpenAIModeration(body []byte, endpoint ActiveEndpoint, enabledScanners []string) (*NormalizedResult, error) {
	var response struct {
		Results []struct {
			Flagged        *bool              `json:"flagged"`
			Categories     map[string]bool    `json:"categories"`
			CategoryScores map[string]float64 `json:"category_scores"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Results) == 0 || response.Results[0].Flagged == nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("OpenAI moderation response invalid")}
	}
	moderation := response.Results[0]
	flaggedCategories := make(map[string]struct{})
	scores := make(map[string]float64)
	confidence := 0.0
	for _, rawCategory := range openAIModerationCategoryOrder {
		category := mapOpenAIModerationCategory(rawCategory)
		if category == "" {
			continue
		}
		if score, ok := moderation.CategoryScores[rawCategory]; ok {
			if math.IsNaN(score) || math.IsInf(score, 0) || score < 0 || score > 1 {
				return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("OpenAI moderation category score invalid")}
			}
			if score > scores[category] {
				scores[category] = score
			}
			if score > confidence {
				confidence = score
			}
		}
		if moderation.Categories[rawCategory] {
			flaggedCategories[category] = struct{}{}
		}
	}
	categories := orderedScannerKeys(flaggedCategories)
	enabled := make(map[string]struct{}, len(enabledScanners))
	for _, scanner := range enabledScanners {
		enabled[NormalizeCategory(scanner)] = struct{}{}
	}
	matched := make([]string, 0, len(categories))
	for _, category := range categories {
		if _, ok := enabled[category]; ok {
			matched = append(matched, category)
		}
	}
	evidence := make(map[string]string, len(categories))
	labels := make([]string, 0, len(categories))
	for _, category := range categories {
		label := openAIModerationReasonLabels[category]
		evidence[category] = "OpenAI 审核模型标记存在" + label + "。"
		labels = append(labels, label)
	}
	result := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: categories, MatchedScanners: matched, ScannerScores: scores, ScannerEvidence: evidence,
		ScannerBackend: "openai-moderation", ScannerVersion: endpoint.Model,
		PolicyID: "openai-moderation", PolicyVersion: 1, Confidence: confidence,
	}
	if *moderation.Flagged {
		if len(labels) == 0 {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("OpenAI moderation flagged result has no mapped category")}
		}
		result.Safety = "Unsafe"
		result.Reason = "OpenAI 审核模型判定命中：" + strings.Join(labels, "、") + "。"
		if len(matched) > 0 {
			result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
		} else {
			result.Decision, result.RiskLevel, result.Action = EventFlag, RiskHigh, ActionWarn
		}
	}
	return result, nil
}

func mapOpenAIModerationCategory(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "illicit/violent", strings.HasPrefix(value, "violence"):
		return "violent"
	case value == "illicit":
		return "non_violent_illegal_acts"
	case strings.HasPrefix(value, "sexual"):
		return "sexual_content_or_sexual_acts"
	case strings.HasPrefix(value, "self-harm"):
		return "suicide_and_self_harm"
	case strings.HasPrefix(value, "harassment"), strings.HasPrefix(value, "hate"):
		return "unethical_acts"
	default:
		return ""
	}
}

const confidenceScoreKey = "confidence_json"

// ParseConfidenceJSON accepts a plain or fenced JSON object from a generic
// chat-completions model. confidence is authoritative when present; flagged is
// retained only as a compatibility fallback for older audit prompts.
func ParseConfidenceJSON(content string, endpoint ActiveEndpoint) (*NormalizedResult, error) {
	object, err := firstJSONObject(content)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	reasonRaw, hasReason := fields["reason"]
	if !hasReason {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("prompt guard reason missing")}
	}
	var reason string
	if err := json.Unmarshal(reasonRaw, &reason); err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("prompt guard reason invalid")}
	}
	// The prompt asks for a concise reason, but upstream models can return a
	// longer explanation. Preserve that complete explanation for administrator
	// review; the HTTP response-size limit still bounds it, and any echoed
	// credentials or identity patterns are masked before persistence.
	reason = RedactSensitiveText(strings.TrimSpace(reason))

	confidence := 0.0
	confidenceRaw, hasConfidence := fields["confidence"]
	if hasConfidence && !bytes.Equal(bytes.TrimSpace(confidenceRaw), []byte("null")) {
		if err := json.Unmarshal(confidenceRaw, &confidence); err != nil || math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1 {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("prompt guard confidence invalid")}
		}
	} else {
		flaggedRaw, hasFlagged := fields["flagged"]
		if !hasFlagged {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("prompt guard confidence missing")}
		}
		var flagged bool
		if err := json.Unmarshal(flaggedRaw, &flagged); err != nil {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: errors.New("prompt guard flagged invalid")}
		}
		if flagged {
			confidence = 1
		}
	}

	flagThreshold, blockThreshold := endpoint.FlagThreshold, endpoint.BlockThreshold
	if blockThreshold <= 0 || blockThreshold > 1 || flagThreshold < 0 || flagThreshold >= blockThreshold {
		flagThreshold, blockThreshold = DefaultFlagThreshold, DefaultBlockThreshold
	}
	result := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: []string{}, MatchedScanners: []string{},
		ScannerScores:   map[string]float64{confidenceScoreKey: confidence},
		ScannerEvidence: map[string]string{confidenceScoreKey: reason},
		ScannerBackend:  "confidence-json-openai", ScannerVersion: endpoint.Model,
		PolicyID: endpoint.PromptTemplateID, PolicyVersion: 1,
		Confidence: confidence, Reason: reason,
	}
	if result.PolicyID == "" {
		result.PolicyID = DefaultPromptTemplateID
	}
	switch {
	case confidence >= blockThreshold:
		result.Decision, result.RiskLevel, result.Action, result.Safety = EventCritical, RiskCritical, ActionBlock, "Unsafe"
		result.MatchedScanners = []string{confidenceScoreKey}
	case confidence >= flagThreshold:
		result.Decision, result.RiskLevel, result.Action, result.Safety = EventFlag, RiskMedium, ActionWarn, "Controversial"
		result.MatchedScanners = []string{confidenceScoreKey}
	}
	return result, nil
}

func firstJSONObject(content string) ([]byte, error) {
	content = strings.TrimSpace(content)
	start := strings.IndexByte(content, '{')
	if start < 0 {
		return nil, errors.New("prompt guard JSON object missing")
	}
	depth := 0
	inString := false
	escaped := false
	for index := start; index < len(content); index++ {
		switch current := content[index]; {
		case inString && escaped:
			escaped = false
		case inString && current == '\\':
			escaped = true
		case current == '"':
			inString = !inString
		case !inString && current == '{':
			depth++
		case !inString && current == '}':
			depth--
			if depth == 0 {
				return []byte(content[start : index+1]), nil
			}
		}
	}
	return nil, errors.New("prompt guard JSON object incomplete")
}

func (s *OpenAICompatibleScanner) clientFor(endpoint ActiveEndpoint) (*http.Client, error) {
	key := fmt.Sprintf("%s|%s|%d", endpoint.ID, endpoint.BaseURL, endpoint.TimeoutMS)
	if cached, ok := s.clients.Load(key); ok {
		client, valid := cached.(*http.Client)
		if !valid {
			s.clients.Delete(key)
			return nil, errors.New("prompt guard client cache invalid")
		}
		return client, nil
	}
	client, err := NewSecureHTTPClient(endpoint)
	if err != nil {
		return nil, err
	}
	actual, _ := s.clients.LoadOrStore(key, client)
	actualClient, ok := actual.(*http.Client)
	if !ok {
		s.clients.Delete(key)
		return nil, errors.New("prompt guard client cache invalid")
	}
	return actualClient, nil
}

func extractOpenAIContent(body []byte) (string, error) {
	var response struct {
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Choices) == 0 {
		return "", errors.New("prompt guard response envelope invalid")
	}
	content := response.Choices[0].Message.Content
	switch typed := content.(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return "", errors.New("prompt guard response content empty")
		}
		return typed, nil
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := object["text"].(string); ok && strings.TrimSpace(text) != "" {
				parts = append(parts, text)
			}
		}
		if len(parts) == 0 {
			return "", errors.New("prompt guard response content empty")
		}
		return strings.Join(parts, "\n"), nil
	default:
		return "", errors.New("prompt guard response content invalid")
	}
}

func ScannerDefinitions() []ScannerDefinition {
	result := make([]ScannerDefinition, 0, len(AllScannerIDs))
	for _, id := range AllScannerIDs {
		result = append(result, ScannerCatalog[id])
	}
	sort.SliceStable(result, func(i, j int) bool { return i < j })
	return result
}
