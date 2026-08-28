package securityaudit

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

const (
	defaultPromptDecisionCacheTTL  = 10 * time.Minute
	defaultPromptDecisionCacheSize = 10000
)

type promptDecisionCacheEntry struct {
	key       string
	result    *NormalizedResult
	expiresAt time.Time
}

// promptDecisionCache is deliberately process-local and bounded. A cache miss
// only costs another audit call; it never weakens enforcement if Redis or the
// database is unavailable.
type promptDecisionCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	lru     *list.List
	ttl     time.Duration
	maxSize int
}

func newPromptDecisionCache(maxSize int, ttl time.Duration) *promptDecisionCache {
	if maxSize < 1 {
		maxSize = defaultPromptDecisionCacheSize
	}
	if ttl <= 0 {
		ttl = defaultPromptDecisionCacheTTL
	}
	return &promptDecisionCache{entries: make(map[string]*list.Element), lru: list.New(), ttl: ttl, maxSize: maxSize}
}

func (c *promptDecisionCache) get(key string, now time.Time) (*NormalizedResult, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	element, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := element.Value.(*promptDecisionCacheEntry)
	if !now.Before(entry.expiresAt) {
		c.remove(element)
		return nil, false
	}
	c.lru.MoveToFront(element)
	return cloneNormalizedResult(entry.result), true
}

func (c *promptDecisionCache) put(key string, result *NormalizedResult, now time.Time) {
	if c == nil || key == "" || result == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, exists := c.entries[key]; exists {
		entry := element.Value.(*promptDecisionCacheEntry)
		entry.result = cloneNormalizedResult(result)
		entry.expiresAt = now.Add(c.ttl)
		c.lru.MoveToFront(element)
		return
	}
	entry := &promptDecisionCacheEntry{
		key: key, result: cloneNormalizedResult(result), expiresAt: now.Add(c.ttl),
	}
	c.entries[key] = c.lru.PushFront(entry)
	if len(c.entries) > c.maxSize {
		c.remove(c.lru.Back())
	}
}

func (c *promptDecisionCache) remove(element *list.Element) {
	if c == nil || element == nil {
		return
	}
	entry, _ := element.Value.(*promptDecisionCacheEntry)
	if entry != nil {
		delete(c.entries, entry.key)
	}
	c.lru.Remove(element)
}

func promptDecisionCacheKey(cfg ActiveConfig, scanText string) string {
	type cacheEndpoint struct {
		ID               string  `json:"id"`
		Priority         int     `json:"priority"`
		Adapter          string  `json:"adapter"`
		BaseURL          string  `json:"base_url"`
		Model            string  `json:"model"`
		TimeoutMS        int     `json:"timeout_ms"`
		InputLimit       int     `json:"input_limit"`
		PromptTemplateID string  `json:"prompt_template_id"`
		SystemPrompt     string  `json:"system_prompt"`
		FlagThreshold    float64 `json:"flag_threshold"`
		BlockThreshold   float64 `json:"block_threshold"`
	}
	type cachePolicy struct {
		ConfigVersion       int64           `json:"config_version"`
		Scanners            []string        `json:"scanners"`
		RiskRouteAccountIDs []int64         `json:"risk_route_account_ids"`
		NoRouteFallbackMode string          `json:"no_route_fallback_mode"`
		MaxTotalInputChars  int             `json:"max_total_input_chars"`
		BlockHTTPStatus     int             `json:"block_http_status"`
		BlockMessage        string          `json:"block_message"`
		Endpoints           []cacheEndpoint `json:"endpoints"`
	}
	policy := cachePolicy{
		ConfigVersion: cfg.ConfigVersion, Scanners: cfg.Scanners,
		RiskRouteAccountIDs: cfg.RiskRouteAccountIDs, MaxTotalInputChars: cfg.MaxTotalInputChars,
		NoRouteFallbackMode: cfg.NoRouteFallbackMode, BlockHTTPStatus: cfg.BlockHTTPStatus, BlockMessage: cfg.BlockMessage,
	}
	for _, endpoint := range cfg.EnabledEndpoints() {
		effectiveSystemPrompt := endpoint.SystemPrompt
		if strings.EqualFold(strings.TrimSpace(endpoint.Adapter), AdapterConfidenceJSON) {
			effectiveSystemPrompt = confidenceJSONSystemPrompt(effectiveSystemPrompt)
		}
		policy.Endpoints = append(policy.Endpoints, cacheEndpoint{
			ID: endpoint.ID, Priority: endpoint.Priority, Adapter: endpoint.Adapter, BaseURL: endpoint.BaseURL, Model: endpoint.Model,
			TimeoutMS: endpoint.TimeoutMS, InputLimit: endpoint.InputLimit,
			PromptTemplateID: endpoint.PromptTemplateID, SystemPrompt: effectiveSystemPrompt,
			FlagThreshold: endpoint.FlagThreshold, BlockThreshold: endpoint.BlockThreshold,
		})
	}
	policyJSON, _ := json.Marshal(policy)
	digest := sha256.New()
	_, _ = digest.Write(policyJSON)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(scanText))
	return hex.EncodeToString(digest.Sum(nil))
}

func cloneNormalizedResult(result *NormalizedResult) *NormalizedResult {
	if result == nil {
		return nil
	}
	cloned := *result
	// Event persistence requires JSON arrays, not null. Start from non-nil
	// empty slices so cached pass results retain the same storage shape as
	// freshly scanned results.
	cloned.Categories = append([]string{}, result.Categories...)
	cloned.MatchedScanners = append([]string{}, result.MatchedScanners...)
	cloned.UnknownCategories = append([]string{}, result.UnknownCategories...)
	cloned.ScannerScores = make(map[string]float64, len(result.ScannerScores))
	for key, value := range result.ScannerScores {
		cloned.ScannerScores[key] = value
	}
	cloned.ScannerEvidence = make(map[string]string, len(result.ScannerEvidence))
	for key, value := range result.ScannerEvidence {
		cloned.ScannerEvidence[key] = value
	}
	return &cloned
}
