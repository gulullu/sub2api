package securityaudit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func cachedTestResult() *NormalizedResult {
	return &NormalizedResult{
		Decision: EventFlag, RiskLevel: RiskMedium, Action: ActionWarn,
		Categories: []string{"cyber"}, MatchedScanners: []string{"confidence"},
		ScannerScores:   map[string]float64{"confidence": .5},
		ScannerEvidence: map[string]string{"confidence": "risk"},
	}
}

func TestPromptDecisionCacheDeepCloneTTLAndLRUEviction(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	cache := newPromptDecisionCache(2, time.Minute)
	original := cachedTestResult()
	cache.put("a", original, now)
	original.Categories[0] = "mutated"
	original.ScannerScores["confidence"] = 1

	first, ok := cache.get("a", now.Add(time.Second))
	require.True(t, ok)
	require.Equal(t, []string{"cyber"}, first.Categories)
	require.Equal(t, .5, first.ScannerScores["confidence"])
	first.Categories[0] = "also-mutated"
	second, ok := cache.get("a", now.Add(2*time.Second))
	require.True(t, ok)
	require.Equal(t, []string{"cyber"}, second.Categories)

	cache.put("b", cachedTestResult(), now.Add(3*time.Second))
	_, ok = cache.get("a", now.Add(4*time.Second)) // a becomes most recently used.
	require.True(t, ok)
	cache.put("c", cachedTestResult(), now.Add(5*time.Second))
	_, ok = cache.get("b", now.Add(6*time.Second))
	require.False(t, ok, "least recently used entry must be evicted in O(1)")
	_, ok = cache.get("a", now.Add(6*time.Second))
	require.True(t, ok)
	_, ok = cache.get("c", now.Add(6*time.Second))
	require.True(t, ok)
	require.Len(t, cache.entries, 2)

	_, ok = cache.get("a", now.Add(2*time.Minute))
	require.False(t, ok)
	require.Len(t, cache.entries, 1)
}

func TestPromptDecisionCacheKeyCoversInputAndPolicy(t *testing.T) {
	base := ActiveConfig{
		ConfigVersion: 7, Scanners: []string{"cyber"}, RiskRouteAccountIDs: []int64{9},
		MaxTotalInputChars: 40000, BlockHTTPStatus: 403, BlockMessage: "blocked",
		Endpoints: []ActiveEndpoint{{
			ID: "deepseek", Adapter: AdapterConfidenceJSON, BaseURL: "https://api.deepseek.com/v1",
			Model: "deepseek-chat", TimeoutMS: 40000, InputLimit: 40000, Enabled: true,
			PromptTemplateID: "default", SystemPrompt: "audit", FlagThreshold: .4, BlockThreshold: .7,
		}},
	}
	baseKey := promptDecisionCacheKey(base, "same prompt")
	require.NotEqual(t, baseKey, promptDecisionCacheKey(base, "different prompt"))

	mutations := []func(*ActiveConfig){
		func(cfg *ActiveConfig) { cfg.ConfigVersion++ },
		func(cfg *ActiveConfig) { cfg.Scanners = []string{"different"} },
		func(cfg *ActiveConfig) { cfg.RiskRouteAccountIDs = []int64{10} },
		func(cfg *ActiveConfig) { cfg.MaxTotalInputChars++ },
		func(cfg *ActiveConfig) { cfg.BlockHTTPStatus = 422 },
		func(cfg *ActiveConfig) { cfg.BlockMessage = "different" },
		func(cfg *ActiveConfig) { cfg.Endpoints[0].Model = "deepseek-v4" },
		func(cfg *ActiveConfig) { cfg.Endpoints[0].SystemPrompt = "different audit policy" },
		func(cfg *ActiveConfig) { cfg.Endpoints[0].FlagThreshold = .3 },
	}
	for index, mutate := range mutations {
		cfg := cloneActiveConfig(base)
		mutate(&cfg)
		require.NotEqualf(t, baseKey, promptDecisionCacheKey(cfg, "same prompt"), "mutation %d must invalidate cache", index)
	}
}
