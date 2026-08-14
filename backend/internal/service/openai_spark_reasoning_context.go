package service

import (
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// normalizeCodexSparkReasoningContextForUpstream keeps the request compatible
// with Spark after all model mappings have resolved. Spark does not accept the
// all_turns context used by Responses Lite; current_turn is its deterministic
// supported equivalent. Other models and already-supported values are left
// untouched.
func normalizeCodexSparkReasoningContextForUpstream(payload []byte, upstreamModel string) ([]byte, bool, error) {
	if !isCodexSparkModel(upstreamModel) {
		return payload, false, nil
	}

	contextValue := gjson.GetBytes(payload, "reasoning.context")
	if contextValue.Type != gjson.String || !strings.EqualFold(strings.TrimSpace(contextValue.String()), "all_turns") {
		return payload, false, nil
	}

	updated, err := sjson.SetBytes(payload, "reasoning.context", "current_turn")
	if err != nil {
		return payload, false, fmt.Errorf("normalize Spark reasoning.context: %w", err)
	}
	return updated, true, nil
}
