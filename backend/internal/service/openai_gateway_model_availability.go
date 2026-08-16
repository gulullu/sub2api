package service

import (
	"context"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

func (s *OpenAIGatewayService) getModelAvailabilityPreflightCache() *modelAvailabilityPreflightCache {
	s.modelAvailabilityCacheOnce.Do(func() {
		s.modelAvailabilityCache = newModelAvailabilityPreflightCache()
	})
	return s.modelAvailabilityCache
}

func (s *OpenAIGatewayService) modelAvailabilityQueryScope(groupID *int64, platform string) (*int64, bool, string) {
	platform = normalizeOpenAICompatiblePlatform(platform)
	queryGroupID := groupID
	includeGrouped := false
	if s.cfg != nil && s.cfg.RunMode == config.RunModeSimple {
		queryGroupID = nil
		includeGrouped = true
	}
	return queryGroupID, includeGrouped, platform
}

func (s *OpenAIGatewayService) queryModelAvailability(
	ctx context.Context,
	queryGroupID *int64,
	includeGrouped bool,
	requestedModel string,
	platform string,
) (ModelAvailabilityDiagnosis, error) {
	accounts, err := s.accountRepo.ListModelAvailabilityCandidates(
		ctx,
		queryGroupID,
		[]string{platform},
		includeGrouped,
	)
	if err != nil {
		return ModelAvailabilityDiagnosis{}, err
	}

	diagnosis := ModelAvailabilityDiagnosis{}
	for i := range accounts {
		diagnosis.HasAccountsInPool = true
		// Mirrors the per-candidate filter used during account selection
		// (openai_account_scheduler.isAccountRequestCompatible): empty
		// model_mapping accepts everything; otherwise the explicit / wildcard
		// mapping must match.
		if accounts[i].IsModelSupported(requestedModel) {
			diagnosis.HasModelSupport = true
			break
		}
	}
	return diagnosis, nil
}

// DiagnoseModelAvailabilityForPlatform reports whether the requested model
// is configured to be served by any persistently eligible OpenAI-compatible
// account in the group for the given platform (e.g. PlatformOpenAI,
// PlatformGrok). The platform scopes the candidate pool so distinct
// OpenAI-compatible platforms do not cross-contaminate diagnosis results.
// The query bypasses scheduler snapshots and ignores transient runtime state.
//
// Safe to call on the error path: returns {true,true} on any internal
// failure or when the inputs preclude meaningful diagnosis (empty model,
// nil service), so callers stay on the 503 fallback branch.
func (s *OpenAIGatewayService) DiagnoseModelAvailabilityForPlatform(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	platform string,
) ModelAvailabilityDiagnosis {
	if s == nil {
		return modelAvailabilitySafeDiagnosis()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		return modelAvailabilitySafeDiagnosis()
	}
	if s.accountRepo == nil {
		return modelAvailabilitySafeDiagnosis()
	}

	queryGroupID, includeGrouped, normalizedPlatform := s.modelAvailabilityQueryScope(groupID, platform)
	diagnosis, err := s.queryModelAvailability(ctx, queryGroupID, includeGrouped, requestedModel, normalizedPlatform)
	if err != nil {
		// Preserve the classifier's original conservative failure behavior.
		return modelAvailabilitySafeDiagnosis()
	}
	return diagnosis
}

// PreflightModelAvailabilityForPlatform is the bounded, short-lived lookup
// used by audited HTTP handlers before Prompt Audit. Unlike the shared
// Diagnose method above, it may rate-limit attacker-controlled cache misses
// and fail open; post-selection error classification remains a fresh lookup.
func (s *OpenAIGatewayService) PreflightModelAvailabilityForPlatform(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	platform string,
) ModelAvailabilityDiagnosis {
	if s == nil {
		return modelAvailabilitySafeDiagnosis()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(requestedModel) == "" {
		return modelAvailabilitySafeDiagnosis()
	}
	if len(requestedModel) > modelAvailabilityPreflightMaxModelBytes {
		return modelAvailabilitySafeDiagnosis()
	}
	if s.accountRepo == nil {
		return modelAvailabilitySafeDiagnosis()
	}

	queryGroupID, includeGrouped, platform := s.modelAvailabilityQueryScope(groupID, platform)
	key := modelAvailabilityPreflightKeyFor(queryGroupID, includeGrouped, requestedModel, platform)
	return s.getModelAvailabilityPreflightCache().diagnose(ctx, key, func(loadCtx context.Context) (ModelAvailabilityDiagnosis, error) {
		return s.queryModelAvailability(loadCtx, queryGroupID, includeGrouped, requestedModel, platform)
	})
}
