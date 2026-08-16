package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
)

// ModelAvailabilityDiagnosis describes whether the requested model can be
// served by any persistently eligible account in the group (active with its
// schedulable setting enabled), ignoring transient state such as rate limits,
// overload, temporary unschedulability, and runtime blocks. Handlers use this
// on the "no available accounts" error path to distinguish 404
// model_not_found from 503 service_unavailable.
type ModelAvailabilityDiagnosis struct {
	// HasAccountsInPool is true if the group has at least one persistently
	// eligible account on the queried platform (or, for Anthropic/Gemini, on
	// the platform plus mixed-scheduled Antigravity accounts).
	HasAccountsInPool bool
	// HasModelSupport is true if at least one account's model mapping admits
	// the requested model.
	HasModelSupport bool
}

// ModelAvailabilityDiagnoser is implemented by gateway services that can
// report whether the requested model is configured to be served by any
// account. Both *GatewayService and *OpenAIGatewayService implement this so
// handlers in either package can share a single classifier.
type ModelAvailabilityDiagnoser interface {
	DiagnoseModelAvailabilityForPlatform(
		ctx context.Context,
		groupID *int64,
		requestedModel string,
		platform string,
	) ModelAvailabilityDiagnosis
}

// ModelAvailabilityScope is the side-effect-free group/platform scope that
// GatewayService account selection will use after Claude Code fallback-group
// resolution. Handlers use it only for the pre-audit structural check.
type ModelAvailabilityScope struct {
	GroupID      *int64
	Platform     string
	RoutingModel string
}

// ResolveModelAvailabilityScope mirrors the scheduler's group fallback and
// platform resolution without selecting an account, reserving capacity,
// billing, or mutating request state.
func (s *GatewayService) ResolveModelAvailabilityScope(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
) (scope ModelAvailabilityScope, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			scope = ModelAvailabilityScope{}
			err = fmt.Errorf("resolve model availability scope: %v", recovered)
		}
	}()
	if s == nil {
		return ModelAvailabilityScope{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Group fallback/composite resolution is part of the pre-audit structural
	// check, not the authoritative scheduler. Bound its repository work so a
	// slow group lookup cannot consume the prompt-audit request budget. Unlike
	// the shared account-cache loader, this keeps caller cancellation and any
	// shorter parent deadline.
	resolveCtx, cancel := context.WithTimeout(ctx, modelAvailabilityPreflightLoadTimeout)
	defer cancel()
	ctx = resolveCtx
	group, resolvedGroupID, err := s.checkClaudeCodeRestriction(ctx, groupID)
	if err != nil {
		return ModelAvailabilityScope{}, err
	}
	if forcePlatform, ok := ctx.Value(ctxkey.ForcePlatform).(string); ok && strings.TrimSpace(forcePlatform) != "" {
		return ModelAvailabilityScope{GroupID: resolvedGroupID, Platform: forcePlatform, RoutingModel: requestedModel}, nil
	}
	if s.concurrencyService == nil || !s.schedulingConfig().LoadBatchEnabled {
		// The legacy branch delegates to SelectAccountForModelWithExclusions,
		// which resolves composite routing and then compares the upstream model.
		if group != nil && group.Platform == PlatformComposite {
			decision, matched, err := s.resolveCompositeRouteDecision(ctx, group, requestedModel, CompositeRouteEndpointAny)
			if err != nil {
				return ModelAvailabilityScope{}, err
			}
			if !matched {
				return ModelAvailabilityScope{}, fmt.Errorf("%w supporting model: %s (composite target platform unknown)", ErrNoAvailableAccounts, requestedModel)
			}
			return ModelAvailabilityScope{
				GroupID:      resolvedGroupID,
				Platform:     decision.TargetPlatform,
				RoutingModel: decision.UpstreamModel,
			}, nil
		}
		platform := PlatformAnthropic
		if group != nil {
			platform = group.Platform
		}
		return ModelAvailabilityScope{GroupID: resolvedGroupID, Platform: platform, RoutingModel: requestedModel}, nil
	}
	// The load-aware branch uses resolvePlatform only; it does not replace the
	// model passed to candidate compatibility checks with a composite upstream
	// model. Keep that existing scheduler behavior exactly.
	platform, _, err := s.resolvePlatform(ctx, resolvedGroupID, group, requestedModel)
	if err != nil {
		return ModelAvailabilityScope{}, err
	}
	return ModelAvailabilityScope{GroupID: resolvedGroupID, Platform: platform, RoutingModel: requestedModel}, nil
}

func (s *GatewayService) getModelAvailabilityPreflightCache() *modelAvailabilityPreflightCache {
	s.modelAvailabilityCacheOnce.Do(func() {
		s.modelAvailabilityCache = newModelAvailabilityPreflightCache()
	})
	return s.modelAvailabilityCache
}

func (s *GatewayService) modelAvailabilityQueryScope(
	groupID *int64,
	platform string,
	useMixed bool,
) (*int64, bool, []string) {
	platforms := []string{platform}
	if useMixed {
		platforms = append(platforms, PlatformAntigravity)
	}

	queryGroupID := groupID
	includeGrouped := false
	if useMixed {
		// Preserve the generic scheduler's scope rules: an explicit group wins
		// for mixed scheduling, while group-less simple mode scans all accounts.
		if groupID == nil && s.cfg != nil && s.cfg.RunMode == config.RunModeSimple {
			includeGrouped = true
		}
	} else if s.cfg != nil && s.cfg.RunMode == config.RunModeSimple {
		queryGroupID = nil
		includeGrouped = true
	}
	return queryGroupID, includeGrouped, platforms
}

func (s *GatewayService) queryModelAvailability(
	ctx context.Context,
	queryGroupID *int64,
	platforms []string,
	includeGrouped bool,
	requestedModel string,
	useMixed bool,
) (ModelAvailabilityDiagnosis, error) {
	accounts, err := s.accountRepo.ListModelAvailabilityCandidates(ctx, queryGroupID, platforms, includeGrouped)
	if err != nil {
		return ModelAvailabilityDiagnosis{}, err
	}

	diagnosis := ModelAvailabilityDiagnosis{}
	for i := range accounts {
		if useMixed && accounts[i].Platform == PlatformAntigravity && !accounts[i].IsMixedSchedulingEnabled() {
			continue
		}
		diagnosis.HasAccountsInPool = true
		if s.isModelSupportedByAccountWithContext(ctx, &accounts[i], requestedModel) {
			diagnosis.HasModelSupport = true
			break
		}
	}
	return diagnosis, nil
}

// DiagnoseModelAvailabilityForPlatform inspects accounts enabled for scheduling
// by persistent configuration and returns whether the requested model is
// configured to be served by any of them. The dedicated repository query
// bypasses scheduler snapshots and deliberately ignores transient rate-limit,
// overload, temporary-unschedulable, expiry, quota, and runtime-block state.
//
// Safe to call on the error path: returns {true,true} on any internal failure
// or when the inputs preclude meaningful diagnosis (empty model, etc.), so
// callers stay on the 503 fallback branch.
func (s *GatewayService) DiagnoseModelAvailabilityForPlatform(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	platform string,
) ModelAvailabilityDiagnosis {
	if s == nil {
		return modelAvailabilitySafeDiagnosis()
	}
	requestedModel = strings.TrimSpace(requestedModel)
	if requestedModel == "" {
		// No model specified — cannot decide model_not_found. Caller falls back to 503.
		return modelAvailabilitySafeDiagnosis()
	}
	if strings.TrimSpace(platform) == "" {
		// Without a platform we cannot scope the lookup; bail out to the
		// 503 branch rather than make an unscoped scan.
		return modelAvailabilitySafeDiagnosis()
	}

	if s.accountRepo == nil {
		return modelAvailabilitySafeDiagnosis()
	}

	useMixed := platform == PlatformAnthropic || platform == PlatformGemini
	queryGroupID, includeGrouped, platforms := s.modelAvailabilityQueryScope(groupID, platform, useMixed)
	diagnosis, err := s.queryModelAvailability(ctx, queryGroupID, platforms, includeGrouped, requestedModel, useMixed)
	if err != nil {
		// Conservative fallback: pretend everything is fine so the caller
		// returns 503 (we don't want to flip to 404 just because a lookup
		// hiccup'd).
		return modelAvailabilitySafeDiagnosis()
	}
	return diagnosis
}

// PreflightModelAvailabilityForPlatform performs the bounded structural lookup
// used by audited HTTP handlers. The raw scheduler model is retained in both
// the cache key and repository comparison; TrimSpace is only an emptiness
// guard so preflight cannot disagree with exact scheduler mappings.
func (s *GatewayService) PreflightModelAvailabilityForPlatform(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	platform string,
) ModelAvailabilityDiagnosis {
	if s == nil || s.accountRepo == nil || strings.TrimSpace(requestedModel) == "" || strings.TrimSpace(platform) == "" {
		return modelAvailabilitySafeDiagnosis()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(requestedModel) > modelAvailabilityPreflightMaxModelBytes {
		return modelAvailabilitySafeDiagnosis()
	}

	_, hasForcePlatform := ctx.Value(ctxkey.ForcePlatform).(string)
	if forcePlatform, ok := ctx.Value(ctxkey.ForcePlatform).(string); ok && strings.TrimSpace(forcePlatform) == "" {
		hasForcePlatform = false
	}
	useMixed := (platform == PlatformAnthropic || platform == PlatformGemini) && !hasForcePlatform
	queryGroupID, includeGrouped, platforms := s.modelAvailabilityQueryScope(groupID, platform, useMixed)
	keyPlatform := platform
	if useMixed {
		keyPlatform = "mixed:" + platform
	} else if hasForcePlatform {
		keyPlatform = "forced:" + platform
	}
	key := modelAvailabilityPreflightKeyFor(queryGroupID, includeGrouped, requestedModel, keyPlatform)
	if thinkingEnabled, ok := ThinkingEnabledFromContext(ctx); ok {
		if thinkingEnabled {
			key.variant = "thinking:on"
		} else {
			key.variant = "thinking:off"
		}
	} else {
		key.variant = "thinking:unset"
	}
	return s.getModelAvailabilityPreflightCache().diagnose(ctx, key, func(loadCtx context.Context) (ModelAvailabilityDiagnosis, error) {
		return s.queryModelAvailability(loadCtx, queryGroupID, platforms, includeGrouped, requestedModel, useMixed)
	})
}
