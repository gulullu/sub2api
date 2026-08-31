package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestPromptRiskRoutePoolExhaustionHasDedicatedErrorAndPreservesCause(t *testing.T) {
	ctx := WithPromptRiskRouteAccounts(context.Background(), []int64{8})
	err := normalizePromptRiskRouteSelectionError(ctx, ErrNoAvailableAccounts)

	require.True(t, errors.Is(err, ErrPromptRiskRouteUnavailable))
	require.True(t, errors.Is(err, ErrNoAvailableAccounts))
	require.Equal(t, http.StatusServiceUnavailable, infraerrors.Code(err))
	require.Equal(t, "PROMPT_RISK_ROUTE_UNAVAILABLE", infraerrors.Reason(err))
	require.False(t, errors.Is(normalizePromptRiskRouteSelectionError(context.Background(), ErrNoAvailableAccounts), ErrPromptRiskRouteUnavailable))
}

func TestPromptRiskRouteStateConflictHasDedicated503(t *testing.T) {
	err := newPromptRiskRouteStateConflictError()

	require.ErrorIs(t, err, ErrPromptRiskRouteStateConflict)
	require.Equal(t, http.StatusServiceUnavailable, infraerrors.Code(err))
	require.Equal(t, "PROMPT_RISK_ROUTE_STATE_CONFLICT", infraerrors.Reason(err))
	require.Equal(t, "Service temporarily unavailable", infraerrors.Message(err))
}

func TestPromptRiskRouteContextIsHardAllowlist(t *testing.T) {
	base := context.Background()
	require.False(t, PromptRiskRouteEnabled(base))
	require.True(t, PromptRiskRouteAllowsAccount(base, 99))

	ctx := WithPromptRiskRouteAccounts(base, []int64{2, 1, 2, 0, -1})
	require.True(t, PromptRiskRouteEnabled(ctx))
	require.True(t, PromptRiskRouteAllowsAccount(ctx, 1))
	require.True(t, PromptRiskRouteAllowsAccount(ctx, 2))
	require.False(t, PromptRiskRouteAllowsAccount(ctx, 3))
	require.False(t, PromptRiskRouteFallbackAllowed(ctx))

	allowCtx := WithPromptRiskRoutePolicy(base, []int64{2, 1}, true)
	require.True(t, PromptRiskRouteEnabled(allowCtx))
	require.True(t, PromptRiskRouteFallbackAllowed(allowCtx))
	require.False(t, PromptRiskRouteAllowsAccount(allowCtx, 3), "fallback must not soften the first-pass hard pool")
}

func TestSelectWithPromptRiskRouteFallbackRetriesOnlyDedicatedPoolExhaustion(t *testing.T) {
	t.Run("allow retries once through ordinary pool", func(t *testing.T) {
		calls := 0
		ctx := WithPromptRiskRoutePolicy(context.Background(), []int64{99}, true)
		value, err := selectWithPromptRiskRouteFallback(ctx, func(attemptCtx context.Context) (int, error) {
			calls++
			if PromptRiskRouteEnabled(attemptCtx) {
				return 0, ErrNoAvailableAccounts
			}
			return 42, nil
		})

		require.NoError(t, err)
		require.Equal(t, 42, value)
		require.Equal(t, 2, calls)
	})

	t.Run("block keeps dedicated unavailable error", func(t *testing.T) {
		calls := 0
		ctx := WithPromptRiskRouteAccounts(context.Background(), []int64{99})
		_, err := selectWithPromptRiskRouteFallback(ctx, func(context.Context) (int, error) {
			calls++
			return 0, ErrNoAvailableAccounts
		})

		require.ErrorIs(t, err, ErrPromptRiskRouteUnavailable)
		require.Equal(t, 1, calls)
	})

	t.Run("state conflict never falls back", func(t *testing.T) {
		calls := 0
		ctx := WithPromptRiskRoutePolicy(context.Background(), []int64{99}, true)
		_, err := selectWithPromptRiskRouteFallback(ctx, func(context.Context) (int, error) {
			calls++
			return 0, newPromptRiskRouteStateConflictError()
		})

		require.ErrorIs(t, err, ErrPromptRiskRouteStateConflict)
		require.Equal(t, 1, calls)
	})

	t.Run("unknown internal error never falls back", func(t *testing.T) {
		calls := 0
		sentinel := errors.New("repository unavailable")
		ctx := WithPromptRiskRoutePolicy(context.Background(), []int64{99}, true)
		_, err := selectWithPromptRiskRouteFallback(ctx, func(context.Context) (int, error) {
			calls++
			return 0, sentinel
		})

		require.ErrorIs(t, err, sentinel)
		require.Equal(t, 1, calls)
	})

	t.Run("canceled request never starts ordinary retry", func(t *testing.T) {
		calls := 0
		base, cancel := context.WithCancel(context.Background())
		ctx := WithPromptRiskRoutePolicy(base, []int64{99}, true)
		_, err := selectWithPromptRiskRouteFallback(ctx, func(context.Context) (int, error) {
			calls++
			cancel()
			return 0, ErrNoAvailableAccounts
		})

		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 1, calls)
	})

	t.Run("ordinary retry failure is marked but preserves cause", func(t *testing.T) {
		calls := 0
		ctx := WithPromptRiskRoutePolicy(context.Background(), []int64{99}, true)
		_, err := selectWithPromptRiskRouteFallback(ctx, func(attemptCtx context.Context) (int, error) {
			calls++
			return 0, ErrNoAvailableAccounts
		})

		require.True(t, IsPromptRiskRouteFallbackResult(err))
		require.ErrorIs(t, err, ErrNoAvailableAccounts)
		require.False(t, errors.Is(err, ErrPromptRiskRouteUnavailable))
		require.Equal(t, 2, calls)
	})
}

func TestPromptRiskRouteFiltersAccountSchedulability(t *testing.T) {
	account := &Account{ID: 7, Status: StatusActive, Schedulable: true}
	require.True(t, account.IsSchedulableForModelWithContext(context.Background(), "model"))
	require.True(t, account.IsSchedulableForModelWithContext(WithPromptRiskRouteAccounts(context.Background(), []int64{7}), "model"))
	require.False(t, account.IsSchedulableForModelWithContext(WithPromptRiskRouteAccounts(context.Background(), []int64{8}), "model"))
}

func TestPromptRiskRouteFiltersAdvancedOpenAISchedulerBeforeScoring(t *testing.T) {
	account := &Account{ID: 7, Platform: PlatformOpenAI, Status: StatusActive, Schedulable: true}
	scheduler := &defaultOpenAIAccountScheduler{}
	req := OpenAIAccountScheduleRequest{RequestedModel: "gpt-test"}

	compatible, reason := scheduler.isAccountRequestCompatibleReason(
		WithPromptRiskRouteAccounts(context.Background(), []int64{8}), account, req,
	)

	require.False(t, compatible)
	require.Equal(t, "prompt_risk_route", reason)
}

func TestPromptRiskRouteDoesNotOverwriteOrdinaryStickyBindings(t *testing.T) {
	ctx := WithPromptRiskRouteAccounts(context.Background(), []int64{8})
	groupID := int64(1)

	gatewayCache := &stubGatewayCache{sessionBindings: map[string]int64{"session": 7}}
	gateway := &GatewayService{cache: gatewayCache}
	require.NoError(t, gateway.BindStickySession(ctx, &groupID, "session", 8))
	require.Equal(t, int64(7), gatewayCache.sessionBindings["session"])

	openAICache := &stubGatewayCache{sessionBindings: map[string]int64{"openai:session": 7}}
	openAI := &OpenAIGatewayService{cache: openAICache}
	require.NoError(t, openAI.BindStickySession(ctx, &groupID, "session", 8))
	require.Equal(t, int64(7), openAICache.sessionBindings["openai:session"])
}
