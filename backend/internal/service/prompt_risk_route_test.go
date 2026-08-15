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
