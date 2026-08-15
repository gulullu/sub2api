//go:build unit

package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestBatchImageSelectionHonorsPromptRiskRouteHardPool(t *testing.T) {
	svc, _, _, _, _ := newTestBatchImagePublicService(true)

	provider, account, err := svc.selectProviderAndAccount(
		WithPromptRiskRouteAccounts(context.Background(), []int64{101}),
		testBatchImageOwner(),
		BatchImageProviderGeminiAPI,
		"gemini-2.5-flash-image",
	)
	require.NoError(t, err)
	require.Equal(t, BatchImageProviderGeminiAPI, provider.Name())
	require.Equal(t, int64(101), account.ID)
}

func TestBatchImageSelectionReturnsDedicated503WhenPromptRiskRoutePoolIsEmpty(t *testing.T) {
	svc, _, _, _, _ := newTestBatchImagePublicService(true)

	_, _, err := svc.selectProviderAndAccount(
		WithPromptRiskRouteAccounts(context.Background(), []int64{999}),
		testBatchImageOwner(),
		BatchImageProviderGeminiAPI,
		"gemini-2.5-flash-image",
	)

	require.Error(t, err)
	require.True(t, errors.Is(err, ErrPromptRiskRouteUnavailable))
	require.True(t, errors.Is(err, ErrBatchImageNoAccountAvailable))
	require.Equal(t, http.StatusServiceUnavailable, infraerrors.Code(err))
	require.Equal(t, "PROMPT_RISK_ROUTE_UNAVAILABLE", infraerrors.Reason(err))
	require.Equal(t, "Service temporarily unavailable", infraerrors.Message(err))
}
