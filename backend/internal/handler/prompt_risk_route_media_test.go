package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestNewAsyncImageContextPreservesPromptRiskRoutePool(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/v1/images/generations/async", nil)
	request = request.WithContext(service.WithPromptRiskRouteAccounts(request.Context(), []int64{17}))
	c.Request = request

	taskCtx, _, cancel := newAsyncImageContext(c, []byte(`{"model":"gpt-image-1","prompt":"hello"}`), time.Second)
	defer cancel()

	require.True(t, service.PromptRiskRouteEnabled(taskCtx.Request.Context()))
	require.True(t, service.PromptRiskRouteAllowsAccount(taskCtx.Request.Context(), 17))
	require.False(t, service.PromptRiskRouteAllowsAccount(taskCtx.Request.Context(), 18))
}
