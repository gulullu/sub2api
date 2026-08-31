package securityaudit

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type fakePromptProbeAdminService struct {
	*fakePromptAdminService
}

func (s *fakePromptProbeAdminService) ListProbeGroups(context.Context, string, string, int, int) (*ProbeGroupPage, error) {
	return &ProbeGroupPage{Items: []ProbeGroupConfig{}}, nil
}

func (s *fakePromptProbeAdminService) SaveProbeGroup(context.Context, int64, UpdateProbeGroupConfigRequest, int64) (ProbeGroupConfig, error) {
	return ProbeGroupConfig{}, nil
}

func (s *fakePromptProbeAdminService) ListProbeEvents(context.Context, int64, ProbeEventFilter, int, int) (*ProbeEventPage, error) {
	return &ProbeEventPage{Items: []ProbeEventSummary{}}, nil
}

func (s *fakePromptProbeAdminService) GetProbeEvent(context.Context, int64) (*ProbeEvent, error) {
	return &ProbeEvent{}, nil
}

func (s *fakePromptProbeAdminService) GetProbeEventEvidence(context.Context, int64) (*ProbeEventEvidence, error) {
	return &ProbeEventEvidence{Available: true, FullPrompt: "exact administrator evidence", PromptLength: 28, Source: "probe_event"}, nil
}

func (s *fakePromptProbeAdminService) ClearProbeEvent(context.Context, int64, int64, string) (*ProbeEvent, error) {
	return &ProbeEvent{}, nil
}

func (s *fakePromptProbeAdminService) ListProbeExemptions(context.Context, int64, string, int, int) (*ProbeExemptionPage, error) {
	return &ProbeExemptionPage{Items: []ProbeExemption{}}, nil
}

func (s *fakePromptProbeAdminService) CreateProbeExemption(context.Context, int64, CreateProbeExemptionRequest, int64) (*ProbeExemption, error) {
	return &ProbeExemption{}, nil
}

func (s *fakePromptProbeAdminService) DeleteProbeExemption(context.Context, int64, int64) error {
	return nil
}

func promptProbeAdminRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	handler := NewPromptAdminHandler(&fakePromptProbeAdminService{fakePromptAdminService: &fakePromptAdminService{}})
	router := gin.New()
	router.GET("/groups", handler.ListProbeGroups)
	router.GET("/groups/:groupID/events", handler.ListProbeEvents)
	router.GET("/events/:id", handler.GetProbeEvent)
	router.GET("/events/:id/evidence", handler.GetProbeEventEvidence)
	router.GET("/groups/:groupID/exemptions", handler.ListProbeExemptions)
	return router
}

func TestProbeAdminSensitiveListsAndDetailAreNoStore(t *testing.T) {
	router := promptProbeAdminRouter()
	for _, path := range []string{
		"/groups",
		"/groups/7/events",
		"/events/9",
		"/events/9/evidence",
		"/groups/7/exemptions",
	} {
		recorder := promptAdminRequest(t, router, http.MethodGet, path, nil)
		require.Equal(t, http.StatusOK, recorder.Code, path)
		require.Equal(t, "private, no-store, max-age=0", recorder.Header().Get("Cache-Control"), path)
		require.Equal(t, "no-cache", recorder.Header().Get("Pragma"), path)
	}
}

func TestProbeEventRawPromptOnlyAppearsOnEvidenceEndpoint(t *testing.T) {
	router := promptProbeAdminRouter()
	detail := promptAdminRequest(t, router, http.MethodGet, "/events/9", nil)
	require.Equal(t, http.StatusOK, detail.Code)
	require.NotContains(t, detail.Body.String(), "exact administrator evidence")

	evidence := promptAdminRequest(t, router, http.MethodGet, "/events/9/evidence", nil)
	require.Equal(t, http.StatusOK, evidence.Code)
	require.Contains(t, evidence.Body.String(), "exact administrator evidence")
}
