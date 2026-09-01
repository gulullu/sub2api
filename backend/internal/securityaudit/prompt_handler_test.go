package securityaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type fakePromptAdminService struct {
	config       PublicConfig
	save         func(context.Context, UpdateConfigRequest, int64) (PublicConfig, error)
	probe        func(context.Context, ProbeRequest) ProbeResult
	runtime      RuntimeSnapshot
	listProfiles func(context.Context, PromptAuditUserProfileFilter, int, int) (*PromptAuditUserProfilePage, error)
	list         func(context.Context, EventFilter, int, int) (*EventPage, error)
	get          func(context.Context, int64) (*Event, error)
	deleteOne    func(context.Context, int64) (*DeleteResult, error)
	deleteIDs    func(context.Context, []int64) (*DeleteResult, error)
	preview      func(context.Context, EventFilter, int64) (*DeletePreview, error)
	deleteFilter func(context.Context, DeleteByFilterRequest, int64) (*DeleteResult, error)
}

func (s *fakePromptAdminService) GetConfig() (PublicConfig, error) {
	return s.config, nil
}
func (s *fakePromptAdminService) SaveConfig(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error) {
	if s.save == nil {
		return PublicConfig{}, errors.New("unexpected SaveConfig call")
	}
	return s.save(ctx, req, actorID)
}
func (s *fakePromptAdminService) Probe(ctx context.Context, req ProbeRequest) ProbeResult {
	if s.probe == nil {
		return ProbeResult{}
	}
	return s.probe(ctx, req)
}
func (s *fakePromptAdminService) Runtime(context.Context) RuntimeSnapshot { return s.runtime }
func (s *fakePromptAdminService) ListUserProfiles(ctx context.Context, filter PromptAuditUserProfileFilter, page, pageSize int) (*PromptAuditUserProfilePage, error) {
	if s.listProfiles == nil {
		return &PromptAuditUserProfilePage{}, nil
	}
	return s.listProfiles(ctx, filter, page, pageSize)
}
func (s *fakePromptAdminService) ListEvents(ctx context.Context, filter EventFilter, page, pageSize int) (*EventPage, error) {
	if s.list == nil {
		return &EventPage{}, nil
	}
	return s.list(ctx, filter, page, pageSize)
}
func (s *fakePromptAdminService) GetEvent(ctx context.Context, id int64) (*Event, error) {
	if s.get == nil {
		return nil, ErrEventNotFound
	}
	return s.get(ctx, id)
}
func (s *fakePromptAdminService) DeleteEvent(ctx context.Context, id int64) (*DeleteResult, error) {
	if s.deleteOne == nil {
		return &DeleteResult{}, nil
	}
	return s.deleteOne(ctx, id)
}
func (s *fakePromptAdminService) DeleteEventsByIDs(ctx context.Context, ids []int64) (*DeleteResult, error) {
	if s.deleteIDs == nil {
		return &DeleteResult{}, nil
	}
	return s.deleteIDs(ctx, ids)
}
func (s *fakePromptAdminService) PreviewDelete(ctx context.Context, filter EventFilter, actorID int64) (*DeletePreview, error) {
	if s.preview == nil {
		return &DeletePreview{}, nil
	}
	return s.preview(ctx, filter, actorID)
}
func (s *fakePromptAdminService) DeleteByFilter(ctx context.Context, req DeleteByFilterRequest, actorID int64) (*DeleteResult, error) {
	if s.deleteFilter == nil {
		return &DeleteResult{}, nil
	}
	return s.deleteFilter(ctx, req, actorID)
}

func promptAdminRouter(service PromptAdminService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(servermiddleware.ContextKeyUser), servermiddleware.AuthSubject{UserID: 42})
		c.Set(string(servermiddleware.ContextKeyUserRole), "admin")
		c.Next()
	})
	handler := NewPromptAdminHandler(service)
	group := router.Group("/admin/prompt-audit")
	group.GET("/config", handler.GetConfig)
	group.PUT("/config", handler.UpdateConfig)
	group.GET("/user-profiles", handler.ListUserProfiles)
	group.POST("/endpoints/probe", handler.ProbeEndpoint)
	group.GET("/runtime", handler.GetRuntime)
	group.GET("/events", handler.ListEvents)
	group.GET("/events/:id", handler.GetEvent)
	group.DELETE("/events/:id", handler.DeleteEvent)
	group.POST("/events/batch-delete", handler.BatchDelete)
	group.POST("/events/delete-preview", handler.DeletePreview)
	group.POST("/events/delete-by-filter", handler.DeleteByFilter)
	group.GET("/cyber/events", handler.ListCyberFeedback)
	group.GET("/cyber/events/:id", handler.GetCyberFeedback)
	group.GET("/cyber/events/:id/evidence", handler.GetCyberFeedbackEvidence)
	group.POST("/cyber/events/:id/adopt", handler.AdoptCyberFeedback)
	group.POST("/cyber/events/:id/reject", handler.RejectCyberFeedback)
	group.POST("/cyber/events/:id/regenerate", handler.RegenerateCyberRuleDraft)
	group.GET("/cyber/rules", handler.ListCyberRules)
	group.POST("/cyber/rules/:id/revoke", handler.RevokeCyberRule)
	group.POST("/cyber/rules/:id/restore", handler.RestoreCyberRule)
	group.DELETE("/cyber/rules/:id", handler.DeleteCyberRule)
	return router
}

type fakePromptCyberAdminService struct {
	*fakePromptAdminService
	listCyber   func(context.Context, CyberFeedbackFilter, int, int) (*CyberFeedbackPage, error)
	getCyber    func(context.Context, int64) (*CyberFeedbackAdminDetailDTO, error)
	getEvidence func(context.Context, int64) (*CyberFeedbackEvidenceAdminDTO, error)
	listRules   func(context.Context) (*CyberRulesPage, error)
	adopt       func(context.Context, int64, AdoptCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error)
	reject      func(context.Context, int64, RejectCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error)
	revoke      func(context.Context, string, RevokeCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
	restore     func(context.Context, string, RestoreCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
	deleteRule  func(context.Context, string, DeleteCyberRuleRequest, int64) (*CyberFeedbackActionResult, error)
	regenerate  func(context.Context, int64, int64) (*CyberFeedbackActionResult, error)
}

func (s *fakePromptCyberAdminService) ListCyberFeedbackAdmin(ctx context.Context, filter CyberFeedbackFilter, page, pageSize int) (*CyberFeedbackPage, error) {
	return s.listCyber(ctx, filter, page, pageSize)
}
func (s *fakePromptCyberAdminService) GetCyberFeedbackAdmin(ctx context.Context, id int64) (*CyberFeedbackAdminDetailDTO, error) {
	return s.getCyber(ctx, id)
}
func (s *fakePromptCyberAdminService) GetCyberFeedbackEvidenceAdmin(ctx context.Context, id int64) (*CyberFeedbackEvidenceAdminDTO, error) {
	return s.getEvidence(ctx, id)
}
func (s *fakePromptCyberAdminService) ListCyberRulesAdmin(ctx context.Context) (*CyberRulesPage, error) {
	return s.listRules(ctx)
}
func (s *fakePromptCyberAdminService) AdoptCyberFeedback(ctx context.Context, id int64, request AdoptCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	return s.adopt(ctx, id, request, actorID)
}
func (s *fakePromptCyberAdminService) RejectCyberFeedback(ctx context.Context, id int64, request RejectCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	return s.reject(ctx, id, request, actorID)
}
func (s *fakePromptCyberAdminService) RevokeCyberRule(ctx context.Context, id string, request RevokeCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	return s.revoke(ctx, id, request, actorID)
}
func (s *fakePromptCyberAdminService) RestoreCyberRule(ctx context.Context, id string, request RestoreCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	return s.restore(ctx, id, request, actorID)
}
func (s *fakePromptCyberAdminService) DeleteCyberRule(ctx context.Context, id string, request DeleteCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
	return s.deleteRule(ctx, id, request, actorID)
}
func (s *fakePromptCyberAdminService) RegenerateCyberRuleDraft(ctx context.Context, id int64, actorID int64) (*CyberFeedbackActionResult, error) {
	return s.regenerate(ctx, id, actorID)
}

func promptAdminRequest(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestPromptAdminConfigRequiresVersionMapsConflictAndNeverEchoesToken(t *testing.T) {
	const canary = "prompt-admin-token-canary"

	t.Run("missing expected version", func(t *testing.T) {
		router := promptAdminRouter(&fakePromptAdminService{})
		response := promptAdminRequest(t, router, http.MethodPut, "/admin/prompt-audit/config", map[string]any{})
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Contains(t, response.Body.String(), "prompt_audit_invalid_config_request")
	})

	t.Run("CAS conflict", func(t *testing.T) {
		service := &fakePromptAdminService{save: func(context.Context, UpdateConfigRequest, int64) (PublicConfig, error) {
			return PublicConfig{}, infraerrors.Conflict(ErrorCodeConfigConflict, "配置已被更新")
		}}
		response := promptAdminRequest(t, promptAdminRouter(service), http.MethodPut, "/admin/prompt-audit/config", validHandlerUpdateRequest(canary))
		require.Equal(t, http.StatusConflict, response.Code)
		require.Contains(t, response.Body.String(), ErrorCodeConfigConflict)
		require.NotContains(t, response.Body.String(), canary)
	})

	t.Run("success public DTO", func(t *testing.T) {
		service := &fakePromptAdminService{save: func(_ context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error) {
			require.Equal(t, int64(42), actorID)
			require.Equal(t, canary, req.Endpoints[0].Token)
			return PublicConfig{ConfigVersion: 8, Endpoints: []PublicEndpoint{{ID: "guard-1", HasToken: true, TokenStatus: "configured"}}}, nil
		}}
		response := promptAdminRequest(t, promptAdminRouter(service), http.MethodPut, "/admin/prompt-audit/config", validHandlerUpdateRequest(canary))
		require.Equal(t, http.StatusOK, response.Code)
		body := response.Body.String()
		require.NotContains(t, body, canary)
		require.NotContains(t, body, "token_ciphertext")
		require.NotContains(t, body, `"token":`)
		require.Contains(t, body, `"has_token":true`)
	})
}

func TestPromptAdminCyberEvidenceResponseIsNoStore(t *testing.T) {
	base := &fakePromptAdminService{}
	service := &fakePromptCyberAdminService{
		fakePromptAdminService: base,
		getEvidence: func(context.Context, int64) (*CyberFeedbackEvidenceAdminDTO, error) {
			return &CyberFeedbackEvidenceAdminDTO{Available: true, FullPrompt: "[user]\ncanary"}, nil
		},
	}
	recorder := promptAdminRequest(t, promptAdminRouter(service), http.MethodGet, "/admin/prompt-audit/cyber/events/9/evidence", nil)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, "private, no-store, max-age=0", recorder.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", recorder.Header().Get("Pragma"))
	require.Contains(t, recorder.Body.String(), "canary")
}

func TestPromptAdminGetConfigReturnsSecretFreeUnavailableError(t *testing.T) {
	const canary = "persisted-config-secret-canary"
	repository := &switchableSettingRepository{loadErr: errors.New("failed to load token " + canary)}
	manager := NewConfigManager(nil, repository, nil, prefixEncryptor{}, testTotpKeyConfig())
	require.Error(t, manager.Reload(context.Background()))
	service := &PromptService{config: manager}

	response := promptAdminRequest(t, promptAdminRouter(service), http.MethodGet, "/admin/prompt-audit/config", nil)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Contains(t, response.Body.String(), ErrorCodeConfigUnavailable)
	require.NotContains(t, response.Body.String(), canary)
	require.NotContains(t, response.Body.String(), `"config_version"`)
	require.NotContains(t, response.Body.String(), `"token"`)
}

func TestPromptAdminProbeSupportsTemporaryOrSavedTokenWithoutEcho(t *testing.T) {
	const canary = "probe-token-canary"
	for _, tc := range []struct {
		name         string
		token        string
		tokenApplied bool
	}{
		{name: "temporary token", token: canary, tokenApplied: true},
		{name: "saved token", token: "", tokenApplied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakePromptAdminService{probe: func(_ context.Context, req ProbeRequest) ProbeResult {
				require.Equal(t, tc.token, req.Endpoint.Token)
				return ProbeResult{OK: true, Status: "healthy", Message: "ok", TokenApplied: tc.tokenApplied}
			}}
			endpoint := validHandlerUpdateRequest(tc.token).Endpoints[0]
			response := promptAdminRequest(t, promptAdminRouter(service), http.MethodPost, "/admin/prompt-audit/endpoints/probe", ProbeRequest{Endpoint: endpoint})
			require.Equal(t, http.StatusOK, response.Code)
			require.NotContains(t, response.Body.String(), canary)
			require.NotContains(t, response.Body.String(), `"token":`)
			require.Contains(t, response.Body.String(), `"token_applied":true`)
		})
	}
}

func TestPromptAdminRejectsInvalidEventIDsTimesAndPagination(t *testing.T) {
	router := promptAdminRouter(&fakePromptAdminService{})
	for _, tc := range []struct {
		method string
		path   string
		body   any
		reason string
	}{
		{http.MethodGet, "/admin/prompt-audit/events/not-a-number", nil, "prompt_audit_invalid_event_id"},
		{http.MethodDelete, "/admin/prompt-audit/events/-1", nil, "prompt_audit_invalid_event_id"},
		{http.MethodGet, "/admin/prompt-audit/events?group_id=bad", nil, "prompt_audit_invalid_filter_id"},
		{http.MethodGet, "/admin/prompt-audit/events?start_at=not-time", nil, "prompt_audit_invalid_time"},
		{http.MethodGet, "/admin/prompt-audit/events?page=0", nil, "prompt_audit_invalid_pagination"},
		{http.MethodGet, "/admin/prompt-audit/user-profiles?days=181", nil, "prompt_audit_invalid_filter_days"},
		{http.MethodGet, "/admin/prompt-audit/user-profiles?min_samples=-1", nil, "prompt_audit_invalid_filter_min_samples"},
		{http.MethodPost, "/admin/prompt-audit/events/batch-delete", map[string]any{"ids": []int64{1, -2}}, "prompt_audit_invalid_event_id"},
	} {
		response := promptAdminRequest(t, router, tc.method, tc.path, tc.body)
		require.Equalf(t, http.StatusBadRequest, response.Code, "%s %s", tc.method, tc.path)
		require.Contains(t, response.Body.String(), tc.reason)
	}
}

func TestPromptAdminUserProfilesUseSafeDefaultWindowAndSampleFloor(t *testing.T) {
	service := &fakePromptAdminService{
		listProfiles: func(_ context.Context, filter PromptAuditUserProfileFilter, page, pageSize int) (*PromptAuditUserProfilePage, error) {
			require.Equal(t, DefaultPromptAuditUserProfileDays, filter.Days)
			require.Equal(t, DefaultPromptAuditUserProfileMinSamples, filter.MinSamples)
			return &PromptAuditUserProfilePage{Page: page, PageSize: pageSize}, nil
		},
	}
	response := promptAdminRequest(t, promptAdminRouter(service), http.MethodGet, "/admin/prompt-audit/user-profiles", nil)
	require.Equal(t, http.StatusOK, response.Code)
}

func TestPromptAdminUserProfilesRouteBindsQueryAndReturnsProfiles(t *testing.T) {
	service := &fakePromptAdminService{
		listProfiles: func(_ context.Context, filter PromptAuditUserProfileFilter, page, pageSize int) (*PromptAuditUserProfilePage, error) {
			require.Equal(t, 2, page)
			require.Equal(t, 10, pageSize)
			require.Equal(t, 14, filter.Days)
			require.Equal(t, "alice", filter.Search)
			require.Equal(t, int64(88), *filter.UserID)
			require.Equal(t, int64(77), *filter.GroupID)
			require.Equal(t, 3, filter.MinSamples)
			return &PromptAuditUserProfilePage{Items: []*PromptAuditUserProfile{{UserID: 1, Username: "alice", HasProfile: true}}, Total: 1, Page: page, PageSize: pageSize, Pages: 1}, nil
		},
	}
	response := promptAdminRequest(t, promptAdminRouter(service), http.MethodGet, "/admin/prompt-audit/user-profiles?days=14&page=2&page_size=10&search=alice&user_id=88&group_id=77&min_samples=3", nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"user_id":1`)
	require.Contains(t, response.Body.String(), `"has_profile":true`)
}

func validHandlerUpdateRequest(token string) UpdateConfigRequest {
	return UpdateConfigRequest{
		ExpectedConfigVersion: 7,
		Strategy:              "priority",
		WorkerCount:           1,
		QueueCapacity:         10,
		Scanners:              []string{"pii"},
		AllGroups:             true,
		Endpoints: []UpdateEndpoint{{
			ID: "guard-1", Name: "Guard One", Protocol: "openai_compatible",
			BaseURL: "http://127.0.0.1:18080", Model: DefaultGuardModel, Token: token,
			TimeoutMS: 1000, InputLimit: 1024, Enabled: true,
		}},
	}
}

func TestPromptAdminDeleteConfirmationErrorsStayGeneric(t *testing.T) {
	service := &fakePromptAdminService{deleteFilter: func(context.Context, DeleteByFilterRequest, int64) (*DeleteResult, error) {
		return nil, errors.New("sensitive-token-or-filter-detail")
	}}
	response := promptAdminRequest(t, promptAdminRouter(service), http.MethodPost, "/admin/prompt-audit/events/delete-by-filter", DeleteByFilterRequest{
		SnapshotMaxID: 3, FilterHash: strings.Repeat("a", 64), ConfirmationToken: "secret-confirmation", Confirm: true,
	})
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Contains(t, response.Body.String(), "prompt_audit_delete_confirmation_invalid")
	require.NotContains(t, response.Body.String(), "sensitive-token")
	require.NotContains(t, response.Body.String(), "secret-confirmation")
}

func TestPromptCyberAdminRoutesBindCASAndNeverRequireRawCaseImport(t *testing.T) {
	base := &fakePromptAdminService{}
	service := &fakePromptCyberAdminService{fakePromptAdminService: base}
	service.listCyber = func(_ context.Context, filter CyberFeedbackFilter, page, pageSize int) (*CyberFeedbackPage, error) {
		require.Equal(t, CyberReviewPending, filter.ReviewStatus)
		require.Equal(t, "generated", filter.GenerationStatus)
		require.Equal(t, 2, page)
		require.Equal(t, 10, pageSize)
		return &CyberFeedbackPage{Items: []CyberFeedbackAdminDTO{{ID: 51, Status: CyberReviewPending}}, Total: 1, Page: page, PageSize: pageSize}, nil
	}
	service.adopt = func(_ context.Context, id int64, request AdoptCyberFeedbackRequest, actorID int64) (*CyberFeedbackActionResult, error) {
		require.Equal(t, int64(51), id)
		require.Equal(t, int64(42), actorID)
		require.Equal(t, int64(9), request.ExpectedConfigVersion)
		require.Empty(t, request.RuleText, "empty adopts the separately generated candidate; no raw prompt field exists")
		return &CyberFeedbackActionResult{ConfigVersion: 10, Rule: &CyberRuleAdminDTO{ID: "cyb-feedback-51", Status: "active"}}, nil
	}
	service.getCyber = func(context.Context, int64) (*CyberFeedbackAdminDetailDTO, error) {
		return &CyberFeedbackAdminDetailDTO{}, nil
	}
	service.listRules = func(context.Context) (*CyberRulesPage, error) { return &CyberRulesPage{}, nil }
	service.reject = func(context.Context, int64, RejectCyberFeedbackRequest, int64) (*CyberFeedbackActionResult, error) {
		return &CyberFeedbackActionResult{}, nil
	}
	service.revoke = func(_ context.Context, id string, request RevokeCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
		require.Equal(t, "cyb-feedback-51", id)
		require.Equal(t, int64(10), request.ExpectedConfigVersion)
		require.Equal(t, int64(42), actorID)
		return &CyberFeedbackActionResult{}, nil
	}
	service.restore = func(_ context.Context, id string, request RestoreCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
		require.Equal(t, "cyb-feedback-51", id)
		require.Equal(t, int64(11), request.ExpectedConfigVersion)
		require.Equal(t, int64(42), actorID)
		return &CyberFeedbackActionResult{}, nil
	}
	service.deleteRule = func(_ context.Context, id string, request DeleteCyberRuleRequest, actorID int64) (*CyberFeedbackActionResult, error) {
		require.Equal(t, "cyb-feedback-51", id)
		require.Equal(t, int64(12), request.ExpectedConfigVersion)
		require.Equal(t, id, request.ConfirmRuleID)
		require.Equal(t, int64(42), actorID)
		return &CyberFeedbackActionResult{}, nil
	}
	service.regenerate = func(context.Context, int64, int64) (*CyberFeedbackActionResult, error) {
		return &CyberFeedbackActionResult{}, nil
	}

	router := promptAdminRouter(service)
	listed := promptAdminRequest(t, router, http.MethodGet, "/admin/prompt-audit/cyber/events?status=pending&candidate_status=generated&page=2&page_size=10", nil)
	require.Equal(t, http.StatusOK, listed.Code)
	require.NotContains(t, listed.Body.String(), "api_key_id")
	require.NotContains(t, listed.Body.String(), "prompt_signature")

	adopted := promptAdminRequest(t, router, http.MethodPost, "/admin/prompt-audit/cyber/events/51/adopt", map[string]any{
		"expected_config_version": 9,
		"raw_prompt":              "must-be-ignored-and-never-imported",
	})
	require.Equal(t, http.StatusOK, adopted.Code)
	require.NotContains(t, adopted.Body.String(), "must-be-ignored")

	disabled := promptAdminRequest(t, router, http.MethodPost, "/admin/prompt-audit/cyber/rules/cyb-feedback-51/revoke", map[string]any{
		"expected_config_version": 10,
	})
	require.Equal(t, http.StatusOK, disabled.Code)

	restored := promptAdminRequest(t, router, http.MethodPost, "/admin/prompt-audit/cyber/rules/cyb-feedback-51/restore", map[string]any{
		"expected_config_version": 11,
	})
	require.Equal(t, http.StatusOK, restored.Code)

	deleted := promptAdminRequest(t, router, http.MethodDelete, "/admin/prompt-audit/cyber/rules/cyb-feedback-51", map[string]any{
		"expected_config_version": 12,
		"confirm_rule_id":         "cyb-feedback-51",
	})
	require.Equal(t, http.StatusOK, deleted.Code)
}
