package securityaudit

import (
	"context"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

type PromptProbeAdminService interface {
	ListProbeGroups(context.Context, string, string, int, int) (*ProbeGroupPage, error)
	SaveProbeGroup(context.Context, int64, UpdateProbeGroupConfigRequest, int64) (ProbeGroupConfig, error)
	ListProbeEvents(context.Context, int64, ProbeEventFilter, int, int) (*ProbeEventPage, error)
	GetProbeEvent(context.Context, int64) (*ProbeEvent, error)
	GetProbeEventEvidence(context.Context, int64) (*ProbeEventEvidence, error)
	ClearProbeEvent(context.Context, int64, int64, string) (*ProbeEvent, error)
	ListProbeExemptions(context.Context, int64, string, int, int) (*ProbeExemptionPage, error)
	CreateProbeExemption(context.Context, int64, CreateProbeExemptionRequest, int64) (*ProbeExemption, error)
	DeleteProbeExemption(context.Context, int64, int64) error
}

func (h *PromptAdminHandler) probeService() (PromptProbeAdminService, error) {
	if h == nil || h.probe == nil {
		return nil, infraerrors.ServiceUnavailable("prompt_probe_unavailable", "探针治理暂不可用")
	}
	return h.probe, nil
}

func (h *PromptAdminHandler) ListProbeGroups(c *gin.Context) {
	setProbeAdminNoStore(c)
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	page, err := positiveIntQuery(c, "page", 1, 0)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pageSize, err := positiveIntQuery(c, "page_size", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := service.ListProbeGroups(c.Request.Context(), c.Query("keyword"), c.Query("status"), page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *PromptAdminHandler) UpdateProbeGroup(c *gin.Context) {
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	groupID, err := positiveProbePathID(c, "groupID", "prompt_probe_invalid_group_id", "分组 ID 无效")
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), nil)
		response.ErrorFrom(c, err)
		return
	}
	var request UpdateProbeGroupConfigRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		appErr := infraerrors.BadRequest("prompt_probe_invalid_config", "探针治理配置请求无效")
		setPromptAdminAudit(c, "failed", infraerrors.Reason(appErr), map[string]any{"group_id": groupID})
		response.ErrorFrom(c, appErr)
		return
	}
	result, err := service.SaveProbeGroup(c.Request.Context(), groupID, request, adminID(c))
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"group_id": groupID})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{"group_id": groupID, "enabled": result.Enabled, "interval_seconds": result.IntervalSeconds, "policy_version": result.PolicyVersion})
	response.Success(c, result)
}

func (h *PromptAdminHandler) ListProbeEvents(c *gin.Context) {
	setProbeAdminNoStore(c)
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	groupID, err := positiveProbePathID(c, "groupID", "prompt_probe_invalid_group_id", "分组 ID 无效")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	page, err := positiveIntQuery(c, "page", 1, 0)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pageSize, err := positiveIntQuery(c, "page_size", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	filter, err := probeEventFilterFromQuery(c)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := service.ListProbeEvents(c.Request.Context(), groupID, filter, page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *PromptAdminHandler) GetProbeEvent(c *gin.Context) {
	setProbeAdminNoStore(c)
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveProbePathID(c, "id", "prompt_probe_invalid_event_id", "探针事件 ID 无效")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := service.GetProbeEvent(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *PromptAdminHandler) GetProbeEventEvidence(c *gin.Context) {
	setProbeAdminNoStore(c)
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveProbePathID(c, "id", "prompt_probe_invalid_event_id", "探针事件 ID 无效")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := service.GetProbeEventEvidence(c.Request.Context(), id)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *PromptAdminHandler) ClearProbeEvent(c *gin.Context) {
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveProbePathID(c, "id", "prompt_probe_invalid_event_id", "探针事件 ID 无效")
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), nil)
		response.ErrorFrom(c, err)
		return
	}
	var request ClearProbeEventRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		appErr := infraerrors.BadRequest("prompt_probe_clear_invalid", "清除请求无效")
		setPromptAdminAudit(c, "failed", infraerrors.Reason(appErr), map[string]any{"event_id": id})
		response.ErrorFrom(c, appErr)
		return
	}
	result, err := service.ClearProbeEvent(c.Request.Context(), id, adminID(c), request.Reason)
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"event_id": id})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{"event_id": id, "group_id": result.GroupID, "family_fingerprint": result.FamilyFingerprint})
	response.Success(c, gin.H{"cleared": true})
}

func (h *PromptAdminHandler) ListProbeExemptions(c *gin.Context) {
	setProbeAdminNoStore(c)
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	groupID, err := positiveProbePathID(c, "groupID", "prompt_probe_invalid_group_id", "分组 ID 无效")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	page, err := positiveIntQuery(c, "page", 1, 0)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pageSize, err := positiveIntQuery(c, "page_size", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := service.ListProbeExemptions(c.Request.Context(), groupID, c.Query("keyword"), page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func setProbeAdminNoStore(c *gin.Context) {
	if c == nil {
		return
	}
	c.Header("Cache-Control", "private, no-store, max-age=0")
	c.Header("Pragma", "no-cache")
}

func (h *PromptAdminHandler) CreateProbeExemption(c *gin.Context) {
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	groupID, err := positiveProbePathID(c, "groupID", "prompt_probe_invalid_group_id", "分组 ID 无效")
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), nil)
		response.ErrorFrom(c, err)
		return
	}
	var request CreateProbeExemptionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		appErr := infraerrors.BadRequest("prompt_probe_exemption_invalid", "探针豁免请求无效")
		setPromptAdminAudit(c, "failed", infraerrors.Reason(appErr), map[string]any{"group_id": groupID})
		response.ErrorFrom(c, appErr)
		return
	}
	result, err := service.CreateProbeExemption(c.Request.Context(), groupID, request, adminID(c))
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"group_id": groupID})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{"group_id": groupID, "exemption_id": result.ID, "user_id": result.UserID, "api_key_id": result.APIKeyID})
	response.Success(c, result)
}

func (h *PromptAdminHandler) DeleteProbeExemption(c *gin.Context) {
	service, err := h.probeService()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	groupID, err := positiveProbePathID(c, "groupID", "prompt_probe_invalid_group_id", "分组 ID 无效")
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), nil)
		response.ErrorFrom(c, err)
		return
	}
	id, err := positiveProbePathID(c, "id", "prompt_probe_invalid_exemption_id", "豁免 ID 无效")
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"group_id": groupID})
		response.ErrorFrom(c, err)
		return
	}
	if err := service.DeleteProbeExemption(c.Request.Context(), groupID, id); err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"group_id": groupID, "exemption_id": id})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{"group_id": groupID, "exemption_id": id})
	response.Success(c, gin.H{"deleted": true})
}

func positiveProbePathID(c *gin.Context, key, reason, message string) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(c.Param(key)), 10, 64)
	if err != nil || value <= 0 {
		return 0, infraerrors.BadRequest(reason, message)
	}
	return value, nil
}

func probeEventFilterFromQuery(c *gin.Context) (ProbeEventFilter, error) {
	userID, err := optionalPositiveInt64Query(c, "user_id")
	if err != nil {
		return ProbeEventFilter{}, err
	}
	apiKeyID, err := optionalPositiveInt64Query(c, "api_key_id")
	if err != nil {
		return ProbeEventFilter{}, err
	}
	startAt, err := optionalProbeTime(c.Query("start_at"))
	if err != nil {
		return ProbeEventFilter{}, infraerrors.BadRequest("prompt_probe_invalid_start_at", "开始时间格式无效")
	}
	endAt, err := optionalProbeTime(c.Query("end_at"))
	if err != nil {
		return ProbeEventFilter{}, infraerrors.BadRequest("prompt_probe_invalid_end_at", "结束时间格式无效")
	}
	return ProbeEventFilter{Verdict: strings.TrimSpace(c.Query("verdict")), UserID: userID, UserEmail: strings.TrimSpace(c.Query("user_email")), APIKeyID: apiKeyID, APIKeyName: strings.TrimSpace(c.Query("api_key_name")), Model: strings.TrimSpace(c.Query("model")), Protocol: strings.TrimSpace(c.Query("protocol")), StartAt: startAt, EndAt: endAt}, nil
}

func optionalProbeTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}
