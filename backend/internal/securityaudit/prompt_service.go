package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type PromptService struct {
	config    ConfigStore
	repo      *PostgreSQLRepository
	payload   *RedisPayloadStore
	enqueuer  *Enqueuer
	runner    *Runner
	evaluator *GuardEvaluator
	scanner   *OpenAICompatibleScanner
	metrics   *AtomicMetrics
	circuit   *endpointCircuitBreaker
	clock     Clock
	// CYB admin mutations span the prompt config CAS and feedback review CAS.
	// Production currently runs one application instance, so this mutex closes
	// the local adopt/reject/revoke/regenerate race. A multi-instance deployment
	// must replace it with a DB-level transaction or shared lock.
	cyberAdminMu     sync.Mutex
	cyberAdminRepo   CyberFeedbackRepository
	cyberAdminConfig CyberSupplementConfigStore

	lifecycleMu  sync.Mutex
	cancel       context.CancelFunc
	background   context.Context
	enqueueWG    sync.WaitGroup
	enqueueSlots chan struct{}
	probeMu      sync.RWMutex
	probes       map[string]ProbeResult
}

type EndpointCredentialSourceResolver interface {
	ResolveEndpointCredentialSource(context.Context, UpdateEndpoint) (UpdateEndpoint, error)
}

func NewPromptService(
	config ConfigStore,
	repo *PostgreSQLRepository,
	payload *RedisPayloadStore,
	scanner *OpenAICompatibleScanner,
	metrics *AtomicMetrics,
) *PromptService {
	enqueuer := NewEnqueuer(config, repo, payload, metrics)
	evaluator := NewGuardEvaluator(scanner, repo, metrics)
	runner := NewRunner(config, repo, payload, scanner, metrics)
	// Blocking and async audit paths share endpoint health so one known-bad
	// dependency is skipped consistently throughout this process.
	sharedCircuit := newEndpointCircuitBreaker(defaultEndpointCircuitCapacity)
	evaluator.failover.circuit = sharedCircuit
	runner.failover.circuit = sharedCircuit
	return &PromptService{
		config: config, repo: repo, payload: payload, scanner: scanner, metrics: metrics,
		enqueuer: enqueuer, evaluator: evaluator, runner: runner, circuit: sharedCircuit, clock: realClock{},
		enqueueSlots: make(chan struct{}, 128), probes: map[string]ProbeResult{},
	}
}

func (s *PromptService) Start(ctx context.Context) error {
	if s == nil || s.config == nil || s.runner == nil {
		return errors.New("prompt audit service unavailable")
	}
	s.lifecycleMu.Lock()
	if s.cancel != nil {
		s.lifecycleMu.Unlock()
		return nil
	}
	background, cancel := context.WithCancel(ctx)
	s.background, s.cancel = background, cancel
	s.lifecycleMu.Unlock()
	configErr := s.config.Start(background)
	workerErr := s.runner.Start(background)
	return errors.Join(configErr, workerErr)
}

func (s *PromptService) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	var workerErr error
	if s.runner != nil {
		workerErr = s.runner.Shutdown(ctx)
	}
	done := make(chan struct{})
	go func() { s.enqueueWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if workerErr == nil {
			workerErr = ctx.Err()
		}
	}
	var configErr error
	if s.config != nil {
		configErr = s.config.Shutdown(ctx)
	}
	if workerErr != nil {
		return workerErr
	}
	return configErr
}

func (s *PromptService) EffectiveMode() Mode {
	if s == nil || s.config == nil {
		return ModeOff
	}
	return s.config.EffectiveMode()
}

// ModeForRequest resolves the global gate and then overlays the policy for the
// request's audit group. It is intentionally an additive method: legacy
// PromptEngine fakes only implement EffectiveMode and continue to work.
func (s *PromptService) ModeForRequest(req Request) Mode {
	if s == nil || s.config == nil {
		return ModeOff
	}
	if s.config.BlockingActivationDegraded() {
		return ModeBlocking
	}
	cfg, ok := s.config.Active()
	if !ok {
		return s.config.EffectiveMode()
	}
	// `enabled` is the global operational kill switch.  Resolve it before the
	// group overlay so a stale/independently enabled group policy cannot bring
	// auditing back while the administrator has disabled the feature globally.
	if !cfg.RiskControlEnabled || !cfg.Enabled {
		return ModeOff
	}
	if !cfg.IncludesGroup(req.GroupID) {
		return ModeOff
	}
	return cfg.EffectiveForGroup(req.GroupID).EffectiveMode()
}

// IncludesCyberFeedbackSource intentionally does not consult EffectiveMode or
// the Prompt Audit group scope. It is a post-upstream capture policy, not an
// instruction to audit the request before routing it.
func (s *PromptService) IncludesCyberFeedbackSource(accountID int64, platform, accountType string) bool {
	if s == nil || s.config == nil {
		return strings.EqualFold(strings.TrimSpace(platform), service.PlatformOpenAI) &&
			strings.EqualFold(strings.TrimSpace(accountType), service.AccountTypeOAuth)
	}
	cfg, ok := s.config.Active()
	if !ok {
		return strings.EqualFold(strings.TrimSpace(platform), service.PlatformOpenAI) &&
			strings.EqualFold(strings.TrimSpace(accountType), service.AccountTypeOAuth)
	}
	return cfg.IncludesCyberFeedbackSource(accountID, platform, accountType)
}

// IncludesCyberFeedbackSourceForGroup scopes administrator-selected CYB
// feedback accounts to the request group while retaining the independent
// OpenAI OAuth evidence path.
func (s *PromptService) IncludesCyberFeedbackSourceForGroup(groupID *int64, accountID int64, platform, accountType string) bool {
	if s == nil || s.config == nil {
		return strings.EqualFold(strings.TrimSpace(platform), service.PlatformOpenAI) &&
			strings.EqualFold(strings.TrimSpace(accountType), service.AccountTypeOAuth)
	}
	cfg, ok := s.config.Active()
	if !ok {
		return strings.EqualFold(strings.TrimSpace(platform), service.PlatformOpenAI) &&
			strings.EqualFold(strings.TrimSpace(accountType), service.AccountTypeOAuth)
	}
	return cfg.IncludesCyberFeedbackSourceForGroup(groupID, accountID, platform, accountType)
}

func (s *PromptService) Enqueue(_ context.Context, req Request) error {
	if s == nil || s.enqueuer == nil || s.ModeForRequest(req) != ModeAsync {
		return nil
	}
	if s.config != nil {
		if cfg, ok := s.config.Active(); ok {
			effective := cfg.EffectiveForGroup(req.GroupID)
			if !effective.IncludesUser(req.UserID) {
				LogInfo(EventEnqueueSkipped, map[string]any{
					"request_id": req.RequestID, "user_id": req.UserID, "status": "skipped", "error_code": "user_excluded",
				})
				return nil
			}
		}
	}
	select {
	case s.enqueueSlots <- struct{}{}:
	default:
		if s.metrics != nil {
			s.metrics.IncDropped()
		}
		LogWarn(EventEnqueueDropped, map[string]any{"request_id": req.RequestID, "status": "dropped", "error_code": "local_enqueue_busy"})
		return nil
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.enqueueSlots
		return errors.New("prompt audit service not started")
	}
	requestCopy := req.Clone()
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.enqueueSlots }()
		ctx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		_ = s.enqueuer.Enqueue(ctx, requestCopy)
	}()
	return nil
}

func (s *PromptService) Evaluate(ctx context.Context, req Request) (*PromptDecision, error) {
	if s == nil || s.config == nil || s.evaluator == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	if s.config.BlockingActivationDegraded() {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	cfg, ok := s.config.Active()
	if !ok {
		if s.ModeForRequest(req) == ModeBlocking {
			return nil, &GuardError{Code: ErrorCodeUnavailable}
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if !cfg.IncludesGroup(req.GroupID) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	effective := cfg.EffectiveForGroup(req.GroupID)
	if !effective.IncludesUser(req.UserID) || effective.EffectiveMode() != ModeBlocking {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	snapshot, err := ExtractBlockingPromptSnapshot(req, effective.BlockingLatestTurnOnly)
	if errors.Is(err, ErrNoPromptText) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	started := s.now()
	decision, evaluateErr := s.evaluator.Evaluate(ctx, effective, snapshot)
	if evaluateErr == nil {
		return decision, nil
	}
	if fallback, ok := s.unavailableRiskRouteFallback(ctx, effective, snapshot, evaluateErr, started); ok {
		return fallback, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, parentGuardContextError(ctxErr)
	}
	return nil, evaluateErr
}

func (s *PromptService) unavailableRiskRouteFallback(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot, evaluateErr error, started time.Time) (*PromptDecision, bool) {
	// This fallback is for an unavailable audit dependency when a configured
	// hard pool can isolate the request.  A per-group "no route" choice must not
	// turn an outage (timeout, invalid response, or no enabled node) into a
	// fail-open allow; that setting is evaluated only after a real finding has
	// been produced by finishDecision/finishOversized.
	if s == nil || ctx.Err() != nil || len(cfg.RiskRouteAccountIDs) == 0 {
		return nil, false
	}
	latency := s.now().Sub(started)
	result := &NormalizedResult{
		Decision: EventFlag, RiskLevel: RiskHigh, Action: ActionWarn, Safety: "Unreviewed",
		Categories: []string{auditUnavailableScannerID}, MatchedScanners: []string{auditUnavailableScannerID},
		ScannerScores:   map[string]float64{auditUnavailableScannerID: 1},
		ScannerEvidence: map[string]string{auditUnavailableScannerID: "prompt audit dependency unavailable"},
		ScannerBackend:  "local-failover", ScannerVersion: "1", LatencyMS: int(latency.Milliseconds()),
		Reason: "prompt audit dependency unavailable; routed to configured risk accounts",
	}
	code := guardErrorCode(evaluateErr)
	decision := &PromptDecision{
		Kind: DecisionFlag, ErrorCode: code, Result: result, AllowNextStage: true,
		RouteAccountIDs: append([]int64(nil), cfg.RiskRouteAccountIDs...),
	}
	baseFields := snapshotLogFields(snapshot)
	baseFields["config_version"] = cfg.ConfigVersion
	if s.evaluator != nil && s.evaluator.repo != nil {
		if _, recordErr := s.evaluator.repo.RecordBlocking(ctx, snapshot.Redacted(), cfg.ConfigVersion, result, cfg.StorePassEvents); recordErr != nil {
			if ctx.Err() == nil {
				if s.evaluator.metrics != nil {
					s.evaluator.metrics.IncRecordFailed()
				}
				LogWarn(EventResultRecordFailed, mergeLogFields(baseFields, map[string]any{
					"decision": DecisionFlag, "error_code": "result_record_failed", "stage": snapshot.Stage, "status": "failed",
				}))
			}
		}
	}
	if ctx.Err() != nil {
		return nil, false
	}
	LogWarn(EventGuardAllowed, mergeLogFields(baseFields, map[string]any{
		"decision": DecisionFlag, "risk_level": RiskHigh, "action": ActionWarn,
		"guard_endpoint_id": "", "chunk_total": 0, "latency_ms": result.LatencyMS,
		"stage": snapshot.Stage, "status": "fallback_routed", "error_code": code,
	}))
	return decision, true
}

func (s *PromptService) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock.Now()
	}
	return time.Now().UTC()
}

func (s *PromptService) GetConfig() (PublicConfig, error) { return s.config.Public() }

func (s *PromptService) SaveConfig(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error) {
	return s.config.Save(ctx, req, actorID)
}

func (s *PromptService) ListUserProfiles(ctx context.Context, filter PromptAuditUserProfileFilter, page, pageSize int) (*PromptAuditUserProfilePage, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("prompt audit profile repository unavailable")
	}
	pageResult, err := s.repo.ListUserProfiles(ctx, filter, page, pageSize)
	if err != nil {
		return nil, err
	}
	if s.config == nil || pageResult == nil {
		return pageResult, nil
	}
	active, ok := s.config.Active()
	if !ok {
		return pageResult, nil
	}
	if filter.GroupID != nil {
		for _, item := range pageResult.Items {
			if item == nil {
				continue
			}
			item.Excluded = !active.IncludesUserForGroup(filter.GroupID, item.UserID)
		}
		return pageResult, nil
	}
	if len(active.ExcludedUserIDs) == 0 {
		return pageResult, nil
	}
	excluded := make(map[int64]struct{}, len(active.ExcludedUserIDs))
	for _, id := range active.ExcludedUserIDs {
		excluded[id] = struct{}{}
	}
	for _, item := range pageResult.Items {
		if item == nil {
			continue
		}
		_, item.Excluded = excluded[item.UserID]
	}
	return pageResult, nil
}

func (s *PromptService) Runtime(ctx context.Context) RuntimeSnapshot {
	expected, activeVersion, loadedAt, loadError := s.config.RuntimeState()
	cfg, hasConfig := s.config.Active()
	mode := s.EffectiveMode()
	workerTotal, queueCapacity := 0, 0
	if hasConfig {
		workerTotal, queueCapacity = cfg.WorkerCount, cfg.QueueCapacity
	}
	runtime := RuntimeSnapshot{
		ProcessStatus: "disabled", EffectiveMode: mode, ExpectedConfigVersion: expected,
		ActiveConfigVersion: activeVersion, ConfigLoadedAt: loadedAt, ConfigLoadError: loadError,
		WorkerTotal: workerTotal, QueueCapacity: queueCapacity, DatabaseStatus: "ok", RedisStatus: "ok",
		Endpoints: s.probeSnapshot(), GuardMetrics: s.metrics.Snapshot(),
	}
	if s.repo != nil {
		stats, err := s.repo.QueueStats(ctx)
		if err != nil {
			runtime.DatabaseStatus = "error"
			runtime.LastErrorCode = "database_unavailable"
		} else {
			runtime.Queue = stats
		}
	} else {
		runtime.DatabaseStatus = "error"
	}
	if s.payload == nil || s.payload.Ping(ctx) != nil {
		runtime.RedisStatus = "error"
		if runtime.LastErrorCode == "" {
			runtime.LastErrorCode = "payload_store_unavailable"
		}
	}
	activeWorkers, processed, failed, heartbeat, lastProcessed, workerCode, workerMessage := s.runner.Snapshot()
	runtime.WorkerActive, runtime.ProcessedTotal, runtime.FailedTotal = activeWorkers, processed, failed
	if s.metrics != nil {
		auditMetrics := s.metrics.AuditSnapshot()
		runtime.EnqueuedTotal, runtime.DroppedTotal = auditMetrics.Enqueued, auditMetrics.Dropped
	}
	runtime.WorkerHeartbeatAt, runtime.LastProcessedAt = heartbeat, lastProcessed
	if workerCode != "" {
		runtime.LastErrorCode, runtime.LastErrorMessage = workerCode, workerMessage
	}
	if mode != ModeOff {
		runtime.ProcessStatus = "running"
		if loadError != "" || runtime.DatabaseStatus != "ok" || runtime.RedisStatus != "ok" || activeVersion != expected {
			runtime.ProcessStatus = "degraded"
		}
		if heartbeat == nil || s.clock.Now().Sub(*heartbeat) > 10*time.Second {
			runtime.ProcessStatus = "degraded"
		}
	}
	return runtime
}

type ProbeRequest struct {
	Endpoint UpdateEndpoint `json:"endpoint"`
}

func (s *PromptService) Probe(ctx context.Context, request ProbeRequest) ProbeResult {
	started := s.clock.Now()
	if strings.TrimSpace(request.Endpoint.CredentialSource) != "" {
		resolver, ok := s.config.(EndpointCredentialSourceResolver)
		if !ok || resolver == nil {
			return s.finishProbe(request.Endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "endpoint_credential_source_unavailable", Message: "审计节点凭据来源不可用"})
		}
		resolved, resolveErr := resolver.ResolveEndpointCredentialSource(ctx, request.Endpoint)
		if resolveErr != nil {
			return s.finishProbe(request.Endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: infraerrors.Reason(resolveErr), Message: "审计节点凭据来源不可用"})
		}
		request.Endpoint = resolved
	}
	endpoint, tokenApplied, err := s.resolveProbeEndpoint(request.Endpoint)
	if err != nil {
		return s.finishProbe(request.Endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "endpoint_invalid", Message: "审计节点配置无效"})
	}
	LogInfo(EventProbeStarted, map[string]any{"guard_endpoint_id": endpoint.ID, "status": "started"})
	if _, err := NewSecureHTTPClient(endpoint); err != nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "endpoint_unsafe", Message: "审计节点地址不在允许范围", TokenApplied: tokenApplied})
	}
	if s.scanner == nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: ErrorCodeUnavailable, Message: "审计节点模型调用失败", TokenApplied: tokenApplied})
	}
	result, scanErr := s.scanner.Scan(ctx, endpoint, "Hello", AllScannerIDs)
	if scanErr == nil && result != nil {
		s.resetCircuitAfterExactProbe(endpoint)
		return s.finishProbe(endpoint.ID, started, ProbeResult{OK: true, Status: "healthy", Message: "审计节点模型调用正常", HTTPStatus: http.StatusOK, TokenApplied: tokenApplied})
	}
	code, status, retryable := guardErrorCode(scanErr), 0, false
	var guardErr *GuardError
	if errors.As(scanErr, &guardErr) {
		status, retryable = guardErr.HTTPStatus, guardErr.Retryable
	}
	if code == "" {
		code = ErrorCodeInvalidResponse
	}
	return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: code, Message: "审计节点模型调用失败", HTTPStatus: status, Retryable: retryable, TokenApplied: tokenApplied})
}

func (s *PromptService) resetCircuitAfterExactProbe(probed ActiveEndpoint) {
	if s == nil || s.circuit == nil || s.config == nil {
		return
	}
	cfg, ok := s.config.Active()
	if !ok {
		return
	}
	for _, configured := range cfg.Endpoints {
		if !sameEndpointProbeIdentity(configured, probed) {
			continue
		}
		if s.circuit.reset(endpointCircuitKey(cfg.ConfigVersion, configured), s.clock.Now()) {
			if s.metrics != nil {
				s.metrics.IncCircuitReset()
			}
			LogInfo(EventEndpointRecovered, map[string]any{
				"config_version": cfg.ConfigVersion, "guard_endpoint_id": configured.ID,
				"endpoint_priority": configured.Priority, "circuit_state": "closed", "status": "probe_recovered",
			})
		}
		return
	}
}

func sameEndpointProbeIdentity(configured, probed ActiveEndpoint) bool {
	return configured.ID == probed.ID && configured.Protocol == probed.Protocol && configured.Adapter == probed.Adapter &&
		configured.BaseURL == probed.BaseURL && configured.Model == probed.Model && configured.Token == probed.Token &&
		configured.TimeoutMS == probed.TimeoutMS && configured.InputLimit == probed.InputLimit &&
		configured.PromptTemplateID == probed.PromptTemplateID && configured.SystemPrompt == probed.SystemPrompt &&
		configured.FlagThreshold == probed.FlagThreshold && configured.BlockThreshold == probed.BlockThreshold
}

func modelsResponseReady(body []byte, model string) bool {
	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &response) != nil || response.Data == nil {
		return false
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return true
	}
	for _, item := range response.Data {
		if strings.TrimSpace(item.ID) == model {
			return true
		}
	}
	return false
}

func (s *PromptService) resolveProbeEndpoint(input UpdateEndpoint) (ActiveEndpoint, bool, error) {
	baseURL, err := NormalizeBaseURL(input.BaseURL)
	if err != nil {
		return ActiveEndpoint{}, false, err
	}
	token := strings.TrimSpace(input.Token)
	adapter := strings.TrimSpace(input.Adapter)
	template := DefaultPromptTemplate()
	cyberRules := []CyberSupplementRule(nil)
	flagThreshold, blockThreshold := DefaultFlagThreshold, DefaultBlockThreshold
	if cfg, ok := s.config.Active(); ok {
		template = activePromptTemplate(cfg.PromptTemplates, cfg.ActivePromptTemplateID)
		cyberRules = cloneCyberSupplementRules(cfg.CyberSupplementRules)
		if cfg.FlagThreshold >= 0 && cfg.FlagThreshold < cfg.BlockThreshold && cfg.BlockThreshold <= 1 {
			flagThreshold, blockThreshold = cfg.FlagThreshold, cfg.BlockThreshold
		}
		for _, endpoint := range cfg.Endpoints {
			if endpoint.ID != strings.TrimSpace(input.ID) {
				continue
			}
			if adapter == "" {
				adapter = endpoint.Adapter
			}
			// Reuse a stored credential only when the probe targets the same
			// normalized base URL. Otherwise an admin probe could exfiltrate
			// the Guard token to an attacker-controlled HTTPS host.
			if token == "" && endpoint.BaseURL == baseURL {
				token = endpoint.Token
			}
			break
		}
	}
	if adapter == "" {
		adapter = AdapterQwen3Guard
	}
	systemPrompt := template.SystemPrompt
	supplementApplied := false
	if adapterSupportsSystemPrompt(adapter) {
		systemPrompt, err = CompileCyberSupplement(template.SystemPrompt, cyberRules)
		if err != nil {
			return ActiveEndpoint{}, false, err
		}
		supplementApplied = len(cyberRules) > 0
	}
	if adapter == AdapterOpenAIModeration {
		systemPrompt = ""
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		model = defaultModelForPromptAdapter(adapter)
	}
	timeout := input.TimeoutMS
	if timeout == 0 {
		timeout = DefaultTimeoutMS
	}
	limit := input.InputLimit
	if limit == 0 {
		limit = DefaultInputLimit
	}
	storage := storageConfig{Enabled: false, Strategy: "priority", WorkerCount: DefaultWorkerCount, QueueCapacity: DefaultQueueCapacity, Scanners: append([]string(nil), AllScannerIDs...), AllGroups: true,
		MaxTotalInputChars: DefaultMaxTotalInputChars,
		PromptTemplates:    []PromptTemplate{DefaultPromptTemplate()}, ActivePromptTemplateID: DefaultPromptTemplateID,
		FlagThreshold: float64Pointer(flagThreshold), BlockThreshold: float64Pointer(blockThreshold), BlockHTTPStatus: DefaultBlockHTTPStatus, BlockMessage: DefaultBlockMessage,
		Endpoints: []StorageEndpoint{{ID: strings.TrimSpace(input.ID), Name: strings.TrimSpace(input.Name), Priority: MinEndpointPriority, Protocol: "openai_compatible", Adapter: adapter, BaseURL: baseURL, Model: model, TimeoutMS: timeout, InputLimit: limit}}}
	if storage.Endpoints[0].ID == "" {
		storage.Endpoints[0].ID = "probe"
	}
	if storage.Endpoints[0].Name == "" {
		storage.Endpoints[0].Name = "Probe"
	}
	if err := validateStorageConfig(storage); err != nil {
		return ActiveEndpoint{}, false, err
	}
	return ActiveEndpoint{ID: storage.Endpoints[0].ID, Name: storage.Endpoints[0].Name, Priority: MinEndpointPriority, Protocol: "openai_compatible", Adapter: adapter,
		BaseURL: baseURL, Model: model, Token: token, TimeoutMS: timeout, InputLimit: limit, Enabled: true,
		PromptTemplateID: template.ID, SystemPrompt: systemPrompt, SupportsSystemPrompt: adapterSupportsSystemPrompt(adapter), CyberSupplementApplied: supplementApplied,
		FlagThreshold: flagThreshold, BlockThreshold: blockThreshold}, token != "", nil
}

func (s *PromptService) finishProbe(id string, started time.Time, result ProbeResult) ProbeResult {
	result.CheckedAt = s.clock.Now()
	result.LatencyMS = int(result.CheckedAt.Sub(started).Milliseconds())
	if result.OK {
		LogInfo(EventProbeFinished, map[string]any{"guard_endpoint_id": id, "status": result.Status, "latency_ms": result.LatencyMS, "http_status": result.HTTPStatus})
	} else {
		LogWarn(EventProbeFailed, map[string]any{"guard_endpoint_id": id, "status": result.Status, "latency_ms": result.LatencyMS, "http_status": result.HTTPStatus, "error_code": result.ErrorCode, "retryable": result.Retryable})
	}
	s.probeMu.Lock()
	s.probes[id] = result
	s.probeMu.Unlock()
	return result
}

func (s *PromptService) probeSnapshot() map[string]ProbeResult {
	s.probeMu.RLock()
	defer s.probeMu.RUnlock()
	result := make(map[string]ProbeResult, len(s.probes))
	for id, probe := range s.probes {
		result[id] = probe
	}
	return result
}

func (s *PromptService) ListEvents(ctx context.Context, filter EventFilter, page, pageSize int) (*EventPage, error) {
	return s.repo.ListEvents(ctx, filter, page, pageSize)
}
func (s *PromptService) GetEvent(ctx context.Context, id int64) (*Event, error) {
	return s.repo.GetEvent(ctx, id)
}

func (s *PromptService) DeleteEvent(ctx context.Context, id int64) (*DeleteResult, error) {
	result, err := s.repo.DeleteEvent(ctx, id)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
	}
	return result, err
}
func (s *PromptService) DeleteEventsByIDs(ctx context.Context, ids []int64) (*DeleteResult, error) {
	result, err := s.repo.DeleteEventsByIDs(ctx, ids)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
	}
	return result, err
}

type deleteClaims struct {
	FilterHash    string    `json:"filter_hash"`
	SnapshotMaxID int64     `json:"snapshot_max_id"`
	AdminID       int64     `json:"admin_id"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s *PromptService) PreviewDelete(ctx context.Context, filter EventFilter, adminID int64) (*DeletePreview, error) {
	preview, err := s.repo.PreviewDelete(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	expires := now.Add(5 * time.Minute)
	claimsRaw, _ := json.Marshal(deleteClaims{FilterHash: preview.FilterHash, SnapshotMaxID: preview.SnapshotMaxID, AdminID: adminID, IssuedAt: now, ExpiresAt: expires})
	token, err := s.config.Encrypt(string(claimsRaw))
	if err != nil {
		return nil, err
	}
	preview.ConfirmationToken, preview.ExpiresAt = token, expires
	LogInfo(EventDeletePreviewed, map[string]any{"user_id": adminID, "status": "previewed"})
	return preview, nil
}

type DeleteByFilterRequest struct {
	Filter            EventFilter `json:"filter"`
	SnapshotMaxID     int64       `json:"snapshot_max_id"`
	FilterHash        string      `json:"filter_hash"`
	ConfirmationToken string      `json:"confirmation_token"`
	Confirm           bool        `json:"confirm"`
}

func (s *PromptService) DeleteByFilter(ctx context.Context, request DeleteByFilterRequest, adminID int64) (*DeleteResult, error) {
	if !request.Confirm {
		return nil, errors.New("prompt audit filter delete requires confirm=true")
	}
	plain, err := s.config.Decrypt(strings.TrimSpace(request.ConfirmationToken))
	if err != nil {
		return nil, errors.New("prompt audit confirmation token invalid")
	}
	var claims deleteClaims
	if json.Unmarshal([]byte(plain), &claims) != nil {
		return nil, errors.New("prompt audit confirmation token invalid")
	}
	computed := FilterHash(request.Filter, request.SnapshotMaxID)
	if claims.AdminID != adminID || claims.SnapshotMaxID != request.SnapshotMaxID || claims.FilterHash != request.FilterHash || request.FilterHash != computed || !s.clock.Now().Before(claims.ExpiresAt) {
		return nil, errors.New("prompt audit confirmation token does not match deletion request")
	}
	result, err := s.repo.DeleteEventsByFilter(ctx, request.Filter, request.SnapshotMaxID, 200)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
		LogWarn(EventEventsFilterDeleted, map[string]any{"user_id": adminID, "status": "deleted"})
	}
	return result, err
}

func (s *PromptService) deletePayloads(ctx context.Context, jobIDs []int64) {
	for _, id := range jobIDs {
		_ = s.payload.Delete(ctx, id)
	}
}

func parseTimeQuery(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	parsed = parsed.UTC()
	return &parsed
}
