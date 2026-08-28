package securityaudit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type GuardEvaluator struct {
	scanner  PromptScanner
	repo     JobRepository
	metrics  Metrics
	clock    Clock
	cache    *promptDecisionCache
	failover *endpointFailoverExecutor

	global       chan struct{}
	perNodeLimit int
	nodeMu       sync.Mutex
	nodes        map[string]chan struct{}
}

func NewGuardEvaluator(scanner PromptScanner, repo JobRepository, metrics Metrics) *GuardEvaluator {
	return newGuardEvaluator(scanner, repo, metrics, 64, 16)
}

func newGuardEvaluator(scanner PromptScanner, repo JobRepository, metrics Metrics, globalLimit, perNodeLimit int) *GuardEvaluator {
	if globalLimit < 1 {
		globalLimit = 64
	}
	if perNodeLimit < 1 {
		perNodeLimit = 16
	}
	evaluator := &GuardEvaluator{scanner: scanner, repo: repo, metrics: metrics, clock: realClock{},
		cache:  newPromptDecisionCache(defaultPromptDecisionCacheSize, defaultPromptDecisionCacheTTL),
		global: make(chan struct{}, globalLimit), perNodeLimit: perNodeLimit, nodes: map[string]chan struct{}{}}
	evaluator.failover = newEndpointFailoverExecutor(scanner, metrics, nil, func() time.Time { return evaluator.clock.Now() }, evaluator.acquireEndpoint)
	return evaluator
}

func (g *GuardEvaluator) Evaluate(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot) (*PromptDecision, error) {
	if err := ctx.Err(); err != nil {
		if g != nil && g.metrics != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				g.metrics.IncTimeout()
			}
			g.metrics.Observe(DecisionUnavailable, 0)
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", 0)
		return nil, parentGuardContextError(err)
	}
	if g == nil || g.scanner == nil {
		if g != nil && g.metrics != nil {
			g.metrics.Observe(DecisionUnavailable, 0)
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", 0)
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	start := g.clock.Now()
	baseFields := snapshotLogFields(snapshot)
	baseFields["config_version"] = cfg.ConfigVersion
	if snapshot.PromptLength > maxTotalInputChars(cfg) {
		return g.finishOversized(ctx, cfg, snapshot, start)
	}
	endpoints := cfg.EnabledEndpoints()
	if len(endpoints) == 0 {
		if g.metrics != nil {
			g.metrics.Observe(DecisionUnavailable, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	inputLimit := minimumInputLimit(endpoints)
	chunks := SplitRunes(snapshot.ScanText, inputLimit)
	if len(chunks) == 0 {
		if g.metrics != nil {
			g.metrics.Observe(DecisionAllow, g.clock.Now().Sub(start))
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	cacheKey := promptDecisionCacheKey(cfg, snapshot.ScanText)
	if cached, ok := g.cache.get(cacheKey, g.clock.Now()); ok {
		cached.LatencyMS = int(g.clock.Now().Sub(start).Milliseconds())
		return g.finishDecision(ctx, cfg, snapshot, cached, start, true), nil
	}
	select {
	case g.global <- struct{}{}:
		defer func() { <-g.global }()
	default:
		if g.metrics != nil {
			g.metrics.IncBulkheadFull()
			g.metrics.Observe(DecisionUnavailable, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	LogInfo(EventEvaluationStarted, mergeLogFields(baseFields, map[string]any{"chunk_total": len(chunks), "status": "started"}))
	results := make([]*NormalizedResult, 0, len(chunks))
	failoverState := newEndpointFailoverState()
	for index, chunk := range chunks {
		chunkStarted := g.clock.Now()
		LogInfo(EventChunkStarted, mergeLogFields(baseFields, map[string]any{
			"chunk_index": index + 1, "chunk_total": len(chunks),
			"chunk_chars": len([]rune(chunk)), "input_chars": snapshot.PromptLength, "input_limit": inputLimit,
			"status": "started",
		}))
		result, err := g.failover.scanChunk(ctx, cfg, endpoints, chunk, failoverState, baseFields)
		if err != nil {
			code := guardErrorCode(err)
			LogWarn(EventChunkFailed, mergeLogFields(baseFields, map[string]any{
				"chunk_index": index + 1, "chunk_total": len(chunks),
				"chunk_chars": len([]rune(chunk)), "input_chars": snapshot.PromptLength, "input_limit": inputLimit,
				"latency_ms": g.clock.Now().Sub(chunkStarted).Milliseconds(), "error_code": code, "status": "failed",
			}))
			kind := DecisionUnavailable
			if code == ErrorCodeInvalidResponse {
				kind = DecisionInvalid
			}
			if g.metrics != nil {
				g.metrics.Observe(kind, g.clock.Now().Sub(start))
			}
			logGuardFailure(snapshot, cfg, kind, code, "", g.clock.Now().Sub(start))
			return nil, err
		}
		result.ChunkTotal = len(chunks)
		results = append(results, result)
		LogInfo(EventChunkCompleted, mergeLogFields(baseFields, map[string]any{
			"chunk_index": index + 1, "chunk_total": len(chunks),
			"chunk_chars": len([]rune(chunk)), "input_chars": snapshot.PromptLength, "input_limit": inputLimit,
			"guard_endpoint_id": result.GuardEndpointID, "action": result.Action,
			"latency_ms": g.clock.Now().Sub(chunkStarted).Milliseconds(), "status": "completed",
		}))
		if result.Action == ActionBlock {
			break
		}
	}
	aggregated, err := AggregateResults(results, g.clock.Now().Sub(start))
	if err != nil {
		if g.metrics != nil {
			g.metrics.Observe(DecisionInvalid, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionInvalid, ErrorCodeInvalidResponse, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	aggregated.ChunkTotal = len(chunks)
	g.cache.put(cacheKey, aggregated, g.clock.Now())
	return g.finishDecision(ctx, cfg, snapshot, aggregated, start, false), nil
}

func (g *GuardEvaluator) finishDecision(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot, aggregated *NormalizedResult, start time.Time, cacheHit bool) *PromptDecision {
	baseFields := snapshotLogFields(snapshot)
	baseFields["config_version"] = cfg.ConfigVersion
	kind := DecisionAllow
	if aggregated.Action == ActionWarn {
		kind = DecisionFlag
	}
	if aggregated.Action == ActionBlock {
		kind = DecisionBlock
	}
	decision := &PromptDecision{Kind: kind, Result: aggregated, AllowNextStage: kind == DecisionAllow || kind == DecisionFlag}
	if kind == DecisionFlag && matchedPromptScanner(aggregated.MatchedScanners, confidenceScoreKey) {
		if len(cfg.RiskRouteAccountIDs) > 0 {
			decision.RouteAccountIDs = append([]int64(nil), cfg.RiskRouteAccountIDs...)
		} else if strings.TrimSpace(cfg.NoRouteFallbackMode) != "" && !cfg.AllowsNoRouteFallback() {
			// A group policy explicitly chose the secure default: a high-risk
			// finding with no destination account must not silently pass through.
			// Keep the persisted event aligned with the actual terminal decision;
			// otherwise the request would be rejected while the event still looked
			// like a warning-only finding.
			kind = DecisionBlock
			decision.Kind = kind
			decision.AllowNextStage = false
			decision.ErrorCode = ErrorCodeNoRiskRoute
			decision.BlockHTTPStatus = cfg.BlockHTTPStatus
			if decision.BlockHTTPStatus < 400 || decision.BlockHTTPStatus > 499 {
				decision.BlockHTTPStatus = DefaultBlockHTTPStatus
			}
			decision.BlockMessage = cfg.BlockMessage
			if decision.BlockMessage == "" {
				decision.BlockMessage = DefaultBlockMessage
			}
			aggregated.Decision = EventCritical
			aggregated.Action = ActionBlock
			if strings.TrimSpace(aggregated.Reason) == "" {
				aggregated.Reason = "high-risk finding has no eligible risk-route account"
			}
		}
	}
	if kind == DecisionBlock {
		if decision.ErrorCode == "" {
			decision.ErrorCode = ErrorCodeBlocked
		}
		decision.BlockHTTPStatus = cfg.BlockHTTPStatus
		if decision.BlockHTTPStatus < 400 || decision.BlockHTTPStatus > 499 {
			decision.BlockHTTPStatus = DefaultBlockHTTPStatus
		}
		decision.BlockMessage = cfg.BlockMessage
		if decision.BlockMessage == "" {
			decision.BlockMessage = DefaultBlockMessage
		}
	}
	if g.metrics != nil {
		g.metrics.Observe(kind, g.clock.Now().Sub(start))
	}
	LogInfo(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"decision":   kind,
		"risk_level": aggregated.RiskLevel, "action": aggregated.Action, "chunk_total": aggregated.ChunkTotal,
		"latency_ms": aggregated.LatencyMS, "guard_endpoint_id": aggregated.GuardEndpointID, "stage": snapshot.Stage,
		"status": "completed", "cache_hit": cacheHit,
	}))
	if g.repo != nil {
		if _, recordErr := g.repo.RecordBlocking(ctx, snapshot.Redacted(), cfg.ConfigVersion, aggregated, cfg.StorePassEvents); recordErr != nil {
			if g.metrics != nil {
				g.metrics.IncRecordFailed()
			}
			LogWarn(EventResultRecordFailed, mergeLogFields(baseFields, map[string]any{
				"decision": kind, "error_code": "result_record_failed", "stage": snapshot.Stage,
				"status": "failed",
			}))
		}
	}
	if kind == DecisionBlock {
		LogWarn(EventGuardBlocked, mergeLogFields(baseFields, map[string]any{
			"guard_endpoint_id": aggregated.GuardEndpointID,
			"decision":          kind, "risk_level": aggregated.RiskLevel, "action": aggregated.Action, "chunk_total": aggregated.ChunkTotal,
			"latency_ms": aggregated.LatencyMS, "status": "blocked", "error_code": decision.ErrorCode,
			"stage": snapshot.Stage, "upstream_dispatched": false, "billing_preconsumed": false,
		}))
	} else {
		LogInfo(EventGuardAllowed, mergeLogFields(baseFields, map[string]any{
			"decision": kind, "risk_level": aggregated.RiskLevel, "action": aggregated.Action,
			"guard_endpoint_id": aggregated.GuardEndpointID, "chunk_total": aggregated.ChunkTotal,
			"latency_ms": aggregated.LatencyMS, "stage": snapshot.Stage, "status": "allowed",
		}))
	}
	return decision
}

func (g *GuardEvaluator) finishOversized(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot, start time.Time) (*PromptDecision, error) {
	result := inputTooLargeResult(false, g.clock.Now().Sub(start))
	decision := &PromptDecision{Kind: DecisionFlag, Result: result, AllowNextStage: true}
	if len(cfg.RiskRouteAccountIDs) > 0 {
		decision.RouteAccountIDs = append([]int64(nil), cfg.RiskRouteAccountIDs...)
	} else if strings.TrimSpace(cfg.NoRouteFallbackMode) != "" && cfg.AllowsNoRouteFallback() {
		// Explicit per-group allow means an oversized prompt may continue when
		// there is no spare risk-route account. Keep the finding as a flag for
		// audit visibility while allowing the upstream request to proceed.
	} else {
		result = inputTooLargeResult(true, g.clock.Now().Sub(start))
		decision.Result = result
		decision.Kind = DecisionBlock
		decision.ErrorCode = ErrorCodeInputTooLarge
		decision.AllowNextStage = false
		decision.BlockHTTPStatus = 413
		decision.BlockMessage = "Prompt is too large for content safety review. Please reduce the input and try again."
	}
	if g.metrics != nil {
		g.metrics.Observe(decision.Kind, g.clock.Now().Sub(start))
	}
	baseFields := snapshotLogFields(snapshot)
	baseFields["config_version"] = cfg.ConfigVersion
	LogWarn(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"decision": decision.Kind, "risk_level": result.RiskLevel, "action": result.Action,
		"chunk_total": 0, "input_chars": snapshot.PromptLength, "max_total_input_chars": maxTotalInputChars(cfg),
		"latency_ms": result.LatencyMS, "guard_endpoint_id": "", "stage": snapshot.Stage,
		"status": "completed", "error_code": ErrorCodeInputTooLarge, "cache_hit": false,
	}))
	if g.repo != nil {
		if _, recordErr := g.repo.RecordBlocking(ctx, snapshot.Redacted(), cfg.ConfigVersion, result, cfg.StorePassEvents); recordErr != nil {
			if g.metrics != nil {
				g.metrics.IncRecordFailed()
			}
			LogWarn(EventResultRecordFailed, mergeLogFields(baseFields, map[string]any{
				"decision": decision.Kind, "error_code": "result_record_failed", "stage": snapshot.Stage, "status": "failed",
			}))
		}
	}
	return decision, nil
}

func inputTooLargeResult(block bool, latency time.Duration) *NormalizedResult {
	result := &NormalizedResult{
		Decision: EventFlag, RiskLevel: RiskHigh, Action: ActionWarn, Safety: "Unreviewed",
		Categories: []string{inputTooLargeScannerID}, MatchedScanners: []string{inputTooLargeScannerID},
		ScannerScores:   map[string]float64{inputTooLargeScannerID: 1},
		ScannerEvidence: map[string]string{inputTooLargeScannerID: "prompt exceeds total audit limit"},
		ScannerBackend:  "local-cost-guard", ScannerVersion: "1", ChunkTotal: 0,
		LatencyMS: int(latency.Milliseconds()), Reason: "prompt exceeds total audit limit",
	}
	if block {
		result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
	}
	return result
}

func maxTotalInputChars(cfg ActiveConfig) int {
	if cfg.MaxTotalInputChars < MinMaxTotalInputChars || cfg.MaxTotalInputChars > MaxMaxTotalInputChars {
		return DefaultMaxTotalInputChars
	}
	return cfg.MaxTotalInputChars
}

func matchedPromptScanner(scanners []string, target string) bool {
	for _, scanner := range scanners {
		if scanner == target {
			return true
		}
	}
	return false
}

func logGuardFailure(snapshot PromptSnapshot, cfg ActiveConfig, kind DecisionKind, code, guardEndpointID string, latency time.Duration) {
	fields := snapshotLogFields(snapshot)
	fields["config_version"] = cfg.ConfigVersion
	LogWarn(EventGuardFailed, mergeLogFields(fields, map[string]any{
		"decision": kind, "guard_endpoint_id": guardEndpointID, "latency_ms": latency.Milliseconds(),
		"status": "failed", "error_code": code, "upstream_dispatched": false, "billing_preconsumed": false,
	}))
}

func (g *GuardEvaluator) acquireEndpoint(ctx context.Context, endpoint ActiveEndpoint) (func(), bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	semaphore := g.nodeSemaphore(endpoint.ID)
	select {
	case semaphore <- struct{}{}:
		return func() { <-semaphore }, true, nil
	case <-ctx.Done():
		return nil, false, ctx.Err()
	default:
		return nil, false, nil
	}
}

func (g *GuardEvaluator) nodeSemaphore(id string) chan struct{} {
	g.nodeMu.Lock()
	defer g.nodeMu.Unlock()
	semaphore := g.nodes[id]
	if semaphore == nil {
		semaphore = make(chan struct{}, g.perNodeLimit)
		g.nodes[id] = semaphore
	}
	return semaphore
}

func minimumInputLimit(endpoints []ActiveEndpoint) int {
	limit := DefaultInputLimit
	for index, endpoint := range endpoints {
		value := endpoint.InputLimit
		if value <= 0 {
			value = DefaultInputLimit
		}
		if index == 0 || value < limit {
			limit = value
		}
	}
	return limit
}

func guardErrorCode(err error) string {
	var guardErr *GuardError
	if errors.As(err, &guardErr) && guardErr.Code != "" {
		return guardErr.Code
	}
	return ErrorCodeUnavailable
}

func pointerLogID(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
