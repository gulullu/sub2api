package securityaudit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type staticSettingRepository struct {
	values map[string]string
}

func (r staticSettingRepository) Get(context.Context, string) (*service.Setting, error) {
	return nil, service.ErrSettingNotFound
}
func (r staticSettingRepository) GetValue(_ context.Context, key string) (string, error) {
	value, ok := r.values[key]
	if !ok {
		return "", service.ErrSettingNotFound
	}
	return value, nil
}
func (r staticSettingRepository) Set(context.Context, string, string) error { return nil }
func (r staticSettingRepository) GetMultiple(_ context.Context, keys []string) (map[string]string, error) {
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		result[key] = r.values[key]
	}
	return result, nil
}
func (r staticSettingRepository) SetMultiple(context.Context, map[string]string) error { return nil }
func (r staticSettingRepository) GetAll(context.Context) (map[string]string, error) {
	return r.values, nil
}
func (r staticSettingRepository) Delete(context.Context, string) error { return nil }

func TestPromptServiceHasExplicitIdempotentLifecycle(t *testing.T) {
	config := NewConfigManager(nil, staticSettingRepository{values: map[string]string{
		SettingKeyPromptAuditConfig: "",
		SettingKeyRiskControl:       "false",
	}}, nil, prefixEncryptor{}, testTotpKeyConfig())
	service := NewPromptService(
		config,
		NewPostgreSQLRepository(nil),
		NewRedisPayloadStore(nil),
		NewOpenAICompatibleScanner(),
		NewAtomicMetrics(),
	)

	require.Nil(t, service.cancel, "construction must not start background work")
	require.NoError(t, service.Start(context.Background()))
	require.NotNil(t, service.cancel)
	require.NoError(t, service.Start(context.Background()), "Start must be idempotent")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, service.Shutdown(ctx))
	require.Nil(t, service.cancel)
	require.NoError(t, service.Shutdown(ctx), "Shutdown must be idempotent")
}

func TestPromptServiceStartReportsDependencyFailureWithoutPanic(t *testing.T) {
	service := &PromptService{}
	require.Error(t, service.Start(context.Background()))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, service.Shutdown(ctx))
}

func TestPromptServiceBlockingLatestTurnOnlyUsesNarrowSnapshot(t *testing.T) {
	seen := make([]string, 0, 2)
	evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		seen = append(seen, chunk)
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	}), nil, NewAtomicMetrics(), 2, 2)
	service := &PromptService{
		config: &fakeConfigStore{active: true, cfg: ActiveConfig{
			RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, BlockingLatestTurnOnly: true, AllGroups: true,
			Scanners: AllScannerIDs, Endpoints: []ActiveEndpoint{{ID: "guard-1", Enabled: true, TimeoutMS: 1000, InputLimit: 4096}},
		}},
		evaluator: evaluator,
	}
	decision, err := service.Evaluate(context.Background(), Request{Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"system","content":"system instruction"},{"role":"user","content":"older user input"},{"role":"assistant","content":"previous output"},{"role":"user","content":"latest user input"}]}`)})
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Equal(t, []string{"latest user input", "previous output"}, seen)
}

func TestPromptServiceExcludedUserSkipsBlockingAudit(t *testing.T) {
	service := &PromptService{
		config: &fakeConfigStore{active: true, cfg: ActiveConfig{
			RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true, ExcludedUserIDs: []int64{77},
			Scanners: AllScannerIDs, Endpoints: []ActiveEndpoint{{ID: "guard-1", Enabled: true, TimeoutMS: 1000, InputLimit: 4096}},
		}},
		evaluator: newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			t.Fatal("excluded users must not reach the prompt audit scanner")
			return nil, nil
		}), nil, NewAtomicMetrics(), 2, 2),
	}
	decision, err := service.Evaluate(context.Background(), Request{UserID: 77, Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`)})
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
}

func TestPromptServiceExcludedUserSkipsAsyncEnqueue(t *testing.T) {
	repo := &fakeJobRepository{}
	payload := &fakePayloadStore{}
	config := &fakeConfigStore{active: true, cfg: ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: false, AllGroups: true, ExcludedUserIDs: []int64{77},
		Scanners: AllScannerIDs, Endpoints: []ActiveEndpoint{{ID: "guard-1", Enabled: true, TimeoutMS: 1000, InputLimit: 4096}},
	}}
	service := &PromptService{
		config:     config,
		enqueuer:   NewEnqueuer(config, repo, payload, NewAtomicMetrics()),
		background: context.Background(),
	}
	require.NoError(t, service.Enqueue(context.Background(), Request{RequestID: "req-1", UserID: 77, Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"hi"}]}`)}))
	require.Zero(t, repo.recordBlockingCalls)
	require.Empty(t, payload.values)
}

func TestPromptServiceUnavailableAuditFallsBackToHardRiskRoute(t *testing.T) {
	now := time.Unix(2_000, 0).UTC()
	cfg := ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true, ConfigVersion: 7,
		Scanners: AllScannerIDs, RiskRouteAccountIDs: []int64{21, 22},
		Endpoints: []ActiveEndpoint{{ID: "guard-1", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 4096}},
	}
	repo := &fakeJobRepository{}
	metrics := NewAtomicMetrics()
	scannerCalls := 0
	evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		scannerCalls++
		return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 503, Retryable: true}
	}), repo, metrics, 2, 2)
	evaluator.clock = fixedClock{now: now}
	service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: evaluator, metrics: metrics, clock: fixedClock{now: now}}
	request := Request{RequestID: "fallback-request", Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"review me"}]}`)}

	decision, err := service.Evaluate(context.Background(), request)

	require.NoError(t, err)
	require.Equal(t, 1, scannerCalls)
	require.Equal(t, DecisionFlag, decision.Kind)
	require.Equal(t, ErrorCodeUnavailable, decision.ErrorCode)
	require.True(t, decision.AllowNextStage)
	require.Equal(t, []int64{21, 22}, decision.RouteAccountIDs)
	cfg.RiskRouteAccountIDs[0] = 999
	require.Equal(t, []int64{21, 22}, decision.RouteAccountIDs, "the decision must own an immutable copy of the hard route pool")
	require.NotNil(t, decision.Result)
	require.Equal(t, EventFlag, decision.Result.Decision)
	require.Equal(t, RiskHigh, decision.Result.RiskLevel)
	require.Equal(t, ActionWarn, decision.Result.Action)
	require.Equal(t, "local-failover", decision.Result.ScannerBackend)
	require.Equal(t, []string{auditUnavailableScannerID}, decision.Result.MatchedScanners)
	require.Equal(t, 1, repo.recordBlockingCalls)
	require.Empty(t, repo.recordBlockingSnapshot.ScanText)
	require.Same(t, decision.Result, repo.recordBlockingResult)
	require.Len(t, BuildIssueSummaries(*decision.Result), 1)
	_, cached := evaluator.cache.get(promptDecisionCacheKey(cfg, "review me"), now)
	require.False(t, cached, "operational fallback decisions must never enter the content decision cache")
	snapshot := metrics.Snapshot()
	require.Equal(t, int64(1), snapshot.Total)
	require.Equal(t, int64(1), snapshot.Unavailable)
	require.Zero(t, snapshot.Flagged, "the evaluator already recorded the dependency failure; fallback must not double count")

	coordinated := prioritize(nil, decision)
	require.Equal(t, DecisionFlag, coordinated.Kind)
	require.Equal(t, ErrorCodeUnavailable, coordinated.ErrorCode)
	require.True(t, coordinated.AllowNextStage)
}

func TestPromptServiceUnavailableAuditFallbackRequiresLiveContextAndRiskPool(t *testing.T) {
	baseConfig := ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true, ConfigVersion: 8,
		Scanners:  AllScannerIDs,
		Endpoints: []ActiveEndpoint{{ID: "guard-1", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 4096}},
	}
	request := Request{Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"review me"}]}`)}

	t.Run("no configured risk pool keeps 503 semantics", func(t *testing.T) {
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 503, Retryable: true}
		}), nil, NewAtomicMetrics(), 2, 2)
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: baseConfig}, evaluator: evaluator}
		decision, err := service.Evaluate(context.Background(), request)
		require.Nil(t, decision)
		var guardErr *GuardError
		require.ErrorAs(t, err, &guardErr)
		require.Equal(t, ErrorCodeUnavailable, guardErr.Code)
	})

	t.Run("caller cancellation never becomes routing", func(t *testing.T) {
		cfg := cloneActiveConfig(baseConfig)
		cfg.RiskRouteAccountIDs = []int64{21}
		calls := 0
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			calls++
			return nil, &GuardError{Code: ErrorCodeUnavailable}
		}), nil, NewAtomicMetrics(), 2, 2)
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: evaluator}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		decision, err := service.Evaluate(ctx, request)
		require.Nil(t, decision)
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, calls)
	})

	t.Run("cancellation while fallback event is persisted never becomes routing", func(t *testing.T) {
		cfg := cloneActiveConfig(baseConfig)
		cfg.RiskRouteAccountIDs = []int64{21}
		entered := make(chan struct{}, 1)
		repo := &fakeJobRepository{recordBlockingEntered: entered, recordBlockingWait: true}
		metrics := NewAtomicMetrics()
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 503, Retryable: true}
		}), repo, metrics, 2, 2)
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: evaluator}
		ctx, cancel := context.WithCancel(context.Background())
		type outcome struct {
			decision *PromptDecision
			err      error
		}
		done := make(chan outcome, 1)
		go func() {
			decision, err := service.Evaluate(ctx, request)
			done <- outcome{decision: decision, err: err}
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("fallback persistence was not reached")
		}
		cancel()
		result := <-done
		require.Nil(t, result.decision)
		require.ErrorIs(t, result.err, context.Canceled)
		require.Zero(t, metrics.Snapshot().RecordFailed, "caller cancellation is not a repository health failure")
	})

	t.Run("invalid endpoint output preserves invalid error code on fallback", func(t *testing.T) {
		cfg := cloneActiveConfig(baseConfig)
		cfg.RiskRouteAccountIDs = []int64{21}
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse}
		}), nil, NewAtomicMetrics(), 2, 2)
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: evaluator}
		decision, err := service.Evaluate(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, DecisionFlag, decision.Kind)
		require.Equal(t, ErrorCodeInvalidResponse, decision.ErrorCode)
		require.Equal(t, []int64{21}, decision.RouteAccountIDs)
	})

	t.Run("valid block remains terminal", func(t *testing.T) {
		cfg := cloneActiveConfig(baseConfig)
		cfg.RiskRouteAccountIDs = []int64{21}
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe"}, nil
		}), nil, NewAtomicMetrics(), 2, 2)
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: evaluator}
		decision, err := service.Evaluate(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, DecisionBlock, decision.Kind)
		require.False(t, decision.AllowNextStage)
		require.Empty(t, decision.RouteAccountIDs)
	})
}

func TestPromptServiceUnavailableRiskRouteCoversNoEndpointAndGlobalBulkhead(t *testing.T) {
	request := Request{Protocol: "openai_chat_completions", Body: []byte(`{"messages":[{"role":"user","content":"review me"}]}`)}
	baseConfig := ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true, ConfigVersion: 9,
		Scanners: AllScannerIDs, RiskRouteAccountIDs: []int64{31},
	}

	t.Run("no usable endpoint", func(t *testing.T) {
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			t.Fatal("scanner must not run without an enabled endpoint")
			return nil, nil
		}), nil, NewAtomicMetrics(), 1, 1)
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: baseConfig}, evaluator: evaluator}
		decision, err := service.Evaluate(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, DecisionFlag, decision.Kind)
		require.Equal(t, []int64{31}, decision.RouteAccountIDs)
	})

	t.Run("global evaluator bulkhead", func(t *testing.T) {
		cfg := cloneActiveConfig(baseConfig)
		cfg.Endpoints = []ActiveEndpoint{{ID: "guard-1", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 4096}}
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			t.Fatal("scanner must not run when the global evaluator bulkhead is full")
			return nil, nil
		}), nil, NewAtomicMetrics(), 1, 1)
		evaluator.global <- struct{}{}
		defer func() { <-evaluator.global }()
		service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: evaluator}
		decision, err := service.Evaluate(context.Background(), request)
		require.NoError(t, err)
		require.Equal(t, DecisionFlag, decision.Kind)
		require.Equal(t, []int64{31}, decision.RouteAccountIDs)
	})
}

func TestPromptServiceRejectsInvalidDeleteConfirmationClaims(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	filter := EventFilter{Decision: string(EventCritical), StartAt: &start, EndAt: &end}
	const snapshotMaxID int64 = 10
	filterHash := FilterHash(filter, snapshotMaxID)
	validClaims := deleteClaims{
		FilterHash: filterHash, SnapshotMaxID: snapshotMaxID, AdminID: 7,
		IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	claimsToken := func(claims deleteClaims) string {
		raw, err := json.Marshal(claims)
		require.NoError(t, err)
		return string(raw)
	}
	validRequest := DeleteByFilterRequest{
		Filter: filter, SnapshotMaxID: snapshotMaxID, FilterHash: filterHash,
		ConfirmationToken: claimsToken(validClaims), Confirm: true,
	}

	tests := []struct {
		name    string
		request DeleteByFilterRequest
		adminID int64
	}{
		{name: "confirm false", request: func() DeleteByFilterRequest { value := validRequest; value.Confirm = false; return value }(), adminID: 7},
		{name: "malformed token", request: func() DeleteByFilterRequest {
			value := validRequest
			value.ConfirmationToken = "not-json"
			return value
		}(), adminID: 7},
		{name: "different administrator", request: validRequest, adminID: 8},
		{name: "filter hash mismatch", request: func() DeleteByFilterRequest {
			value := validRequest
			value.FilterHash = strings.Repeat("b", 64)
			return value
		}(), adminID: 7},
		{name: "snapshot mismatch", request: func() DeleteByFilterRequest { value := validRequest; value.SnapshotMaxID++; return value }(), adminID: 7},
		{name: "expired", request: func() DeleteByFilterRequest {
			value := validRequest
			claims := validClaims
			claims.ExpiresAt = now
			value.ConfirmationToken = claimsToken(claims)
			return value
		}(), adminID: 7},
	}

	service := &PromptService{config: &fakeConfigStore{}, clock: fixedClock{now: now}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.DeleteByFilter(context.Background(), test.request, test.adminID)
			require.Error(t, err)
			require.Nil(t, result)
		})
	}
}
