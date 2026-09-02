package securityaudit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type scriptedScanner struct {
	mu      sync.Mutex
	calls   []string
	block   <-chan struct{}
	entered chan<- struct{}
}

func (s *scriptedScanner) Scan(ctx context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
	s.mu.Lock()
	s.calls = append(s.calls, endpoint.ID)
	s.mu.Unlock()
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: ctx.Err()}
		}
	}
	if endpoint.ID == "bad" {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
	}
	if endpoint.ID == "invalid" {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe", ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, GuardEndpointID: endpoint.ID}, nil
}

func guardConfig(endpoints ...ActiveEndpoint) ActiveConfig {
	return ActiveConfig{RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, ConfigVersion: 2, Scanners: AllScannerIDs, Endpoints: endpoints}
}

func TestGuardEvaluatorOrderedFailoverIncludesInvalidResponses(t *testing.T) {
	scanner := &scriptedScanner{}
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 4, 2)
	snapshot := PromptSnapshot{RequestID: "r", ScanText: "hello", PromptLength: 5}
	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "bad", Enabled: true, TimeoutMS: 1000, InputLimit: 100},
		ActiveEndpoint{ID: "good", Enabled: true, TimeoutMS: 1000, InputLimit: 100},
	), snapshot)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Equal(t, int64(1), metrics.Snapshot().Failovers)
	decision, err = evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "invalid", Enabled: true, TimeoutMS: 1000, InputLimit: 100},
		ActiveEndpoint{ID: "good", Enabled: true, TimeoutMS: 1000, InputLimit: 100},
	), snapshot)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	snapshotMetrics := metrics.Snapshot()
	require.Equal(t, int64(2), snapshotMetrics.Total)
	require.Equal(t, int64(2), snapshotMetrics.Allowed)
	require.Equal(t, int64(2), snapshotMetrics.Failovers)
	require.Zero(t, snapshotMetrics.Invalid)
}

func TestGuardEvaluatorEndpointLocalFailureMatrixFallsBackRegardlessOfRetryable(t *testing.T) {
	tests := []struct {
		name   string
		result *NormalizedResult
		err    error
	}{
		{name: "401", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 401, Retryable: false}},
		{name: "402", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 402, Retryable: false}},
		{name: "403", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 403, Retryable: false}},
		{name: "404", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 404, Retryable: false}},
		{name: "418", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 418, Retryable: false}},
		{name: "429", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 429, Retryable: true}},
		{name: "503", err: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 503, Retryable: true}},
		{name: "invalid JSON", err: &GuardError{Code: ErrorCodeInvalidResponse, Retryable: false}},
		{name: "empty result"},
		{name: "invalid schema", result: &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionBlock}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := []string{}
			scanner := PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
				calls = append(calls, endpoint.ID)
				if endpoint.ID == "primary" {
					return tt.result, tt.err
				}
				return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
			})
			metrics := NewAtomicMetrics()
			evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
			decision, err := evaluator.Evaluate(context.Background(), guardConfig(
				ActiveEndpoint{ID: "primary", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
				ActiveEndpoint{ID: "backup", Priority: 2, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
			), PromptSnapshot{ScanText: "review", PromptLength: 6})
			require.NoError(t, err)
			require.Equal(t, DecisionAllow, decision.Kind)
			require.Equal(t, []string{"primary", "backup"}, calls)
			require.Equal(t, int64(1), metrics.Snapshot().Failovers)
		})
	}
}

func TestGuardEvaluatorPriorityStableTiesAndValidResultsAreTerminal(t *testing.T) {
	t.Run("lower priority number wins regardless of array order", func(t *testing.T) {
		calls := []string{}
		evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			calls = append(calls, endpoint.ID)
			return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
		}), nil, NewAtomicMetrics(), 2, 2)
		_, err := evaluator.Evaluate(context.Background(), guardConfig(
			ActiveEndpoint{ID: "second", Priority: 2, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
			ActiveEndpoint{ID: "first", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
		), PromptSnapshot{ScanText: "priority", PromptLength: 8})
		require.NoError(t, err)
		require.Equal(t, []string{"first"}, calls)
	})

	t.Run("equal priorities retain original array order", func(t *testing.T) {
		calls := []string{}
		evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			calls = append(calls, endpoint.ID)
			if endpoint.ID == "tie-a" {
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: false}
			}
			return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
		}), nil, NewAtomicMetrics(), 2, 2)
		_, err := evaluator.Evaluate(context.Background(), guardConfig(
			ActiveEndpoint{ID: "tie-a", Priority: 5, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
			ActiveEndpoint{ID: "tie-b", Priority: 5, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
		), PromptSnapshot{ScanText: "ties", PromptLength: 4})
		require.NoError(t, err)
		require.Equal(t, []string{"tie-a", "tie-b"}, calls)
	})

	for _, tt := range []struct {
		name   string
		result *NormalizedResult
		kind   DecisionKind
	}{
		{name: "allow", result: &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, kind: DecisionAllow},
		{name: "flag", result: &NormalizedResult{Decision: EventFlag, RiskLevel: RiskMedium, Action: ActionWarn}, kind: DecisionFlag},
		{name: "block", result: &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock}, kind: DecisionBlock},
	} {
		t.Run("valid "+tt.name+" stops failover", func(t *testing.T) {
			calls := []string{}
			evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
				calls = append(calls, endpoint.ID)
				if endpoint.ID == "backup" {
					t.Fatal("valid result must never try a lower-priority endpoint")
				}
				copyResult := *tt.result
				return &copyResult, nil
			}), nil, NewAtomicMetrics(), 2, 2)
			decision, err := evaluator.Evaluate(context.Background(), guardConfig(
				ActiveEndpoint{ID: "primary", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
				ActiveEndpoint{ID: "backup", Priority: 2, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
			), PromptSnapshot{ScanText: tt.name, PromptLength: len(tt.name)})
			require.NoError(t, err)
			require.Equal(t, tt.kind, decision.Kind)
			require.Equal(t, []string{"primary"}, calls)
		})
	}
}

func TestGuardEvaluatorMultiChunkFailoverAffinityDoesNotRetryFailedEndpoint(t *testing.T) {
	calls := []string{}
	evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		calls = append(calls, endpoint.ID)
		if endpoint.ID == "primary" {
			return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 402, Retryable: false}
		}
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
	}), nil, NewAtomicMetrics(), 2, 2)
	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "primary", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 3},
		ActiveEndpoint{ID: "backup", Priority: 2, Enabled: true, TimeoutMS: 1000, InputLimit: 3},
	), PromptSnapshot{ScanText: "abcdefghi", PromptLength: 9})
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Equal(t, []string{"primary", "backup", "backup", "backup"}, calls)
}

func TestGuardEvaluatorMultiChunkFailureSummaryAccumulatesAcrossRequest(t *testing.T) {
	calls := []string{}
	evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, chunk string, _ []string) (*NormalizedResult, error) {
		calls = append(calls, endpoint.ID)
		switch {
		case endpoint.ID == "primary":
			return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 503, Retryable: true}
		case chunk == "abc":
			return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
		default:
			return nil, &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 401, Retryable: false}
		}
	}), nil, NewAtomicMetrics(), 2, 2)

	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "primary", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 3},
		ActiveEndpoint{ID: "backup", Priority: 2, Enabled: true, TimeoutMS: 1000, InputLimit: 3},
	), PromptSnapshot{ScanText: "abcdef", PromptLength: 6})

	require.Nil(t, decision)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.Equal(t, ErrorCodeUnavailable, guardErr.Code)
	require.True(t, guardErr.Retryable, "a transient failure on an earlier chunk must survive a later permanent failure")
	require.False(t, guardErr.Timeout)
	require.Equal(t, []string{"primary", "backup", "backup"}, calls)
}

func TestGuardEvaluatorFailureSummaryCodeIsInvalidOnlyWhenEveryEndpointIsInvalid(t *testing.T) {
	for _, tt := range []struct {
		name     string
		second   error
		wantCode string
	}{
		{name: "all invalid", second: &GuardError{Code: ErrorCodeInvalidResponse}, wantCode: ErrorCodeInvalidResponse},
		{name: "mixed invalid and unavailable", second: &GuardError{Code: ErrorCodeUnavailable, HTTPStatus: 503, Retryable: true}, wantCode: ErrorCodeUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := newGuardEvaluator(PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
				if endpoint.ID == "first" {
					return nil, &GuardError{Code: ErrorCodeInvalidResponse}
				}
				return nil, tt.second
			}), nil, NewAtomicMetrics(), 2, 2)
			_, err := evaluator.Evaluate(context.Background(), guardConfig(
				ActiveEndpoint{ID: "first", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
				ActiveEndpoint{ID: "second", Priority: 2, Enabled: true, TimeoutMS: 1000, InputLimit: 100},
			), PromptSnapshot{ScanText: "review", PromptLength: 6})
			var guardErr *GuardError
			require.ErrorAs(t, err, &guardErr)
			require.Equal(t, tt.wantCode, guardErr.Code)
		})
	}
}

func TestGuardEvaluatorTotalEndpointBudgetCoversAllChunks(t *testing.T) {
	var allowances []time.Duration
	calls := 0
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(PromptScannerFunc(func(ctx context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		calls++
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		allowances = append(allowances, time.Until(deadline))
		if calls == 1 {
			select {
			case <-time.After(100 * time.Millisecond):
				return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if calls == 2 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
	}), nil, metrics, 2, 2)
	started := time.Now()
	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "only", Priority: 1, Enabled: true, TimeoutMS: 250, InputLimit: 3},
	), PromptSnapshot{ScanText: "abcdef", PromptLength: 6})

	require.Nil(t, decision)
	var guardErr *GuardError
	require.ErrorAs(t, err, &guardErr)
	require.True(t, guardErr.Timeout)
	require.Equal(t, 2, calls)
	require.Len(t, allowances, 2)
	require.Greater(t, allowances[0], 220*time.Millisecond)
	require.Greater(t, allowances[1], 100*time.Millisecond)
	require.Less(t, allowances[1], 200*time.Millisecond, "the second chunk must receive only the first chunk's remaining scanner-time budget")
	require.Less(t, time.Since(started), 400*time.Millisecond)
	require.Zero(t, metrics.Snapshot().CircuitOpen, "a residual request-budget timeout must not mark a healthy endpoint down")

	secondDecision, secondErr := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "only", Priority: 1, Enabled: true, TimeoutMS: 250, InputLimit: 3},
	), PromptSnapshot{ScanText: "ghijkl", PromptLength: 6})
	require.NoError(t, secondErr)
	require.Equal(t, DecisionAllow, secondDecision.Kind)
	require.Equal(t, 4, calls, "the next request must still call an endpoint truncated only by the prior request budget")
	require.Zero(t, metrics.Snapshot().CircuitSkip)
}

func TestGuardEvaluatorAllHangingEndpointsEachReceiveFullTimeoutThenOpen(t *testing.T) {
	calls := 0
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(PromptScannerFunc(func(ctx context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		calls++
		<-ctx.Done()
		return nil, ctx.Err()
	}), nil, metrics, 2, 2)
	cfg := guardConfig(
		ActiveEndpoint{ID: "first", Priority: 1, Enabled: true, TimeoutMS: 100, InputLimit: 100},
		ActiveEndpoint{ID: "second", Priority: 2, Enabled: true, TimeoutMS: 100, InputLimit: 100},
	)

	_, firstErr := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "first", PromptLength: 5})
	require.Error(t, firstErr)
	require.Equal(t, 2, calls)
	require.Equal(t, int64(2), metrics.Snapshot().CircuitOpen)
	_, secondErr := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "second", PromptLength: 6})
	require.Error(t, secondErr)
	require.Equal(t, 2, calls, "both fully timed-out endpoints must be circuit-skipped on the next request")
	require.Equal(t, int64(2), metrics.Snapshot().CircuitSkip)
}

func TestGuardEvaluatorEndpointTimeoutOpensCircuitAtRequestBudgetBoundary(t *testing.T) {
	calls := 0
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(PromptScannerFunc(func(ctx context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		calls++
		<-ctx.Done()
		return nil, ctx.Err()
	}), nil, metrics, 2, 2)
	cfg := guardConfig(ActiveEndpoint{ID: "only", Priority: 1, Enabled: true, TimeoutMS: 100, InputLimit: 100})

	_, firstErr := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "first", PromptLength: 5})
	require.Error(t, firstErr)
	_, secondErr := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "second", PromptLength: 6})
	require.Error(t, secondErr)
	require.Equal(t, 1, calls, "a timeout at the internal budget boundary must open the shared endpoint circuit")
	snapshot := metrics.Snapshot()
	require.Equal(t, int64(1), snapshot.Timeouts)
	require.Equal(t, int64(1), snapshot.CircuitOpen)
	require.Equal(t, int64(1), snapshot.CircuitSkip)
}

func TestGuardEvaluatorGlobalBulkheadIsNonBlocking(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	scanner := &scriptedScanner{block: release, entered: entered}
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 1, 1)
	cfg := guardConfig(ActiveEndpoint{ID: "good", Enabled: true, TimeoutMS: 2000, InputLimit: 100})
	done := make(chan error, 1)
	go func() {
		_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "one", PromptLength: 3})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first evaluation did not enter scanner")
	}
	start := time.Now()
	_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "two", PromptLength: 3})
	require.Error(t, err)
	require.Less(t, time.Since(start), 200*time.Millisecond)
	require.Equal(t, int64(1), metrics.Snapshot().BulkheadFull)
	close(release)
	require.NoError(t, <-done)
	_, err = evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "three", PromptLength: 5})
	require.NoError(t, err, "local bulkhead pressure must not open the endpoint circuit")
	require.Zero(t, metrics.Snapshot().CircuitOpen)
	snapshotMetrics := metrics.Snapshot()
	require.Equal(t, int64(3), snapshotMetrics.Total)
	require.Equal(t, int64(2), snapshotMetrics.Allowed)
	require.Equal(t, int64(1), snapshotMetrics.Unavailable)
}

func TestGuardEvaluatorPerNodeBulkheadIsNonBlocking(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	scanner := &scriptedScanner{block: release, entered: entered}
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 1)
	cfg := guardConfig(ActiveEndpoint{ID: "same-node", Enabled: true, TimeoutMS: 2000, InputLimit: 100})
	done := make(chan error, 1)
	go func() {
		_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "one", PromptLength: 3})
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first evaluation did not enter scanner")
	}
	started := time.Now()
	_, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "two", PromptLength: 3})
	require.Error(t, err)
	require.Less(t, time.Since(started), 200*time.Millisecond)
	require.GreaterOrEqual(t, metrics.Snapshot().BulkheadFull, int64(1))
	close(release)
	require.NoError(t, <-done)
}

func TestGuardEvaluatorLastChunkFailureNeverAllows(t *testing.T) {
	call := 0
	scanner := PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		call++
		if call == 2 {
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: errors.New("down")}
		}
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	})
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
	_, err := evaluator.Evaluate(context.Background(), guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 3}), PromptSnapshot{ScanText: "abcdef", PromptLength: 6})
	require.Error(t, err)
}

func TestGuardEvaluatorTotalInputLimitRoutesOrFailsClosedWithoutScannerCalls(t *testing.T) {
	for _, tt := range []struct {
		name         string
		routeIDs     []int64
		fallbackMode string
		wantKind     DecisionKind
		wantCode     string
		wantFallback bool
	}{
		{name: "risk pool block fallback", routeIDs: []int64{21, 22}, fallbackMode: NoRouteFallbackBlock, wantKind: DecisionFlag},
		{name: "risk pool allow fallback", routeIDs: []int64{21, 22}, fallbackMode: NoRouteFallbackAllow, wantKind: DecisionFlag, wantFallback: true},
		{name: "no risk pool", wantKind: DecisionBlock, wantCode: ErrorCodeInputTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				calls++
				return nil, errors.New("scanner must not be called")
			}), nil, NewAtomicMetrics(), 2, 2)
			cfg := guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 3})
			cfg.MaxTotalInputChars = MinMaxTotalInputChars
			cfg.RiskRouteAccountIDs = tt.routeIDs
			cfg.NoRouteFallbackMode = tt.fallbackMode
			text := strings.Repeat("x", MinMaxTotalInputChars+1)

			decision, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: text, PromptLength: len([]rune(text))})

			require.NoError(t, err)
			require.Equal(t, 0, calls)
			require.Equal(t, tt.wantKind, decision.Kind)
			require.Equal(t, tt.wantCode, decision.ErrorCode)
			require.Equal(t, tt.routeIDs, decision.RouteAccountIDs)
			require.Equal(t, tt.wantFallback, decision.AllowRiskRouteFallback)
			if tt.wantKind == DecisionBlock {
				require.Equal(t, 413, decision.BlockHTTPStatus)
				require.False(t, decision.AllowNextStage)
			} else {
				require.True(t, decision.AllowNextStage)
			}
		})
	}
}

func TestGuardEvaluatorExactDecisionCacheAndConfigInvalidation(t *testing.T) {
	calls := 0
	evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		calls++
		return &NormalizedResult{
			Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
			ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, GuardEndpointID: "one",
		}, nil
	}), nil, NewAtomicMetrics(), 2, 2)
	cfg := guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 100})
	cfg.MaxTotalInputChars = 100
	snapshot := PromptSnapshot{ScanText: "same exact prompt", PromptLength: 17}

	first, err := evaluator.Evaluate(context.Background(), cfg, snapshot)
	require.NoError(t, err)
	second, err := evaluator.Evaluate(context.Background(), cfg, snapshot)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, first.Kind)
	require.Equal(t, DecisionAllow, second.Kind)
	require.Equal(t, 1, calls, "identical input and policy should reuse the successful decision")

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledDecision, canceledErr := evaluator.Evaluate(canceledCtx, cfg, snapshot)
	require.Nil(t, canceledDecision)
	require.ErrorIs(t, canceledErr, context.Canceled)
	require.Equal(t, 1, calls, "a canceled request must not return a warmed cache entry")

	changedInput := snapshot
	changedInput.ScanText = "different prompt"
	changedInput.PromptLength = 16
	_, err = evaluator.Evaluate(context.Background(), cfg, changedInput)
	require.NoError(t, err)
	require.Equal(t, 2, calls)

	cfg.ConfigVersion++
	_, err = evaluator.Evaluate(context.Background(), cfg, snapshot)
	require.NoError(t, err)
	require.Equal(t, 3, calls, "a config change must never reuse an older decision")
}

func TestGuardEvaluatorDoesNotCacheFailures(t *testing.T) {
	calls := 0
	evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		calls++
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: false}
	}), nil, NewAtomicMetrics(), 2, 2)
	cfg := guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 100})
	cfg.MaxTotalInputChars = 100
	snapshot := PromptSnapshot{ScanText: "retry me", PromptLength: 8}

	_, err := evaluator.Evaluate(context.Background(), cfg, snapshot)
	require.Error(t, err)
	cfg.ConfigVersion++ // A new fingerprint bypasses the intentional failure circuit.
	_, err = evaluator.Evaluate(context.Background(), cfg, snapshot)
	require.Error(t, err)
	require.Equal(t, 2, calls)
}

func TestGuardEvaluatorScansLatestUserPromptAsIndependentFirstChunk(t *testing.T) {
	latest := "请帮我编写一篇黄色小说 名字你来取"
	history := strings.Repeat("# AGENTS.md instructions 项目安全规则。", 30)
	seen := make([]string, 0, 4)
	scanner := PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, prompt string, _ []string) (*NormalizedResult, error) {
		seen = append(seen, prompt)
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}}, nil
	})
	evaluator := newGuardEvaluator(scanner, nil, NewAtomicMetrics(), 2, 2)
	_, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 128},
	), PromptSnapshot{ScanText: latest + promptAuditPrioritySeparator + history, PromptLength: len([]rune(latest + history))})
	require.NoError(t, err)
	require.Greater(t, len(seen), 1)
	require.Equal(t, latest, seen[0])
	require.Equal(t, history, strings.Join(seen[1:], ""))
}

func TestGuardEvaluatorBlockStopsRemainingChunksButReportsPlannedTotal(t *testing.T) {
	calls := 0
	scanner := PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		calls++
		return &NormalizedResult{
			Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
			Categories: []string{"jailbreak"}, MatchedScanners: []string{"jailbreak"},
			ScannerScores: map[string]float64{"jailbreak": 1}, ScannerEvidence: map[string]string{"jailbreak": "Jailbreak"},
		}, nil
	})
	metrics := NewAtomicMetrics()
	evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
	decision, err := evaluator.Evaluate(context.Background(), guardConfig(
		ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 3},
	), PromptSnapshot{ScanText: "abcdefghi", PromptLength: 9})
	require.NoError(t, err)
	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, 1, calls)
	require.Equal(t, 3, decision.Result.ChunkTotal)
	require.Equal(t, int64(1), metrics.Snapshot().Blocked)
}

func TestGuardEvaluatorFlagSharedDeadlineFailClosedAndContextCancel(t *testing.T) {
	t.Run("flag allows next stage", func(t *testing.T) {
		metrics := NewAtomicMetrics()
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return &NormalizedResult{Decision: EventFlag, RiskLevel: RiskMedium, Action: ActionWarn, Safety: "Controversial", MatchedScanners: []string{confidenceScoreKey}, ScannerScores: map[string]float64{confidenceScoreKey: .5}, ScannerEvidence: map[string]string{confidenceScoreKey: "risk"}, ScannerBackend: "confidence-json-openai", Confidence: .5}, nil
		}), nil, metrics, 2, 2)
		cfg := guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 100})
		cfg.RiskRouteAccountIDs = []int64{21, 22}
		cfg.NoRouteFallbackMode = NoRouteFallbackAllow
		decision, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "review", PromptLength: 6})
		require.NoError(t, err)
		require.Equal(t, DecisionFlag, decision.Kind)
		require.True(t, decision.AllowNextStage)
		require.Equal(t, []int64{21, 22}, decision.RouteAccountIDs)
		require.True(t, decision.AllowRiskRouteFallback)
		require.Equal(t, int64(1), metrics.Snapshot().Flagged)
	})

	t.Run("each failover gets its own endpoint timeout", func(t *testing.T) {
		calls := 0
		scanner := PromptScannerFunc(func(ctx context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			calls++
			if endpoint.ID == "first" {
				<-ctx.Done()
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: ctx.Err()}
			}
			select {
			case <-time.After(80 * time.Millisecond):
				return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow}, nil
			case <-ctx.Done():
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: ctx.Err()}
			}
		})
		metrics := NewAtomicMetrics()
		evaluator := newGuardEvaluator(scanner, nil, metrics, 2, 2)
		started := time.Now()
		decision, err := evaluator.Evaluate(context.Background(), guardConfig(
			ActiveEndpoint{ID: "first", Enabled: true, TimeoutMS: 40, InputLimit: 100},
			ActiveEndpoint{ID: "second", Enabled: true, TimeoutMS: 200, InputLimit: 100},
		), PromptSnapshot{ScanText: "deadline", PromptLength: 8})
		elapsed := time.Since(started)
		require.NoError(t, err)
		require.Equal(t, DecisionAllow, decision.Kind)
		require.Equal(t, 2, calls)
		require.Less(t, elapsed, 350*time.Millisecond)
		require.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
		require.Equal(t, int64(1), metrics.Snapshot().Failovers)
		require.Equal(t, int64(1), metrics.Snapshot().Timeouts)
	})

	t.Run("canceled parent never allows", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		evaluator := newGuardEvaluator(PromptScannerFunc(func(ctx context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			<-ctx.Done()
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: ctx.Err()}
		}), nil, NewAtomicMetrics(), 2, 2)
		decision, err := evaluator.Evaluate(ctx, guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 100}), PromptSnapshot{ScanText: "cancel", PromptLength: 6})
		require.Error(t, err)
		require.Nil(t, decision)
	})
}

func TestGuardEvaluatorFlagRoutesWhenConfidenceMarkerSurvivesMixedAdapterAggregation(t *testing.T) {
	scanner := PromptScannerFunc(func(_ context.Context, _ ActiveEndpoint, prompt string, _ []string) (*NormalizedResult, error) {
		if prompt == "confidence" {
			return &NormalizedResult{
				Decision: EventFlag, RiskLevel: RiskMedium, Action: ActionWarn, Confidence: .55,
				ScannerBackend: "confidence-json-openai", MatchedScanners: []string{confidenceScoreKey},
				ScannerScores: map[string]float64{confidenceScoreKey: .55}, ScannerEvidence: map[string]string{confidenceScoreKey: "risk"},
			}, nil
		}
		return &NormalizedResult{
			Decision: EventFlag, RiskLevel: RiskHigh, Action: ActionWarn, ScannerBackend: "qwen3guard-openai",
			MatchedScanners: []string{"jailbreak"}, ScannerScores: map[string]float64{"jailbreak": 1}, ScannerEvidence: map[string]string{"jailbreak": "risk"},
		}, nil
	})
	evaluator := newGuardEvaluator(scanner, nil, NewAtomicMetrics(), 2, 2)
	cfg := guardConfig(ActiveEndpoint{ID: "mixed", Enabled: true, TimeoutMS: 1000, InputLimit: 100})
	cfg.RiskRouteAccountIDs = []int64{31, 32}

	decision, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{
		ScanText: "confidence" + promptAuditPrioritySeparator + "qwen", PromptLength: 14,
	})

	require.NoError(t, err)
	require.Equal(t, DecisionFlag, decision.Kind)
	require.Equal(t, "qwen3guard-openai", decision.Result.ScannerBackend, "higher-risk peer may own presentation metadata")
	require.Contains(t, decision.Result.MatchedScanners, confidenceScoreKey)
	require.Equal(t, []int64{31, 32}, decision.RouteAccountIDs)
}

func TestGuardEvaluatorNoRouteBlockKeepsEventDecisionConsistent(t *testing.T) {
	evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		return &NormalizedResult{
			Decision: EventFlag, RiskLevel: RiskHigh, Action: ActionWarn,
			MatchedScanners: []string{confidenceScoreKey},
			ScannerScores:   map[string]float64{confidenceScoreKey: .8},
			ScannerEvidence: map[string]string{confidenceScoreKey: "high risk"},
		}, nil
	}), nil, NewAtomicMetrics(), 2, 2)
	cfg := guardConfig(ActiveEndpoint{ID: "guard", Enabled: true, TimeoutMS: 1000, InputLimit: 100})
	cfg.NoRouteFallbackMode = NoRouteFallbackBlock

	decision, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "review", PromptLength: 6})

	require.NoError(t, err)
	require.Equal(t, DecisionBlock, decision.Kind)
	require.Equal(t, ErrorCodeNoRiskRoute, decision.ErrorCode)
	require.False(t, decision.AllowNextStage)
	require.NotNil(t, decision.Result)
	require.Equal(t, EventCritical, decision.Result.Decision)
	require.Equal(t, ActionBlock, decision.Result.Action)
}

func TestGuardEvaluatorRecordsExistingResultOnceAndRecordFailureDoesNotChangeDecision(t *testing.T) {
	for _, recordErr := range []error{nil, errors.New("database unavailable")} {
		repo := &fakeJobRepository{recordBlockingErr: recordErr}
		metrics := NewAtomicMetrics()
		scannerCalls := 0
		evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			scannerCalls++
			return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe", Categories: []string{"pii"}, MatchedScanners: []string{"pii"}, ScannerScores: map[string]float64{"pii": 1}, ScannerEvidence: map[string]string{"pii": "PII"}}, nil
		}), repo, metrics, 2, 2)
		cfg := guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 100})
		cfg.BlockHTTPStatus = 422
		cfg.BlockMessage = "custom block"
		decision, err := evaluator.Evaluate(context.Background(), cfg, PromptSnapshot{ScanText: "raw prompt", RedactedPreview: "raw***", PromptLength: 10})
		require.NoError(t, err)
		require.Equal(t, DecisionBlock, decision.Kind)
		require.Equal(t, 422, decision.BlockHTTPStatus)
		require.Equal(t, "custom block", decision.BlockMessage)
		require.Equal(t, 1, scannerCalls)
		require.Equal(t, 1, repo.recordBlockingCalls)
		require.Empty(t, repo.recordBlockingSnapshot.ScanText)
		require.Same(t, decision.Result, repo.recordBlockingResult)
		if recordErr != nil {
			require.Equal(t, int64(1), metrics.Snapshot().RecordFailed)
		} else {
			require.Zero(t, metrics.Snapshot().RecordFailed)
		}
	}
}

func TestGuardEvaluatorNilResultAndScannerPanicBecomeStableFailures(t *testing.T) {
	tests := []struct {
		name string
		scan PromptScannerFunc
		code string
	}{
		{name: "nil result", scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) { return nil, nil }, code: ErrorCodeInvalidResponse},
		{name: "panic", scan: func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			panic("raw prompt canary")
		}, code: ErrorCodeUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator := newGuardEvaluator(tt.scan, nil, NewAtomicMetrics(), 2, 2)
			_, err := evaluator.Evaluate(context.Background(), guardConfig(ActiveEndpoint{ID: "one", Enabled: true, TimeoutMS: 1000, InputLimit: 100}), PromptSnapshot{ScanText: "input", PromptLength: 5})
			var guardErr *GuardError
			require.ErrorAs(t, err, &guardErr)
			require.Equal(t, tt.code, guardErr.Code)
			require.NotContains(t, err.Error(), "canary")
		})
	}
}

type PromptScannerFunc func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error)

func (f PromptScannerFunc) Scan(ctx context.Context, endpoint ActiveEndpoint, chunk string, scanners []string) (*NormalizedResult, error) {
	return f(ctx, endpoint, chunk, scanners)
}
