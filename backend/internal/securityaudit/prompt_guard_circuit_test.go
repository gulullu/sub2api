package securityaudit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func openTestCircuit(t *testing.T, breaker *endpointCircuitBreaker, key string, now time.Time, cooldown time.Duration) {
	t.Helper()
	permit, allowed, state, _ := breaker.allow(key, now)
	require.True(t, allowed)
	require.Equal(t, "closed", state)
	require.True(t, breaker.fail(permit, now, cooldown))
}

func TestEndpointCircuitBreakerCooldownHalfOpenReleaseAndRecovery(t *testing.T) {
	breaker := newEndpointCircuitBreaker(8)
	now := time.Unix(100, 0).UTC()
	openTestCircuit(t, breaker, "endpoint", now, time.Second)

	_, allowed, state, remaining := breaker.allow("endpoint", now.Add(500*time.Millisecond))
	require.False(t, allowed)
	require.Equal(t, "open", state)
	require.Equal(t, 500*time.Millisecond, remaining)

	permit, allowed, state, _ := breaker.allow("endpoint", now.Add(2*time.Second))
	require.True(t, allowed)
	require.Equal(t, "half_open", state)
	_, allowed, state, _ = breaker.allow("endpoint", now.Add(2*time.Second))
	require.False(t, allowed)
	require.Equal(t, "half_open_busy", state)

	breaker.release(permit)
	permit, allowed, state, _ = breaker.allow("endpoint", now.Add(2*time.Second))
	require.True(t, allowed)
	require.Equal(t, "half_open", state)
	require.True(t, breaker.succeed(permit))
	permit, allowed, state, _ = breaker.allow("endpoint", now.Add(2*time.Second))
	require.True(t, allowed)
	require.Equal(t, "closed", state)
	breaker.release(permit)
}

func TestEndpointCircuitGenerationRejectsStaleCompletions(t *testing.T) {
	now := time.Unix(110, 0).UTC()

	t.Run("stale success cannot close newer open", func(t *testing.T) {
		breaker := newEndpointCircuitBreaker(4)
		permitA, allowed, _, _ := breaker.allow("endpoint", now)
		require.True(t, allowed)
		permitB, allowed, _, _ := breaker.allow("endpoint", now)
		require.True(t, allowed)
		require.True(t, breaker.fail(permitA, now, time.Second))
		require.False(t, breaker.succeed(permitB))
		_, allowed, state, _ := breaker.allow("endpoint", now.Add(500*time.Millisecond))
		require.False(t, allowed)
		require.Equal(t, "open", state)
	})

	t.Run("stale failure cannot reopen recovered generation", func(t *testing.T) {
		breaker := newEndpointCircuitBreaker(4)
		permitA, allowed, _, _ := breaker.allow("endpoint", now)
		require.True(t, allowed)
		stalePermitB, allowed, _, _ := breaker.allow("endpoint", now)
		require.True(t, allowed)
		require.True(t, breaker.fail(permitA, now, time.Second))

		probePermit, allowed, state, _ := breaker.allow("endpoint", now.Add(2*time.Second))
		require.True(t, allowed)
		require.Equal(t, "half_open", state)
		require.True(t, breaker.succeed(probePermit))
		require.False(t, breaker.fail(stalePermitB, now.Add(3*time.Second), time.Minute))

		currentPermit, allowed, state, _ := breaker.allow("endpoint", now.Add(3*time.Second))
		require.True(t, allowed)
		require.Equal(t, "closed", state)
		breaker.release(currentPermit)
	})
}

func TestEndpointCircuitCapacityNeverEvictsLiveHalfOpenOwner(t *testing.T) {
	breaker := newEndpointCircuitBreaker(1)
	now := time.Unix(120, 0).UTC()
	openTestCircuit(t, breaker, "primary", now, time.Second)
	probePermit, allowed, state, _ := breaker.allow("primary", now.Add(2*time.Second))
	require.True(t, allowed)
	require.Equal(t, "half_open", state)

	otherPermit, allowed, _, _ := breaker.allow("other", now.Add(2*time.Second))
	require.True(t, allowed, "capacity is soft while the only existing entry is live")
	_, allowed, state, _ = breaker.allow("primary", now.Add(2*time.Second))
	require.False(t, allowed)
	require.Equal(t, "half_open_busy", state)

	breaker.release(otherPermit)
	require.True(t, breaker.succeed(probePermit))
}

func TestEndpointCircuitCapacityNeverEvictsUnexpiredCooldown(t *testing.T) {
	breaker := newEndpointCircuitBreaker(1)
	now := time.Unix(125, 0).UTC()
	openTestCircuit(t, breaker, "primary", now, time.Minute)

	otherPermit, allowed, state, _ := breaker.allow("other", now.Add(time.Second))
	require.True(t, allowed, "capacity is soft while the existing entry is cooling down")
	require.Equal(t, "closed", state)
	breaker.release(otherPermit)

	_, allowed, state, remaining := breaker.allow("primary", now.Add(time.Second))
	require.False(t, allowed)
	require.Equal(t, "open", state)
	require.Equal(t, 59*time.Second, remaining)
}

func TestEndpointCircuitCapacityNeverEvictsExpiredUnprobedState(t *testing.T) {
	breaker := newEndpointCircuitBreaker(1)
	now := time.Unix(130, 0).UTC()
	openTestCircuit(t, breaker, "primary", now, time.Second)

	otherPermit, allowed, _, _ := breaker.allow("other", now.Add(2*time.Second))
	require.True(t, allowed)
	breaker.release(otherPermit)

	probePermit, allowed, state, _ := breaker.allow("primary", now.Add(2*time.Second))
	require.True(t, allowed)
	require.Equal(t, "half_open", state)
	_, allowed, state, _ = breaker.allow("primary", now.Add(2*time.Second))
	require.False(t, allowed)
	require.Equal(t, "half_open_busy", state)
	breaker.release(probePermit)
}

func TestEndpointCircuitFingerprintAndFailurePolicies(t *testing.T) {
	endpoint := ActiveEndpoint{ID: "guard", Priority: 1, BaseURL: "https://guard.example.test/v1", Model: "model", Token: "token-one", TimeoutMS: 1000, InputLimit: 1000}
	base := endpointCircuitKey(7, endpoint)
	require.NotEqual(t, base, endpointCircuitKey(8, endpoint))
	endpoint.Token = "token-two"
	require.NotEqual(t, base, endpointCircuitKey(7, endpoint))
	endpoint.Token = "token-one"
	endpoint.Priority = 2
	require.NotEqual(t, base, endpointCircuitKey(7, endpoint))

	for _, tt := range []struct {
		name     string
		err      error
		class    string
		cooldown time.Duration
		open     bool
	}{
		{name: "payment", err: &GuardError{HTTPStatus: 402}, class: "auth_payment", cooldown: authPaymentCircuitCooldown, open: true},
		{name: "forbidden", err: &GuardError{HTTPStatus: 403}, class: "auth_payment", cooldown: authPaymentCircuitCooldown, open: true},
		{name: "not found", err: &GuardError{HTTPStatus: 404}, class: "configuration", cooldown: configurationCircuitCooldown, open: true},
		{name: "rate limit", err: &GuardError{HTTPStatus: 429}, class: "rate_limit", cooldown: rateLimitCircuitCooldown, open: true},
		{name: "upstream", err: &GuardError{HTTPStatus: 503}, class: "http_upstream", cooldown: transientCircuitCooldown, open: true},
		{name: "invalid", err: &GuardError{Code: ErrorCodeInvalidResponse}, class: "invalid_response"},
		{name: "ordinary 4xx", err: &GuardError{HTTPStatus: 418}, class: "http_client"},
		{name: "timeout", err: &GuardError{Timeout: true}, class: "timeout", cooldown: transientCircuitCooldown, open: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			class, cooldown, open := endpointFailurePolicy(tt.err)
			require.Equal(t, tt.class, class)
			require.Equal(t, tt.cooldown, cooldown)
			require.Equal(t, tt.open, open)
		})
	}
}

func TestEndpointFailoverReleasesPermitOnParentCancelBulkheadAndLocalInvalid(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	endpoint := ActiveEndpoint{ID: "guard", Priority: 1, Enabled: true, TimeoutMS: 1000, InputLimit: 100}
	cfg := guardConfig(endpoint)
	key := endpointCircuitKey(cfg.ConfigVersion, endpoint)

	t.Run("parent cancellation", func(t *testing.T) {
		breaker := newEndpointCircuitBreaker(4)
		openTestCircuit(t, breaker, key, now.Add(-2*time.Second), time.Second)
		entered := make(chan struct{})
		executor := newEndpointFailoverExecutor(PromptScannerFunc(func(ctx context.Context, _ ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
			close(entered)
			<-ctx.Done()
			return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: ctx.Err()}
		}), NewAtomicMetrics(), breaker, func() time.Time { return now }, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := executor.scanChunk(ctx, cfg, []ActiveEndpoint{endpoint}, "input", newEndpointFailoverState(), nil)
			done <- err
		}()
		<-entered
		cancel()
		err := <-done
		require.True(t, errors.Is(err, context.Canceled))
		permit, allowed, state, _ := breaker.allow(key, now)
		require.True(t, allowed)
		require.Equal(t, "half_open", state)
		breaker.release(permit)
	})

	t.Run("local bulkhead", func(t *testing.T) {
		breaker := newEndpointCircuitBreaker(4)
		openTestCircuit(t, breaker, key, now.Add(-2*time.Second), time.Second)
		metrics := NewAtomicMetrics()
		executor := newEndpointFailoverExecutor(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			t.Fatal("bulkhead rejection must not call scanner")
			return nil, nil
		}), metrics, breaker, func() time.Time { return now }, func(context.Context, ActiveEndpoint) (func(), bool, error) {
			return nil, false, nil
		})
		_, err := executor.scanChunk(context.Background(), cfg, []ActiveEndpoint{endpoint}, "input", newEndpointFailoverState(), nil)
		require.Error(t, err)
		require.Zero(t, metrics.Snapshot().CircuitOpen)
		permit, allowed, state, _ := breaker.allow(key, now)
		require.True(t, allowed)
		require.Equal(t, "half_open", state)
		breaker.release(permit)
	})

	t.Run("half-open invalid response", func(t *testing.T) {
		breaker := newEndpointCircuitBreaker(4)
		openTestCircuit(t, breaker, key, now.Add(-2*time.Second), time.Second)
		executor := newEndpointFailoverExecutor(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse}
		}), NewAtomicMetrics(), breaker, func() time.Time { return now }, nil)
		_, err := executor.scanChunk(context.Background(), cfg, []ActiveEndpoint{endpoint}, "input", newEndpointFailoverState(), nil)
		require.Error(t, err)
		permit, allowed, state, _ := breaker.allow(key, now)
		require.True(t, allowed, "local-only failure must release the half-open owner")
		require.Equal(t, "half_open", state)
		breaker.release(permit)
	})
}

func TestExactProbeIdentityResetsCircuitAndStaleFailureCannotReopen(t *testing.T) {
	now := time.Unix(250, 0).UTC()
	endpoint := ActiveEndpoint{
		ID: "guard", Name: "Guard", Priority: 3, Protocol: "openai_compatible", Adapter: AdapterConfidenceJSON,
		BaseURL: "https://guard.example.test/v1", Model: "model", Token: "token", TimeoutMS: 1000, InputLimit: 1000,
		PromptTemplateID: "default", SystemPrompt: "policy", FlagThreshold: .4, BlockThreshold: .7, Enabled: true,
	}
	cfg := ActiveConfig{ConfigVersion: 9, Endpoints: []ActiveEndpoint{endpoint}}
	breaker := newEndpointCircuitBreaker(4)
	key := endpointCircuitKey(cfg.ConfigVersion, endpoint)
	stalePermit, allowed, _, _ := breaker.allow(key, now)
	require.True(t, allowed)
	openPermit, allowed, _, _ := breaker.allow(key, now)
	require.True(t, allowed)
	require.True(t, breaker.fail(openPermit, now, time.Minute))

	service := &PromptService{
		config: &fakeConfigStore{cfg: cfg, active: true}, circuit: breaker,
		metrics: NewAtomicMetrics(), clock: fixedClock{now: now.Add(time.Second)},
	}
	service.resetCircuitAfterExactProbe(endpoint)
	require.False(t, breaker.fail(stalePermit, now.Add(2*time.Second), time.Minute), "pre-probe stale failure cannot reopen reset generation")
	currentPermit, allowed, state, _ := breaker.allow(key, now.Add(2*time.Second))
	require.True(t, allowed)
	require.Equal(t, "closed", state)
	require.Equal(t, int64(1), service.metrics.Snapshot().CircuitReset)
	require.True(t, breaker.fail(currentPermit, now.Add(2*time.Second), time.Minute))

	mismatch := endpoint
	mismatch.Token = "temporary-token"
	service.resetCircuitAfterExactProbe(mismatch)
	_, allowed, state, _ = breaker.allow(key, now.Add(3*time.Second))
	require.False(t, allowed, "temporary or draft credentials must not reset the saved endpoint circuit")
	require.Equal(t, "open", state)
}

func TestEndpointCircuitBreakerConcurrentTransitions(t *testing.T) {
	breaker := newEndpointCircuitBreaker(32)
	now := time.Unix(300, 0).UTC()
	var wg sync.WaitGroup
	for index := 0; index < 256; index++ {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			permit, allowed, _, _ := breaker.allow("endpoint", now.Add(time.Duration(index)*time.Millisecond))
			if !allowed {
				return
			}
			switch index % 3 {
			case 0:
				breaker.fail(permit, now, time.Millisecond)
			case 1:
				breaker.release(permit)
			default:
				breaker.succeed(permit)
			}
		}()
	}
	wg.Wait()
}
