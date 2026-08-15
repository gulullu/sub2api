package securityaudit

import (
	"context"
	"errors"
	"time"
)

type endpointFailureSummary struct {
	observed     bool
	allInvalid   bool
	anyRetryable bool
	anyTimeout   bool
}

func (s *endpointFailureSummary) add(err error) {
	if s == nil || err == nil {
		return
	}
	code := guardErrorCode(err)
	if !s.observed {
		s.allInvalid = true
	}
	s.observed = true
	if code != ErrorCodeInvalidResponse {
		s.allInvalid = false
	}
	var guardErr *GuardError
	if errors.As(err, &guardErr) {
		s.anyRetryable = s.anyRetryable || guardErr.Retryable
		s.anyTimeout = s.anyTimeout || guardErr.Timeout
	}
}

func (s endpointFailureSummary) err() error {
	code := ErrorCodeUnavailable
	if s.observed && s.allInvalid {
		code = ErrorCodeInvalidResponse
	}
	return &GuardError{Code: code, Retryable: s.anyRetryable, Timeout: s.anyTimeout}
}

type endpointFailoverState struct {
	failed            map[string]struct{}
	preferred         string
	failures          endpointFailureSummary
	budgetRemaining   time.Duration
	budgetInitialized bool
}

type guardEndpointCandidate struct {
	endpoint ActiveEndpoint
	key      string
}

type endpointAcquireFunc func(context.Context, ActiveEndpoint) (release func(), acquired bool, err error)

// Shared by synchronous Guard and asynchronous workers so both paths use the
// same priority, timeout, validation, request affinity, failure aggregation,
// and circuit semantics.
type endpointFailoverExecutor struct {
	scanner PromptScanner
	metrics Metrics
	circuit *endpointCircuitBreaker
	now     func() time.Time
	acquire endpointAcquireFunc
}

func newEndpointFailoverExecutor(scanner PromptScanner, metrics Metrics, circuit *endpointCircuitBreaker, now func() time.Time, acquire endpointAcquireFunc) *endpointFailoverExecutor {
	if circuit == nil {
		circuit = newEndpointCircuitBreaker(defaultEndpointCircuitCapacity)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &endpointFailoverExecutor{scanner: scanner, metrics: metrics, circuit: circuit, now: now, acquire: acquire}
}

func newEndpointFailoverState() *endpointFailoverState {
	return &endpointFailoverState{failed: make(map[string]struct{})}
}

func (e *endpointFailoverExecutor) scanChunk(callerCtx context.Context, cfg ActiveConfig, endpoints []ActiveEndpoint, chunk string, state *endpointFailoverState, baseFields map[string]any) (*NormalizedResult, error) {
	if err := callerCtx.Err(); err != nil {
		e.observeContextTimeout(err)
		return nil, parentGuardContextError(err)
	}
	if state == nil {
		state = newEndpointFailoverState()
	}
	if state.failed == nil {
		state.failed = make(map[string]struct{})
	}
	if state.budgetInitialized && state.budgetRemaining <= 0 {
		e.observeRequestBudgetTimeout(state)
		return nil, state.failures.err()
	}
	candidates := orderedGuardCandidates(cfg.ConfigVersion, endpoints, state)
	for index, candidate := range candidates {
		if err := callerCtx.Err(); err != nil {
			e.observeContextTimeout(err)
			return nil, parentGuardContextError(err)
		}
		if state.budgetInitialized && state.budgetRemaining <= 0 {
			e.observeRequestBudgetTimeout(state)
			return nil, state.failures.err()
		}
		endpoint, circuitKey := candidate.endpoint, candidate.key
		permit, allowed, circuitState, remaining := e.circuit.allow(circuitKey, e.now())
		if !allowed {
			err := &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
			state.failed[circuitKey] = struct{}{}
			state.failures.add(err)
			if e.metrics != nil {
				e.metrics.IncCircuitSkip()
			}
			LogWarn(EventEndpointCircuitSkip, mergeLogFields(baseFields, map[string]any{
				"config_version": cfg.ConfigVersion, "guard_endpoint_id": endpoint.ID, "endpoint_priority": endpoint.Priority,
				"circuit_state": circuitState, "circuit_cooldown_ms": remaining.Milliseconds(), "status": "skipped",
				"error_code": ErrorCodeUnavailable,
			}))
			e.observeFailover(baseFields, cfg.ConfigVersion, endpoint, candidates, index)
			continue
		}

		release := func() {}
		if e.acquire != nil {
			var acquired bool
			var acquireErr error
			release, acquired, acquireErr = e.acquire(callerCtx, endpoint)
			if acquireErr != nil {
				e.circuit.release(permit)
				if callerErr := callerCtx.Err(); callerErr != nil {
					e.observeContextTimeout(callerErr)
					return nil, parentGuardContextError(callerErr)
				}
				return nil, parentGuardContextError(acquireErr)
			}
			if !acquired {
				e.circuit.release(permit)
				err := &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
				state.failed[circuitKey] = struct{}{}
				state.failures.add(err)
				if e.metrics != nil {
					e.metrics.IncBulkheadFull()
				}
				e.logEndpointFailure(baseFields, cfg.ConfigVersion, endpoint, err, "bulkhead", "closed", 0, 0)
				e.observeFailover(baseFields, cfg.ConfigVersion, endpoint, candidates, index)
				continue
			}
			if release == nil {
				release = func() {}
			}
		}

		attemptStarted := e.now()
		if !state.budgetInitialized {
			state.budgetRemaining = endpointRequestBudget(endpoints)
			state.budgetInitialized = true
		}
		if state.budgetRemaining <= 0 {
			release()
			e.circuit.release(permit)
			e.observeRequestBudgetTimeout(state)
			return nil, state.failures.err()
		}
		timeout := endpointTimeout(endpoint)
		allowance := timeout
		if state.budgetRemaining < allowance {
			allowance = state.budgetRemaining
		}
		fullNodeAllowance := allowance == timeout
		scanStarted := time.Now()
		endpointCtx, cancel := context.WithDeadline(callerCtx, scanStarted.Add(allowance))
		result, scanErr := callPromptScanner(endpointCtx, e.scanner, endpoint, chunk, cfg.Scanners)
		scanElapsed := time.Since(scanStarted)
		state.consumeBudget(scanElapsed, allowance)
		endpointContextErr := endpointCtx.Err()
		cancel()
		release()
		if parentErr := callerCtx.Err(); parentErr != nil {
			e.circuit.release(permit)
			e.observeContextTimeout(parentErr)
			return nil, parentGuardContextError(parentErr)
		}
		deadlineExpired := errors.Is(endpointContextErr, context.DeadlineExceeded) || scanElapsed >= allowance
		requestBudgetTimeout := deadlineExpired && !fullNodeAllowance
		if deadlineExpired {
			scanErr = &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: context.DeadlineExceeded}
			result = nil
		}
		if scanErr == nil && result != nil {
			if validationErr := validateGuardResult(result); validationErr != nil {
				scanErr, result = validationErr, nil
			}
		}
		if scanErr == nil && result != nil {
			if result.GuardEndpointID == "" {
				result.GuardEndpointID = endpoint.ID
			}
			state.preferred = circuitKey
			if e.circuit.succeed(permit) {
				if e.metrics != nil {
					e.metrics.IncCircuitReset()
				}
				LogInfo(EventEndpointRecovered, mergeLogFields(baseFields, map[string]any{
					"config_version": cfg.ConfigVersion, "guard_endpoint_id": endpoint.ID,
					"endpoint_priority": endpoint.Priority, "circuit_state": "closed", "status": "recovered",
				}))
			}
			return result, nil
		}
		if scanErr == nil {
			scanErr = &GuardError{Code: ErrorCodeInvalidResponse}
		}
		state.failed[circuitKey] = struct{}{}
		state.failures.add(scanErr)
		if e.metrics != nil {
			var guardErr *GuardError
			if errors.As(scanErr, &guardErr) && guardErr.Timeout {
				e.metrics.IncTimeout()
			}
		}
		failureClass, cooldown, shouldOpen := endpointFailurePolicy(scanErr)
		if requestBudgetTimeout {
			failureClass, cooldown, shouldOpen = "request_budget_timeout", 0, false
		}
		circuitOutcome := circuitState
		if shouldOpen && e.circuit.fail(permit, e.now(), cooldown) {
			circuitOutcome = "open"
			if e.metrics != nil {
				e.metrics.IncCircuitOpen()
			}
		} else {
			e.circuit.release(permit)
		}
		e.logEndpointFailure(baseFields, cfg.ConfigVersion, endpoint, scanErr, failureClass, circuitOutcome, cooldown, e.now().Sub(attemptStarted))
		if requestBudgetTimeout || state.budgetRemaining <= 0 {
			return nil, state.failures.err()
		}
		e.observeFailover(baseFields, cfg.ConfigVersion, endpoint, candidates, index)
	}
	if err := callerCtx.Err(); err != nil {
		e.observeContextTimeout(err)
		return nil, parentGuardContextError(err)
	}
	return nil, state.failures.err()
}

func (s *endpointFailoverState) consumeBudget(elapsed, allowance time.Duration) {
	if s == nil || !s.budgetInitialized || elapsed <= 0 || allowance <= 0 {
		return
	}
	if elapsed > allowance {
		elapsed = allowance
	}
	if elapsed > s.budgetRemaining {
		elapsed = s.budgetRemaining
	}
	s.budgetRemaining -= elapsed
}

func (e *endpointFailoverExecutor) observeRequestBudgetTimeout(state *endpointFailoverState) {
	err := &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: true, Cause: context.DeadlineExceeded}
	state.failures.add(err)
	if e != nil && e.metrics != nil {
		e.metrics.IncTimeout()
	}
}

func (e *endpointFailoverExecutor) observeContextTimeout(err error) {
	if e != nil && e.metrics != nil && errors.Is(err, context.DeadlineExceeded) {
		e.metrics.IncTimeout()
	}
}

func endpointTimeout(endpoint ActiveEndpoint) time.Duration {
	timeout := time.Duration(endpoint.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultTimeoutMS * time.Millisecond
	}
	return timeout
}

func endpointRequestBudget(endpoints []ActiveEndpoint) time.Duration {
	var total time.Duration
	for _, endpoint := range endpoints {
		timeout := endpointTimeout(endpoint)
		if time.Duration(1<<63-1)-total < timeout {
			return time.Duration(1<<63 - 1)
		}
		total += timeout
	}
	if total <= 0 {
		return DefaultTimeoutMS * time.Millisecond
	}
	return total
}

func orderedGuardCandidates(configVersion int64, endpoints []ActiveEndpoint, state *endpointFailoverState) []guardEndpointCandidate {
	all := make([]guardEndpointCandidate, 0, len(endpoints))
	for _, endpoint := range endpoints {
		key := endpointCircuitKey(configVersion, endpoint)
		if state != nil {
			if _, failed := state.failed[key]; failed {
				continue
			}
		}
		all = append(all, guardEndpointCandidate{endpoint: endpoint, key: key})
	}
	if state == nil || state.preferred == "" || len(all) < 2 {
		return all
	}
	preferredIndex := -1
	for index := range all {
		if all[index].key == state.preferred {
			preferredIndex = index
			break
		}
	}
	if preferredIndex <= 0 {
		return all
	}
	ordered := make([]guardEndpointCandidate, 0, len(all))
	ordered = append(ordered, all[preferredIndex:]...)
	ordered = append(ordered, all[:preferredIndex]...)
	return ordered
}

func validateGuardResult(result *NormalizedResult) error {
	if result == nil {
		return &GuardError{Code: ErrorCodeInvalidResponse}
	}
	valid := false
	switch result.Decision {
	case EventPass:
		valid = result.Action == ActionAllow
	case EventFlag:
		valid = result.Action == ActionWarn
	case EventCritical:
		valid = result.Action == ActionBlock
	}
	if !valid {
		return &GuardError{Code: ErrorCodeInvalidResponse}
	}
	switch result.RiskLevel {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return nil
	default:
		return &GuardError{Code: ErrorCodeInvalidResponse}
	}
}

func parentGuardContextError(err error) error {
	return &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: errors.Is(err, context.DeadlineExceeded), Cause: err}
}

func (e *endpointFailoverExecutor) logEndpointFailure(baseFields map[string]any, configVersion int64, endpoint ActiveEndpoint, err error, failureClass, circuitState string, cooldown, latency time.Duration) {
	fields := mergeLogFields(baseFields, safeGuardErrorFields(err))
	fields = mergeLogFields(fields, map[string]any{
		"config_version": configVersion, "guard_endpoint_id": endpoint.ID, "endpoint_priority": endpoint.Priority,
		"failure_class": failureClass, "circuit_state": circuitState, "circuit_cooldown_ms": cooldown.Milliseconds(),
		"latency_ms": latency.Milliseconds(), "status": "failed",
	})
	LogWarn(EventEndpointFailed, fields)
}

func (e *endpointFailoverExecutor) observeFailover(baseFields map[string]any, configVersion int64, endpoint ActiveEndpoint, candidates []guardEndpointCandidate, index int) {
	if index >= len(candidates)-1 {
		return
	}
	next := candidates[index+1].endpoint
	if e.metrics != nil {
		e.metrics.IncFailover()
	}
	LogWarn(EventEndpointFailover, mergeLogFields(baseFields, map[string]any{
		"config_version": configVersion, "guard_endpoint_id": endpoint.ID, "endpoint_priority": endpoint.Priority,
		"next_guard_endpoint_id": next.ID, "next_endpoint_priority": next.Priority, "status": "failover",
	}))
}

func callPromptScanner(ctx context.Context, scanner PromptScanner, endpoint ActiveEndpoint, chunk string, scanners []string) (result *NormalizedResult, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = &GuardError{Code: ErrorCodeUnavailable, Retryable: false}
		}
	}()
	return scanner.Scan(ctx, endpoint, chunk, scanners)
}
