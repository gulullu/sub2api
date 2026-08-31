package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// ErrPromptRiskRouteStateConflict means a request carries upstream-affine
// state that is pinned to an account outside the audit-selected hard pool and
// cannot safely move. Callers surface it as retryable service unavailability;
// they must not strip or replay the state on another account.
var ErrPromptRiskRouteStateConflict = errors.New("prompt risk route state conflict")

// ErrPromptRiskRouteUnavailable identifies exhaustion of the audit-selected
// hard pool. It is intentionally distinct from model-not-found so handlers
// keep it on 503 and operators can distinguish it in logs.
var ErrPromptRiskRouteUnavailable = errors.New("prompt risk route account pool unavailable")

type promptRiskRouteUnavailableError struct {
	cause error
}

func (e promptRiskRouteUnavailableError) Error() string {
	if e.cause == nil {
		return ErrPromptRiskRouteUnavailable.Error()
	}
	return ErrPromptRiskRouteUnavailable.Error() + ": " + e.cause.Error()
}

func (e promptRiskRouteUnavailableError) Unwrap() error { return e.cause }

func (e promptRiskRouteUnavailableError) Is(target error) bool {
	return target == ErrPromptRiskRouteUnavailable
}

func normalizePromptRiskRouteSelectionError(ctx context.Context, err error) error {
	if IsPromptRiskRouteFallbackResult(err) {
		return err
	}
	if err == nil || !PromptRiskRouteEnabled(ctx) || errors.Is(err, ErrPromptRiskRouteStateConflict) || errors.Is(err, ErrPromptRiskRouteUnavailable) {
		return err
	}
	if errors.Is(err, ErrNoAvailableAccounts) || errors.Is(err, ErrNoAvailableCompactAccounts) {
		return newPromptRiskRouteUnavailableError(err)
	}
	return err
}

func newPromptRiskRouteUnavailableError(cause error) error {
	return infraerrors.New(
		http.StatusServiceUnavailable,
		"PROMPT_RISK_ROUTE_UNAVAILABLE",
		"Service temporarily unavailable",
	).WithCause(promptRiskRouteUnavailableError{cause: cause})
}

func newPromptRiskRouteStateConflictError() error {
	return infraerrors.New(
		http.StatusServiceUnavailable,
		"PROMPT_RISK_ROUTE_STATE_CONFLICT",
		"Service temporarily unavailable",
	).WithCause(ErrPromptRiskRouteStateConflict)
}

// promptRiskRouteContextKey is deliberately private to the server process.
// Only a completed prompt-audit decision can install this value; client
// headers and request JSON are never consulted by the routing layer.
type promptRiskRouteContextKey struct{}

type promptRiskRoutePool struct {
	accountIDs    map[int64]struct{}
	allowFallback bool
}

// WithPromptRiskRouteAccounts installs a hard upstream account allowlist.
// Empty/invalid input removes no capacity and leaves the context unchanged.
func WithPromptRiskRouteAccounts(ctx context.Context, accountIDs []int64) context.Context {
	return WithPromptRiskRoutePolicy(ctx, accountIDs, false)
}

// WithPromptRiskRoutePolicy installs the audit-selected hard pool together
// with its per-group runtime exhaustion policy. The fallback bit is entirely
// server-derived and cannot be supplied by client input.
func WithPromptRiskRoutePolicy(ctx context.Context, accountIDs []int64, allowFallback bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	pool := make(map[int64]struct{}, len(accountIDs))
	for _, accountID := range accountIDs {
		if accountID > 0 {
			pool[accountID] = struct{}{}
		}
	}
	if len(pool) == 0 {
		return ctx
	}
	return context.WithValue(ctx, promptRiskRouteContextKey{}, promptRiskRoutePool{
		accountIDs: pool, allowFallback: allowFallback,
	})
}

// PromptRiskRouteEnabled reports whether prompt audit installed a hard pool.
func PromptRiskRouteEnabled(ctx context.Context) bool {
	pool, ok := promptRiskRoutePoolFromContext(ctx)
	return ok && len(pool.accountIDs) > 0
}

// PromptRiskRouteFallbackAllowed reports whether the effective audit-group
// policy permits a one-shot retry through the ordinary pool after the hard
// pool is genuinely exhausted.
func PromptRiskRouteFallbackAllowed(ctx context.Context) bool {
	pool, ok := promptRiskRoutePoolFromContext(ctx)
	return ok && len(pool.accountIDs) > 0 && pool.allowFallback
}

// PromptRiskRouteAllowsAccount is true when routing is unrestricted or the
// account is in the server-installed hard pool.
func PromptRiskRouteAllowsAccount(ctx context.Context, accountID int64) bool {
	pool, ok := promptRiskRoutePoolFromContext(ctx)
	if !ok || len(pool.accountIDs) == 0 {
		return true
	}
	_, allowed := pool.accountIDs[accountID]
	return allowed
}

func promptRiskRoutePoolFromContext(ctx context.Context) (promptRiskRoutePool, bool) {
	if ctx == nil {
		return promptRiskRoutePool{}, false
	}
	pool, ok := ctx.Value(promptRiskRouteContextKey{}).(promptRiskRoutePool)
	return pool, ok
}

// withoutPromptRiskRoute shadows the current hard pool for the single
// ordinary-pool retry. The original request context remains unchanged.
func withoutPromptRiskRoute(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, promptRiskRouteContextKey{}, promptRiskRoutePool{})
}

type promptRiskRouteFallbackResultError struct {
	cause error
}

func (e promptRiskRouteFallbackResultError) Error() string {
	if e.cause == nil {
		return "prompt risk route fallback failed"
	}
	return e.cause.Error()
}

func (e promptRiskRouteFallbackResultError) Unwrap() error { return e.cause }

// IsPromptRiskRouteFallbackResult lets handlers distinguish an ordinary-pool
// retry result from a still-strict hard-pool failure even though their request
// context intentionally retains the original audit decision.
func IsPromptRiskRouteFallbackResult(err error) bool {
	var target promptRiskRouteFallbackResultError
	return errors.As(err, &target)
}

// selectWithPromptRiskRouteFallback executes the normal hard-pool selection
// first. Only a dedicated hard-pool exhaustion error and an explicit per-group
// allow policy trigger one ordinary-pool retry. State conflicts and arbitrary
// repository errors never fail open.
func selectWithPromptRiskRouteFallback[T any](ctx context.Context, selectOnce func(context.Context) (T, error)) (T, error) {
	value, err := selectOnce(ctx)
	err = normalizePromptRiskRouteSelectionError(ctx, err)
	if err == nil || !PromptRiskRouteFallbackAllowed(ctx) || !errors.Is(err, ErrPromptRiskRouteUnavailable) {
		return value, err
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return value, ctxErr
	}

	slog.Warn("prompt_risk_route.fallback_to_normal_pool", "reason", "runtime_pool_unavailable")
	fallbackCtx := withoutPromptRiskRoute(ctx)
	value, err = selectOnce(fallbackCtx)
	err = normalizePromptRiskRouteSelectionError(fallbackCtx, err)
	if err != nil {
		return value, promptRiskRouteFallbackResultError{cause: err}
	}
	return value, nil
}
