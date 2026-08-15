package service

import (
	"context"
	"errors"
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
	accountIDs map[int64]struct{}
}

// WithPromptRiskRouteAccounts installs a hard upstream account allowlist.
// Empty/invalid input removes no capacity and leaves the context unchanged.
func WithPromptRiskRouteAccounts(ctx context.Context, accountIDs []int64) context.Context {
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
	return context.WithValue(ctx, promptRiskRouteContextKey{}, promptRiskRoutePool{accountIDs: pool})
}

// PromptRiskRouteEnabled reports whether prompt audit installed a hard pool.
func PromptRiskRouteEnabled(ctx context.Context) bool {
	pool, ok := promptRiskRoutePoolFromContext(ctx)
	return ok && len(pool.accountIDs) > 0
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
